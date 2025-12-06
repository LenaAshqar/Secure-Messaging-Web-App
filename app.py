from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from datetime import datetime
import logging
import json
import hashlib
import uuid
import base64
import encryptionUtility as eu   # your existing module

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "demo-secret-key-change-me"
logging.basicConfig(level=logging.INFO)

# -------------------------------------------------------
# SERVER-SIDE key store (CRITICAL fix)
# -------------------------------------------------------
KEY_STORE = {}
# username -> {"priv_pem": str, "pub_pem": str}

# Public directory (used by sender)
PUBLIC_KEYS = {}               # username -> pub_pem
TRUSTED_FINGERPRINTS = {}      # username -> fingerprint  (key pinning)
MESSAGES = []                  # stored encrypted bundles

VALID_USERS = ["alice", "bob", "mallory"]

# Toggle this TRUE if you want MITM to succeed anyway
ALLOW_UNPINNED = False


# -------------------------------------------------------
# Helpers
# -------------------------------------------------------
def fingerprint_pem(pem_str: str) -> str:
    """Short fingerprint for key pinning."""
    h = hashlib.sha256(pem_str.encode("utf-8")).hexdigest()
    return h[:24]


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def make_transport_bundle(ct, nonce, esk, signature, sender_pub_pem, timestamp, message_id):
    """A canonical JSON-safe bundle."""
    return {
        "ciphertext": b64e(ct),
        "nonce": b64e(nonce),
        "enc_session_key": b64e(esk),
        "signature": b64e(signature),
        "sender_pub_pem": sender_pub_pem,
        "timestamp": timestamp,
        "message_id": message_id
    }


def parse_transport_bundle(bundle_json):
    """Decode a bundle back into bytes."""
    return {
        "ciphertext": b64d(bundle_json["ciphertext"]),
        "nonce": b64d(bundle_json["nonce"]),
        "enc_session_key": b64d(bundle_json["enc_session_key"]),
        "signature": b64d(bundle_json["signature"]),
        "sender_pub_pem": bundle_json["sender_pub_pem"],
        "timestamp": bundle_json.get("timestamp"),
        "message_id": bundle_json.get("message_id")
    }


def signing_material_from_bundle(b):
    """Both encrypt & decrypt use the *same* bytes for signatures."""
    return b["ciphertext"] + b["nonce"] + b["enc_session_key"]


# -------------------------------------------------------
# Disable caching
# -------------------------------------------------------
@app.after_request
def add_header(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


# -------------------------------------------------------
# LOGIN / SESSION
# -------------------------------------------------------
@app.route("/", methods=["GET"])
def landing():
    return render_template("login.html", users=VALID_USERS)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip().lower()
    if username not in VALID_USERS:
        return render_template("login.html", users=VALID_USERS, error="Invalid username")

    session.clear()
    session["logged_in"] = True
    session["username"] = username

    # Generate a new keypair for this user's session (server-side)
    priv, pub = eu.generate_rsa_keypair()
    priv_pem = eu.serialize_private_key_to_pem(priv).decode()
    pub_pem = eu.serialize_public_key_to_pem(pub).decode()

    KEY_STORE[username] = {
        "priv_pem": priv_pem,
        "pub_pem": pub_pem
    }

    app.logger.info(f"[LOGIN] {username} logged in, keypair generated.")
    return redirect(url_for("app_page"))


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("landing"))


@app.route("/app", methods=["GET"])
def app_page():
    if not session.get("logged_in"):
        return redirect(url_for("landing"))
    return render_template("index.html", username=session["username"], users=VALID_USERS)


# -------------------------------------------------------
# KEY MANAGEMENT
# -------------------------------------------------------
@app.route("/generate_keys", methods=["POST"])
def generate_keys():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    username = session["username"]

    priv, pub = eu.generate_rsa_keypair()
    priv_pem = eu.serialize_private_key_to_pem(priv).decode()
    pub_pem = eu.serialize_public_key_to_pem(pub).decode()

    KEY_STORE[username] = {"priv_pem": priv_pem, "pub_pem": pub_pem}
    app.logger.info(f"[KEYGEN] {username} regenerated their keys.")

    return jsonify({"ok": True, "pub_pem": pub_pem})


@app.route("/register/<username>", methods=["POST"])
def register_pubkey(username):
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    data = request.get_json(force=True)
    pub_pem = data.get("pub_pem")
    if not pub_pem:
        return jsonify({"error": "missing pub_pem"}), 400

    u = username.lower()
    PUBLIC_KEYS[u] = pub_pem

    if u not in TRUSTED_FINGERPRINTS:
        TRUSTED_FINGERPRINTS[u] = fingerprint_pem(pub_pem)

    return jsonify({"ok": True, "fingerprint": TRUSTED_FINGERPRINTS[u]})


@app.route("/pubkey/<username>", methods=["GET"])
def get_pubkey(username):
    u = username.lower()
    p = PUBLIC_KEYS.get(u)
    if not p:
        return jsonify({"error": "no such user registered"}), 404
    return jsonify({"pub_pem": p, "fingerprint": fingerprint_pem(p)})


@app.route("/replace_pubkey/<username>", methods=["POST"])
def replace_pubkey(username):
    # MITM attack simulation
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    data = request.get_json(force=True)
    pub_pem = data.get("pub_pem")
    if not pub_pem:
        return jsonify({"error": "missing pub_pem"}), 400

    u = username.lower()
    PUBLIC_KEYS[u] = pub_pem

    app.logger.warning(f"[MITM] Public key for {u} replaced by attacker {session['username']}.")
    return jsonify({"ok": True, "new_fingerprint": fingerprint_pem(pub_pem)})


@app.route("/my_pubkey", methods=["GET"])
def my_pubkey():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    username = session["username"]
    pub = KEY_STORE[username]["pub_pem"]
    return jsonify({"pub_pem": pub, "fingerprint": fingerprint_pem(pub)})


# -------------------------------------------------------
# MESSAGE ENCRYPTION
# -------------------------------------------------------
@app.route("/encrypt", methods=["POST"])
def api_encrypt():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    try:
        data = request.get_json(force=True)
        plaintext = data.get("plaintext", "")
        aad = data.get("aad")
        receiver_username = data.get("receiver_username")

        if not plaintext:
            return jsonify({"error": "missing plaintext"}), 400
        if not receiver_username:
            return jsonify({"error": "missing receiver_username"}), 400

        receiver_pub_pem = PUBLIC_KEYS.get(receiver_username.lower())
        if not receiver_pub_pem:
            return jsonify({"error": "receiver has no registered public key"}), 400

        # Load keys
        sender = session["username"]
        sender_priv_pem = KEY_STORE[sender]["priv_pem"]
        sender_priv = eu.load_private_key_from_pem(sender_priv_pem.encode())
        sender_pub_pem = KEY_STORE[sender]["pub_pem"]

        receiver_pub = eu.load_public_key_from_pem(receiver_pub_pem.encode())

        # Build message
        session_key = eu.generate_chacha_key()
        ct, nonce = eu.encrypt_message_with_key(
            plaintext.encode(),
            session_key,
            aad.encode() if aad else None
        )
        enc_session_key = eu.rsa_encrypt_session_key(receiver_pub, session_key)

        signing_material = ct + nonce + enc_session_key
        signature = eu.sign_bytes_rsa(sender_priv, signing_material)

        ts = datetime.utcnow().isoformat()
        msg_id = str(uuid.uuid4())

        bundle = make_transport_bundle(
            ct, nonce, enc_session_key, signature,
            sender_pub_pem, ts, msg_id
        )

        MESSAGES.append({
            "id": msg_id,
            "from": sender,
            "to": receiver_username,
            "bundle": bundle,
            "time": ts
        })

        return jsonify(bundle)

    except Exception as e:
        app.logger.error(f"[ENCRYPT ERROR] {e}")
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------------
# MESSAGE DECRYPTION
# -------------------------------------------------------
@app.route("/decrypt", methods=["POST"])
def api_decrypt():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    try:
        raw = request.get_json(force=True)
        bundle = parse_transport_bundle(raw)

        receiver = session["username"]
        receiver_priv_pem = KEY_STORE[receiver]["priv_pem"]
        receiver_priv = eu.load_private_key_from_pem(receiver_priv_pem.encode())

        sender_pub_pem = bundle["sender_pub_pem"]
        sender_pub = eu.load_public_key_from_pem(sender_pub_pem.encode())

        # MITM detection (fingerprint mismatch)
        sender_fp = fingerprint_pem(sender_pub_pem)
        sender_name = raw.get("from")  # optional if you want to store it

        if sender_name in TRUSTED_FINGERPRINTS:
            if sender_fp != TRUSTED_FINGERPRINTS[sender_name]:
                if not ALLOW_UNPINNED:
                    return jsonify({"error": "MITM DETECTED (fingerprint mismatch)"}), 400
                else:
                    app.logger.warning("[MITM IGNORED] unpinned mode")

        # Verify signature
        signing_material = signing_material_from_bundle(bundle)
        if not eu.verify_signature_rsa(sender_pub, bundle["signature"], signing_material):
            return jsonify({"error": "signature verification failed"}), 400

        # Decrypt symmetric key
        session_key = eu.rsa_decrypt_session_key(receiver_priv, bundle["enc_session_key"])

        # Decrypt message
        plaintext = eu.decrypt_message_with_key(
            bundle["ciphertext"], bundle["nonce"], session_key
        )

        return jsonify({
            "plaintext": plaintext.decode(),
            "timestamp": bundle["timestamp"],
            "message_id": bundle["message_id"]
        })

    except Exception as e:
        app.logger.error(f"[DECRYPT ERROR] {e}")
        return jsonify({"error": str(e)}), 500


# -------------------------------------------------------
# DEBUG ENDPOINT: encrypt → decrypt in one shot
# -------------------------------------------------------
@app.route("/roundtrip_test", methods=["GET"])
def roundtrip():
    """Test encryption/decryption without UI."""
    sender = "alice"
    receiver = "bob"

    # must be logged in (just a helper)
    return jsonify({"status": "not implemented for UI"})


# -------------------------------------------------------
# RUN
# -------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8011, debug=True)
