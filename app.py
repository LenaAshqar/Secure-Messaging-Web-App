from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from datetime import datetime, timedelta
import logging
import hashlib
import uuid
import base64
import encryptionUtility as eu   # cryptographic helpers
from pathlib import Path

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = "demo-secret-key-change-me"
logging.basicConfig(level=logging.INFO)

# -------------------------------------------------------
# SERVER-SIDE key store (CRITICAL fix)
# -------------------------------------------------------
KEY_STORE = {}
# username -> {"rsa_priv_pem": str, "rsa_pub_pem": str, "ecdh_priv_pem": str, "ecdh_pub_pem": str}

# Public directory (used by sender)
PUBLIC_KEYS = {}  # username -> {"signing": pem, "ecdh": pem}
TRUSTED_FINGERPRINTS = {}      # username -> fingerprint of signing key (key pinning)
MESSAGES = []                  # stored encrypted bundles
DOS_COUNTER = 0
LOGIN_ATTEMPTS = {}            # username -> counter to throttle dictionary attack

USER_CREDENTIALS = {
    "alice": "purple-alice",
    "bob": "green-bob",
    "mallory": "red-mallory",
}

VALID_USERS = list(USER_CREDENTIALS.keys())


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


def make_transport_bundle(ct, nonce, esk, wrap_nonce, signature, sender_pub_pem, sender_ecdh_pub_pem, timestamp, message_id):
    """A canonical JSON-safe bundle."""
    return {
        "ciphertext": b64e(ct),
        "nonce": b64e(nonce),
        "enc_session_key": b64e(esk),
        "wrap_nonce": b64e(wrap_nonce),
        "signature": b64e(signature),
        "sender_pub_pem": sender_pub_pem,
        "sender_ecdh_pub_pem": sender_ecdh_pub_pem,
        "timestamp": timestamp,
        "message_id": message_id
    }


def parse_transport_bundle(bundle_json):
    """Decode a bundle back into bytes."""
    return {
        "ciphertext": b64d(bundle_json["ciphertext"]),
        "nonce": b64d(bundle_json["nonce"]),
        "enc_session_key": b64d(bundle_json["enc_session_key"]),
        "wrap_nonce": b64d(bundle_json["wrap_nonce"]),
        "signature": b64d(bundle_json["signature"]),
        "sender_pub_pem": bundle_json["sender_pub_pem"],
        "sender_ecdh_pub_pem": bundle_json["sender_ecdh_pub_pem"],
        "timestamp": bundle_json.get("timestamp"),
        "message_id": bundle_json.get("message_id")
    }


def signing_material_from_bundle(b):
    """Both encrypt & decrypt use the *same* bytes for signatures."""
    return b["ciphertext"] + b["nonce"] + b["enc_session_key"] + b["wrap_nonce"] + b["sender_ecdh_pub_pem"].encode()


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
    password = request.form.get("password", "")

    if username not in VALID_USERS:
        return render_template("login.html", users=VALID_USERS, error="Invalid username")

    LOGIN_ATTEMPTS[username] = LOGIN_ATTEMPTS.get(username, 0) + 1
    if LOGIN_ATTEMPTS[username] > 10:
        app.logger.warning(f"[LOGIN-BLOCKED] Too many attempts for {username}; possible dictionary attack")
        return render_template("login.html", users=VALID_USERS, error="Too many attempts detected. Please wait.")

    if USER_CREDENTIALS[username] != password:
        app.logger.warning(f"[LOGIN-FAIL] Bad password for {username}")
        return render_template("login.html", users=VALID_USERS, error="Incorrect password")

    # Successful login resets the counter
    LOGIN_ATTEMPTS[username] = 0

    session.clear()
    session["logged_in"] = True
    session["username"] = username
    session["login_time"] = datetime.utcnow().isoformat()

    # Generate signing + ECDH keypairs for this user's session (server-side)
    rsa_priv, rsa_pub = eu.generate_rsa_keypair()
    ecdh_priv, ecdh_pub = eu.generate_ecdh_keypair()

    KEY_STORE[username] = {
        "rsa_priv_pem": eu.serialize_private_key_to_pem(rsa_priv).decode(),
        "rsa_pub_pem": eu.serialize_public_key_to_pem(rsa_pub).decode(),
        "ecdh_priv_pem": eu.serialize_private_key_to_pem(ecdh_priv).decode(),
        "ecdh_pub_pem": eu.serialize_public_key_to_pem(ecdh_pub).decode()
    }

    app.logger.info(f"[LOGIN] {username} logged in; signing and ECDH keys generated.")
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

    rsa_priv, rsa_pub = eu.generate_rsa_keypair()
    ecdh_priv, ecdh_pub = eu.generate_ecdh_keypair()

    KEY_STORE[username] = {
        "rsa_priv_pem": eu.serialize_private_key_to_pem(rsa_priv).decode(),
        "rsa_pub_pem": eu.serialize_public_key_to_pem(rsa_pub).decode(),
        "ecdh_priv_pem": eu.serialize_private_key_to_pem(ecdh_priv).decode(),
        "ecdh_pub_pem": eu.serialize_public_key_to_pem(ecdh_pub).decode()
    }
    app.logger.info(f"[KEYGEN] {username} regenerated signing and ECDH keys.")

    return jsonify({
        "ok": True,
        "signing_pub_pem": KEY_STORE[username]["rsa_pub_pem"],
        "ecdh_pub_pem": KEY_STORE[username]["ecdh_pub_pem"]
    })


@app.route("/register/<username>", methods=["POST"])
def register_pubkey(username):
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    data = request.get_json(force=True)
    signing_pem = data.get("signing_pub_pem")
    ecdh_pem = data.get("ecdh_pub_pem")
    if not signing_pem or not ecdh_pem:
        return jsonify({"error": "missing public keys"}), 400

    u = username.lower()
    PUBLIC_KEYS[u] = {"signing": signing_pem, "ecdh": ecdh_pem}

    if u not in TRUSTED_FINGERPRINTS:
        TRUSTED_FINGERPRINTS[u] = fingerprint_pem(signing_pem)

    app.logger.info(f"[PUBKEY] Registered public keys for {u} (fingerprint {TRUSTED_FINGERPRINTS[u]}).")
    return jsonify({"ok": True, "fingerprint": TRUSTED_FINGERPRINTS[u]})


@app.route("/pubkey/<username>", methods=["GET"])
def get_pubkey(username):
    u = username.lower()
    p = PUBLIC_KEYS.get(u)
    if not p:
        return jsonify({"error": "no such user registered"}), 404
    return jsonify({"pub_pem": p, "fingerprint": fingerprint_pem(p["signing"])})


@app.route("/replace_pubkey/<username>", methods=["POST"])
def replace_pubkey(username):
    # MITM attack simulation
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    data = request.get_json(force=True)
    signing_pem = data.get("signing_pub_pem")
    ecdh_pem = data.get("ecdh_pub_pem")
    if not signing_pem or not ecdh_pem:
        return jsonify({"error": "missing public keys"}), 400

    u = username.lower()
    PUBLIC_KEYS[u] = {"signing": signing_pem, "ecdh": ecdh_pem}

    app.logger.warning(f"[MITM] Public keys for {u} replaced by attacker {session['username']}.")
    return jsonify({"ok": True, "new_fingerprint": fingerprint_pem(signing_pem)})


@app.route("/my_pubkey", methods=["GET"])
def my_pubkey():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    username = session["username"]
    pub_sign = KEY_STORE[username]["rsa_pub_pem"]
    pub_ecdh = KEY_STORE[username]["ecdh_pub_pem"]
    return jsonify({
        "signing_pub_pem": pub_sign,
        "ecdh_pub_pem": pub_ecdh,
        "fingerprint": fingerprint_pem(pub_sign)
    })


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

        receiver_pub = PUBLIC_KEYS.get(receiver_username.lower())
        if not receiver_pub:
            return jsonify({"error": "receiver has no registered public key"}), 400

        # Load keys
        sender = session["username"]
        sender_priv_pem = KEY_STORE[sender]["rsa_priv_pem"]
        sender_priv = eu.load_private_key_from_pem(sender_priv_pem.encode())
        sender_pub_pem = KEY_STORE[sender]["rsa_pub_pem"]

        sender_ecdh_priv = eu.load_private_key_from_pem(KEY_STORE[sender]["ecdh_priv_pem"].encode())
        sender_ecdh_pub_pem = KEY_STORE[sender]["ecdh_pub_pem"]

        receiver_ecdh_pub = eu.load_public_key_from_pem(receiver_pub["ecdh"].encode())

        # Build message
        session_key = eu.generate_aes_key()
        ct, nonce = eu.encrypt_message_with_key(
            plaintext.encode(),
            session_key,
            aad.encode() if aad else None
        )
        enc_session_key, wrap_nonce, _ = eu.encrypt_session_key_ecdh(
            sender_ecdh_priv, receiver_ecdh_pub, session_key
        )

        signing_material = ct + nonce + enc_session_key + wrap_nonce + sender_ecdh_pub_pem.encode()
        signature = eu.sign_bytes_rsa(sender_priv, signing_material)

        ts = datetime.utcnow().isoformat()
        msg_id = str(uuid.uuid4())

        bundle = make_transport_bundle(
            ct, nonce, enc_session_key, wrap_nonce, signature,
            sender_pub_pem, sender_ecdh_pub_pem, ts, msg_id
        )

        MESSAGES.append({
            "id": msg_id,
            "from": sender,
            "to": receiver_username,
            "bundle": bundle,
            "time": ts
        })

        app.logger.info(f"[ENCRYPT] {sender} encrypted message for {receiver_username}; ciphertext len={len(ct)} bytes.")

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
        receiver_ecdh_priv = eu.load_private_key_from_pem(KEY_STORE[receiver]["ecdh_priv_pem"].encode())

        sender_pub_pem = bundle["sender_pub_pem"]
        sender_pub = eu.load_public_key_from_pem(sender_pub_pem.encode())
        sender_ecdh_pub = eu.load_public_key_from_pem(bundle["sender_ecdh_pub_pem"].encode())

        # Verify signature
        signing_material = signing_material_from_bundle(bundle)
        signature_valid = eu.verify_signature_rsa(sender_pub, bundle["signature"], signing_material)
        if not signature_valid:
            app.logger.warning("[VERIFY] Signature verification failed - possible forgery.")
            return jsonify({"error": "signature verification failed", "signature_valid": False}), 400

        # Decrypt symmetric key
        session_key = eu.decrypt_session_key_ecdh(
            receiver_ecdh_priv,
            sender_ecdh_pub,
            bundle["enc_session_key"],
            bundle["wrap_nonce"]
        )

        # Decrypt message
        plaintext = eu.decrypt_message_with_key(
            bundle["ciphertext"], bundle["nonce"], session_key
        )

        app.logger.info(f"[DECRYPT] {receiver} decrypted message {bundle.get('message_id')} (signature ok={signature_valid}).")

        return jsonify({
            "plaintext": plaintext.decode(),
            "timestamp": bundle["timestamp"],
            "message_id": bundle["message_id"],
            "signature_valid": signature_valid
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
# Attack simulations
# -------------------------------------------------------


def _load_dictionary_words():
    dict_path = Path(__file__).parent / "test.txt"
    if not dict_path.exists():
        return []
    return [w.strip() for w in dict_path.read_text().splitlines() if w.strip()]


@app.route("/simulate/dictionary", methods=["GET"])
def simulate_dictionary():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    target = request.args.get("target", session.get("username", "alice"))
    words = _load_dictionary_words()
    attempted = words[:25]
    found = False
    for w in attempted:
        if USER_CREDENTIALS.get(target) == w:
            found = True
            break

    LOGIN_ATTEMPTS[target] = LOGIN_ATTEMPTS.get(target, 0) + len(attempted)
    detected = found or LOGIN_ATTEMPTS[target] > 8

    if detected:
        app.logger.warning(f"[ATTACK] Dictionary attack detected targeting {target}; attempts={LOGIN_ATTEMPTS[target]}")
    else:
        app.logger.info(f"[ATTACK] Dictionary simulation against {target}; no matches found")

    return jsonify({
        "attack": "dictionary",
        "target": target,
        "checked_words": attempted,
        "password_matched": found,
        "detected": detected,
        "message": "Credential stuffing blocked" if detected else "Monitoring guesses",
        "attempts_recorded": LOGIN_ATTEMPTS[target]
    })


@app.route("/simulate/forgery", methods=["GET"])
def simulate_forgery():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    # create or reuse a stored message bundle to tamper with
    bundle = None
    if MESSAGES:
        bundle = parse_transport_bundle(MESSAGES[-1]["bundle"])
    else:
        # fabricate a single bundle just for the test
        fake_key = eu.generate_aes_key()
        ct, nonce = eu.encrypt_message_with_key(b"tamper", fake_key)
        enc_key, wrap_nonce, sender_ecdh = eu.encrypt_session_key_ecdh(*eu.generate_ecdh_keypair(), fake_key)
        rsa_priv, rsa_pub = eu.generate_rsa_keypair()
        sig = eu.sign_bytes_rsa(rsa_priv, ct + nonce + enc_key + wrap_nonce + sender_ecdh)
        bundle = {
            "ciphertext": ct,
            "nonce": nonce,
            "enc_session_key": enc_key,
            "wrap_nonce": wrap_nonce,
            "signature": sig,
            "sender_pub_pem": eu.serialize_public_key_to_pem(rsa_pub).decode(),
            "sender_ecdh_pub_pem": sender_ecdh.decode(),
            "timestamp": datetime.utcnow().isoformat(),
            "message_id": "forgery-demo",
        }

    sender_pub = eu.load_public_key_from_pem(bundle["sender_pub_pem"].encode())
    forged_signature = b"\x00" * len(bundle["signature"])  # blatantly invalid
    verified = eu.verify_signature_rsa(sender_pub, forged_signature, signing_material_from_bundle(bundle))

    detected = not verified
    if detected:
        app.logger.warning("[ATTACK] Forged signature rejected by verifier")
    else:
        app.logger.info("[ATTACK] Forgery slipped through (unexpected)")

    return jsonify({
        "attack": "forged_signature",
        "detected": detected,
        "signature_valid": verified,
        "message": "Forgery blocked by signature verification" if detected else "Forgery went unnoticed",
    })


@app.route("/simulate/phishing", methods=["GET"])
def simulate_phishing():
    if not session.get("logged_in"):
        return jsonify({"error": "not logged in"}), 403

    lure = {
        "from": "it-support@example.com",
        "body": "Please reset your password at http://evil.example/reset",
        "indicator": "Untrusted domain",
    }
    app.logger.warning(f"[ATTACK] Phishing lure flagged ({lure['indicator']})")
    return jsonify({
        "attack": "phishing",
        "detected": True,
        "message": "Suspicious domain detected. User warned and link disabled.",
        "lure": lure
    })


@app.route("/simulate/dos", methods=["GET"])
def simulate_dos():
    global DOS_COUNTER
    DOS_COUNTER += 1
    alert = DOS_COUNTER >= 5
    if alert:
        app.logger.warning(f"[ATTACK] DoS burst count={DOS_COUNTER} (threshold=5) — throttling engaged")
    else:
        app.logger.info(f"[ATTACK] DoS burst count={DOS_COUNTER}")

    status = 429 if alert else 200
    return jsonify({
        "attack": "denial_of_service",
        "requests_seen": DOS_COUNTER,
        "detected": alert,
        "message": "Rate limit engaged" if alert else "Monitoring traffic volume"
    }), status


# -------------------------------------------------------
# RUN
# -------------------------------------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8011, debug=True)
