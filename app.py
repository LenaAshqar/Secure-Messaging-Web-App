from flask import Flask, render_template, request, jsonify
import base64

from encryptionUtility import (
    encrypt_with_key,
    decrypt_with_key,
    generate_ecdh_keypair,
    derive_shared_key,
    generate_signing_keypair,
    sign_data,
    verify_signature,
    serialize_public_key,
)

from attackUtility import (
    run_dictionary_attack,
    pretty_print_attack_result
)


app = Flask(__name__)

# --------- In-memory "users" for simulation ---------
# Each user has: ECDH keypair + signing keypair + password
USERS = {}
MAX_FAILED_ATTEMPTS = 5  # lock account after 5 failed attempts

def create_user(username: str, password: str):
    ecdh_priv, ecdh_pub = generate_ecdh_keypair()
    sign_priv, sign_pub = generate_signing_keypair()
    USERS[username] = {
        "password": password,      # demo only; never do plaintext in real systems
        "ecdh_priv": ecdh_priv,
        "ecdh_pub": ecdh_pub,
        "sign_priv": sign_priv,
        "sign_pub": sign_pub,
        "failed_attempts": 0,      # number of bad login tries
        "locked": False,           # whether the account is locked
    }

# Pre-create three demo users (you can change passwords if you like)
create_user("Alice",   "alice123")
create_user("Bob",     "bob123")
create_user("Charlie", "charlie123")



@app.route("/", methods=["GET"])
def index():
    """
    Serve the main GUI. User selection happens client-side (login form).
    """
    return render_template("index.html")


@app.route("/users", methods=["GET"])
def list_users():
    """
    Expose list of usernames so the frontend can show them in login/recipient.
    """
    return jsonify({"users": list(USERS.keys())})

@app.route("/login", methods=["POST"])
def login():
    """
    Very simple login with lockout:
    - checks username + password
    - increments failed_attempts on wrong password
    - locks account after MAX_FAILED_ATTEMPTS
    """
    try:
        data = request.get_json(force=True)
        username = data.get("username")
        password = data.get("password")

        if not username or not password:
            raise ValueError("Username and password are required.")

        info = USERS.get(username)
        if info is None:
            raise ValueError("Unknown user.")

        # Check if account is locked
        if info.get("locked"):
            return jsonify({
                "error": "Account is locked due to too many failed attempts.",
                "locked": True,
                "failed_attempts": info.get("failed_attempts", 0),
                "max_failed_attempts": MAX_FAILED_ATTEMPTS,
            }), 403

        # Check password
        if info["password"] != password:
            info["failed_attempts"] = info.get("failed_attempts", 0) + 1
            remaining = max(0, MAX_FAILED_ATTEMPTS - info["failed_attempts"])

            # Lock if threshold reached
            if info["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                info["locked"] = True
                return jsonify({
                    "error": "Account locked after too many failed login attempts.",
                    "locked": True,
                    "failed_attempts": info["failed_attempts"],
                    "max_failed_attempts": MAX_FAILED_ATTEMPTS,
                }), 403

            return jsonify({
                "error": "Invalid password.",
                "locked": False,
                "failed_attempts": info["failed_attempts"],
                "remaining_attempts": remaining,
                "max_failed_attempts": MAX_FAILED_ATTEMPTS,
            }), 401

        # Success → reset counters
        info["failed_attempts"] = 0
        info["locked"] = False

        return jsonify({
            "ok": True,
            "locked": False,
            "failed_attempts": 0,
            "max_failed_attempts": MAX_FAILED_ATTEMPTS,
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400



@app.route("/pubkeys", methods=["GET"])
def pubkeys():
    """
    Optional: expose public keys for inspection/debugging.
    """
    data = {}
    for name, info in USERS.items():
        data[name] = {
            "ecdh_pub_pem": serialize_public_key(info["ecdh_pub"]).decode(),
            "sign_pub_pem": serialize_public_key(info["sign_pub"]).decode(),
        }
    return jsonify(data)


# --------- Encrypt + Sign (sender side) ---------

@app.route("/encrypt", methods=["POST"])
def encrypt_route():
    try:
        data = request.get_json(force=True)
        sender = data.get("sender")
        receiver = data.get("receiver")
        plaintext = data.get("plaintext", "")

        if not sender or not receiver:
            raise ValueError("Sender and receiver are required.")
        if sender not in USERS or receiver not in USERS:
            raise ValueError("Unknown sender or receiver.")
        if not plaintext:
            raise ValueError("No plaintext provided.")

        plaintext_bytes = plaintext.encode("utf-8")

        # Derive shared session key using ECDH: sender's priv, receiver's pub
        s_info = USERS[sender]
        r_info = USERS[receiver]
        session_key = derive_shared_key(s_info["ecdh_priv"], r_info["ecdh_pub"])

        # Encrypt with ChaCha20-Poly1305
        ciphertext, nonce = encrypt_with_key(session_key, plaintext_bytes, aad=None)

        # Sign (ciphertext || nonce) with sender's signing private key
        to_sign = ciphertext + nonce
        signature = sign_data(s_info["sign_priv"], to_sign)

        # Return bundle + metadata
        return jsonify({
            "sender": sender,
            "receiver": receiver,
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "signature": base64.b64encode(signature).decode()
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400


# --------- Verify + Decrypt (receiver side) ---------

@app.route("/decrypt", methods=["POST"])
def decrypt_route():
    try:
        data = request.get_json(force=True)
        sender   = data.get("sender")
        receiver = data.get("receiver")  # acting user (logged in)

        ct_b64   = data.get("ciphertext", "")
        nonce_b64 = data.get("nonce", "")
        sig_b64   = data.get("signature", "")

        if not sender or not receiver:
            raise ValueError("Sender and receiver are required.")
        if sender not in USERS or receiver not in USERS:
            raise ValueError("Unknown sender or receiver.")
        if not ct_b64 or not nonce_b64 or not sig_b64:
            raise ValueError("ciphertext, nonce, and signature are required.")

        ciphertext = base64.b64decode(ct_b64)
        nonce      = base64.b64decode(nonce_b64)
        signature  = base64.b64decode(sig_b64)

        s_info = USERS[sender]
        r_info = USERS[receiver]

        # 1) verify signature using sender's signing public key
        to_sign = ciphertext + nonce
        if not verify_signature(s_info["sign_pub"], to_sign, signature):
            # integrity/authentication failure
            raise ValueError("Signature verification failed (message was tampered or forged).")

        # 2) derive the shared session key from ECDH
        session_key = derive_shared_key(r_info["ecdh_priv"], s_info["ecdh_pub"])

        # 3) decrypt with ChaCha20-Poly1305
        try:
            plaintext_bytes = decrypt_with_key(session_key, ciphertext, nonce, aad=None)
        except Exception:
            # Wrong key → almost always means “not the right recipient”
            raise ValueError("Decryption failed: wrong key or you are not the intended recipient.")

        return jsonify({"plaintext": plaintext_bytes.decode("utf-8", errors="ignore")})
    except Exception as e:
        return jsonify({"error": str(e)}), 400



# ----------- Attacks ------------

# ---- Dictionary Attack -----
@app.route("/attack/dictionary", methods=["POST"])
def simulate_dictionary_attack():
    """
    Simulate a dictionary attack against the given username.
    Uses USERS for password and lockout state. Each simulation
    consumes failed_attempts just like real login attempts would.
    """
    try:
        data = request.get_json(force=True)
        username = data.get("username")

        if not username:
            return jsonify({"error": "username is required"}), 400

        info = USERS.get(username)
        if info is None:
            return jsonify({"error": f"user '{username}' does not exist"}), 404

        # If account is already locked, do not allow more guesses
        if info.get("locked"):
            return jsonify({
                "success": False,
                "username": username,
                "attempts": 0,
                "guessed_password": None,
                "note": f"Account for '{username}' is already locked. No guesses allowed.",
                "tried_passwords": [],
                "remaining_passwords": 0,
                "failed_attempts": info.get("failed_attempts", 0),
                "max_failed_attempts": MAX_FAILED_ATTEMPTS,
                "locked": True,
            }), 200

        current_failed = info.get("failed_attempts", 0)
        remaining_allowed = MAX_FAILED_ATTEMPTS - current_failed
        if remaining_allowed <= 0:
            info["locked"] = True
            return jsonify({
                "success": False,
                "username": username,
                "attempts": 0,
                "guessed_password": None,
                "note": f"Account for '{username}' has reached maximum failed attempts and is now locked.",
                "tried_passwords": [],
                "remaining_passwords": 0,
                "failed_attempts": info["failed_attempts"],
                "max_failed_attempts": MAX_FAILED_ATTEMPTS,
                "locked": True,
            }), 200

        # Run dictionary attack with limited attempts to simulate lockout
        result = run_dictionary_attack(username, USERS, max_attempts=remaining_allowed)

        # Consume the attempts in the user's failed_attempts counter
        info["failed_attempts"] = current_failed + result.attempts

        # Check if lockout is now reached
        if info["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            info["locked"] = True

        return jsonify({
            "success": result.success,
            "username": result.username,
            "attempts": result.attempts,
            "guessed_password": result.guessed_password,
            "note": result.note,
            "tried_passwords": result.tried_passwords,
            "remaining_passwords": result.remaining_passwords,
            "failed_attempts": info["failed_attempts"],
            "max_failed_attempts": MAX_FAILED_ATTEMPTS,
            "locked": info.get("locked", False),
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400



if __name__ == "__main__":
    app.run(debug=True, port=8011)
