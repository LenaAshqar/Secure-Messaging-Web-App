"""Attack simulation helpers kept separate from the Flask view logic."""

from datetime import datetime
from pathlib import Path
import encryptionUtility as eu


DOS_COUNTER = 0
DOS_THRESHOLD = 5


def _load_dictionary_words(dict_path: Path) -> list[str]:
    if not dict_path.exists():
        return []
    return [w.strip() for w in dict_path.read_text().splitlines() if w.strip()]


def dictionary_attack(target: str, credentials: dict[str, str], login_attempts: dict[str, int], dict_path: Path) -> dict:
    words = _load_dictionary_words(dict_path)
    attempted = words[:25]
    found = False
    for w in attempted:
        if credentials.get(target) == w:
            found = True
            break

    login_attempts[target] = login_attempts.get(target, 0) + len(attempted)
    detected = found or login_attempts[target] > 8

    return {
        "attack": "dictionary",
        "target": target,
        "checked_words": attempted,
        "password_matched": found,
        "detected": detected,
        "message": "Credential stuffing blocked" if detected else "Monitoring guesses",
        "attempts_recorded": login_attempts[target],
    }


def _decode_bundle(bundle_json: dict) -> dict:
    return {
        "ciphertext": eu.ub64(bundle_json["ciphertext"]),
        "nonce": eu.ub64(bundle_json["nonce"]),
        "enc_session_key": eu.ub64(bundle_json["enc_session_key"]),
        "wrap_nonce": eu.ub64(bundle_json["wrap_nonce"]),
        "signature": eu.ub64(bundle_json["signature"]),
        "sender_pub_pem": bundle_json["sender_pub_pem"].encode(),
        "sender_ecdh_pub_pem": bundle_json["sender_ecdh_pub_pem"].encode(),
        "timestamp": bundle_json.get("timestamp"),
        "message_id": bundle_json.get("message_id"),
    }


def _signing_material(bundle: dict) -> bytes:
    return (
        bundle["ciphertext"]
        + bundle["nonce"]
        + bundle["enc_session_key"]
        + bundle["wrap_nonce"]
        + bundle["sender_ecdh_pub_pem"]
    )


def forged_signature_attack(messages: list[dict]) -> dict:
    if messages:
        bundle = _decode_bundle(messages[-1]["bundle"])
    else:
        fake_key = eu.generate_chacha_key()
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
            "sender_pub_pem": eu.serialize_public_key_to_pem(rsa_pub),
            "sender_ecdh_pub_pem": sender_ecdh,
            "timestamp": datetime.utcnow().isoformat(),
            "message_id": "forgery-demo",
        }

    sender_pub = eu.load_public_key_from_pem(bundle["sender_pub_pem"])
    forged_signature = b"\x00" * len(bundle["signature"])
    verified = eu.verify_signature_rsa(sender_pub, forged_signature, _signing_material(bundle))
    detected = not verified

    return {
        "attack": "forged_signature",
        "detected": detected,
        "signature_valid": verified,
        "message": "Forgery blocked by signature verification" if detected else "Forgery went unnoticed",
    }


def phishing_attack() -> dict:
    lure = {
        "from": "it-support@example.com",
        "body": "Please reset your password at http://evil.example/reset",
        "indicator": "Untrusted domain",
    }
    return {
        "attack": "phishing",
        "detected": True,
        "message": "Suspicious domain detected. User warned and link disabled.",
        "lure": lure,
    }


def dos_attack() -> tuple[dict, bool]:
    global DOS_COUNTER
    DOS_COUNTER += 1
    alert = DOS_COUNTER >= DOS_THRESHOLD
    return (
        {
            "attack": "denial_of_service",
            "requests_seen": DOS_COUNTER,
            "detected": alert,
            "message": "Rate limit engaged" if alert else "Monitoring traffic volume",
        },
        alert,
    )
