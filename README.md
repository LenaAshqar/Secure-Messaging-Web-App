# Secure Messaging Demo

This Flask demo shows an end-to-end secure messaging workflow that combines authenticated encryption, ECDH key exchange, and digital signatures. The UI surfaces cryptographic outputs (ciphertext, signature verification) and allows simulation of common attacks.

## Cryptography overview
- **Confidentiality**: Messages are encrypted with randomly generated 256-bit ChaCha20-Poly1305 session keys and 96-bit nonces (`encryptionUtility.encrypt_message_with_key`). Ciphertext is displayed in the UI after encryption.
- **Key exchange**: Each session generates a P-256 ECDH key pair plus an RSA-2048 signing key pair. The sender derives a shared secret with the receiver's ECDH public key and wraps the symmetric session key with AES-GCM (`encrypt_session_key_ecdh`).
- **Integrity & authentication**: The sender signs the ciphertext + nonces + encrypted session key + sender ECDH key with RSA-PSS SHA-256. The receiver verifies the signature before unwrapping the session key and decrypting the ciphertext.

## Workflow
1. **Keys** are generated automatically on login and before sending/decrypting. You can still view and register them so other users can fetch verified fingerprints.
2. **Encrypt** a plaintext to a recipient. The API returns a transport bundle containing ciphertext, IVs, encrypted session key, signature, and sender public keys. The UI shows both the bundle and ciphertext.
3. **Decrypt** by pasting a transport bundle. The app verifies the signature, derives the shared key to unwrap the AES key, decrypts, and reports signature validity in the UI.
4. **Attack simulations**: Dedicated buttons trigger dictionary attack, forged signature, phishing, and DoS simulations. The API now performs actual checks (credential guessing vs demo passwords, signature tampering attempts, DoS throttling) and returns detection results for the UI.

## Demo login
- Username/password pairs: `alice`/`purple-alice`, `bob`/`green-bob`, `mallory`/`red-mallory`.
- Too many failed attempts for the same user will be blocked to mimic dictionary-attack throttling.

## Logging
Server logs capture key lifecycle events (generation, encryption, verification, attack detection) to make the security posture visible during demos.
