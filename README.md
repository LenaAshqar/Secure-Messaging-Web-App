# Secure Web Messaging Application

> A secure web messaging app prototype combining authenticated encryption and key exchange  
> — demo implementation using Python and web technologies.

---

## 🚀 **Overview**

This project implements a simple **secure messaging web application** with demo users, encrypted message exchange, and simulated attack endpoints.  
It demonstrates core concepts such as:

- **Elliptic‑curve Diffie‑Hellman (ECDH)** for shared key generation  
- **ChaCha20‑Poly1305 AEAD encryption**  
- **ECDSA signatures** for message authentication  
- Simple login with account lockout on repeated failed attempts  
- Attack simulation endpoints (dictionary & DoS) for educational purposes

> Note: This is a **demo/educational prototype** and **not suitable for real production use**.  
Real deployments must handle secure password storage, authentication, rate‑limiting, CSRF/headers, HTTPS, and more.

---

## 🧠 **Key Concepts & Features**

### 🔐 Security

- **ECDH Key Exchange** – Derive a shared symmetric key between sender and recipient.  
- **ChaCha20‑Poly1305 Encryption** – Authenticated encryption with associated data (AEAD).  
- **ECDSA Signatures** – Ensure integrity and authenticity of encrypted messages.  
- **Public Key Exposure** – Optional endpoint to introspect public keys (for debugging/testing).

### 🔄 Authentication & Login

- Simple login API with:
  - Basic username/password check
  - Failed attempts counter and account lockout after a threshold

### 🛠 Attack Simulation (for learning)

Endpoints exist to simulate:

- **Dictionary attack** against credentials  
- **DoS attack** (computational flood simulation)

---

## 📦 **Repository Structure**
```
Secure-Messaging-Web-App
  ├── static/
  ├── templates/
  ├── app.py
  ├── encryptionUtility.py
  ├── attackUtility.py
  ├── package.json
  ├── README.md (you’re here!)
  ├── Technical Report.pdf
  └── User Guide.pdf
```

---

## 🧪 Installation & Running Locally

1. **Clone the repo**
   ```bash
   git clone https://github.com/LenaAshqar/Secure-Messaging-Web-App.git
   cd Secure-Messaging-Web-App
   ```
2. **Create a Python virtual env**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```
3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Start the web server**
   ```bash
   python app.py
   ```
5. **Open the UI** Visit: http://localhost:8011 in your browser.
  

---

## 🛠 API Summary

**🧑‍💻 Authentication**
| Endpoint |	Method |	Description|
| --- | --- | --- |
| /login	| POST	| Login with username & password (locks out on too many failures) |
| /users |	GET |	Returns list of demo users available |

**🗝 Public Keys**
| Endpoint |	Method |	Description |
| --- | --- | --- |
| /pubkeys |	GET |	Public keys (ECDH + ECDSA) for all users (debug) |

**🔒 Encrypt/Decrypt**
|Endpoint |	Method |	Description |
| --- | --- | --- |
|/encrypt |	POST | Encrypt + sign message for a recipient |
|/decrypt |	POST | Verify signature & decrypt if intended recipient |

**🧪 Attack Simulation**
| Endpoint |	Method |	Description |
| --- | --- | --- |
| /attack/dictionary |	POST |	Simulate login guessing attempts |
| /attack/dos |	POST | Simulate DoS (CPU heavy crypto loop) |

---

## 🧠 How It Works (Simplified)
**Key Exchange & Encryption**
1. Users have an ECDH keypair.
2. To send a message:
    - Derive shared key: sender’s private + recipient’s public ECDH key.
    - Encrypt plaintext with ChaCha20‑Poly1305.
    - Sign ciphertext + nonce with ECDSA.
3. To receive:
    - Verify signature with sender’s public signing key.
    - Derive shared key and decrypt.

This workflow ensures:

- ✔ Confidentiality
- ✔ Integrity
- ✔ Authentication

---

## 🧾 Utility Modules
📌 encryptionUtility.py

Contains encryption, decryption, key generation, signing and verification helper functions using:

- cryptography Python library
- AEAD ChaCha20‑Poly1305
- ECDH and ECDSA primitives

---

## 📜 User Guide & Technical Report

For detailed explanations of design choices, attack assumptions, and UI workflows — see:

- User Guide.pdf
- Technical Report.pdf

Both are included in this repo.
