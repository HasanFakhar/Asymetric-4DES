# Asymmetric 4DES with Integrity (HMAC)

This project is a *conceptual* security mechanism combining:
1. *Asymmetric Encryption (RSA)* for key wrapping.  
2. *Four-pass DES* (4DES) for confidentiality.  
3. *HMAC (SHA-256)* for integrity.

> *Note: For real-world use, prefer **AES* over DES and standard protocols like TLS.

---

## Features

- *Key Generation*  
  - Generates an RSA key pair (public and private).  
  - Generates four DES keys for multiple encryption passes.  
  - Generates a 256-bit HMAC key (for integrity).
  
- *Encryption*  
  - Encrypts plaintext using 4 passes of DES in succession.  
  - Computes HMAC over the final ciphertext.  
  - Wraps (encrypts) all DES keys and the HMAC key with RSA.

- *Decryption*  
  - Unwraps (decrypts) all keys using the RSA private key.  
  - Verifies ciphertext integrity via HMAC.  
  - Decrypts ciphertext using the four DES keys in reverse order.

---
## steps to run

1. `python -m http.server 8000` 
2. run `run.py`
# Asymmetric 4DES with Integrity (HMAC)

This project is a *conceptual* security mechanism combining:
1.⁠ ⁠*Asymmetric Encryption (RSA)* for key wrapping.  
2.⁠ ⁠*Four-pass DES* (4DES) for confidentiality.  
3.⁠ ⁠*HMAC (SHA-256)* for integrity.

	⁠*Note: For real-world use, prefer **AES* over DES and standard protocols like TLS.

---

## Features

•⁠  ⁠*Key Generation*  
  - Generates an RSA key pair (public and private).  
  - Generates four DES keys for multiple encryption passes.  
  - Generates a 256-bit HMAC key (for integrity).
  
•⁠  ⁠*Encryption*  
  - Encrypts plaintext using 4 passes of DES in succession.  
  - Computes HMAC over the final ciphertext.  
  - Wraps (encrypts) all DES keys and the HMAC key with RSA.

•⁠  ⁠*Decryption*  
  - Unwraps (decrypts) all keys using the RSA private key.  
  - Verifies ciphertext integrity via HMAC.  
  - Decrypts ciphertext using the four DES keys in reverse order.

---
