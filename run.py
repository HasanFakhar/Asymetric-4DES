import os
import base64
import secrets
from flask import Flask, request, jsonify
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from flask import Flask
from flask_cors import CORS




app = Flask(__name__)
CORS(app)  # Enable CORS for all routes
# -------------------------------
# 1. Generate 4DES + HMAC Keys
# -------------------------------

# Generate four DES keys (each 8 bytes)
four_des_keys = [get_random_bytes(8) for _ in range(4)]
# Generate a 256-bit HMAC key
hmac_key = get_random_bytes(32)

# Dictionary to store HMACs keyed by an ID
# For demonstration, we assume each encryption call generates a unique ID,
# and the client provides that ID on decryption
mac_store = {}


# -------------------------------
# 2. Helper Functions
# -------------------------------

# def four_des_encrypt(plaintext: bytes, keys):
#     """
#     Encrypt 'plaintext' with 4DES in ECB mode (for demonstration).
#     In real usage, adopt secure modes like CBC/GCM.
#     """
#     data = plaintext
#     for k in keys:
#         cipher = DES.new(k, DES.MODE_ECB)
#         # Pad data to 8-byte multiples
#         pad_len = 8 - (len(data) % 8)
#         data += bytes([pad_len]) * pad_len
#         data = cipher.encrypt(data)

#     print(data)
#     return data

# def four_des_decrypt(ciphertext: bytes, keys):
#     """Decrypt 'ciphertext' with 4DES in reverse order (ECB mode)."""
#     data = ciphertext
#     for k in reversed(keys):
#         cipher = DES.new(k, DES.MODE_ECB)
#         data = cipher.decrypt(data)
#     # Remove padding
 
#     print("RAW Decrypted (hex):", data.hex())

#     pad_len = data[-1]

#     data = data[:-pad_len]
    
#     return data


def four_des_encrypt(plaintext: bytes, keys):
    """
    Encrypt 'plaintext' with 4DES in ECB mode (for demonstration).
    In real usage, adopt secure modes like CBC/GCM.
    """
    # ---- Pad once BEFORE all passes ----
    pad_len = 8 - (len(plaintext) % 8)
    if pad_len == 0:
        pad_len = 8  # if already multiple of 8, add a full block of padding
    plaintext += bytes([pad_len]) * pad_len

    data = plaintext
    for k in keys:
        cipher = DES.new(k, DES.MODE_ECB)
        data = cipher.encrypt(data)

    print("Encrypted (hex):", data.hex())
    return data

def four_des_decrypt(ciphertext: bytes, keys):
    """Decrypt 'ciphertext' with 4DES in reverse order (ECB mode)."""
    data = ciphertext
    for k in reversed(keys):
        cipher = DES.new(k, DES.MODE_ECB)
        data = cipher.decrypt(data)

    print("RAW Decrypted (hex):", data.hex())

    # ---- Remove padding once AFTER all passes ----
    pad_len = data[-1]
    # Optional: Validate that all trailing bytes match pad_len
    if any(byte_val != pad_len for byte_val in data[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding.")
    data = data[:-pad_len]

    return data

def compute_hmac(ciphertext: bytes, key: bytes):
    """Compute HMAC-SHA256 over ciphertext using 'key'."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

def verify_hmac(ciphertext: bytes, key: bytes, expected_mac: bytes):
    """Verify HMAC; raises ValueError if mismatch."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciphertext)
    h.verify(expected_mac)


# -------------------------------
# 3. Flask Endpoints
# -------------------------------

@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    """
    Expects JSON: { "plaintext": "some text" }
    Returns JSON: { "id": "<unique>", "ciphertext": "<base64-encoded>" }
    """
    data = request.get_json()
    plaintext_str = data.get("plaintext", "")
    plaintext_bytes = plaintext_str.encode("utf-8")  # Convert to bytes

    # 3.1 Encrypt with 4DES
    ciphertext = four_des_encrypt(plaintext_bytes, four_des_keys)

    # 3.2 Compute HMAC
    mac = compute_hmac(ciphertext, hmac_key)

    # 3.3 Generate unique ID to store HMAC for this ciphertext
    unique_id = secrets.token_hex(8)  # 16 hex chars

    # 3.4 Store the HMAC in mac_store
    mac_store[unique_id] = mac
    # 3.5 Base64-encode the ciphertext for JSON transmission
    ciphertext_b64 = base64.b64encode(ciphertext).decode("utf-8")

    return jsonify({
        "id": unique_id,
        "ciphertext": ciphertext_b64
    })


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    """
    Expects JSON: { "id": "<unique>", "ciphertext": "<base64-encoded>" }
    Returns JSON: { "plaintext": "some text" }
    """
    data = request.get_json()
    unique_id = data.get("id", "")
    ciphertext_b64 = data.get("ciphertext", "")

    # Retrieve the HMAC from storage
    mac = mac_store.get(unique_id, None)
    if mac is None:
        return jsonify({"error": "Invalid or expired ID"}), 400

    # Decode the base64 ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)
   
    # 3.1 Verify HMAC
    try:
        verify_hmac(ciphertext, hmac_key, mac)
    except ValueError:
        return jsonify({"error": "Integrity check failed: HMAC mismatch"}), 400

    # 3.2 Decrypt with 4DES
    plaintext_bytes = four_des_decrypt(ciphertext, four_des_keys)
    plaintext_str = plaintext_bytes.decode("utf-8", errors="ignore")

    # Optionally remove the used ID from storage if you want one-time decryption
    # mac_store.pop(unique_id, None)
   
    return jsonify({"plaintext": plaintext_str})


# -------------------------------
# 4. Run the Flask App
# -------------------------------
if __name__ == "__main__":
    # For development/testing only
    app.run(debug=True)
