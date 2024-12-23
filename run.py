import os
import base64
import secrets
from flask import Flask, request, jsonify
from flask_cors import CORS

from Crypto.Random import get_random_bytes
from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# ---------------------------------------------------------------------
# 1. RSA Key Pair (Generated Once for This Demo)
# ---------------------------------------------------------------------
def generate_rsa_keys(key_size=2048):
    """Generate an RSA key pair (private/public) for wrapping/unwrapping."""
    key = RSA.generate(key_size)
    private_key = key.export_key()      # PEM-encoded
    public_key = key.publickey().export_key()  # PEM-encoded
    return private_key, public_key

# Generate a single RSA key pair for the server (demo only!)
private_key_pem, public_key_pem = generate_rsa_keys()

# ---------------------------------------------------------------------
# 2. Dictionary Stores:
#    - HMAC for each ciphertext
#    - The RSA-encrypted (wrapped) ephemeral DES/HMAC keys
# ---------------------------------------------------------------------
mac_store = {}               # maps unique_id -> HMAC tag
wrapped_keys_store = {}      # maps unique_id -> RSA-encrypted symmetric keys

# ---------------------------------------------------------------------
# 3. Helper Functions (4DES, HMAC, RSA wrap/unwrap)
# ---------------------------------------------------------------------
def four_des_encrypt(plaintext: bytes, keys):
    """
    Encrypt 'plaintext' with 4DES in ECB mode (demo).
    Real usage: use secure modes like CBC/GCM and AES.
    """
    # Pad once BEFORE all passes
    pad_len = 8 - (len(plaintext) % 8)
    if pad_len == 0:
        pad_len = 8
    plaintext += bytes([pad_len]) * pad_len

    data = plaintext
    for k in keys:
        cipher = DES.new(k, DES.MODE_ECB)
        data = cipher.encrypt(data)

    return data

def four_des_decrypt(ciphertext: bytes, keys):
    """
    Decrypt 'ciphertext' with 4DES in reverse order (ECB mode).
    Remove padding once at the end.
    """
    data = ciphertext
    for k in reversed(keys):
        cipher = DES.new(k, DES.MODE_ECB)
        data = cipher.decrypt(data)

    # Remove padding
    pad_len = data[-1]
    if any(b != pad_len for b in data[-pad_len:]):
        raise ValueError("Invalid PKCS#7 padding.")
    data = data[:-pad_len]
    return data

def compute_hmac(ciphertext: bytes, key: bytes):
    """Compute HMAC-SHA256 using 'key' over 'ciphertext'."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

def verify_hmac(ciphertext: bytes, key: bytes, expected_mac: bytes):
    """Verify HMAC; raises ValueError if mismatch."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(ciphertext)
    h.verify(expected_mac)

def wrap_keys_with_rsa(des_keys, hmac_key, rsa_public_key_pem):
    """
    Encrypt (wrap) the DES keys + HMAC key using the RSA public key.
    Returns the 'encrypted_blob' (bytes).
    """
    rsa_key = RSA.import_key(rsa_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    # Combine (4 DES keys) + (HMAC key) into one blob
    combined = b''.join(des_keys) + hmac_key
    encrypted_blob = cipher_rsa.encrypt(combined)
    return encrypted_blob

def unwrap_keys_with_rsa(encrypted_blob, rsa_private_key_pem):
    """
    Decrypt (unwrap) the DES keys + HMAC key using the RSA private key.
    Returns (list_of_des_keys, hmac_key).
    """
    rsa_key = RSA.import_key(rsa_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    combined = cipher_rsa.decrypt(encrypted_blob)
    # first 32 bytes = 4 * 8 = 4 DES keys
    # next 32 bytes = HMAC key (assuming 32 bytes)
    des_keys = [combined[8*i : 8*(i+1)] for i in range(4)]
    hmac_key = combined[32:]
    return des_keys, hmac_key

# ---------------------------------------------------------------------
# 4. Flask Endpoints
# ---------------------------------------------------------------------

@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    """
    Expects JSON: { "plaintext": "some text" }
    Returns JSON: { "id": "<unique>", "ciphertext": "<base64-encoded>" }
    """
    data = request.get_json()
    plaintext_str = data.get("plaintext", "")
    plaintext_bytes = plaintext_str.encode("utf-8")

    # Generate ephemeral 4DES keys and HMAC key for this request
    ephemeral_des_keys = [get_random_bytes(8) for _ in range(4)]
    ephemeral_hmac_key = get_random_bytes(32)  # 256-bit

    # Encrypt with 4DES
    ciphertext = four_des_encrypt(plaintext_bytes, ephemeral_des_keys)
    # Compute HMAC for integrity
    mac = compute_hmac(ciphertext, ephemeral_hmac_key)

    # Wrap the ephemeral keys with RSA
    wrapped_keys = wrap_keys_with_rsa(ephemeral_des_keys, ephemeral_hmac_key, public_key_pem)

    # Generate a unique ID
    unique_id = secrets.token_hex(8)

    # Store HMAC and RSA-wrapped keys in dictionaries
    mac_store[unique_id] = mac
    wrapped_keys_store[unique_id] = wrapped_keys

    # Base64-encode the ciphertext for JSON transmission
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

    # Retrieve the HMAC & wrapped keys from storage
    mac = mac_store.get(unique_id, None)
    wrapped_keys = wrapped_keys_store.get(unique_id, None)

    if mac is None or wrapped_keys is None:
        return jsonify({"error": "Invalid or expired ID"}), 400

    # Decode the base64 ciphertext
    ciphertext = base64.b64decode(ciphertext_b64)

    # Unwrap ephemeral keys (DES & HMAC) using RSA private key
    try:
        des_keys, ephemeral_hmac_key = unwrap_keys_with_rsa(wrapped_keys, private_key_pem)
    except ValueError:
        return jsonify({"error": "Failed to unwrap keys with RSA"}), 400

    # Verify HMAC for integrity
    try:
        verify_hmac(ciphertext, ephemeral_hmac_key, mac)
    except ValueError:
        return jsonify({"error": "Integrity check failed: HMAC mismatch"}), 400

    # Decrypt with 4DES
    try:
        plaintext_bytes = four_des_decrypt(ciphertext, des_keys)
    except ValueError as e:
        return jsonify({"error": str(e)}), 400

    plaintext_str = plaintext_bytes.decode("utf-8", errors="ignore")

    # (Optional) If you want one-time usage, remove them from store:
    # mac_store.pop(unique_id, None)
    # wrapped_keys_store.pop(unique_id, None)

    return jsonify({"plaintext": plaintext_str})

# ---------------------------------------------------------------------
# 5. Run the Flask App
# ---------------------------------------------------------------------
if __name__ == "__main__":
    # For development/testing only
    app.run(debug=True)
