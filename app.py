from Crypto.Cipher import DES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

def generate_rsa_keys(key_size=2048):
    """Generate an RSA key pair."""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def generate_des_key():
    """Generate an 8-byte DES key."""
    return get_random_bytes(8)

def generate_four_des_keys():
    """Generate four DES keys for 4DES."""
    return [generate_des_key() for _ in range(4)]

def four_des_encrypt(plaintext, keys):
    """
    Encrypt plaintext with 4 DES passes in ECB mode (for simplicity).
    In practice, use modes like CBC, GCM, or CTR for stronger security.
    """
    data = plaintext
    for k in keys:
        cipher = DES.new(k, DES.MODE_ECB)
        # Pad data to 8 bytes multiples, as DES operates on 64-bit blocks
        pad_len = 8 - (len(data) % 8)
        data += bytes([pad_len]) * pad_len
        data = cipher.encrypt(data)
    return data

def four_des_decrypt(ciphertext, keys):
    """Decrypt ciphertext with 4 DES passes in reverse order."""
    data = ciphertext
    for k in reversed(keys):
        cipher = DES.new(k, DES.MODE_ECB)
        data = cipher.decrypt(data)
    # Remove padding
    pad_len = data[-1]
    data = data[:-pad_len]
    return data


def compute_hmac(ciphertext, hmac_key):
    """Compute an HMAC-SHA256 over the given ciphertext."""
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(ciphertext)
    return h.digest()

def verify_hmac(ciphertext, hmac_key, expected_hmac):
    """Verify the HMAC. Raises ValueError if verification fails."""
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(ciphertext)
    h.verify(expected_hmac)  # Will raise ValueError on mismatch


def wrap_keys_with_rsa(des_keys, hmac_key, rsa_public_key_pem):
    """Encrypt 4 DES keys + 1 HMAC key using RSA public key."""
    rsa_key = RSA.import_key(rsa_public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    # Combine all keys into a single blob
    combined = b''.join(des_keys) + hmac_key
    encrypted_blob = cipher_rsa.encrypt(combined)
    return encrypted_blob

def unwrap_keys_with_rsa(encrypted_blob, rsa_private_key_pem):
    """Decrypt (unwrap) keys using RSA private key."""
    rsa_key = RSA.import_key(rsa_private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    combined = cipher_rsa.decrypt(encrypted_blob)
    # The last 32 bytes is the HMAC key (example length)
    # The first 4 * 8 = 32 bytes are the four DES keys
    four_des_keys = [combined[i*8:(i+1)*8] for i in range(4)]
    hmac_key = combined[32:]  # next 32 bytes or however long you chose
    return four_des_keys, hmac_key
