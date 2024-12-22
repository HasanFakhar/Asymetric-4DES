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
