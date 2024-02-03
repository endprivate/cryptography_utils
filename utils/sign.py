from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import hash

def generate_signature(private_key: bytes, data: bytes, hash_type: str="sha256") -> bytes:
    key = RSA.import_key(private_key)
    hash_obj = hash.Hash(hash_type, data)
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature

def verify_signature(public_key: bytes, data: bytes, signature: bytes, hash_type: str="sha256") -> bool:
    key = RSA.import_key(public_key)
    hash_obj = hash.Hash(hash_type, data)
    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
