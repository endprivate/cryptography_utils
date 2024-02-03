from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
import hashlib

def generate_signature(private_key: bytes, data: bytes, hash_type: str="sha256") -> bytes:
    key = RSA.import_key(private_key)
    hash_obj = _hash(hash_type, data)
    signature = pkcs1_15.new(key).sign(hash_obj)
    return signature

def verify_signature(public_key: bytes, data: bytes, signature: bytes, hash_type: str="sha256") -> bool:
    key = RSA.import_key(public_key)
    hash_obj = _hash(hash_type, data)
    try:
        pkcs1_15.new(key).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


def _hash(type: str, data: str="sha256") -> str:
    hash_functions = {
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512,
        'sha1': hashlib.sha1,
        'md5': hashlib.md5
    }
    if type in hash_functions:
        return hash_functions[type](data.encode('utf-8')).hexdigest()
    else:
        raise ValueError("Unsupported hash type")