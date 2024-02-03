import os
from Crypto.PublicKey import RSA
import hash
def generate_private_key(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    return private_key

def generate_public_key(private_key, hash_type: str):
    """
    :param hash_type: now available: sha256, sha512, sha1 and md5 
    """
    return hash.Hash(type=hash_type, data=private_key)