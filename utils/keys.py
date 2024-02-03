import os
from Crypto.PublicKey import RSA, ECC
import hash
def generate_private_key_rsa(key_size=2048):
    key = RSA.generate(key_size)
    private_key = key.export_key()
    return private_key

def generate_private_key_ecc(curve='P-256'):
    key = ECC.generate(curve=curve)
    private_key = key.export_key()
    return private_key

def generate_public_key(private_key, hash_type: str):
    """
    :param hash_type: now available: sha256, sha512, sha1 and md5 
    """
    return hash.Hash(type=hash_type, data=private_key)