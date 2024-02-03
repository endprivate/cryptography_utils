import os
from Crypto.PublicKey import RSA, ECC
import hash_generator
def generate_private_key_rsa(key_size=2048) -> str:
    key = RSA.generate(key_size)
    private_key = key.export_key().decode('utf-8')
    return private_key + '\n'
def generate_private_key_ecc(curve='P-256') -> str:
    """l\
    Supported curves:
    - 'P-256'
    - 'P-384'
    - 'P-521'
    """
    key = ECC.generate(curve=curve)
    private_key = key.export_key(format='PEM')
    return str(private_key)

def generate_public_key(private_key, hash_type: str="sha256"):
    """
    :param hash_type: now available: sha256, sha512, sha1 and md5 
    """
    return hash_generator.Hash(type=hash_type, data=private_key)
