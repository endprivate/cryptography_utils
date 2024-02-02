import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class AESCipher:
    def __init__(self, key, mode=AES.MODE_GCM):
        self.key = key
        self.mode = mode

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = AES.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        cipher = AES.new(self.key, self.mode, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

def generate_key(key_size=16):
    return get_random_bytes(key_size)