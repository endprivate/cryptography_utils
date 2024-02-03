import os
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4
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
#TODO: Fix classes below AESCipher
class _DESCipher:
    def __init__(self, key, mode=DES.MODE_ECB):
        self.key = key
        self.mode = mode

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = DES.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        cipher = DES.new(self.key, self.mode, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

class _DES3Cipher:
    def __init__(self, key, mode=DES3.MODE_ECB):
        self.key = key
        self.mode = mode

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = DES3.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        cipher = DES3.new(self.key, self.mode, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

class _BlowfishCipher:
    def __init__(self, key, mode=Blowfish.MODE_ECB):
        self.key = key
        self.mode = mode

    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = Blowfish.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        cipher = Blowfish.new(self.key, self.mode, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

class _ARC4Cipher:
    def __init__(self, key):
        self.key = key

    
    def encrypt(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        cipher = ARC4.new(self.key, self.mode)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return ciphertext, tag, cipher.nonce

    def decrypt(self, ciphertext, tag, nonce):
        cipher = ARC4.new(self.key, self.mode, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext.decode('utf-8')

def generate_key(key_size=16):
    return get_random_bytes(key_size)

