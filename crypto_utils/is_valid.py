def is_hash(hash_value: str, hash_type: str) -> bool:
    hash_functions = {
        'sha256': 64,
        'sha512': 128,
        'sha1': 40,
        'md5':   32
    }
    expected_length = hash_functions.get(hash_type)
    if expected_length:
        return len(hash_value) == expected_length
    else:
        return False

def is_private_key(private_key: bytes) -> bool:
    try:
        from Crypto.PublicKey import RSA
        RSA.import_key(private_key)
        return True
    except (ValueError, IndexError):
        return False
