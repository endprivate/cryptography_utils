import hashlib
def Hash(type: str, data: str="sha256") -> str:
    hash_functions = {
        'sha256': sha256,
        'sha512': sha512,
        'sha1': sha1,
        'md5': md5
    }
    if type in hash_functions:
        return hash_functions[type](data)
    else:
        raise ValueError("Unsupported hash type")

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
def sha512(data: str) -> str:
    return hashlib.sha512(data.encode('utf-8')).hexdigest()
def sha1(data: str) -> str:
    return hashlib.sha1(data.encode('utf-8')).hexdigest()
def md5(data: str) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()

