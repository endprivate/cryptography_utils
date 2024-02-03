import hashlib
def Hash(type: str, data: str="sha256"):
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

def sha256(data: str):
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
def sha512(data: str):
    return hashlib.sha512(data.encode('utf-8')).hexdigest()
def sha1(data: str):
    return hashlib.sha1(data.encode('utf-8')).hexdigest()
def md5(data: str):
    return hashlib.md5(data.encode('utf-8')).hexdigest()
