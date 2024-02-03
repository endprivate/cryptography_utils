import hashlib

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode('utf-8')).hexdigest()
def sha512(data: str) -> str:
    return hashlib.sha512(data.encode('utf-8')).hexdigest()
def sha1(data: str) -> str:
    return hashlib.sha1(data.encode('utf-8')).hexdigest()
def md5(data: str) -> str:
    return hashlib.md5(data.encode('utf-8')).hexdigest()

