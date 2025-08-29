import os, hashlib
IP_SALT = os.environ.get("IP_SALT", "X3565657")

def hash_ip(ip: str) -> str:
    return hashlib.sha256((ip + IP_SALT).encode("utf-8")).hexdigest()
