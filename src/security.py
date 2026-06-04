import hashlib
import secrets
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

# Realm used for HTTP Digest Authentication
DIGEST_REALM = "Auth2Prod Realm"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def compute_digest_ha1(username: str, password: str) -> str:
    """
    Computes HA1 for HTTP Digest Auth.
    HA1 = MD5(username:realm:password)
    """
    text = f"{username}:{DIGEST_REALM}:{password}"
    return hashlib.md5(text.encode("utf-8")).hexdigest()

def generate_random_token(length: int = 32) -> str:
    """Generates a secure random URL-safe string."""
    return secrets.token_urlsafe(length)

def hash_api_key(key: str) -> str:
    """Computes a SHA-256 hash of an API key for secure storage."""
    return hashlib.sha256(key.encode("utf-8")).hexdigest()
