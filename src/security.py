import secrets
import jwt
from datetime import datetime, timedelta, timezone
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

SECRET_KEY = "oauth-playground-secret-key-super-secure-12345"
ALGORITHM = "HS256"

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def generate_random_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)

def create_jwt_token(payload: dict, expires_delta: timedelta) -> str:
    to_encode = payload.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": int(expire.timestamp())})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def decode_jwt_token(token: str) -> dict:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.PyJWTError:
        return None
