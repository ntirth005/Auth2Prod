import jwt
from datetime import datetime, timedelta, timezone
from fastapi import Request, Response, HTTPException, status
from .config import settings

ALGORITHM = "HS256"

def create_session_cookie(response: Response, user_id: int):
    expire = datetime.now(timezone.utc) + timedelta(days=settings.SESSION_EXPIRY_DAYS)
    payload = {
        "sub": str(user_id),
        "exp": int(expire.timestamp())
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=ALGORITHM)
    
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production environments
        path="/",
        max_age=settings.SESSION_EXPIRY_DAYS * 24 * 3600
    )
    return token

def get_session_user_id(request: Request) -> int:
    token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload.get("sub"))
    except jwt.PyJWTError:
        return None

def delete_session_cookie(response: Response):
    response.delete_cookie(settings.SESSION_COOKIE_NAME, path="/")
