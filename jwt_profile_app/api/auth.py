from datetime import datetime, timedelta
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from jwt_profile_app.core.database import get_db
from jwt_profile_app.models.models import User, RefreshToken
from jwt_profile_app.schemas.schemas import (
    UserRegister, UserLogin, UserResponse, TokenResponse
)
from jwt_profile_app.core.security import hash_password, verify_password
from jwt_profile_app.core.jwt_helper import (
    create_access_token, create_refresh_token, generate_jti, decode_token
)
from jwt_profile_app.core.logging import get_logger
from jwt_profile_app.core.config import settings
from .utils import capture_debug_meta

router = APIRouter()
logger = get_logger("jwt_profile_app")

@router.post("/api/register")
async def register(request: Request, user_in: UserRegister, db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT * FROM users WHERE username = '{user_in.username}'"
    ]
    existing = db.query(User).filter(User.username == user_in.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken."
        )
    
    hashed = hash_password(user_in.password)
    new_user = User(
        username=user_in.username,
        hashed_password=hashed,
        display_name=user_in.display_name or user_in.username,
        email=user_in.email,
        bio=user_in.bio
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.info("New user registered successfully", extra={"extra_fields": {"username": new_user.username, "user_id": new_user.id}})
    db_queries.append("INSERT INTO users VALUES (...)")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "message": f"User '{new_user.username}' registered successfully!",
        "user": UserResponse.model_validate(new_user),
        "debug": debug_meta
    }

@router.post("/api/login")
async def login(request: Request, response: Response, login_in: UserLogin, db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT * FROM users WHERE username = '{login_in.username}'"
    ]
    user = db.query(User).filter(User.username == login_in.username).first()
    if not user or not verify_password(login_in.password, user.hashed_password):
        logger.warning("Failed login attempt", extra={"extra_fields": {"username": login_in.username}})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password."
        )

    # 1. Issue Access Token (Stateless)
    access_token = create_access_token(user.id, user.username)
    
    # 2. Issue Refresh Token (Database tracked for rotation/revocation)
    jti = generate_jti()
    refresh_token = create_refresh_token(user.id, jti)
    
    # Save Refresh Token state in database
    expires_at = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRY_MINUTES)
    db_refresh_token = RefreshToken(
        token_jti=jti,
        user_id=user.id,
        expires_at=expires_at,
        is_revoked=False
    )
    db.add(db_refresh_token)
    db.commit()
    
    logger.info("User logged in, tokens issued", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    db_queries.append(f"INSERT INTO refresh_tokens (token_jti, user_id, expires_at, is_revoked) VALUES ('{jti[:8]}...', {user.id}, ..., False)")

    # 3. Store Refresh Token in HttpOnly cookie
    response.set_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        value=refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production environments
        max_age=settings.REFRESH_TOKEN_EXPIRY_MINUTES * 60
    )
    
    resp_headers = {
        "Set-Cookie": f"{settings.REFRESH_TOKEN_COOKIE_NAME}={refresh_token[:12]}...; Max-Age={settings.REFRESH_TOKEN_EXPIRY_MINUTES*60}; SameSite=Lax; HttpOnly"
    }

    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "message": "Login successful!",
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.post("/api/refresh")
async def refresh(request: Request, response: Response, db: Session = Depends(get_db)):
    """Refreshes the Access Token using the HttpOnly Refresh Token.
    
    Implements Refresh Token Rotation (RTR):
    - Invalidates the used Refresh Token.
    - Issues a new Refresh Token (rotating the cookie).
    - Returns a brand new stateless Access Token.
    """
    refresh_token = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    db_queries = []
    
    if not refresh_token:
        logger.warning("Token refresh failed: No refresh cookie found")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token cookie found. Please log in again."
        )
        
    try:
        payload = decode_token(refresh_token)
        jti = payload.get("jti")
        user_id = int(payload.get("sub"))
    except jwt.ExpiredSignatureError:
        logger.warning("Token refresh failed: Expired refresh token signature")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired. Please log in again."
        )
    except jwt.InvalidTokenError:
        logger.warning("Token refresh failed: Invalid refresh token signature")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token. Please log in again."
        )

    db_queries.append(f"SELECT * FROM refresh_tokens WHERE token_jti = '{jti[:8]}...'")
    token_record = db.query(RefreshToken).filter(RefreshToken.token_jti == jti).first()
    
    # Refresh Token Rotation Security Check:
    # If the token is not found or is already revoked, it suggests malicious replay attacks.
    # Industry practice: Revoke all active tokens for the user as a safety measure.
    if not token_record or token_record.is_revoked or token_record.expires_at < datetime.utcnow():
        if token_record and token_record.is_revoked:
            logger.warning(
                "Refresh Token reuse detected! Revoking all sessions for user.", 
                extra={"extra_fields": {"user_id": user_id}}
            )
            db.query(RefreshToken).filter(RefreshToken.user_id == user_id).update({"is_revoked": True})
            db.commit()
            db_queries.append(f"UPDATE refresh_tokens SET is_revoked = True WHERE user_id = {user_id}")
            
        response.delete_cookie(settings.REFRESH_TOKEN_COOKIE_NAME)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid, expired, or reused refresh token. Access denied."
        )

    # 1. Rotate current token: Revoke/delete the used token
    token_record.is_revoked = True
    db.commit()
    db_queries.append(f"UPDATE refresh_tokens SET is_revoked = True WHERE token_jti = '{jti[:8]}...'")
    
    # 2. Get user info and generate new tokens
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User associated with token not found."
        )

    access_token = create_access_token(user.id, user.username)
    new_jti = generate_jti()
    new_refresh_token = create_refresh_token(user.id, new_jti)
    
    # Save the rotated refresh token to database
    expires_at = datetime.utcnow() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRY_MINUTES)
    db_new_token = RefreshToken(
        token_jti=new_jti,
        user_id=user.id,
        expires_at=expires_at,
        is_revoked=False
    )
    db.add(db_new_token)
    db.commit()
    
    db_queries.append(f"INSERT INTO refresh_tokens (token_jti, user_id, expires_at, is_revoked) VALUES ('{new_jti[:8]}...', {user.id}, ..., False)")
    logger.info("Rotated refresh token, issued new access token", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    
    # Set the rotated Refresh Token in cookie
    response.set_cookie(
        key=settings.REFRESH_TOKEN_COOKIE_NAME,
        value=new_refresh_token,
        httponly=True,
        samesite="lax",
        secure=False,
        max_age=settings.REFRESH_TOKEN_EXPIRY_MINUTES * 60
    )
    
    resp_headers = {
        "Set-Cookie": f"{settings.REFRESH_TOKEN_COOKIE_NAME}={new_refresh_token[:12]}...; Max-Age={settings.REFRESH_TOKEN_EXPIRY_MINUTES*60}; SameSite=Lax; HttpOnly"
    }

    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "debug": debug_meta
    }

@router.post("/api/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    refresh_token = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    db_queries = []
    
    if refresh_token:
        try:
            payload = decode_token(refresh_token)
            jti = payload.get("jti")
            token_record = db.query(RefreshToken).filter(RefreshToken.token_jti == jti).first()
            if token_record:
                token_record.is_revoked = True
                db.commit()
                logger.info("Logged out, revoked refresh token", extra={"extra_fields": {"jti_prefix": jti[:8]}})
                db_queries.append(f"UPDATE refresh_tokens SET is_revoked = True WHERE token_jti = '{jti[:8]}...'")
        except Exception:
            pass

    response.delete_cookie(settings.REFRESH_TOKEN_COOKIE_NAME)
    resp_headers = {
        "Set-Cookie": f"{settings.REFRESH_TOKEN_COOKIE_NAME}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    }
    
    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "message": "Successfully logged out.",
        "debug": debug_meta
    }
