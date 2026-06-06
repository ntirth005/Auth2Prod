import secrets
import hashlib
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from session_profile_app.core.database import get_db
from session_profile_app.models.models import User, LoginChallenge
from session_profile_app.schemas.schemas import (
    UserRegister, UserLogin, UserResponse,
    ChallengeRequest, ChallengeLoginRequest
)
from session_profile_app.core.security import hash_password, verify_password
from session_profile_app.core.session import DatabaseSessionManager
from session_profile_app.core.logging import get_logger
from session_profile_app.core.config import settings
from .utils import capture_debug_meta

router = APIRouter()
logger = get_logger("session_profile_app")

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
    salt = secrets.token_hex(16)
    client_key = hashlib.sha256((user_in.password + salt).encode('utf-8')).hexdigest()
    new_user = User(
        username=user_in.username,
        hashed_password=hashed,
        salt=salt,
        client_key=client_key,
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
        logger.warning("Failed standard login attempt", extra={"extra_fields": {"username": login_in.username}})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password."
        )

    # Create Session
    session_mgr = DatabaseSessionManager(db)
    expires_delta = timedelta(minutes=settings.SESSION_EXPIRY_MINUTES)
    session_id = session_mgr.create_session(user.id, expires_delta)
    logger.info("User authenticated via standard login", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    db_queries.append(f"INSERT INTO session_records (session_id, user_id, expires_at) VALUES ('{session_id[:6]}...', {user.id}, ...)")

    # Set Session Cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=login_in.secure_cookie,
        max_age=settings.SESSION_EXPIRY_MINUTES * 60
    )
    
    resp_headers = {
        "Set-Cookie": f"{settings.SESSION_COOKIE_NAME}={session_id[:6]}...; Max-Age={settings.SESSION_EXPIRY_MINUTES*60}; SameSite=Lax; HttpOnly" + ("; Secure" if login_in.secure_cookie else "")
    }

    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "message": "Login successful!",
        "session_id": session_id,
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.post("/api/auth/challenge")
async def get_challenge(request: Request, req_in: ChallengeRequest, db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT * FROM users WHERE username = '{req_in.username}'"
    ]
    user = db.query(User).filter(User.username == req_in.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
    
    # Generate single-use nonce
    nonce = secrets.token_hex(16)
    
    # Save challenge nonce
    expires_at = datetime.utcnow() + timedelta(minutes=2)
    challenge = LoginChallenge(
        username=req_in.username,
        nonce=nonce,
        expires_at=expires_at
    )
    db.add(challenge)
    db_queries.append(f"INSERT INTO login_challenges (username, nonce, expires_at) VALUES ('{req_in.username}', '{nonce[:6]}...', ...)")
    db.commit()
    logger.info("Generated authentication challenge nonce", extra={"extra_fields": {"username": req_in.username}})
    
    # Fallback salt if user registered before adding salt column
    user_salt = user.salt or "0000000000000000"
    
    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "username": req_in.username,
        "nonce": nonce,
        "salt": user_salt,
        "debug": debug_meta
    }

@router.post("/api/auth/challenge-login")
async def challenge_login(request: Request, response: Response, login_in: ChallengeLoginRequest, db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT * FROM login_challenges WHERE nonce = '{login_in.nonce[:6]}...' AND username = '{login_in.username}'",
        f"SELECT * FROM users WHERE username = '{login_in.username}'"
    ]
    
    # Verify challenge nonce
    challenge = db.query(LoginChallenge).filter(
        LoginChallenge.nonce == login_in.nonce,
        LoginChallenge.username == login_in.username
    ).first()
    
    if not challenge or challenge.expires_at < datetime.utcnow():
        logger.warning("Failed challenge-login: Invalid/expired challenge nonce", extra={"extra_fields": {"username": login_in.username}})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired challenge nonce. Please request a new challenge."
        )
    
    # Consume challenge to prevent replay
    db.delete(challenge)
    db_queries.append(f"DELETE FROM login_challenges WHERE nonce = '{login_in.nonce[:6]}...'")
    
    user = db.query(User).filter(User.username == login_in.username).first()
    if not user:
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found."
        )
        
    # Ensure client_key is populated (for older registered users)
    stored_client_key = user.client_key
    if not stored_client_key:
        db.commit()
        logger.warning("Failed challenge-login: Legacy user account missing client_key", extra={"extra_fields": {"username": login_in.username}})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Legacy user account. Please rotate your password to enable cryptographic auth."
        )
        
    # Verify signature: expected_hash = SHA-256(stored_client_key + nonce)
    expected_payload = (stored_client_key + login_in.nonce).encode('utf-8')
    expected_hash = hashlib.sha256(expected_payload).hexdigest()
    
    if login_in.auth_hash != expected_hash:
        db.commit()
        logger.warning("Failed challenge-login: Cryptographic signature mismatch", extra={"extra_fields": {"username": login_in.username}})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Cryptographic verification failed. Incorrect password."
        )
        
    # Establish Session
    session_mgr = DatabaseSessionManager(db)
    expires_delta = timedelta(minutes=settings.SESSION_EXPIRY_MINUTES)
    session_id = session_mgr.create_session(user.id, expires_delta)
    logger.info("User authenticated via Zero-Password challenge handshake", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    db_queries.append(f"INSERT INTO session_records (session_id, user_id, expires_at) VALUES ('{session_id[:6]}...', {user.id}, ...)")
    
    # Set Session Cookie
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=login_in.secure_cookie,
        max_age=settings.SESSION_EXPIRY_MINUTES * 60
    )
    
    resp_headers = {
        "Set-Cookie": f"{settings.SESSION_COOKIE_NAME}={session_id[:6]}...; Max-Age={settings.SESSION_EXPIRY_MINUTES*60}; SameSite=Lax; HttpOnly" + ("; Secure" if login_in.secure_cookie else "")
    }

    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "message": "Cryptographic authentication successful!",
        "session_id": session_id,
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.post("/api/logout")
async def logout(request: Request, response: Response, db: Session = Depends(get_db)):
    session_id = request.cookies.get(settings.SESSION_COOKIE_NAME)
    db_queries = []
    
    if session_id:
        session_mgr = DatabaseSessionManager(db)
        session_mgr.delete_session(session_id)
        logger.info("User session logged out successfully", extra={"extra_fields": {"session_prefix": session_id[:8]}})
        db_queries.append(f"DELETE FROM session_records WHERE session_id = '{session_id[:6]}...'")

    response.delete_cookie(settings.SESSION_COOKIE_NAME)
    resp_headers = {
        "Set-Cookie": f"{settings.SESSION_COOKIE_NAME}=; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
    }
    
    debug_meta = await capture_debug_meta(request, db_queries, resp_headers)
    return {
        "message": "Successfully logged out.",
        "debug": debug_meta
    }
