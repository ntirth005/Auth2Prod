import secrets
import hashlib
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from session_profile_app.core.database import get_db
from session_profile_app.models.models import User, SessionRecord
from session_profile_app.schemas.schemas import (
    ProfileUpdate, PasswordChange, UserResponse
)
from session_profile_app.core.security import hash_password, verify_password
from session_profile_app.core.session import DatabaseSessionManager
from session_profile_app.core.logging import get_logger
from session_profile_app.core.config import settings
from .utils import get_current_user, capture_debug_meta

router = APIRouter()
logger = get_logger("session_profile_app")

@router.get("/api/profile")
async def get_profile(request: Request, user: User = Depends(get_current_user)):
    db_queries = [
        f"SELECT * FROM session_records WHERE session_id = '{request.cookies.get(settings.SESSION_COOKIE_NAME)[:6]}...'",
        f"SELECT * FROM users WHERE id = {user.id}"
    ]
    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.put("/api/profile")
async def update_profile(request: Request, profile_in: ProfileUpdate, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT * FROM users WHERE id = {user.id}"
    ]
    
    if profile_in.display_name is not None:
        user.display_name = profile_in.display_name
    if profile_in.email is not None:
        user.email = profile_in.email
    if profile_in.bio is not None:
        user.bio = profile_in.bio
        
    db.commit()
    db.refresh(user)
    db_queries.append(f"UPDATE users SET display_name='{user.display_name}', email='{user.email}', bio='...' WHERE id={user.id}")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "message": "Profile updated successfully!",
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.post("/api/change-password")
async def change_password(request: Request, pwd_in: PasswordChange, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    db_queries = [
        f"SELECT hashed_password FROM users WHERE id = {user.id}"
    ]
    
    if not verify_password(pwd_in.current_password, user.hashed_password):
        logger.warning("Failed password rotation attempt: incorrect current password", extra={"extra_fields": {"username": user.username}})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Incorrect current password."
        )
        
    user.hashed_password = hash_password(pwd_in.new_password)
    user.salt = secrets.token_hex(16)
    user.client_key = hashlib.sha256((pwd_in.new_password + user.salt).encode('utf-8')).hexdigest()
    db.commit()
    db_queries.append(f"UPDATE users SET hashed_password='...', salt='...', client_key='...' WHERE id={user.id}")

    # Log out of other sessions to increase security
    session_mgr = DatabaseSessionManager(db)
    current_session = request.cookies.get(settings.SESSION_COOKIE_NAME)
    
    # Invalidate all sessions except the current one
    db.query(SessionRecord).filter(
        SessionRecord.user_id == user.id,
        SessionRecord.session_id != current_session
    ).delete()
    db.commit()
    logger.info("Password rotated successfully; other active sessions invalidated", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    db_queries.append(f"DELETE FROM session_records WHERE user_id={user.id} AND session_id != current_session")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "message": "Password updated successfully! Other active sessions invalidated.",
        "debug": debug_meta
    }
