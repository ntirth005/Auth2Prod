import secrets
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from jwt_profile_app.core.database import get_db
from jwt_profile_app.models.models import User, RefreshToken
from jwt_profile_app.schemas.schemas import (
    ProfileUpdate, PasswordChange, UserResponse
)
from jwt_profile_app.core.security import hash_password, verify_password
from jwt_profile_app.core.logging import get_logger
from jwt_profile_app.core.config import settings
from .utils import get_current_user, capture_debug_meta

router = APIRouter()
logger = get_logger("jwt_profile_app")

@router.get("/api/profile")
async def get_profile(request: Request, user: User = Depends(get_current_user)):
    auth_header = request.headers.get("Authorization", "")
    token_pref = auth_header.split(" ")[1][:8] + "..." if " " in auth_header else "None"
    
    db_queries = [
        f"SELECT * FROM users WHERE id = {user.id} (Stateless check completed via Token: {token_pref})"
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
    db.commit()
    db_queries.append(f"UPDATE users SET hashed_password='...' WHERE id={user.id}")

    # Identify the current session's refresh token JTI so we don't revoke it,
    # maintaining parity with the stateful session cookie app which keeps the current session alive.
    from jwt_profile_app.core.jwt_helper import decode_token
    current_refresh_token = request.cookies.get(settings.REFRESH_TOKEN_COOKIE_NAME)
    current_jti = None
    if current_refresh_token:
        try:
            payload = decode_token(current_refresh_token)
            current_jti = payload.get("jti")
        except Exception:
            pass

    # Revoke all other refresh tokens for the user in the database
    query = db.query(RefreshToken).filter(RefreshToken.user_id == user.id)
    if current_jti:
        query = query.filter(RefreshToken.token_jti != current_jti)
    query.update({"is_revoked": True})
    db.commit()
    
    logger.info("Password rotated successfully; other active sessions invalidated", extra={"extra_fields": {"username": user.username, "user_id": user.id}})
    db_queries.append(f"UPDATE refresh_tokens SET is_revoked = True WHERE user_id={user.id} AND token_jti != '{current_jti[:8] if current_jti else 'None'}...'")

    debug_meta = await capture_debug_meta(request, db_queries)
    return {
        "message": "Password updated successfully! Other active sessions and devices have been logged out.",
        "debug": debug_meta
    }
