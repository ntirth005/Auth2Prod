from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session
from rbac_profile_app.core.database import get_db
from rbac_profile_app.core.security import get_current_user, RequirePermission
from rbac_profile_app.schemas.schemas import ProfileUpdate, UserResponse
from rbac_profile_app.api.utils import capture_debug_meta

router = APIRouter(prefix="/api/profile", tags=["profile"])

@router.get("/me")
async def get_profile(
    request: Request,
    current_user = Depends(RequirePermission("user:read")),
    db: Session = Depends(get_db)
):
    """Retrieves current user details (Gated by permission: user:read)."""
    debug_meta = await capture_debug_meta(request)
    return {
        "user": UserResponse.model_validate(current_user),
        "debug": debug_meta
    }

@router.put("/me")
async def update_profile(
    payload: ProfileUpdate,
    request: Request,
    current_user = Depends(RequirePermission("user:write")),
    db: Session = Depends(get_db)
):
    """Updates user display name, email, bio, and avatar (Gated by permission: user:write)."""
    if payload.display_name is not None:
        current_user.display_name = payload.display_name
    if payload.email is not None:
        current_user.email = payload.email
    if payload.bio is not None:
        current_user.bio = payload.bio
    if payload.avatar_url is not None:
        current_user.avatar_url = payload.avatar_url

    db.commit()
    db.refresh(current_user)

    debug_meta = await capture_debug_meta(request)
    return {
        "message": "Profile updated successfully!",
        "user": UserResponse.model_validate(current_user),
        "debug": debug_meta
    }
