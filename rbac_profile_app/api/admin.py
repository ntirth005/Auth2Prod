from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
from rbac_profile_app.core.database import get_db
from rbac_profile_app.core.security import RequireRole, RequirePermission
from rbac_profile_app.models.models import User, Role
from rbac_profile_app.schemas.schemas import RoleProvisionRequest, UserResponse
from rbac_profile_app.api.utils import capture_debug_meta

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/users", response_model=None)
async def list_users(
    request: Request,
    current_user = Depends(RequirePermission("user:read")),
    db: Session = Depends(get_db)
):
    """Lists all registered users (Gated by permission: user:read)."""
    users = db.query(User).all()
    debug_meta = await capture_debug_meta(request)
    return {
        "users": [UserResponse.model_validate(u) for u in users],
        "debug": debug_meta
    }

@router.put("/user/{user_id}/roles")
async def provision_roles(
    user_id: int,
    payload: RoleProvisionRequest,
    request: Request,
    admin_user = Depends(RequireRole(["Admin"])),
    db: Session = Depends(get_db)
):
    """Reassigns roles to a target user (Gated by role: Admin)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User ID {user_id} not found."
        )

    # Don't let Admin remove their own Admin role to prevent self-lockout
    if user.id == admin_user.id and "Admin" not in payload.roles:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-Lockout Protection: You cannot strip the 'Admin' role from yourself."
        )

    # Resolve roles
    db_roles = db.query(Role).filter(Role.name.in_(payload.roles)).all()
    user.roles = db_roles
    db.commit()
    db.refresh(user)

    debug_meta = await capture_debug_meta(request)
    return {
        "message": f"Successfully updated roles for user '{user.username}' to {payload.roles}.",
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }

@router.delete("/user/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    admin_user = Depends(RequirePermission("user:delete")),
    db: Session = Depends(get_db)
):
    """Deletes a target user (Gated by permission: user:delete)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User ID {user_id} not found."
        )

    # Prevent self-deletion
    if user.id == admin_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Self-Deletion Protection: You cannot delete your own account."
        )

    db.delete(user)
    db.commit()

    debug_meta = await capture_debug_meta(request)
    return {
        "message": f"User '{user.username}' has been successfully deleted.",
        "debug": debug_meta
    }

@router.post("/ban/{user_id}")
async def ban_user(
    user_id: int,
    request: Request,
    moderator_user = Depends(RequireRole(["Admin", "Moderator"])),
    permission_guard = Depends(RequirePermission("user:write")),
    db: Session = Depends(get_db)
):
    """Bans a target user by modifying their profile state (Gated by role: Admin/Moderator and permission: user:write)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User ID {user_id} not found."
        )

    # Prevent banning oneself
    if user.id == moderator_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Suspension Protection: You cannot suspend/ban your own account."
        )

    # Simulate ban by editing their display name and bio
    if not user.display_name.startswith("[BANNED]"):
        user.display_name = f"[BANNED] {user.display_name}"
    user.bio = "This account has been suspended by a Moderator/Administrator."
    
    db.commit()
    db.refresh(user)

    debug_meta = await capture_debug_meta(request)
    return {
        "message": f"User '{user.username}' has been successfully suspended/banned.",
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }
