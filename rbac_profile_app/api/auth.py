from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from datetime import timedelta
from rbac_profile_app.core.database import get_db
from rbac_profile_app.core.security import hash_password, verify_password, create_access_token
from rbac_profile_app.models.models import User, Role
from rbac_profile_app.schemas.schemas import UserRegister, UserLogin, UserResponse
from rbac_profile_app.api.utils import capture_debug_meta

router = APIRouter(prefix="/api/auth", tags=["auth"])

@router.post("/register")
async def register(payload: UserRegister, request: Request, db: Session = Depends(get_db)):
    """Registers a new user and grants the default 'User' role."""
    # Check if username exists
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken. Choose another name."
        )

    # Hash passwords via bcrypt
    hashed_pw = hash_password(payload.password)
    
    new_user = User(
        username=payload.username,
        hashed_password=hashed_pw,
        email=payload.email,
        display_name=payload.display_name or payload.username
    )

    # Associate default 'User' role
    user_role = db.query(Role).filter(Role.name == "User").first()
    if user_role:
        new_user.roles.append(user_role)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    debug_meta = await capture_debug_meta(request)
    return {
        "message": f"User '{new_user.username}' registered successfully!",
        "user": UserResponse.model_validate(new_user),
        "debug": debug_meta
    }

@router.post("/login")
async def login(payload: UserLogin, request: Request, db: Session = Depends(get_db)):
    """Authenticates credentials and issues a JWT token."""
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password."
        )

    # Sign JWT token
    access_token = create_access_token(data={"sub": user.id})
    debug_meta = await capture_debug_meta(request)

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": UserResponse.model_validate(user),
        "debug": debug_meta
    }
