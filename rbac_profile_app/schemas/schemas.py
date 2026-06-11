from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime

# Auth Schemas
class UserRegister(BaseModel):
    username: str
    password: str
    email: Optional[EmailStr] = None
    display_name: Optional[str] = None

class UserLogin(BaseModel):
    username: str
    password: str

# Profile Updates
class ProfileUpdate(BaseModel):
    display_name: Optional[str] = None
    email: Optional[EmailStr] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None

# Admin / Provisioning Schemas
class RoleProvisionRequest(BaseModel):
    roles: List[str]

# Response Schemas
class PermissionResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None

    class Config:
        from_attributes = True

class RoleResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    permissions: List[PermissionResponse] = []

    class Config:
        from_attributes = True

class UserResponse(BaseModel):
    id: int
    username: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None
    created_at: datetime
    roles: List[RoleResponse] = []

    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UserResponse
