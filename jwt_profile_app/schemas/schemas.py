from typing import Optional
from pydantic import BaseModel, EmailStr, Field

class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)
    display_name: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None
    bio: Optional[str] = Field(None, max_length=500)


class UserLogin(BaseModel):
    username: str
    password: str


class ProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(None, max_length=100)
    email: Optional[EmailStr] = None
    bio: Optional[str] = Field(None, max_length=500)


class PasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6)


class UserResponse(BaseModel):
    id: int
    username: str
    display_name: Optional[str]
    email: Optional[str]
    bio: Optional[str]

    class Config:
        from_attributes = True


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

