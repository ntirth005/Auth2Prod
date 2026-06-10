import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from .database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    email = Column(String, nullable=True)
    display_name = Column(String, nullable=True)
    bio = Column(String, nullable=True)

class OAuthClient(Base):
    __tablename__ = "oauth_clients"

    client_id = Column(String, primary_key=True, index=True)
    client_secret = Column(String, nullable=False)
    client_name = Column(String, nullable=False)
    redirect_uri = Column(String, nullable=False)

class OAuthAuthCode(Base):
    __tablename__ = "oauth_auth_codes"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String, unique=True, index=True, nullable=False)
    client_id = Column(String, ForeignKey("oauth_clients.client_id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scope = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_used = Column(Boolean, default=False)

    user = relationship("User")
    client = relationship("OAuthClient")

class OAuthAccessToken(Base):
    __tablename__ = "oauth_access_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String, unique=True, index=True, nullable=False)
    client_id = Column(String, ForeignKey("oauth_clients.client_id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scope = Column(String, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    is_revoked = Column(Boolean, default=False)

    user = relationship("User")
    client = relationship("OAuthClient")
