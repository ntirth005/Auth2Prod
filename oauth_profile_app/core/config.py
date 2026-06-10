import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Settings:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "prod-oauth-app-secret-key-999-secure")
    
    # GitHub OAuth Settings
    GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
    GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
    GITHUB_REDIRECT_URI: str = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:8000/api/auth/github/callback")
    
    # Google OAuth Settings
    GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET: str = os.getenv("GOOGLE_CLIENT_SECRET", "")
    GOOGLE_REDIRECT_URI: str = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/api/auth/google/callback")
    
    # Cookie Session Settings
    SESSION_COOKIE_NAME: str = "oauth_session"
    SESSION_EXPIRY_DAYS: int = 7

settings = Settings()
