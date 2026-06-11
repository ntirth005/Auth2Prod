import os

class Settings:
    PROJECT_NAME: str = "Auth2Prod - Modular RBAC Profile App"
    DATABASE_URL: str = "sqlite:///rbac_app.db"
    
    # Security Configuration
    JWT_SECRET: str = os.getenv("JWT_SECRET", "rbac-system-secret-key-9284719284")
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

settings = Settings()
