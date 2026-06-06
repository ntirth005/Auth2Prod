import os

class Settings:
    JWT_SECRET_KEY: str = os.getenv("JWT_SECRET_KEY", "industry-grade-secret-key-for-auth2prod-study-123456")
    JWT_ALGORITHM: str = "HS256"
    
    # Token expiry limits (industry standard: short access, long refresh)
    ACCESS_TOKEN_EXPIRY_MINUTES: int = 5
    REFRESH_TOKEN_EXPIRY_MINUTES: int = 30
    
    REFRESH_TOKEN_COOKIE_NAME: str = "jwt_refresh_token"
    
    # Database is placed inside the jwt_profile_app root directory
    DB_PATH: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "jwt_app.db"
    )
    SQLALCHEMY_DATABASE_URL: str = f"sqlite:///{DB_PATH}"

settings = Settings()
