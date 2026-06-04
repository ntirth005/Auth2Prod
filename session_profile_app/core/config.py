import os

class Settings:
    SESSION_COOKIE_NAME: str = "session_profile_id"
    SESSION_EXPIRY_MINUTES: int = 15
    # Database is placed inside the session_profile_app root directory
    DB_PATH: str = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
        "session_app.db"
    )
    SQLALCHEMY_DATABASE_URL: str = f"sqlite:///{DB_PATH}"

settings = Settings()
