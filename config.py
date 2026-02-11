import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration settings for the application."""
    # Flask Configuration
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

    # JWT Configuration
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRES") or 3600)
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        seconds=int(os.getenv("JWT_REFRESH_TOKEN_EXPIRES") or 1296000)
    )

    # Database Configuration
    DB_TYPE = os.getenv("DATABASE_CONNECTION", "sqlite")
    DB_USER = os.getenv("DB_USER", "")
    DB_PASSWORD = os.getenv("DB_PASSWORD", "")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "5433")
    DB_NAME = os.getenv("DB_NAME", "app.db")

    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = False

    @staticmethod
    def get_database_uri(db_type, db_user, db_password, db_host, db_port, db_name):
        """Generate database URI based on DB_TYPE"""
        db_type = db_type.lower()

        if db_type == "sqlite":
            return f"sqlite:///{db_name}"
        elif db_type in ("postgresql", "postgres"):
            return f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        elif db_type == "mysql":
            return f"mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        else:
            raise ValueError(
                f"Unsupported database type: {db_type}. "
                "Supported types: sqlite, postgresql, mysql"
            )

    # Set SQLALCHEMY_DATABASE_URI as a class attribute
    SQLALCHEMY_DATABASE_URI = get_database_uri.__func__(
        DB_TYPE, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT, DB_NAME
    )


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    TESTING = False
    SQLALCHEMY_ECHO = True

    # Auto-generate temporary keys for development if not set
    if not Config.SECRET_KEY:
        import secrets
        SECRET_KEY = secrets.token_hex(32)

    if not Config.JWT_SECRET_KEY:
        import secrets
        JWT_SECRET_KEY = secrets.token_hex(32)


class TestingConfig(Config):
    """Testing configuration"""
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() in ("true", "1", "yes")
    DB_TYPE = "sqlite"
    DB_NAME = ":memory:"

    # Regenerate URI for testing
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_NAME}"


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = os.getenv("FLASK_DEBUG", "False").lower() in ("true", "1", "yes")
    TESTING = False
    SQLALCHEMY_ECHO = False

    def __init__(self):
        super().__init__()
        # Validate critical variables only when production config is used
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY must be set in production!")
        if not self.JWT_SECRET_KEY:
            raise ValueError("JWT_SECRET_KEY must be set in production!")


# Configuration dictionary
config = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig
}