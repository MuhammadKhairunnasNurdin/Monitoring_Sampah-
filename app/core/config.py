import secrets
from typing import Annotated, Any, Literal

from pydantic import (
    AnyUrl,
    BeforeValidator,
    MySQLDsn,
    computed_field,
)
from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_cors(v: Any) -> list[str] | str:
    if isinstance(v, str) and not v.startswith("["):
        return [i.strip() for i in v.split(",") if i.strip()]
    elif isinstance(v, list | str):
        return v
    raise ValueError(v)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_ignore_empty=True,
        extra="ignore",
    )

    # ------------------------------------------------------------------ #
    # Security
    # ------------------------------------------------------------------ #
    # Used to HMAC-sign session cookie values (equivalent to SESSION_SECRET
    # in Express's express-session config). MUST be set in .env for production.
    SECRET_KEY: str

    # ------------------------------------------------------------------ #
    # Session
    # ------------------------------------------------------------------ #
    # 1440 minutes = 24 hours
    SESSION_MAX_AGE: int = 1440

    ENVIRONMENT: Literal["local", "production"] = "local"

    # ------------------------------------------------------------------ #
    # Cookie Settings
    # ------------------------------------------------------------------ #
    # Single source of truth for cookie name — used in set_cookie, delete_cookie,
    # and Cookie() parameter declarations. Equivalent to express-session's
    # `name: "session_cookie_name"` option. Keep this in sync with the frontend.
    COOKIE_NAME: str = "session_cookies_name"

    COOKIE_SECURE: bool = True  # HTTPS only (auto-disabled in local env below)
    COOKIE_HTTPONLY: bool = True  # Prevent JS access — mirrors httpOnly: true in Express
    COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "strict"  # CSRF protection
    COOKIE_DOMAIN: str | None = None  # Set for subdomain sharing

    @computed_field
    @property
    def cookie_secure(self) -> bool:
        """
        Auto-disable secure flag in local environment.
        Mirrors: secure: process.env.NODE_ENV === 'production' in Express.
        """
        return self.ENVIRONMENT != "local" and self.COOKIE_SECURE

    # ------------------------------------------------------------------ #
    # CORS
    # ------------------------------------------------------------------ #
    FRONTEND_HOST: str = "http://localhost:5173"
    BACKEND_CORS_ORIGINS: Annotated[
        list[AnyUrl] | str, BeforeValidator(parse_cors)
    ] = []

    @computed_field  # type: ignore[prop-decorator]
    @property
    def all_cors_origins(self) -> list[str]:
        return [str(origin).rstrip("/") for origin in self.BACKEND_CORS_ORIGINS] + [
            self.FRONTEND_HOST
        ]

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    PROJECT_NAME: str
    MYSQL_SERVER: str
    MYSQL_PORT: int = 3306
    MYSQL_USER: str
    MYSQL_PASSWORD: str = ""
    MYSQL_DB: str = ""

    @computed_field  # type: ignore[prop-decorator]
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> MySQLDsn:
        return MySQLDsn.build(
            scheme="mysql+pymysql",
            username=self.MYSQL_USER,
            password=self.MYSQL_PASSWORD,
            host=self.MYSQL_SERVER,
            port=self.MYSQL_PORT,
            path=self.MYSQL_DB,
        )


settings = Settings()  # type: ignore