from fastapi import Cookie, HTTPException, status

from app.core.config import settings
from app.core.database import SessionDep
from app.models.user import User
from app.services.auth_service import AuthService


def is_authenticated(
    db: SessionDep,
    # Cookie name is read from config — single source of truth, mirrors
    # express-session's `name` option which is also centralised in main.ts
    session_id: str | None = Cookie(default=None, alias=settings.COOKIE_NAME),
) -> User:
    """
    Dependency to validate the session cookie and return the authenticated User.

    Mirrors Express isAuthenticated middleware:
      - Checks cookie presence
      - Verifies HMAC signature (express-session does this automatically)
      - Looks up session in DB store and returns the User object
      - Raises 401 (equivalent to res.status(401).json(...)) if any step fails

    The returned User is injected directly into route handlers via FastAPI's
    dependency system — no second DB lookup needed in the handler itself.
    """
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Silakan login terlebih dahulu1",
        )

    # validate_session handles signature verification + DB lookup + expiry check
    user = AuthService.validate_session(db, session_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Silakan login terlebih dahulu2",
        )

    return user