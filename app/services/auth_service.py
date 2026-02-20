import re
import secrets
from datetime import timedelta
from typing import Optional

from itsdangerous import BadSignature, Signer
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher
from sqlmodel import Session, select

from app.core.config import settings
from app.models.session import Session as SessionModel
from app.models.user import User, UserBase
from app.utils.timestamp import get_datetime_utc

password_hash = PasswordHash(
    (
        Argon2Hasher(),
        BcryptHasher(),
    )
)

EMAIL_REGEX = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

# ---------------------------------------------------------------------------
# Cookie Signer
# ---------------------------------------------------------------------------
# Equivalent to express-session signing cookies with SESSION_SECRET.
# express-session prepends "s:" and appends an HMAC signature to the session ID.
# Here we use itsdangerous.Signer (already a Starlette/FastAPI transitive dep)
# which does the same: raw_token → raw_token.HMAC_SIGNATURE
#
# The raw session ID is stored in the DB.
# The SIGNED value is what goes into the browser cookie.
# On every request, the signature is verified BEFORE any DB lookup is attempted.
# This prevents cookie tampering and forgery.
# ---------------------------------------------------------------------------
def _get_signer() -> Signer:
    return Signer(settings.SECRET_KEY, salt="session", sep=".")


def sign_session_id(session_id: str) -> str:
    """
    Sign a session ID for safe storage in a browser cookie.

    Mirrors: express-session internally calling
      cookieSignature.sign(sessionId, secret) before Set-Cookie.
    """
    return _get_signer().sign(session_id.encode()).decode()


def unsign_session_id(signed_value: str) -> Optional[str]:
    """
    Verify and extract the raw session ID from a signed cookie value.

    Mirrors: express-session internally calling
      cookieSignature.unsign(cookieValue, secret) on every incoming request.

    Returns None if the signature is invalid or tampered — equivalent to
    express-session silently rejecting an unsigned/forged session cookie.
    """
    try:
        return _get_signer().unsign(signed_value.encode()).decode()
    except BadSignature:
        return None


class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        return password_hash.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return password_hash.verify(plain_password, hashed_password)

    @staticmethod
    def generate_session_id() -> str:
        """
        Generate a cryptographically secure random session ID.

        Equivalent to express-session's internal uid-safe token generation.
        This raw value is stored in the DB; the signed version goes to the cookie.
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def validate_password(db: Session, credentials: UserCredential) -> bool:
        user = db.exec(select(User).where(User.email == credentials.email)).first()

        if not user:
            # Guard: no user → treat as wrong credentials, same as bcrypt.compare → false
            return False

        return AuthService.verify_password(credentials.password, user.password)

    @staticmethod
    def create_session(db: Session, user_id: int) -> str:
        """
        Create a new DB session and return the SIGNED cookie value.

        Mirrors the express-session flow on login:
          1. Session data is written to the store (here: MySQL DB row)
          2. The signed session ID is placed into Set-Cookie header

        Returns the SIGNED token (ready to be set as cookie value directly).
        The raw (unsigned) token is what is persisted in the DB.
        """
        # Delete all existing sessions for this user (single active session policy)
        old_sessions = db.exec(
            select(SessionModel).where(SessionModel.user_id == user_id)
        ).all()
        for old_session in old_sessions:
            db.delete(old_session)

        # Generate raw session ID and persist in DB
        raw_session_id = AuthService.generate_session_id()
        expires_at = get_datetime_utc() + timedelta(minutes=settings.SESSION_MAX_AGE)

        session = SessionModel(
            user_id=user_id,
            session_id=raw_session_id,
            expires_at=expires_at,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

        # Return the SIGNED value for cookie — never expose raw ID directly
        return sign_session_id(raw_session_id)

    @staticmethod
    def validate_session(db: Session, signed_cookie_value: str) -> Optional[User]:
        """
        Validate a signed session cookie and return the associated user.

        Mirrors express-session's per-request middleware:
          1. Verifies HMAC signature — rejects tampered cookies before any DB hit
          2. Looks up the raw session ID in the store (DB)
          3. Checks server-side expiry (express-session uses cookie maxAge for expiry;
             here we use the DB expires_at field as authoritative source)
          4. Returns the hydrated User (equivalent to populating req.session.userId)
        """
        # Step 1: Verify HMAC signature — reject tampered/forged cookies immediately
        raw_session_id = unsign_session_id(signed_cookie_value)
        if not raw_session_id:
            return None

        # Step 2: Look up session in DB
        session = db.exec(
            select(SessionModel).where(SessionModel.session_id == raw_session_id)
        ).first()

        if not session:
            return None

        # Step 3: Check server-side expiry
        now = get_datetime_utc()
        expires_at = session.expires_at

        if expires_at.tzinfo is None or expires_at.tzinfo.utcoffset(expires_at) is None:
            now = now.replace(tzinfo=None)
        else:
            expires_at = expires_at.astimezone(now.tzinfo)

        if expires_at < now:
            db.delete(session)
            db.commit()
            return None

        # Step 4: Return hydrated user
        user = db.exec(select(User).where(User.id == session.user_id)).first()
        return user

    @staticmethod
    def delete_session(db: Session, signed_cookie_value: str) -> bool:
        """
        Delete a session by signed cookie value (logout).

        Mirrors session.destroy() in Express:
          - Verifies signature first (no DB lookup for tampered cookies)
          - Removes DB row
          - Returns False if session not found (no-op)
        """
        raw_session_id = unsign_session_id(signed_cookie_value)
        if not raw_session_id:
            return False  # Invalid/tampered cookie — nothing to delete

        session = db.exec(
            select(SessionModel).where(SessionModel.session_id == raw_session_id)
        ).first()

        if not session:
            return False

        db.delete(session)
        db.commit()
        return True

    @staticmethod
    def register_user(
        db: Session, email: str, password: str
    ) -> tuple[bool, str, Optional[User]]:
        existing_user = db.exec(
            select(User).where(User.email == email)
        ).first()
        if existing_user:
            return False, "Email sudah terdaftar", None

        # 2. Email format
        if not EMAIL_REGEX.match(email):
            return False, "Format email tidak valid", None

        # 3. Password length
        if len(password) < 6:
            return False, "Password minimal 6 karakter", None

        # 4. Create user
        hashed_password = AuthService.hash_password(password)
        new_user = User(email=email, password=hashed_password)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return True, "Pendaftaran berhasil", new_user