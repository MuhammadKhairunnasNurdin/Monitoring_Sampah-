from typing import Annotated

from fastapi import APIRouter, Cookie, Depends, status, Request
from starlette.responses import JSONResponse

from app.core.config import settings
from app.core.database import SessionDep
from app.dependencies import is_authenticated
from app.models.user import User, UserBase
from app.services.auth_service import AuthService
from app.services.user_service import UserService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login")
async def login(
    request: Request,
    db: SessionDep,
):
    data = await request.json()
    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "Email dan password wajib diisi"},
        )

    credentials = UserBase(email=email, password=password)
    if not AuthService.validate_password(db, credentials):
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": "Email atau password salah"},
        )

    user = UserService.find_user_by_email(db, credentials.email)
    if not user:
        # Defensive guard — validate_password already confirmed user exists
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"success": False, "message": "User tidak ditemukan"},
        )

    signed_session = AuthService.create_session(db, user.id)

    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "success": True,
            "message": "Login berhasil",
            "user": {"id": user.id, "email": user.email},
        },
    )

    # Set signed session cookie — mirrors express-session Set-Cookie header
    # SESSION_MAX_AGE is in minutes; cookie max_age expects seconds
    resp.set_cookie(
        key=settings.COOKIE_NAME,           # Same source as Cookie() params below
        value=signed_session,               # SIGNED value, not raw token
        httponly=settings.COOKIE_HTTPONLY,  # httpOnly: true
        secure=settings.cookie_secure,      # secure: NODE_ENV === 'production'
        samesite=settings.COOKIE_SAMESITE,
        max_age=settings.SESSION_MAX_AGE * 60,
        path="/",
        domain=settings.COOKIE_DOMAIN,
    )

    return resp


@router.post("/register")
def register(
    credentials: UserBase,
    db: SessionDep,
):
    if not credentials.email or not credentials.password:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"success": False, "message": "Email dan password wajib diisi"},
        )

    success, message, new_user = AuthService.register_user(
        db, credentials.email, credentials.password
    )

    if not success:
        status_code = (
            status.HTTP_409_CONFLICT
            if "sudah terdaftar" in message
            else status.HTTP_400_BAD_REQUEST
        )
        return JSONResponse(
            status_code=status_code,
            content={"success": False, "message": message},
        )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={"success": True, "message": message, "userId": new_user.id},
    )


@router.post("/logout")
def logout(
    db: SessionDep,
    # Use alias so the cookie name is always read from config — never hardcoded
    session_id: str | None = Cookie(default=None, alias=settings.COOKIE_NAME),
):
    if session_id:
        # Pass the signed value — delete_session verifies signature before DB lookup
        AuthService.delete_session(db, session_id)

    resp = JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"success": True, "message": "Logout berhasil"},
    )
    # Clear cookie using the same name and path/domain as when it was set
    resp.delete_cookie(
        key=settings.COOKIE_NAME,
        path="/",
        domain=settings.COOKIE_DOMAIN,
    )

    return resp


@router.get("/check")
def check_auth(
    db: SessionDep,
    session_id: str | None = Cookie(default=None, alias=settings.COOKIE_NAME),
):
    if not session_id:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "isAuthenticated": False},
        )

    user = AuthService.validate_session(db, session_id)

    if not user:
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"success": True, "isAuthenticated": False},
        )

    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={
            "success": True,
            "isAuthenticated": True,
            "userId": user.id,
            "email": user.email,
        },
    )


@router.get("/profile")
def get_profile(
    current_user: Annotated[User, Depends(is_authenticated)],
):
    return {
        "success": True,
        "user": {
            "id": current_user.id,
            "email": current_user.email,
            "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        },
    }