from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.exception import setup_exception_handlers
from app.middleware.security_header import SecurityHeadersMiddleware
from app.routes.main import api_router

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(
    title=settings.PROJECT_NAME,
    description=f"Backend API for '{settings.PROJECT_NAME}'",
    version="1.0.0",
)

# Security headers — add FIRST so they are applied to every response
# (Starlette middleware wraps in reverse order; first added = outermost = last to run on response)
app.add_middleware(SecurityHeadersMiddleware)

# CORS — must allow credentials for session cookies to be sent cross-origin
# Mirrors: cors({ origin: ..., credentials: true }) in Express
if settings.all_cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.all_cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

# Global exception handlers
setup_exception_handlers(app)

# Routes
app.include_router(api_router)