# ---------------------------------------------------------------------------
# Security Headers Middleware — equivalent to helmet() in Express
# ---------------------------------------------------------------------------
# helmet() sets a collection of well-known HTTP security headers automatically.
# Below we replicate each header helmet sets by default:
#
#   X-Content-Type-Options: nosniff
#     → Prevents MIME-type sniffing attacks (browser won't guess content type)
#   X-Frame-Options: DENY
#     → Prevents clickjacking by blocking the page from being embedded in iframes
#   X-XSS-Protection: 0
#     → Modern recommendation: disable the legacy XSS auditor (it caused more
#        harm than good; CSP is the correct mitigation now)
#   Referrer-Policy: no-referrer
#     → Prevents leaking URL paths in the Referer header to third parties
#   Cross-Origin-Opener-Policy: same-origin
#     → Isolates the browsing context to prevent cross-origin attacks
#   Cross-Origin-Resource-Policy: same-origin
#     → Restricts which origins can load this server's resources
#   Permissions-Policy: (restrictive)
#     → Disables sensitive browser features (camera, microphone, geolocation, etc.)
#   Strict-Transport-Security (HSTS) — production only
#     → Forces HTTPS for 1 year; equivalent to helmet's hsts option
# ---------------------------------------------------------------------------
from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.config import settings


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        # Prevent MIME sniffing
        response.headers["X-Content-Type-Options"] = "nosniff"
        # Block iframe embedding (clickjacking protection)
        response.headers["X-Frame-Options"] = "DENY"
        # Disable legacy XSS auditor (modern recommendation)
        response.headers["X-XSS-Protection"] = "0"
        # Limit referrer information leakage
        response.headers["Referrer-Policy"] = "no-referrer"
        # Cross-origin isolation
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        # Restrict browser feature access
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )

        # HSTS — only in production (HTTPS required for this header to be meaningful)
        if settings.ENVIRONMENT == "production":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response
