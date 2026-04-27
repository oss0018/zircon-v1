"""
Security Headers Middleware for Zircon FRT.

Adds XSS-protection and other security HTTP headers to every response.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response


_SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        # Alpine.js v3 CDN build evaluates x-data/x-show/x-bind expressions via the
        # Function() constructor, which requires 'unsafe-eval'.  This is the minimal
        # relaxation needed; all other directives remain strict.
        "script-src 'self' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com "
        "https://fonts.googleapis.com; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net https://unpkg.com "
        "https://fonts.gstatic.com; "
        # Allow CDN hosts so DevTools sourcemap (.map) requests don't violate CSP.
        "connect-src 'self' https://cdn.jsdelivr.net https://unpkg.com; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware that appends security headers to every HTTP response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers[header] = value
        return response
