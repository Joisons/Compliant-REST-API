"""
Rate-limiting middleware.

Applies:
  - A strict IP-keyed limit on POST /auth/login (brute-force protection on
    the one endpoint that doesn't require a token to call).
  - A role-keyed limit (looked up from the caller's JWT) on every other
    request, so a VIEWER and an ADMIN calling the same endpoint are held to
    different ceilings -- reflecting that higher-privilege, more accountable
    roles are trusted with a higher request budget.
  - A conservative flat limit, keyed by IP, for any request that carries no
    valid token at all (mostly relevant to /health and docs).

On a 429, the response includes a `Retry-After` header (RFC 6585) and the
denial is attributed to the request's audit-log entry via `request.state`,
so it shows up in the audit trail as an explicit RATE_LIMITED outcome rather
than silently disappearing.
"""
import json
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.core.rate_limiter import (login_limiter, role_limiter, ROLE_LIMITS,
                                    LOGIN_ATTEMPTS_PER_WINDOW, UNAUTHENTICATED_LIMIT_PER_WINDOW)
from app.core.security import decode_access_token
from jose import JWTError


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"

        if request.url.path == "/auth/login" and request.method == "POST":
            result = login_limiter.check(f"login:{client_ip}", LOGIN_ATTEMPTS_PER_WINDOW)
            if not result.allowed:
                request.state.audit_detail = "Login attempt rate limit exceeded"
                return _too_many_requests(result.retry_after_seconds, result.limit)
            return await call_next(request)

        auth_header = request.headers.get("authorization", "")
        username, role = None, None
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1]
            try:
                payload = decode_access_token(token)
                username, role = payload.get("sub"), payload.get("role")
            except JWTError:
                pass

        if username and role:
            limit = ROLE_LIMITS.get(role, ROLE_LIMITS["VIEWER"])
            result = role_limiter.check(f"{username}:{role}", limit)
            request.state.audit_username = username
            request.state.audit_role = role
            if not result.allowed:
                request.state.audit_detail = f"Role rate limit exceeded ({limit}/min for {role})"
                return _too_many_requests(result.retry_after_seconds, result.limit)
        else:
            result = role_limiter.check(f"anon:{client_ip}", UNAUTHENTICATED_LIMIT_PER_WINDOW)
            if not result.allowed:
                request.state.audit_detail = "Unauthenticated request rate limit exceeded"
                return _too_many_requests(result.retry_after_seconds, result.limit)

        return await call_next(request)


def _too_many_requests(retry_after: float, limit: int) -> JSONResponse:
    body = {
        "type": "about:blank",
        "title": "Too Many Requests",
        "status": 429,
        "detail": f"Rate limit of {limit} requests/minute exceeded. Retry after {retry_after:.1f}s.",
    }
    resp = JSONResponse(status_code=429, content=body,
                         media_type="application/problem+json")
    resp.headers["Retry-After"] = str(int(retry_after) + 1)
    return resp
