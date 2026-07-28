"""
Compliant FinTech Data API -- application entry point.

Middleware registration order matters: Starlette executes the *last*-added
middleware *first* on the way in (it becomes the outermost layer) and
therefore last on the way out. AuditLogMiddleware is added last so that it
sees the true final status code of every request -- including a 429 from
RateLimitMiddleware or a 403/401 raised by an RBAC dependency deep inside a
route -- and can log it with the correct outcome. If the order were
reversed, rate-limited requests would never reach the audit log at all.
"""
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.config import get_settings
from app.database import Base, engine
from app.middleware.rate_limit import RateLimitMiddleware
from app.middleware.audit_logging import AuditLogMiddleware
from app.api import auth, accounts, transactions, reports, audit, health

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=(
        "A demonstration REST API implementing three compliance-oriented governance "
        "controls for a regulated FinTech data platform: role-based access control, "
        "tamper-evident audit logging, and role-tiered rate limiting. Built as a working "
        "companion to the 2022 paper on leadership practices in overseeing data engineers "
        "in regulated financial-technology environments."
    ),
    lifespan=lifespan,
)

# NOTE: added in this order so AuditLogMiddleware ends up OUTERMOST -- see module docstring.
app.add_middleware(RateLimitMiddleware)
app.add_middleware(AuditLogMiddleware)

app.include_router(health.router)
app.include_router(auth.router)
app.include_router(accounts.router)
app.include_router(transactions.router)
app.include_router(reports.router)
app.include_router(audit.router)


# --- RFC 7807 "Problem Details" style error responses, for consistency ---
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"type": "about:blank", "title": exc.detail, "status": exc.status_code,
                 "instance": str(request.url.path)},
        media_type="application/problem+json",
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"type": "about:blank", "title": "Validation Error", "status": 422,
                 "instance": str(request.url.path), "errors": exc.errors()},
        media_type="application/problem+json",
    )


@app.get("/", tags=["Health"])
def root():
    return {"service": settings.app_name, "version": settings.app_version, "docs": "/docs"}
