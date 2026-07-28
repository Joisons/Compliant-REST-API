"""
Shared pytest fixtures.

Each test module gets a fresh, isolated SQLite database (a temp file, not
the dev database used by `uvicorn app.main:app`), pre-seeded with the same
four demo users used in scripts/seed_data.py, so tests never depend on --
or interfere with -- whatever state is sitting in compliant_api.db.
"""
import os
import tempfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


@pytest.fixture()
def client(monkeypatch):
    db_fd, db_path = tempfile.mkstemp(suffix=".db")
    os.close(db_fd)

    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")

    # app.database reads settings at import time, so we must patch its
    # already-created engine/session rather than relying on the env var
    # alone (the module may already be imported by a prior test).
    import app.database as database_module
    import app.middleware.audit_logging as audit_mw

    test_engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

    database_module.engine = test_engine
    database_module.SessionLocal = TestSessionLocal
    audit_mw.SessionLocal = TestSessionLocal

    from app.database import Base
    Base.metadata.create_all(bind=test_engine)

    from app.models.db_models import User, Account, Role
    from app.core.security import hash_password

    db = TestSessionLocal()
    db.add_all([
        User(username="vera_viewer", full_name="Vera Viewer", role=Role.VIEWER,
             hashed_password=hash_password("ViewerPass123!")),
        User(username="alex_analyst", full_name="Alex Analyst", role=Role.ANALYST,
             hashed_password=hash_password("AnalystPass123!")),
        User(username="amara_auditor", full_name="Amara Auditor", role=Role.AUDITOR,
             hashed_password=hash_password("AuditorPass123!")),
        User(username="admin", full_name="Admin", role=Role.ADMIN,
             hashed_password=hash_password("AdminPass123!")),
    ])
    db.add(Account(account_number="ACC-TEST-1", holder_name="Test Holder",
                    account_type="Individual", balance=1000.0, risk_rating="Low"))
    db.commit()
    db.close()

    from app.core.rate_limiter import login_limiter, role_limiter
    login_limiter.reset()
    role_limiter.reset()

    from app.main import app as fastapi_app
    with TestClient(fastapi_app) as c:
        yield c

    os.remove(db_path)


@pytest.fixture()
def tokens(client):
    def _login(username, password):
        r = client.post("/auth/login", data={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]

    return {
        "VIEWER": _login("vera_viewer", "ViewerPass123!"),
        "ANALYST": _login("alex_analyst", "AnalystPass123!"),
        "AUDITOR": _login("amara_auditor", "AuditorPass123!"),
        "ADMIN": _login("admin", "AdminPass123!"),
    }


def auth_header(token):
    return {"Authorization": f"Bearer {token}"}
