from tests.conftest import auth_header


def test_login_success(client):
    r = client.post("/auth/login", data={"username": "admin", "password": "AdminPass123!"})
    assert r.status_code == 200
    body = r.json()
    assert body["role"] == "ADMIN"
    assert body["token_type"] == "bearer"
    assert len(body["access_token"]) > 20


def test_login_wrong_password(client):
    r = client.post("/auth/login", data={"username": "admin", "password": "wrong"})
    assert r.status_code == 401


def test_login_unknown_user(client):
    r = client.post("/auth/login", data={"username": "nobody", "password": "x"})
    assert r.status_code == 401


def test_protected_endpoint_without_token(client):
    r = client.get("/api/v1/accounts")
    assert r.status_code == 401


def test_protected_endpoint_with_garbage_token(client):
    r = client.get("/api/v1/accounts", headers=auth_header("not-a-real-token"))
    assert r.status_code == 401


def test_only_admin_can_create_users(client, tokens):
    payload = {"username": "newbie", "full_name": "New Person", "password": "SomePass123!", "role": "VIEWER"}
    r = client.post("/auth/users", json=payload, headers=auth_header(tokens["ANALYST"]))
    assert r.status_code == 403

    r2 = client.post("/auth/users", json=payload, headers=auth_header(tokens["ADMIN"]))
    assert r2.status_code == 201
    assert r2.json()["role"] == "VIEWER"


def test_deactivated_user_is_rejected_immediately(client, tokens):
    """A JWT issued before deactivation must stop working on the very next
    request, not merely after it expires -- this is the point of re-checking
    `is_active` against the database on every request rather than trusting
    the token's claims alone."""
    from app.database import SessionLocal
    from app.models.db_models import User

    db = SessionLocal()
    user = db.query(User).filter(User.username == "alex_analyst").first()
    user.is_active = False
    db.commit()
    db.close()

    r = client.get("/api/v1/transactions", headers=auth_header(tokens["ANALYST"]))
    assert r.status_code == 403
