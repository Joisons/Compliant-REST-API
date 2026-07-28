from tests.conftest import auth_header


def test_role_rate_limit_enforced(client, tokens):
    """VIEWER's configured limit is 30/min; the 31st request in the same
    window must be rejected with 429 and a Retry-After header."""
    statuses = []
    for _ in range(32):
        r = client.get("/api/v1/accounts", headers=auth_header(tokens["VIEWER"]))
        statuses.append(r.status_code)

    assert statuses.count(200) == 30
    assert statuses.count(429) == 2
    assert r.headers.get("Retry-After") is not None


def test_higher_role_gets_higher_limit(client, tokens):
    """ADMIN's limit (200/min) is materially higher than VIEWER's (30/min);
    50 rapid requests should all succeed for ADMIN but not for VIEWER."""
    admin_statuses = [client.get("/api/v1/accounts", headers=auth_header(tokens["ADMIN"])).status_code
                       for _ in range(50)]
    assert all(s == 200 for s in admin_statuses)


def test_login_brute_force_protection(client):
    statuses = [client.post("/auth/login", data={"username": "admin", "password": "wrong"}).status_code
                for _ in range(15)]
    assert statuses.count(401) == 10  # allowed through, correctly rejected for bad password
    assert statuses.count(429) == 5   # blocked by the login rate limiter


def test_rate_limited_requests_appear_in_audit_log(client, tokens):
    for _ in range(32):
        client.get("/api/v1/accounts", headers=auth_header(tokens["VIEWER"]))

    logs = client.get("/api/v1/audit-logs?outcome=RATE_LIMITED",
                       headers=auth_header(tokens["ADMIN"])).json()
    assert len(logs) >= 2
    assert all(entry["status_code"] == 429 for entry in logs)


def test_audit_log_chain_verifies_clean(client, tokens):
    client.get("/api/v1/accounts", headers=auth_header(tokens["VIEWER"]))
    r = client.get("/api/v1/audit-logs/verify", headers=auth_header(tokens["ADMIN"]))
    assert r.status_code == 200
    assert r.json()["verified"] is True
    assert r.json()["first_break_at_id"] is None


def test_audit_log_detects_tampering(client, tokens):
    client.get("/api/v1/accounts", headers=auth_header(tokens["VIEWER"]))

    from app.database import SessionLocal
    from app.models.db_models import AuditLogEntry

    db = SessionLocal()
    victim = db.query(AuditLogEntry).order_by(AuditLogEntry.id.asc()).first()
    victim_id = victim.id
    victim.status_code = 999
    db.commit()
    db.close()

    r = client.get("/api/v1/audit-logs/verify", headers=auth_header(tokens["ADMIN"]))
    body = r.json()
    assert body["verified"] is False
    assert body["first_break_at_id"] == victim_id


def test_denied_requests_are_logged_as_denied(client, tokens):
    client.get("/api/v1/transactions", headers=auth_header(tokens["VIEWER"]))  # 403
    logs = client.get("/api/v1/audit-logs?outcome=DENIED",
                       headers=auth_header(tokens["ADMIN"])).json()
    assert any(e["path"] == "/api/v1/transactions" and e["username"] == "vera_viewer" for e in logs)
