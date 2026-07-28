import pytest
from tests.conftest import auth_header


@pytest.mark.parametrize("role,expected", [
    ("VIEWER", 200), ("ANALYST", 200), ("AUDITOR", 200), ("ADMIN", 200),
])
def test_all_roles_can_read_accounts(client, tokens, role, expected):
    r = client.get("/api/v1/accounts", headers=auth_header(tokens[role]))
    assert r.status_code == expected


@pytest.mark.parametrize("role,expected", [
    ("VIEWER", 403), ("ANALYST", 200), ("AUDITOR", 200), ("ADMIN", 200),
])
def test_only_analyst_auditor_admin_can_read_transactions(client, tokens, role, expected):
    r = client.get("/api/v1/transactions", headers=auth_header(tokens[role]))
    assert r.status_code == expected


@pytest.mark.parametrize("role,expected", [
    ("VIEWER", 403), ("ANALYST", 403), ("AUDITOR", 200), ("ADMIN", 200),
])
def test_only_auditor_admin_can_read_audit_log(client, tokens, role, expected):
    r = client.get("/api/v1/audit-logs", headers=auth_header(tokens[role]))
    assert r.status_code == expected


def test_auditor_has_no_write_access_to_accounts(client, tokens):
    """Segregation of duties: an AUDITOR can read everything but write
    nothing, preserving independence from the activity being reviewed."""
    payload = {"account_number": "ACC-AUDIT-TEST", "holder_name": "X", "account_type": "Individual"}
    r = client.post("/api/v1/accounts", json=payload, headers=auth_header(tokens["AUDITOR"]))
    assert r.status_code == 403


def test_only_admin_can_delete_accounts(client, tokens):
    create = client.post("/api/v1/accounts",
                          json={"account_number": "ACC-DEL-TEST", "holder_name": "X", "account_type": "Individual"},
                          headers=auth_header(tokens["ANALYST"]))
    assert create.status_code == 201
    account_id = create.json()["id"]

    denied = client.delete(f"/api/v1/accounts/{account_id}", headers=auth_header(tokens["ANALYST"]))
    assert denied.status_code == 403

    allowed = client.delete(f"/api/v1/accounts/{account_id}", headers=auth_header(tokens["ADMIN"]))
    assert allowed.status_code == 204


def test_viewer_cannot_generate_reports(client, tokens):
    r = client.post("/api/v1/reports/generate", json={"report_type": "risk_summary"},
                     headers=auth_header(tokens["VIEWER"]))
    assert r.status_code == 403


def test_analyst_can_generate_reports(client, tokens):
    r = client.post("/api/v1/reports/generate", json={"report_type": "risk_summary"},
                     headers=auth_header(tokens["ANALYST"]))
    assert r.status_code == 200
    assert "data" in r.json()
