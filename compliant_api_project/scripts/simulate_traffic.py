"""
Traffic simulator.

Generates a realistic mixed workload against a *running* instance of the API
(start the server first: `uvicorn app.main:app`), including:
  - Normal, in-policy activity from each of the four demo roles
  - A deliberate rate-limit-triggering burst from the VIEWER account, to
    demonstrate the 429 path end-to-end
  - Deliberate unauthorized-access attempts (VIEWER trying to read the
    audit log; ANALYST trying to delete an account), to demonstrate the
    403 path end-to-end
  - A brute-force login attempt against the admin account, to demonstrate
    the IP-based login rate limiter

Every one of these is real traffic against the real, running application --
not a mock -- so everything it produces shows up in the actual audit log,
verifiable afterward via GET /api/v1/audit-logs/verify.

Usage:
    python -m scripts.simulate_traffic --base-url http://localhost:8000 --rounds 3
"""
import argparse
import random
import time
import sys

import httpx

DEMO_CREDENTIALS = {
    "VIEWER": ("vera_viewer", "ViewerPass123!"),
    "ANALYST": ("alex_analyst", "AnalystPass123!"),
    "AUDITOR": ("amara_auditor", "AuditorPass123!"),
    "ADMIN": ("admin", "AdminPass123!"),
}


def login(client: httpx.Client, role: str) -> str:
    username, password = DEMO_CREDENTIALS[role]
    r = client.post("/auth/login", data={"username": username, "password": password})
    r.raise_for_status()
    return r.json()["access_token"]


def h(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def normal_activity(client: httpx.Client, tokens: dict, log):
    role = random.choices(
        ["VIEWER", "ANALYST", "AUDITOR", "ADMIN"], weights=[0.40, 0.35, 0.15, 0.10]
    )[0]
    token = tokens[role]

    if role == "VIEWER":
        action = random.choice(["list_accounts", "get_account"])
        if action == "list_accounts":
            r = client.get("/api/v1/accounts", headers=h(token))
        else:
            r = client.get(f"/api/v1/accounts/{random.randint(1, 5)}", headers=h(token))

    elif role == "ANALYST":
        action = random.choice(["list_accounts", "list_transactions", "create_transaction", "generate_report"])
        if action == "list_accounts":
            r = client.get("/api/v1/accounts", headers=h(token))
        elif action == "list_transactions":
            r = client.get("/api/v1/transactions", headers=h(token))
        elif action == "create_transaction":
            r = client.post("/api/v1/transactions", headers=h(token), json={
                "account_id": random.randint(1, 5),
                "amount": round(random.uniform(-2000, 5000), 2),
                "transaction_type": random.choice(["deposit", "withdrawal", "transfer", "fee"]),
                "description": "Simulated activity",
            })
        else:
            r = client.post("/api/v1/reports/generate", headers=h(token), json={
                "report_type": random.choice(["risk_summary", "transaction_volume"])
            })

    elif role == "AUDITOR":
        action = random.choice(["list_transactions", "view_audit_log", "verify_integrity", "generate_report"])
        if action == "list_transactions":
            r = client.get("/api/v1/transactions", headers=h(token))
        elif action == "view_audit_log":
            r = client.get("/api/v1/audit-logs?limit=20", headers=h(token))
        elif action == "verify_integrity":
            r = client.get("/api/v1/audit-logs/verify", headers=h(token))
        else:
            r = client.post("/api/v1/reports/generate", headers=h(token), json={"report_type": "risk_summary"})

    else:  # ADMIN
        action = random.choice(["list_users", "list_accounts", "view_audit_log"])
        if action == "list_users":
            r = client.get("/auth/users", headers=h(token))
        elif action == "list_accounts":
            r = client.get("/api/v1/accounts", headers=h(token))
        else:
            r = client.get("/api/v1/audit-logs?limit=20", headers=h(token))

    log(f"  [{role:7s}] {action:20s} -> {r.status_code}")


def violation_scenarios(client: httpx.Client, tokens: dict, log):
    log("\n--- Scenario: unauthorized access attempts ---")
    r1 = client.get("/api/v1/audit-logs", headers=h(tokens["VIEWER"]))
    log(f"  VIEWER attempts to read audit log       -> {r1.status_code} (expect 403)")

    r2 = client.delete("/api/v1/accounts/1", headers=h(tokens["ANALYST"]))
    log(f"  ANALYST attempts to delete an account    -> {r2.status_code} (expect 403)")

    r3 = client.post("/api/v1/reports/generate", headers=h(tokens["VIEWER"]),
                      json={"report_type": "risk_summary"})
    log(f"  VIEWER attempts to generate a report     -> {r3.status_code} (expect 403)")

    log("\n--- Scenario: rate-limit burst (VIEWER, limit 30/min) ---")
    statuses = []
    for _ in range(40):
        r = client.get("/api/v1/accounts", headers=h(tokens["VIEWER"]))
        statuses.append(r.status_code)
    log(f"  40 rapid requests -> {statuses.count(200)} succeeded, {statuses.count(429)} rate-limited")

    log("\n--- Scenario: brute-force login attempt against admin ---")
    statuses = []
    for _ in range(15):
        r = client.post("/auth/login", data={"username": "admin", "password": f"guess{random.randint(0,999)}"})
        statuses.append(r.status_code)
    log(f"  15 bad-password attempts -> {statuses.count(401)} rejected (bad creds), "
        f"{statuses.count(429)} blocked by rate limiter")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--rounds", type=int, default=3, help="normal-activity requests per round")
    ap.add_argument("--rounds-count", type=int, default=20, help="how many normal-activity requests total")
    ap.add_argument("--skip-violations", action="store_true")
    args = ap.parse_args()

    def log(msg):
        print(msg)
        sys.stdout.flush()

    with httpx.Client(base_url=args.base_url, timeout=10.0) as client:
        log(f"Connecting to {args.base_url} ...")
        r = client.get("/health")
        r.raise_for_status()
        log(f"Server healthy: {r.json()}\n")

        tokens = {role: login(client, role) for role in DEMO_CREDENTIALS}
        log("Logged in as all four demo roles.\n")

        log(f"--- Simulating {args.rounds_count} normal requests across roles ---")
        for i in range(args.rounds_count):
            normal_activity(client, tokens, log)
            time.sleep(0.05)

        if not args.skip_violations:
            violation_scenarios(client, tokens, log)

        log("\n--- Done. Verify the audit trail with: ---")
        log("    curl -H \"Authorization: Bearer <admin_token>\" "
            f"{args.base_url}/api/v1/audit-logs/verify")


if __name__ == "__main__":
    main()
