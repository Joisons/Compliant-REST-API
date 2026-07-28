"""
Seed the database with demo users (one per role) and sample accounts.

Run once before starting the server for the first time:
    python -m scripts.seed_data
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, engine, SessionLocal
from app.models.db_models import User, Account, Role
from app.core.security import hash_password

DEMO_USERS = [
    {"username": "vera_viewer", "full_name": "Vera Nwosu (Viewer)", "password": "ViewerPass123!", "role": Role.VIEWER},
    {"username": "alex_analyst", "full_name": "Alex Chen (Analyst)", "password": "AnalystPass123!", "role": Role.ANALYST},
    {"username": "amara_auditor", "full_name": "Amara Okafor (Auditor)", "password": "AuditorPass123!", "role": Role.AUDITOR},
    {"username": "admin", "full_name": "System Administrator", "password": "AdminPass123!", "role": Role.ADMIN},
]

DEMO_ACCOUNTS = [
    {"account_number": "ACC-10001", "holder_name": "Meridian Trading LLC", "account_type": "Corporate", "balance": 452_300.00, "risk_rating": "Medium"},
    {"account_number": "ACC-10002", "holder_name": "Chidinma Eze", "account_type": "Individual", "balance": 18_450.75, "risk_rating": "Low"},
    {"account_number": "ACC-10003", "holder_name": "Blueline Freight Ltd", "account_type": "Corporate", "balance": 1_204_900.00, "risk_rating": "High"},
    {"account_number": "ACC-10004", "holder_name": "Tunde Bakare", "account_type": "Individual", "balance": 6_120.00, "risk_rating": "Low"},
    {"account_number": "ACC-10005", "holder_name": "Northgate Holdings", "account_type": "Corporate", "balance": 88_760.40, "risk_rating": "Medium"},
]


def main():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        created_users, created_accounts = 0, 0

        for u in DEMO_USERS:
            if not db.query(User).filter(User.username == u["username"]).first():
                db.add(User(username=u["username"], full_name=u["full_name"],
                             hashed_password=hash_password(u["password"]), role=u["role"]))
                created_users += 1

        for a in DEMO_ACCOUNTS:
            if not db.query(Account).filter(Account.account_number == a["account_number"]).first():
                db.add(Account(**a))
                created_accounts += 1

        db.commit()
        print(f"Seed complete. Created {created_users} users, {created_accounts} accounts.")
        print("\nDemo credentials (username / password / role):")
        for u in DEMO_USERS:
            print(f"  {u['username']:14s} / {u['password']:18s} / {u['role'].value}")
    finally:
        db.close()


if __name__ == "__main__":
    main()
