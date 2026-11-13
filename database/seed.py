"""Creates the first admin account.

Run it from the project folder with:  python -m database.seed
The password is typed in the terminal (hidden) and is never saved in a file.
"""
from getpass import getpass

from sqlalchemy import or_

from app import create_app
from database.db import db
from models.user import ROLE_ADMIN, User
from utils.validators import validate_email, validate_password, validate_username


def main():
    app = create_app()
    with app.app_context():
        print("Create the first admin account for CyberGuard AI")
        username = input("Admin username: ").strip()
        email = input("Admin email: ").strip().lower()
        password = getpass("Admin password (typing is hidden): ")
        confirm_password = getpass("Repeat the password: ")

        problems = []
        for problem in (validate_username(username), validate_email(email), validate_password(password)):
            if problem:
                problems.append(problem)
        if password != confirm_password:
            problems.append("Passwords do not match.")

        already_used = User.query.filter(
            or_(db.func.lower(User.username) == username.lower(), User.email == email)
        ).first()
        if already_used:
            problems.append("A user with that username or email already exists.")

        if problems:
            print("Admin was not created:")
            for problem in problems:
                print(" -", problem)
            return

        admin = User(username=username, email=email, role=ROLE_ADMIN)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        print("Admin account created. You can now log in at http://127.0.0.1:5000/login")


if __name__ == "__main__":
    main()