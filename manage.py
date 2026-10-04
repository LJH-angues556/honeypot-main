import os
from getpass import getpass

from dotenv import load_dotenv

from app import create_app
from app.extensions import db
from app.models import User


def init_db():
    app = create_app()
    with app.app_context():
        db.create_all()
        app.logger.info('Database tables created (or already exist).')


def create_admin():
    app = create_app()
    with app.app_context():
        username = os.getenv('ADMIN_USERNAME') or input('Admin username: ').strip()
        password = os.getenv('ADMIN_PASSWORD') or getpass('Admin password: ').strip()

        user = User.query.filter_by(username=username).first()
        if user:
            app.logger.info('Admin user already exists.')
            return
        user = User(username=username, role='super_admin')
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        app.logger.info('Admin user created.')


def main():
    load_dotenv()
    import argparse

    parser = argparse.ArgumentParser(description='Honeypot management')
    parser.add_argument('command', choices=['init-db', 'create-admin', 'all'])
    args = parser.parse_args()

    if args.command == 'init-db':
        init_db()
    elif args.command == 'create-admin':
        create_admin()
    elif args.command == 'all':
        init_db()
        create_admin()


if __name__ == '__main__':
    main()


