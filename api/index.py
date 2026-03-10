import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

from app import app, db, bcrypt, User

with app.app_context():
    db.create_all()
    try:
        if User.query.count() == 0:
            hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
            from app import User
            admin_user = User(
                username='admin',
                email='admin@phishguard.ai',
                password=hashed,
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
    except Exception as e:
        print(f"Admin creation error: {e}")
        pass