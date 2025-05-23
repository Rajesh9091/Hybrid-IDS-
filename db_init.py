"""
Initialize the database
"""
import os
from models import db, DetectionSession, DetectedAnomaly
from flask import Flask

def init_db():
    """Initialize the database and create tables"""
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    
    db.init_app(app)
    
    with app.app_context():
        # Create tables
        db.create_all()
        print("Database tables created successfully.")

if __name__ == "__main__":
    init_db()
