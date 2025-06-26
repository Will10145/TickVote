from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class Poll(db.Model):
    __tablename__ = 'polls'
    
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(32), unique=True, nullable=False)
    stats_token = db.Column(db.String(32), unique=True, nullable=False)
    owner_token = db.Column(db.String(32), nullable=False)
    firebase_uid = db.Column(db.String(128), nullable=True)  # <-- Add this line
    expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.utcnow())
    paused = db.Column(db.Boolean, default=False, nullable=False)
    locked = db.Column(db.Boolean, default=False, nullable=False)
    options = db.relationship('Option', backref='poll', lazy=True)

class Option(db.Model):
    __tablename__ = 'options'
    
    id = db.Column(db.Integer, primary_key=True)
    poll_id = db.Column(db.Integer, db.ForeignKey('polls.id'), nullable=False)
    text = db.Column(db.String(255), nullable=False)
    votes = db.Column(db.Integer, default=0)

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)