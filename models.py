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

class UserPrivacyPreferences(db.Model):
    __tablename__ = 'user_privacy_preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    firebase_uid = db.Column(db.String(128), unique=True, nullable=False)
    functional_cookies = db.Column(db.Boolean, default=True, nullable=False)
    analytics_cookies = db.Column(db.Boolean, default=False, nullable=False)
    auto_delete_polls = db.Column(db.Boolean, default=False, nullable=False)
    email_notifications = db.Column(db.Boolean, default=True, nullable=False)
    data_retention_days = db.Column(db.Integer, default=365, nullable=False)
    consent_given_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    consent_updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

class DataProcessingLog(db.Model):
    __tablename__ = 'data_processing_log'
    
    id = db.Column(db.Integer, primary_key=True)
    firebase_uid = db.Column(db.String(128), nullable=True)
    action = db.Column(db.String(100), nullable=False)  # 'create_poll', 'vote', 'login', etc.
    legal_basis = db.Column(db.String(50), nullable=False)  # 'consent', 'contract', 'legitimate_interest'
    data_categories = db.Column(db.Text, nullable=False)  # JSON string of data categories
    purpose = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)  # Support IPv6
    user_agent = db.Column(db.String(500), nullable=True)

class DataExportRequest(db.Model):
    __tablename__ = 'data_export_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    firebase_uid = db.Column(db.String(128), nullable=False)
    request_type = db.Column(db.String(50), nullable=False)  # 'export', 'deletion', 'correction'
    status = db.Column(db.String(20), default='pending', nullable=False)  # 'pending', 'processing', 'completed', 'failed'
    requested_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    completed_at = db.Column(db.DateTime, nullable=True)
    notes = db.Column(db.Text, nullable=True)
    export_file_path = db.Column(db.String(255), nullable=True)  # For data exports