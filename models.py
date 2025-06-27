from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255))
    role = db.Column(db.String(20), default='employee', nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Employee(db.Model):
    __tablename__ = 'employee'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(50))
    role = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Template(db.Model):
    __tablename__ = 'template'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    html_content = db.Column(db.Text, nullable=False)
    text_content = db.Column(db.Text, nullable=False)
    banner_url = db.Column(db.String(255))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ClickTrack(db.Model):
    __tablename__ = 'click_track'
    id = db.Column(db.Integer, primary_key=True)
    track_id = db.Column(db.String(50), unique=True, nullable=False)
    template_id = db.Column(db.Integer, db.ForeignKey('template.id'))
    employee_id = db.Column(db.Integer, db.ForeignKey('employee.id'))
    url = db.Column(db.String(255), nullable=False)
    clicks = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    clicked_at = db.Column(db.DateTime)

class Campaign(db.Model):
    __tablename__ = 'campaign'
    id = db.Column(db.Integer, primary_key=True)
    template_ids = db.Column(db.Text, nullable=False)
    department = db.Column(db.String(50))
    start_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class SignatureHistory(db.Model):
    __tablename__ = 'signature_history'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, nullable=False)
    template_id = db.Column(db.Integer, nullable=False)
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)

class NotificationLog(db.Model):
    __tablename__ = 'notification_log'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    message = db.Column(db.Text, nullable=False)
    method = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)