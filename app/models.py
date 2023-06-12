from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(UUID(as_uuid=True), unique=True, nullable=False)
    name = db.Column(db.String(50))
    email = db.Column(db.String(120))
    password = db.Column(db.String(180))
    admin = db.Column(db.Boolean)

