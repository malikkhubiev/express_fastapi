from sqlalchemy.orm import Session
from . import models, auth

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, username: str, password: str):
    salt = auth.gen_salt()
    hashed = auth.hash_password(password, salt)
    db_user = models.User(username=username, password_hash=hashed, salt=salt)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user
