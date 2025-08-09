import os
import base64
from datetime import datetime, timedelta
from typing import Optional
from passlib.context import CryptContext
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY", "CHANGE_ME")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))

# Используем PBKDF2 через passlib
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def gen_salt() -> str:
    """Возвращает base64-строку соли."""
    return base64.b64encode(os.urandom(16)).decode()

def hash_password(password: str, salt: str) -> str:
    """
    Хешируем явным образом: комбинируем пароль и соль, и передаём в passlib.
    Храним полученный хеш и соль отдельно.
    """
    return pwd_context.hash(password + salt)

def verify_password(password: str, salt: str, hashed: str) -> bool:
    """Проверяем пароль, комбинируя с сохранённой солью."""
    return pwd_context.verify(password + salt, hashed)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
