import os
from datetime import datetime, timedelta, timezone
from typing import Optional
from passlib.context import CryptContext
from jose import jwt
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from pathlib import Path
import secrets
import string

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

# Validate required environment variables
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY must be set in environment variables")

try:
    fernet = Fernet(ENCRYPTION_KEY.encode())
except Exception as e:
    raise ValueError(f"Invalid ENCRYPTION_KEY format. Must be a valid Fernet key: {e}")

SECRET_KEY = os.getenv("JWT_SECRET")
if not SECRET_KEY:
    raise ValueError("JWT_SECRET must be set in environment variables")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def encrypt_password(password: str) -> bytes:
    return fernet.encrypt(password.encode())

def decrypt_password(encrypted_password: bytes) -> str:
    return fernet.decrypt(encrypted_password).decode()

def generate_verification_token(length: int = 32) -> str:
    """Generate a secure verification token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def generate_password_reset_token(length: int = 32) -> str:
    """Generate a secure password reset token"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))
