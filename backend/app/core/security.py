from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
from .config import SECRET_KEY, ALGORITHM

# ตั้งค่าเครื่องมือเข้ารหัส
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password):
    """แปลงรหัสผ่านปกติเป็น Hash"""
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    """ตรวจสอบรหัสผ่านว่าตรงกับ Hash ใน DB ไหม"""
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
