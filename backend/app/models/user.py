from sqlalchemy import Column, Integer, String, Boolean
from app.core.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String) # เก็บ password ที่เข้ารหัสแล้วเท่านั้น!
    is_active = Column(Boolean, default=True)
    role = Column(String, default="viewer") # admin หรือ viewer