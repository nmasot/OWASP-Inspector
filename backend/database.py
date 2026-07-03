import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
from datetime import datetime

# - Aislamiento de persistencia
DATA_DIR = "./data"
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

SQLALCHEMY_DATABASE_URL = f"sqlite:///{DATA_DIR}/inspector.db"

engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# ... 

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    
    # Relación uno a muchos: Un usuario tiene muchos escaneos
    scans = relationship("ScanHistory", back_populates="owner")

class ScanHistory(Base):
    __tablename__ = "scan_history"
    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, index=True)
    date = Column(DateTime, default=datetime.utcnow)
    mode = Column(String)
    critical_vulns = Column(Integer, default=0)
    high_vulns = Column(Integer, default=0)
    medium_vulns = Column(Integer, default=0)
    user_id = Column(Integer, ForeignKey("users.id"))
    
    owner = relationship("User", back_populates="scans")

# Importante: Esto creará la nueva tabla automáticamente
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()