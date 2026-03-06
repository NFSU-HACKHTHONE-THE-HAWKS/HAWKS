from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase

# SQLite URL: '///' means a relative path to forensics.db
# This is the DB that will be wiped every 24 hours
SQLALCHEMY_DATABASE_URL = "sqlite:///./forensics.db"

# Create the Engine
# 'check_same_thread=False' is REQUIRED for SQLite + FastAPI
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Create a Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# SQLAlchemy 2.0 Base class
class Base(DeclarativeBase):
    pass

# Dependency for FastAPI routes
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()