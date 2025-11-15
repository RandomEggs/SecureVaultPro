import os
from pathlib import Path

from contextlib import contextmanager

from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base, sessionmaker

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

DATABASE_URL = os.getenv("DATABASE_URL")

# Create engine with better connection settings for cloud databases
engine = create_engine(
    DATABASE_URL,
    echo=False,  # Disable SQL logging in production
    pool_pre_ping=True,  # Check connections before use
    pool_recycle=300,    # Recycle connections every 5 minutes
    connect_args={
        "connect_timeout": 10,
        "options": "-c timezone=utc"
    }
)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

Base = declarative_base()

@contextmanager
def get_session():
    """Get database session with error handling and retry logic"""
    max_retries = 3
    for attempt in range(max_retries):
        db = SessionLocal()
        try:
            # Test the connection
            db.execute(text("SELECT 1"))
            yield db
            break
        except Exception as e:
            db.close()
            if attempt < max_retries - 1:
                print(f"Database connection attempt {attempt + 1} failed, retrying... Error: {e}")
                continue
            else:
                print(f"Database connection failed after {max_retries} attempts: {e}")
                raise
        finally:
            if 'db' in locals():
                db.close()

def create_tables():
    Base.metadata.create_all(bind=engine)
