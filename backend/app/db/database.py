import os
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from app.config import settings

logger = logging.getLogger(__name__)

# Determine database connection string with fallback
db_url = settings.MSSQL_URL or settings.DATABASE_URL
engine_kwargs = {}

if db_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}

try:
    engine = create_engine(db_url, **engine_kwargs)
    # Test connection
    with engine.connect() as conn:
        pass
    logger.info(f"Connected to database: {db_url.split('://')[0]}://...")
except Exception as e:
    logger.warning(f"Failed to connect to primary database ({db_url}): {e}. Falling back to SQLite.")
    db_url = "sqlite:///./socpilot.db"
    engine = create_engine(db_url, connect_args={"check_same_thread": False})

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    from app.db import models
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables initialized successfully.")
