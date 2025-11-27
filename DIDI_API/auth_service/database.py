from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# APUNTA A LA DB EXISTENTE users.db (no la recrea)
SQLALCHEMY_DATABASE_URI = "sqlite:///./users.db"

# connect_args required for sqlite in multithread dev servers
engine = create_engine(SQLALCHEMY_DATABASE_URI, connect_args={"check_same_thread": False})

# Session factory
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

Base = declarative_base()

# dependencia para endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()