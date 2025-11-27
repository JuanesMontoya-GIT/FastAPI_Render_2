from dotenv import load_dotenv
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

load_dotenv()   # ← OBLIGATORIO

DATABASE_URL = os.getenv("DATABASE_URL")


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

print("DATABASE_URL:", DATABASE_URL)
