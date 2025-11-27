from dotenv import load_dotenv
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# Cargar .env desde la raíz del proyecto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# URL para la BD local (usa ORDERS_DATABASE_URL si existe, sino orders.db local)
DATABASE_URL = os.getenv("ORDERS_DATABASE_URL", "sqlite:///./orders.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
