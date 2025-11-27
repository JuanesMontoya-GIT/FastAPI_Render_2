from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI
from routes import router as auth_router

# IMPORTANTE: agregar estas dos líneas
from database import Base, engine
import models

# Crear tablas automáticamente
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Auth Service",
    description="Sistema de autenticación y gestión",
    version="1.0.0"
)

app.include_router(auth_router, tags=["auth"])
