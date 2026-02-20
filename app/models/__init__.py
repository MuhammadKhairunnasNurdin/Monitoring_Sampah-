from sqlmodel import SQLModel

# Import all your models here so Alembic can detect them
from app.models.user import *
from app.models.session import *

# Export SQLModel for use in alembic env.py
__all__ = ["SQLModel"]