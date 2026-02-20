from datetime import datetime

from pydantic import EmailStr
from sqlalchemy import DateTime
from sqlmodel import Field, SQLModel

from app.utils.timestamp import get_datetime_utc


class UserBase(SQLModel):
    email: EmailStr = Field(unique=True, max_length=255, nullable=False)
    password: str = Field(nullable=False, max_length=255)

class User(UserBase, table=True):
    id: int | None = Field(default=None, primary_key=True)
    created_at: datetime | None = Field(
        default_factory=get_datetime_utc,
        sa_type=DateTime(timezone=True),  # type: ignore
    )