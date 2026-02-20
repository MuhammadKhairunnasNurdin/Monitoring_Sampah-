from datetime import datetime

from sqlalchemy import DateTime
from sqlmodel import SQLModel, Field

from app.utils.timestamp import get_datetime_utc


class Session(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    user_id: int = Field(
        foreign_key="user.id",
        nullable=False,
        ondelete="CASCADE",
    )
    session_id: str = Field(nullable=False, unique=True, max_length=255)
    created_at: datetime | None = Field(
        default_factory=get_datetime_utc,
        sa_type=DateTime(timezone=True),  # type: ignore
    )
    expires_at: datetime = Field(nullable=False)
