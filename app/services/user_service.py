from typing import Optional

from sqlmodel import Session, select

from app.models.user import User


class UserService:
    @staticmethod
    def get_user_by_id(db: Session, user_id: int) -> Optional[User]:
        """Get a user by ID"""
        return db.exec(select(User).where(User.id == user_id)).first()

    @staticmethod
    def find_user_by_email(db: Session, email: str) -> Optional[User]:
        """Find a user by email"""
        return db.exec(select(User).where(User.email == email)).first()