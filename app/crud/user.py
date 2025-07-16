from sqlalchemy.orm import Session
from app.models.user import User
from app.schemas.auth import RegisterSchema
from app.core.security import get_password_hash

def get_user_by_email(db: Session, email: str):
    return db.query(User).filter(User.email == email.lower()).first()

def get_user_by_id(db: Session, user_id: int):
    return db.query(User).filter(User.id == user_id).first()

def create_user(db: Session, user: RegisterSchema):
    hashed_password = get_password_hash(user.password)
    db_user = User(
        email=user.email.lower(),
        hashed_password=hashed_password,
        role="simple_user"
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def user_exists(db: Session, email: str) -> bool:
    return db.query(User).filter(User.email == email.lower()).first() is not None

def list_users(db: Session):
    return db.query(User).order_by(User.id.desc()).all()

def update_user_role(db: Session, user_id: int, new_role: str):
    user = get_user_by_id(db, user_id)
    if not user:
        return None
    user.role = new_role
    db.commit()
    db.refresh(user)
    return user
