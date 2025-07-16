from datetime import datetime, timedelta
from typing import Optional

import jwt
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt import PyJWTError
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.core.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from app.core.database import get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: HTTPAuthorizationCredentials = Depends(HTTPBearer()), db: Session = Depends(get_db)):
    from app.crud.user import get_user_by_email
    
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
    try:
        payload = verify_token(token.credentials)
        print("[DEBUG] JWT payload:", payload)
        email = payload.get("sub")
        print("[DEBUG] Extracted email from JWT:", email)
        if not isinstance(email, str) or not email:
            print("[DEBUG] Email is None or not a string in JWT payload")
            raise credentials_exception
    except Exception as e:
        print("[DEBUG] Exception in JWT decode:", e)
        raise credentials_exception
    
    user = get_user_by_email(db, email=email)
    print("[DEBUG] User lookup result:", user)
    if user is None:
        print(f"[DEBUG] No user found in DB for email: {email}")
        raise credentials_exception
    return user

def require_role(allowed_roles: list):
    def role_checker(current_user = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker
