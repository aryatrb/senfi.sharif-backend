from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.core.database import get_db
from app.core.security import get_current_user, verify_password, create_access_token, require_role
from app.crud import user as crud_user
from app.schemas.auth import *
from app.utils.helpers import *

# In-memory store for verification codes
verification_codes = {}

router = APIRouter()

@router.post("/auth/check-email", response_model=dict)
def check_email(body: EmailSchema, db: Session = Depends(get_db)):
    if not is_sharif_email(body.email):
        return {"exists": False}
    user = crud_user.get_user_by_email(db, email=body.email)
    return {"exists": user is not None}

@router.post("/auth/send-code", response_model=dict)
def send_verification_code(body: EmailSchema, db: Session = Depends(get_db)):
    if not is_sharif_email(body.email):
        raise HTTPException(status_code=400, detail="Email must end with @sharif.edu")
    code = generate_code()
    verification_codes[body.email.lower()] = code
    sent = send_verification_email_gmail(body.email, code)
    if sent:
        print(f"[INFO] Verification code sent to {body.email}")
    else:
        print(f"[DEBUG] Verification code for {body.email}: {code}")
    return {"success": True}

@router.post("/auth/verify-code", response_model=dict)
def verify_code(body: CodeSchema):
    code = verification_codes.get(body.email.lower())
    valid = code == body.code
    return {"valid": valid}

@router.post("/auth/register", response_model=dict)
def register_user(body: RegisterSchema, db: Session = Depends(get_db)):
    if not is_sharif_email(body.email) or crud_user.user_exists(db, email=body.email):
        raise HTTPException(status_code=400, detail="Invalid email")
    created_user = crud_user.create_user(db, user=body)
    return {"success": True, "userId": created_user.id}

@router.post("/auth/login", response_model=TokenResponse)
def login_user(body: LoginSchema, db: Session = Depends(get_db)):
    user = crud_user.get_user_by_email(db, email=body.email)
    # Debug: print type of user.hashed_password
    if user:
        print("[DEBUG] hashed_password type:", type(user.hashed_password), user.hashed_password)
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.email, "user_id": user.id})
    return {"success": True, "token": token, "user": user}

@router.get("/auth/validate", response_model=ValidateTokenResponse)
def validate_token_user(current_user: UserResponse = Depends(get_current_user)):
    return {"valid": True, "user": current_user}

@router.get("/auth/users", response_model=list[UserResponse])
def list_all_users(db: Session = Depends(get_db), current_user=Depends(require_role(['superadmin', 'head']))):
    users = crud_user.list_users(db)
    return users

@router.get("/auth/user/{user_id}", response_model=UserResponse)
def get_user_by_id(user_id: int, db: Session = Depends(get_db), current_user=Depends(require_role(['superadmin', 'head']))):
    user = crud_user.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="کاربر پیدا نشد")
    return user

class RoleUpdateRequest(BaseModel):
    new_role: str

@router.put("/user/{user_id}/role")
def update_user_role_api(
    user_id: int,
    req: RoleUpdateRequest,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Only superadmin can change roles
    if current_user.role != "superadmin":
        raise HTTPException(status_code=403, detail="Only superadmin can change user roles.")
    if req.new_role == "superadmin":
        raise HTTPException(status_code=400, detail="Cannot assign superadmin role.")
    # Accept 'simple_senfi_member' as a valid role (no restriction needed)
    user = crud_user.get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
    if getattr(user, 'role', None) == "superadmin":
        raise HTTPException(status_code=400, detail="Cannot change role of another superadmin.")
    updated = crud_user.update_user_role(db, user_id, req.new_role)
    if not updated:
        return {"success": False, "message": "Failed to update user role."}
    return {
        "success": True,
        "message": "User role updated successfully.",
        "user": {
        "id": updated.id,
        "email": updated.email,
        "role": updated.role,
        "unit": updated.unit
        }
    }
