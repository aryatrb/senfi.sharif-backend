from pydantic import BaseModel, EmailStr
from typing import Optional

class EmailSchema(BaseModel):
    email: EmailStr

class CodeSchema(EmailSchema):
    code: str

class RegisterSchema(EmailSchema):
    password: str

class LoginSchema(RegisterSchema):
    pass

class UserResponse(BaseModel):
    id: int
    email: str
    role: str
    unit: Optional[str] = None
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    success: bool
    token: str
    user: UserResponse

class ValidateTokenResponse(BaseModel):
    valid: bool
    user: UserResponse
