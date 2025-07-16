# This file is kept for backwards compatibility
# The new modular structure is in the app/ directory

from app.main import app

# Re-export the app for uvicorn
__all__ = ["app"]

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False, default="simple_user")  # superadmin, head, center_member, unit_head, unit_member, simple_user
    unit = Column(String, nullable=True)  # فقط برای دبیر/عضو واحد

# --- Campaign Model ---
class PendingCampaign(Base):
    __tablename__ = "pending_campaigns"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    email = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")
    is_anonymous = Column(String, default="public")  # public یا anonymous
    end_datetime = Column(DateTime, nullable=False)  # تاریخ و ساعت پایان

# --- Campaign Signature Model ---
class CampaignSignature(Base):
    __tablename__ = "campaign_signatures"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    user_email = Column(String, nullable=False)
    signed_at = Column(DateTime, default=datetime.utcnow)
    is_anonymous = Column(String, default="public")  # public یا anonymous

Base.metadata.create_all(bind=engine)

# --- Schemas ---
class EmailSchema(BaseModel):
    email: EmailStr

class CodeSchema(EmailSchema):
    code: str

class RegisterSchema(EmailSchema):
    password: str

class LoginSchema(RegisterSchema):
    pass

# --- In-memory store for verification codes ---
verification_codes = {}

# --- Utils ---
def is_sharif_email(email: str) -> bool:
    return email.lower().endswith("@sharif.edu")

def generate_code() -> str:
    return ''.join(random.choices(string.digits, k=6))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_token(token: str):
    """Verify JWT token and return user data"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

def get_current_user(token: str = Depends(HTTPBearer()), db: Session = Depends(get_db)):
    """Get current user from JWT token"""
    credentials_exception = HTTPException(status_code=401, detail="Invalid credentials")
    try:
        payload = verify_token(token.credentials)
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
    except:
        raise credentials_exception
    
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise credentials_exception
    return user

def require_role(allowed_roles: list):
    """Decorator to check user role"""
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user
    return role_checker

def send_verification_email_gmail(to_email: str, code: str) -> bool:
    """
    Send the verification code to the user's email using Gmail SMTP.
    Returns True if sent, False otherwise.
    """
    gmail_user = os.environ.get("GMAIL_USER")
    gmail_pass = os.environ.get("GMAIL_PASS")
    if not gmail_user or not gmail_pass:
        return False
    try:
        msg = EmailMessage()
        msg["Subject"] = "Sharif Verification Code"
        msg["From"] = gmail_user
        msg["To"] = to_email
        msg.set_content(f"Your verification code is: {code}")
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(gmail_user, gmail_pass)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False

# --- Campaign Schemas ---
class CampaignSubmitSchema(BaseModel):
    title: str
    description: str
    email: Optional[EmailStr] = None
    is_anonymous: str = "public"  # public یا anonymous
    end_datetime: datetime  # تاریخ و ساعت پایان (میلادی)
    class Config:
        json_schema_extra = {
            "example": {
                "title": "کمپین نمونه",
                "description": "توضیحات کمپین",
                "email": "user@sharif.edu",
                "is_anonymous": "public",
                "end_datetime": "2024-07-20T23:59:00"
            }
        }

class CampaignSubmitResponse(BaseModel):
    success: bool
    campaignId: int
    status: str
    created_at: datetime
    end_datetime: datetime

class CampaignListResponse(BaseModel):
    success: bool
    campaigns: list
    total: int

class CampaignApprovalSchema(BaseModel):
    campaign_id: int
    approved: bool
    admin_notes: Optional[str] = None

class CampaignApprovalResponse(BaseModel):
    success: bool
    message: str
    campaign_id: int
    new_status: str

class CampaignStatusUpdateSchema(BaseModel):
    approved: Optional[bool] = None
    status: Optional[str] = None  # 'approved', 'rejected', 'pending'

class CampaignSignatureSchema(BaseModel):
    is_anonymous: str = "public"  # public یا anonymous

class CampaignSignatureResponse(BaseModel):
    success: bool
    message: str
    signature_id: int
    total_signatures: int

# --- Endpoints ---

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, restrict to your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.post("/api/auth/check-email")
def check_email(body: EmailSchema, db: Session = Depends(get_db)):
    """
    Check if an email exists in the user database.
    Input: { "email": "user@sharif.edu" }
    Output: { "exists": true }
    """
    if not is_sharif_email(body.email):
        return {"exists": False}
    user = db.query(User).filter(User.email == body.email.lower()).first()
    return {"exists": bool(user)}

@app.post("/api/auth/send-code")
def send_code(body: EmailSchema, db: Session = Depends(get_db)):
    """
    Send a 6-digit verification code to the email (real email via Gmail if configured).
    Input: { "email": "user@sharif.edu" }
    Output: { "success": true }
    """
    if not is_sharif_email(body.email):
        raise HTTPException(status_code=400, detail="Email must end with @sharif.edu")
    code = generate_code()
    verification_codes[body.email.lower()] = code
    # Try to send real email, fallback to console
    sent = send_verification_email_gmail(body.email, code)
    if sent:
        print(f"[INFO] Verification code sent to {body.email}")
    else:
        print(f"[DEBUG] Verification code for {body.email}: {code}")
    return {"success": True}

@app.post("/api/auth/verify-code")
def verify_code(body: CodeSchema):
    """
    Verify the 6-digit code for the email.
    Input: { "email": "user@sharif.edu", "code": "123456" }
    Output: { "valid": true }
    """
    code = verification_codes.get(body.email.lower())
    valid = code == body.code
    return {"valid": valid}

@app.post("/api/auth/register")
def register(body: RegisterSchema, db: Session = Depends(get_db)):
    """
    Register a new user with email and password.
    Input: { "email": "user@sharif.edu", "password": "pass1234" }
    Output: { "success": true, "userId": 1 }
    """
    if not is_sharif_email(body.email):
        raise HTTPException(status_code=400, detail="Email must end with @sharif.edu")
    if db.query(User).filter(User.email == body.email.lower()).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed = get_password_hash(body.password)
    user = User(email=body.email.lower(), hashed_password=hashed, role="simple_user")
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"success": True, "userId": user.id}

@app.post("/api/auth/login")
def login(body: LoginSchema, db: Session = Depends(get_db)):
    """
    Login with email and password, returns JWT token and user info.
    Input: { "email": "user@sharif.edu", "password": "pass1234" }
    Output: { "success": true, "token": "JWT_TOKEN", "user": { ... } }
    """
    user = db.query(User).filter(User.email == body.email.lower()).first()
    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": user.email, "user_id": user.id})
    return {
        "success": True,
        "token": token,
        "user": {"id": user.id, "email": user.email, "role": user.role, "unit": user.unit}
    }

@app.post("/api/campaigns/submit", response_model=CampaignSubmitResponse)
def submit_campaign(body: CampaignSubmitSchema, db: Session = Depends(get_db)):
    """
    ثبت کارزار جدید (pending)
    نمونه درخواست:
    {
      "title": "کمپین نمونه",
      "description": "توضیحات کمپین",
      "email": "user@sharif.edu",
      "is_anonymous": "public",
      "end_datetime": "2024-07-20T23:59:00"
    }
    نمونه پاسخ موفق:
    {
      "success": true,
      "campaignId": 1,
      "status": "pending",
      "created_at": "2024-07-15T21:00:00Z",
      "end_datetime": "2024-07-20T23:59:00Z"
    }
    """
    if body.end_datetime <= datetime.utcnow():
        raise HTTPException(status_code=400, detail="تاریخ پایان باید بعد از اکنون باشد.")
    campaign = PendingCampaign(
        title=body.title,
        description=body.description,
        email=body.email,
        status="pending",
        is_anonymous=body.is_anonymous,
        end_datetime=body.end_datetime
    )
    db.add(campaign)
    db.commit()
    db.refresh(campaign)
    return {
        "success": True,
        "campaignId": campaign.id,
        "status": campaign.status,
        "created_at": campaign.created_at,
        "end_datetime": campaign.end_datetime
    }

@app.get("/api/admin/campaigns", response_model=CampaignListResponse)
def get_pending_campaigns(
    current_user: User = Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    """
    مشاهده لیست کمپین‌های در انتظار تأیید
    فقط برای superadmin، head، و center_member
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    """
    campaigns = db.query(PendingCampaign).filter(PendingCampaign.status == "pending").all()
    campaign_list = []
    for campaign in campaigns:
        campaign_list.append({
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email,
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        })
    
    return {
        "success": True,
        "campaigns": campaign_list,
        "total": len(campaign_list)
    }

@app.post("/api/admin/campaigns/approve", response_model=CampaignApprovalResponse)
def approve_campaign(
    body: CampaignApprovalSchema,
    current_user: User = Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    """
    تأیید یا رد کمپین
    فقط برای superadmin، head، و center_member
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    
    نمونه درخواست:
    {
      "campaign_id": 1,
      "approved": true,
      "admin_notes": "کمپین تأیید شد"
    }
    """
    campaign = db.query(PendingCampaign).filter(PendingCampaign.id == body.campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    if body.approved:
        campaign.status = "approved"
        message = "کمپین تأیید شد"
    else:
        campaign.status = "rejected"
        message = "کمپین رد شد"
    
    # در آینده می‌توان admin_notes را هم ذخیره کرد
    db.commit()
    
    return {
        "success": True,
        "message": message,
        "campaign_id": campaign.id,
        "new_status": campaign.status
    }

@app.put("/api/campaigns/{campaign_id}/status")
def update_campaign_status(
    campaign_id: int,
    data: CampaignStatusUpdateSchema,
    current_user: User = Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    """
    تغییر وضعیت کارزار (تایید، رد، یا بازگرداندن به بررسی)
    Body: {"approved": true/false} یا {"status": "pending"}
    """
    campaign = db.query(PendingCampaign).filter(PendingCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    if data.status:
        if data.status not in ["approved", "rejected", "pending"]:
            raise HTTPException(status_code=400, detail="وضعیت نامعتبر است")
        campaign.status = data.status
        db.commit()
        return {"success": True, "message": f"وضعیت کارزار به {data.status} تغییر یافت"}
    elif data.approved is not None:
        if data.approved:
            campaign.status = "approved"
            message = "کارزار با موفقیت تایید شد"
        else:
            campaign.status = "rejected"
            message = "کارزار با موفقیت رد شد"
        db.commit()
        return {"success": True, "message": message}
    else:
        raise HTTPException(status_code=400, detail="باید یکی از status یا approved ارسال شود")

@app.get("/api/campaigns/approved", response_model=CampaignListResponse)
def get_approved_campaigns(db: Session = Depends(get_db)):
    """
    مشاهده لیست کارزارهای تأیید شده
    نیاز به authentication ندارد - همه کاربران می‌توانند ببینند
    """
    campaigns = db.query(PendingCampaign).filter(PendingCampaign.status == "approved").all()
    campaign_list = []
    for campaign in campaigns:
        campaign_list.append({
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email,
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        })
    
    return {
        "success": True,
        "campaigns": campaign_list,
        "total": len(campaign_list)
    }

@app.get("/api/campaigns/rejected", response_model=CampaignListResponse)
def get_rejected_campaigns(db: Session = Depends(get_db)):
    """
    مشاهده لیست کارزارهای رد شده
    نیاز به authentication ندارد - همه کاربران می‌توانند ببینند
    """
    campaigns = db.query(PendingCampaign).filter(PendingCampaign.status == "rejected").all()
    campaign_list = []
    for campaign in campaigns:
        campaign_list.append({
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email,
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        })
    return {
        "success": True,
        "campaigns": campaign_list,
        "total": len(campaign_list)
    }

@app.post("/api/campaigns/{campaign_id}/sign", response_model=CampaignSignatureResponse)
def sign_campaign(
    campaign_id: int,
    body: CampaignSignatureSchema,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    امضا کردن کارزار
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    
    نمونه درخواست:
    POST /api/campaigns/1/sign
    Body: {"is_anonymous": "public"}
    
    نمونه پاسخ موفق:
    {
      "success": true,
      "message": "کارزار با موفقیت امضا شد",
      "signature_id": 1,
      "total_signatures": 5
    }
    """
    # بررسی وجود کارزار
    campaign = db.query(PendingCampaign).filter(PendingCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    # بررسی اینکه کاربر قبلاً امضا کرده یا نه
    existing_signature = db.query(CampaignSignature).filter(
        CampaignSignature.campaign_id == campaign_id,
        CampaignSignature.user_id == current_user.id
    ).first()
    
    if existing_signature:
        raise HTTPException(status_code=400, detail="شما قبلاً این کارزار را امضا کرده‌اید")
    
    # ایجاد امضا
    signature = CampaignSignature(
        campaign_id=campaign_id,
        user_id=current_user.id,
        user_email=current_user.email,
        is_anonymous=body.is_anonymous
    )
    db.add(signature)
    db.commit()
    db.refresh(signature)
    
    # شمارش کل امضاها
    total_signatures = db.query(CampaignSignature).filter(
        CampaignSignature.campaign_id == campaign_id
    ).count()
    
    return {
        "success": True,
        "message": "کارزار با موفقیت امضا شد",
        "signature_id": signature.id,
        "total_signatures": total_signatures
    }

@app.get("/api/campaigns/{campaign_id}/signatures")
def get_campaign_signatures(campaign_id: int, db: Session = Depends(get_db)):
    """
    مشاهده لیست امضاکنندگان کارزار
    نیاز به authentication ندارد
    
    نمونه پاسخ:
    {
      "success": true,
      "signatures": [
        {
          "id": 1,
          "user_email": "user@sharif.edu",
          "signed_at": "2025-07-15T23:30:00",
          "is_anonymous": "public"
        }
      ],
      "total": 1,
      "campaign_is_anonymous": "public"
    }
    """
    campaign = db.query(PendingCampaign).filter(PendingCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    # اگر کارزار anonymous است، فقط تعداد را برگردان
    if campaign.is_anonymous == "anonymous":
        total_signatures = db.query(CampaignSignature).filter(
            CampaignSignature.campaign_id == campaign_id
        ).count()
        return {
            "success": True,
            "signatures": [],
            "total": total_signatures,
            "campaign_is_anonymous": "anonymous"
        }
    
    # اگر public است، لیست امضاها را برگردان
    signatures = db.query(CampaignSignature).filter(
        CampaignSignature.campaign_id == campaign_id
    ).all()
    
    signature_list = []
    for sig in signatures:
        # اگر امضا anonymous است، ایمیل را مخفی کن
        email = sig.user_email if sig.is_anonymous == "public" else "ناشناس"
        signature_list.append({
            "id": sig.id,
            "user_email": email,
            "signed_at": sig.signed_at,
            "is_anonymous": sig.is_anonymous
        })
    
    return {
        "success": True,
        "signatures": signature_list,
        "total": len(signature_list),
        "campaign_is_anonymous": campaign.is_anonymous
    }

@app.get("/api/user/signed-campaigns")
def get_user_signed_campaigns(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    مشاهده لیست کارزارهایی که کاربر امضا کرده
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    
    نمونه پاسخ:
    {
      "success": true,
      "campaigns": [
        {
          "campaign_id": 1,
          "campaign_title": "عنوان کارزار",
          "signed_at": "2025-07-15T23:30:00",
          "is_anonymous": "public"
        }
      ],
      "total": 1
    }
    """
    # دریافت کارزارهایی که کاربر امضا کرده
    signatures = db.query(CampaignSignature).filter(
        CampaignSignature.user_id == current_user.id
    ).all()
    
    campaign_list = []
    for sig in signatures:
        campaign = db.query(PendingCampaign).filter(PendingCampaign.id == sig.campaign_id).first()
        if campaign:
            campaign_list.append({
                "campaign_id": sig.campaign_id,
                "campaign_title": campaign.title,
                "signed_at": sig.signed_at,
                "is_anonymous": sig.is_anonymous
            })
    
    return {
        "success": True,
        "campaigns": campaign_list,
        "total": len(campaign_list)
    }

@app.get("/api/campaigns/{campaign_id}/check-signature")
def check_user_signature(
    campaign_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    بررسی اینکه آیا کاربر فعلی قبلاً این کارزار را امضا کرده یا نه
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    
    نمونه پاسخ:
    {
      "has_signed": true,
      "signature": {
        "id": 1,
        "signed_at": "2025-07-15T23:30:00",
        "is_anonymous": "public"
      }
    }
    """
    # بررسی وجود کارزار
    campaign = db.query(PendingCampaign).filter(PendingCampaign.id == campaign_id).first()
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    # بررسی امضای کاربر
    signature = db.query(CampaignSignature).filter(
        CampaignSignature.campaign_id == campaign_id,
        CampaignSignature.user_id == current_user.id
    ).first()
    
    if signature:
        return {
            "has_signed": True,
            "signature": {
                "id": signature.id,
                "signed_at": signature.signed_at,
                "is_anonymous": signature.is_anonymous
            }
        }
    else:
        return {
            "has_signed": False,
            "signature": None
        }

@app.get("/api/auth/validate-token")
def validate_token(current_user: User = Depends(get_current_user)):
    """
    بررسی اعتبار توکن JWT
    نیاز به Authorization header: Bearer <JWT_TOKEN>
    
    نمونه پاسخ:
    {
      "valid": true,
      "user": {
        "email": "user@sharif.edu",
        "role": "superadmin",
        "unit": null
      }
    }
    """
    return {
        "valid": True,
        "user": {
            "email": current_user.email,
            "role": current_user.role,
            "unit": current_user.unit
        }
    }

