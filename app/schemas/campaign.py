from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, EmailStr

class CampaignBase(BaseModel):
    title: str
    description: str
    email: Optional[EmailStr] = None
    is_anonymous: str = "public"
    end_datetime: datetime

class CampaignCreate(CampaignBase):
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

class CampaignResponse(BaseModel):
    id: int
    title: str
    description: str
    email: Optional[str] = None
    created_at: datetime
    status: str
    end_datetime: datetime
    
    class Config:
        from_attributes = True

class CampaignSubmitResponse(BaseModel):
    success: bool
    campaignId: int
    status: str
    created_at: datetime
    end_datetime: datetime

class CampaignListResponse(BaseModel):
    success: bool
    campaigns: List[CampaignResponse]
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
    status: Optional[str] = None

class CampaignSignatureSchema(BaseModel):
    is_anonymous: str = "public"

class CampaignSignatureResponse(BaseModel):
    success: bool
    message: str
    signature_id: int
    total_signatures: int

class SignatureResponse(BaseModel):
    id: int
    user_email: str
    signed_at: datetime
    is_anonymous: str
    
    class Config:
        from_attributes = True

class CampaignSignaturesResponse(BaseModel):
    success: bool
    signatures: List[SignatureResponse]
    total: int
    campaign_is_anonymous: str

class UserSignedCampaignResponse(BaseModel):
    campaign_id: int
    campaign_title: str
    signed_at: datetime
    is_anonymous: str

class UserSignedCampaignsResponse(BaseModel):
    success: bool
    campaigns: List[UserSignedCampaignResponse]
    total: int

class CheckSignatureResponse(BaseModel):
    has_signed: bool
    signature: Optional[dict] = None
