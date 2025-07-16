from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import get_current_user, require_role
from app.crud import campaign as crud_campaign
from app.schemas.campaign import *

router = APIRouter()

@router.post("/campaigns/submit", response_model=CampaignSubmitResponse)
def submit_campaign(body: CampaignCreate, db: Session = Depends(get_db)):
    if body.end_datetime <= datetime.utcnow():
        raise HTTPException(status_code=400, detail="تاریخ پایان باید بعد از اکنون باشد.")
    
    campaign = crud_campaign.create_campaign(db, campaign=body)
    return {
        "success": True,
        "campaignId": campaign.id,
        "status": campaign.status,
        "created_at": campaign.created_at,
        "end_datetime": campaign.end_datetime
    }

@router.get("/campaigns/approved", response_model=CampaignListResponse)
def get_approved_campaigns(db: Session = Depends(get_db)):
    campaigns = crud_campaign.get_campaigns_by_status(db, status="approved")
    campaign_list = [
        {
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email,
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        }
        for campaign in campaigns
    ]
    return {"success": True, "campaigns": campaign_list, "total": len(campaign_list)}

@router.get("/campaigns/rejected", response_model=CampaignListResponse)
def get_rejected_campaigns(db: Session = Depends(get_db)):
    campaigns = crud_campaign.get_campaigns_by_status(db, status="rejected")
    campaign_list = [
        {
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email,
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        }
        for campaign in campaigns
    ]
    return {"success": True, "campaigns": campaign_list, "total": len(campaign_list)}

@router.post("/campaigns/{campaign_id}/sign", response_model=CampaignSignatureResponse)
def sign_campaign(
    campaign_id: int,
    body: CampaignSignatureSchema,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    campaign = crud_campaign.get_campaign_by_id(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    existing_signature = crud_campaign.get_signature_by_user_and_campaign(db, current_user.id, campaign_id)
    if existing_signature:
        raise HTTPException(status_code=400, detail="شما قبلاً این کارزار را امضا کرده‌اید")
    
    signature = crud_campaign.create_signature(db, campaign_id, current_user.id, current_user.email, body.is_anonymous)
    total_signatures = crud_campaign.count_signatures_by_campaign(db, campaign_id)
    
    return {
        "success": True,
        "message": "کارزار با موفقیت امضا شد",
        "signature_id": signature.id,
        "total_signatures": total_signatures
    }

@router.get("/campaigns/{campaign_id}/signatures")
def get_campaign_signatures(campaign_id: int, db: Session = Depends(get_db)):
    campaign = crud_campaign.get_campaign_by_id(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    if campaign.is_anonymous == "anonymous":
        total_signatures = crud_campaign.count_signatures_by_campaign(db, campaign_id)
        return {
            "success": True,
            "signatures": [],
            "total": total_signatures,
            "campaign_is_anonymous": "anonymous"
        }
    
    signatures = crud_campaign.get_signatures_by_campaign(db, campaign_id)
    signature_list = []
    for sig in signatures:
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

@router.get("/campaigns/{campaign_id}/check-signature")
def check_user_signature(
    campaign_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    campaign = crud_campaign.get_campaign_by_id(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    signature = crud_campaign.get_signature_by_user_and_campaign(db, current_user.id, campaign_id)
    
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

@router.get("/user/signed-campaigns")
def get_user_signed_campaigns(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    signatures = crud_campaign.get_signatures_by_user(db, current_user.id)
    campaign_list = []
    
    for sig in signatures:
        campaign = crud_campaign.get_campaign_by_id(db, sig.campaign_id)
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

@router.get("/user/{user_id}/signed-campaigns")
def get_signed_campaigns_for_user(
    user_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    require_role(["superadmin", "head"])(current_user)
    signatures = crud_campaign.get_signatures_by_user(db, user_id)
    campaign_list = []
    for sig in signatures:
        campaign = crud_campaign.get_campaign_by_id(db, sig.campaign_id)
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
