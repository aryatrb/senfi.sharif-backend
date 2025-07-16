from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_role
from app.crud import campaign as crud_campaign
from app.schemas.campaign import *

router = APIRouter()

@router.get("/admin/campaigns", response_model=CampaignListResponse)
def get_pending_campaigns(
    current_user=Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    campaigns = crud_campaign.get_campaigns_by_status(db, status="pending")
    campaign_list = [
        {
            "id": campaign.id,
            "title": campaign.title,
            "description": campaign.description,
            "email": campaign.email or "",  # Handle None values
            "created_at": campaign.created_at,
            "status": campaign.status,
            "end_datetime": campaign.end_datetime
        }
        for campaign in campaigns
    ]
    return {"success": True, "campaigns": campaign_list, "total": len(campaign_list)}

@router.post("/admin/campaigns/approve", response_model=CampaignApprovalResponse)
def approve_campaign(
    body: CampaignApprovalSchema,
    current_user=Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    campaign = crud_campaign.get_campaign_by_id(db, body.campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="Campaign not found")
    
    status = "approved" if body.approved else "rejected"
    message = "کمپین تأیید شد" if body.approved else "کمپین رد شد"
    
    updated_campaign = crud_campaign.update_campaign_status(db, body.campaign_id, status)
    
    return {
        "success": True,
        "message": message,
        "campaign_id": updated_campaign.id,
        "new_status": updated_campaign.status
    }

@router.put("/campaigns/{campaign_id}/status")
def update_campaign_status(
    campaign_id: int,
    data: CampaignStatusUpdateSchema,
    current_user=Depends(require_role(["superadmin", "head", "center_member"])),
    db: Session = Depends(get_db)
):
    campaign = crud_campaign.get_campaign_by_id(db, campaign_id)
    if not campaign:
        raise HTTPException(status_code=404, detail="کارزار یافت نشد")
    
    if data.status:
        if data.status not in ["approved", "rejected", "pending"]:
            raise HTTPException(status_code=400, detail="وضعیت نامعتبر است")
        crud_campaign.update_campaign_status(db, campaign_id, data.status)
        return {"success": True, "message": f"وضعیت کارزار به {data.status} تغییر یافت"}
    elif data.approved is not None:
        status = "approved" if data.approved else "rejected"
        message = "کارزار با موفقیت تایید شد" if data.approved else "کارزار با موفقیت رد شد"
        crud_campaign.update_campaign_status(db, campaign_id, status)
        return {"success": True, "message": message}
    else:
        raise HTTPException(status_code=400, detail="باید یکی از status یا approved ارسال شود")
