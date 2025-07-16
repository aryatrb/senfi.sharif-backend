from datetime import datetime
from typing import List
from sqlalchemy.orm import Session
from app.models.campaign import PendingCampaign, CampaignSignature
from app.schemas.campaign import CampaignCreate

def create_campaign(db: Session, campaign: CampaignCreate) -> PendingCampaign:
    db_campaign = PendingCampaign(
        title=campaign.title,
        description=campaign.description,
        email=campaign.email,
        status="pending",
        is_anonymous=campaign.is_anonymous,
        end_datetime=campaign.end_datetime
    )
    db.add(db_campaign)
    db.commit()
    db.refresh(db_campaign)
    return db_campaign

def get_campaign_by_id(db: Session, campaign_id: int) -> PendingCampaign:
    return db.query(PendingCampaign).filter(PendingCampaign.id == campaign_id).first()

def get_campaigns_by_status(db: Session, status: str) -> List[PendingCampaign]:
    return db.query(PendingCampaign).filter(PendingCampaign.status == status).all()

def update_campaign_status(db: Session, campaign_id: int, status: str) -> PendingCampaign:
    campaign = get_campaign_by_id(db, campaign_id)
    if campaign:
        campaign.status = status
        db.commit()
        db.refresh(campaign)
    return campaign

def create_signature(db: Session, campaign_id: int, user_id: int, user_email: str, is_anonymous: str) -> CampaignSignature:
    signature = CampaignSignature(
        campaign_id=campaign_id,
        user_id=user_id,
        user_email=user_email,
        is_anonymous=is_anonymous
    )
    db.add(signature)
    db.commit()
    db.refresh(signature)
    return signature

def get_signature_by_user_and_campaign(db: Session, user_id: int, campaign_id: int) -> CampaignSignature:
    return db.query(CampaignSignature).filter(
        CampaignSignature.user_id == user_id,
        CampaignSignature.campaign_id == campaign_id
    ).first()

def get_signatures_by_campaign(db: Session, campaign_id: int) -> List[CampaignSignature]:
    return db.query(CampaignSignature).filter(CampaignSignature.campaign_id == campaign_id).all()

def get_signatures_by_user(db: Session, user_id: int) -> List[CampaignSignature]:
    return db.query(CampaignSignature).filter(CampaignSignature.user_id == user_id).all()

def count_signatures_by_campaign(db: Session, campaign_id: int) -> int:
    return db.query(CampaignSignature).filter(CampaignSignature.campaign_id == campaign_id).count()
