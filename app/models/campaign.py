from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime

from app.core.database import Base

class PendingCampaign(Base):
    __tablename__ = "pending_campaigns"
    
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, nullable=False)
    description = Column(String, nullable=False)
    email = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="pending")
    is_anonymous = Column(String, default="public")
    end_datetime = Column(DateTime, nullable=False)

class CampaignSignature(Base):
    __tablename__ = "campaign_signatures"
    
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=False)
    user_email = Column(String, nullable=False)
    signed_at = Column(DateTime, default=datetime.utcnow)
    is_anonymous = Column(String, default="public")
