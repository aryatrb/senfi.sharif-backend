from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import auth, campaigns, admin
from app.core.database import engine
from app.models import user, campaign

# Create database tables
user.Base.metadata.create_all(bind=engine)
campaign.Base.metadata.create_all(bind=engine)

app = FastAPI(title="Senfi Web API", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # For production, restrict to your frontend domains
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router, prefix="/api", tags=["Authentication"])
app.include_router(campaigns.router, prefix="/api", tags=["Campaigns"])
app.include_router(admin.router, prefix="/api", tags=["Admin"])

@app.get("/")
def root():
    return {"message": "Senfi Web API is running"}
