# This file is kept for backwards compatibility
# The new modular structure is in the app/ directory

from app.main import app

# Re-export the app for uvicorn
__all__ = ["app"]
