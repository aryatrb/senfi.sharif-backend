import os
from dotenv import load_dotenv

load_dotenv()

# Database Configuration
DATABASE_URL = "sqlite:///./users.db"

# JWT Configuration
SECRET_KEY = os.getenv("SECRET_KEY", "your_jwt_secret_key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

# Email Configuration
GMAIL_USER = os.environ.get("GMAIL_USER")
GMAIL_PASS = os.environ.get("GMAIL_PASS")
