import random
import string
import smtplib
from email.message import EmailMessage

from app.core.config import GMAIL_USER, GMAIL_PASS

def is_sharif_email(email: str) -> bool:
    """Check if email is from Sharif University domain"""
    return email.lower().endswith("@sharif.edu")

def generate_code() -> str:
    """Generate a 6-digit verification code"""
    return ''.join(random.choices(string.digits, k=6))

def send_verification_email_gmail(to_email: str, code: str) -> bool:
    """
    Send the verification code to the user's email using Gmail SMTP.
    Returns True if sent, False otherwise.
    """
    if not GMAIL_USER or not GMAIL_PASS:
        return False
    
    try:
        msg = EmailMessage()
        msg["Subject"] = "Sharif Verification Code"
        msg["From"] = GMAIL_USER
        msg["To"] = to_email
        msg.set_content(f"Your verification code is: {code}")
        
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as smtp:
            smtp.login(GMAIL_USER, GMAIL_PASS)
            smtp.send_message(msg)
        return True
    except Exception as e:
        print(f"[ERROR] Failed to send email: {e}")
        return False
