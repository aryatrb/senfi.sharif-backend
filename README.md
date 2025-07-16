# Sharif Auth API Backend

A simple FastAPI backend for user registration and login, compatible with the specified API contract and frontend.

## Features
- Email check, code sending/verification, registration, and login endpoints
- Only @sharif.edu emails allowed
- SQLite database for users
- Passwords hashed with bcrypt
- JWT token generation for login
- In-memory verification code storage

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Run the server:**
   ```bash
   uvicorn main:app --reload
   ```
   The API will be available at http://localhost:8000

## API Endpoints & Sample Usage

### 1. Check Email
- **POST** `/api/auth/check-email`
- **Body:** `{ "email": "user@sharif.edu" }`
- **Response:** `{ "exists": true }`
- **Sample:**
  ```bash
  curl -X POST http://localhost:8000/api/auth/check-email \
    -H "Content-Type: application/json" \
    -d '{"email": "user@sharif.edu"}'
  ```

### 2. Send Verification Code
- **POST** `/api/auth/send-code`
- **Body:** `{ "email": "user@sharif.edu" }`
- **Response:** `{ "success": true }`
- **Sample:**
  ```bash
  curl -X POST http://localhost:8000/api/auth/send-code \
    -H "Content-Type: application/json" \
    -d '{"email": "user@sharif.edu"}'
  ```

### 3. Verify Code
- **POST** `/api/auth/verify-code`
- **Body:** `{ "email": "user@sharif.edu", "code": "123456" }`
- **Response:** `{ "valid": true }`
- **Sample:**
  ```bash
  curl -X POST http://localhost:8000/api/auth/verify-code \
    -H "Content-Type: application/json" \
    -d '{"email": "user@sharif.edu", "code": "123456"}'
  ```

### 4. Register
- **POST** `/api/auth/register`
- **Body:** `{ "email": "user@sharif.edu", "password": "pass1234" }`
- **Response:** `{ "success": true, "userId": 1 }`
- **Sample:**
  ```bash
  curl -X POST http://localhost:8000/api/auth/register \
    -H "Content-Type: application/json" \
    -d '{"email": "user@sharif.edu", "password": "pass1234"}'
  ```

### 5. Login
- **POST** `/api/auth/login`
- **Body:** `{ "email": "user@sharif.edu", "password": "pass1234" }`
- **Response:** `{ "success": true, "token": "JWT_TOKEN", "user": { ... } }`
- **Sample:**
  ```bash
  curl -X POST http://localhost:8000/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email": "user@sharif.edu", "password": "pass1234"}'
  ```

## ارسال ایمیل واقعی (اختیاری)

برای اینکه کد تأیید به صورت واقعی از طریق جیمیل ارسال شود:

1. یک Gmail مخصوص ارسال (مثلاً sharif.sut.archives@gmail.com) بسازید یا از یک جیمیل موجود استفاده کنید.
2. برای امنیت بیشتر، یک **App Password** بسازید (در تنظیمات Google Account > Security > App Passwords).
3. دو متغیر محیطی زیر را تنظیم کنید:
   - `GMAIL_USER` : ایمیل جیمیل (مثلاً sharif.sut.archives@gmail.com)
   - `GMAIL_PASS` : App Password جیمیل

در لینوکس می‌توانید این متغیرها را اینگونه ست کنید:
```bash
export GMAIL_USER=sharif.sut.archives@gmail.com
export GMAIL_PASS=your_app_password_here
```
سپس سرور را اجرا کنید:
```bash
uvicorn main:app --reload
```

اگر این متغیرها ست نباشند، کد تأیید فقط در کنسول چاپ می‌شود و ایمیل واقعی ارسال نمی‌شود.

## Notes
- Verification codes are printed to the server console for testing.
- Change `SECRET_KEY` in `main.py` for production use.
- The SQLite database file (`users.db`) will be created in the project directory. # senfi.sharif-backend
