# 🔐 SecureVault Pro

<div align="center">

![SecureVault Pro](https://img.shields.io/badge/SecureVault-Pro-6b0f8a?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.x-000000?style=for-the-badge&logo=flask)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

**A modern, secure password manager with military-grade encryption**

[Features](#features) • [Installation](#installation) • [Security](#security) • [License](#license)

</div>

---

## About

SecureVault Pro is a full-stack password management application built with Flask, featuring enterprise-grade security, beautiful UI, and comprehensive password management capabilities.

## Features

- 🔒 **Encrypted Vault** – Fernet symmetric encryption for every stored password
- 🔐 **Two-Factor Authentication** – TOTP-based 2FA with QR setup + backup codes
- 📧 **Transactional Email** – Email verification and password-reset flows via Gmail API
- 🔑 **Strong Password Generator** – One-click generator with live strength feedback
- 📥 **CSV Import / Export** – Bulk management with Chrome/Firefox/Edge formats
- 📊 **Analytics Dashboard** – Password strength insights, reuse detection, top sites
- 🎨 **Responsive UI** – Modern, dark-themed dashboard tuned for desktop & mobile
- 🛡️ **Security Hardening** – CSRF, HSTS, rate limiting, secure cookies, strict CSP

## Tech Stack

| Layer | Tools |
| --- | --- |
| Backend | Flask, SQLAlchemy, Flask-Login, Flask-Limiter |
| Database | PostgreSQL (Neon or self-hosted) |
| Security | bcrypt, cryptography (Fernet), PyOTP, Flask-WTF |
| Frontend | HTML5, Bootstrap 5, Vanilla JS + jQuery |
| Deployment | Gunicorn, Render / Docker-compatible environments |

---

## Getting Started

### 1. Prerequisites

- Python **3.11+**
- PostgreSQL instance (local, Docker, or managed such as Neon)
- Gmail API credentials if you plan to send verification/reset emails (optional for local dev)

### 2. Clone & Setup

```bash
git clone https://github.com/yourusername/securevault-pro.git
cd securevault-pro/backend

# Create and activate a virtual environment
python -m venv .venv
# Windows
.\.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure Environment

Create a `.env` file inside `backend/` (you can copy from `.env.example` if present) and supply the required keys:

```env
FLASK_SECRET_KEY="your-flask-secret"
SESSION_COOKIE_SECURE=False           # True in production over HTTPS
FORCE_HTTPS=False                     # True in production (Render, etc.)

# Database
DATABASE_URL="postgresql://user:password@host:5432/securevault"

# Encryption key for password storage (32 url-safe base64 bytes)
ENCRYPTION_KEY="<generated_fernet_key>"

# (Optional) Gmail OAuth credentials for email flows
GMAIL_CLIENT_ID="..."
GMAIL_CLIENT_SECRET="..."
GMAIL_REFRESH_TOKEN="..."
GMAIL_SENDER_EMAIL="your-address@gmail.com"

# Application URL (used in email links)
APP_URL="http://localhost:5000"
```

> ⚠️ Generate a Fernet key via `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`

If you plan to use Gmail, run `generate_gmail_token.py` once to obtain a refresh token (store `credentials.json` and resulting `token.json` outside of version control).

### 4. Initialize Database

```bash
python init_db.py
```

This will create tables using SQLAlchemy models. Ensure your `DATABASE_URL` is reachable.

### 5. Run the Development Server

```bash
python app.py
```

Visit **http://127.0.0.1:5000** and sign up with a new account. In development you can toggle `FLASK_DEBUG` in `.env` for auto-reload.

---

## Gmail Email Integration (Optional)

1. Enable the Gmail API in Google Cloud Console and create an OAuth client (Desktop).
2. Save `credentials.json` inside `backend/`.
3. Run `python generate_gmail_token.py` to authorize and create `token.json`.
4. Copy the printed `GMAIL_*` values into `.env`.

The app will automatically use Gmail API for verification and reset emails once these values are present. Without them, email calls fail gracefully.

---

## Command Reference

| Task | Command |
| --- | --- |
| Run tests (if added) | `pytest` |
| Format with black | `black .` |
| Start dev server | `python app.py` |
| Refresh requirements | `pip freeze > requirements.txt` |

---

## Database Notes

- Uses PostgreSQL with SQLAlchemy.
- Connection pooling configured with `pool_pre_ping` to avoid Neon cold-start staleness.
- Passwords are encrypted at rest; only decrypted in memory per-request.

To inspect schema quickly:

```bash
python - <<'PY'
from database import get_session
from models import User, Password
with get_session() as session:
    print(session.execute("SELECT count(*) FROM users").scalar())
PY
```

---

## Frontend Overview

- Dashboard located in `backend/templates/dashboard.html`.
- Responsive layout with CSS defined in `base.html`.
- Password analytics + CSV import logic implemented directly in the template JS.

---

## Deployment Checklist

1. Set `FORCE_HTTPS=True` and `SESSION_COOKIE_SECURE=True`.
2. Provide production `.env` via environment variables (Render, Heroku, etc.).
3. Use Gunicorn entrypoint: `gunicorn app:app`.
4. Attach a managed Postgres database; run `python init_db.py` once.
5. Configure Gmail credentials or swap to your preferred email provider.

For Render-specific steps, see `Procfile` or create a Render service pointing at `/backend` with the above command.

---

## Security Practices

- Fernet (AES-128) encryption for stored passwords
- bcrypt password hashing w/ per-user salt
- CSRF protection, strict Content-Security-Policy via Flask-Talisman
- Rate limiting on auth endpoints (Flask-Limiter)
- HTTPOnly, Secure session cookies + SameSite=Lax
- Two-factor authentication (TOTP) support

---

## Contributing

Pull requests and issues are welcome! Please:

1. Fork the repo and create a feature branch.
2. Ensure lint/tests pass.
3. Describe your changes and attach screenshots for UI tweaks.

---

## License

Distributed under the MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with ❤️ using Flask & PostgreSQL**

If this project helps you, consider leaving a ⭐

</div>
