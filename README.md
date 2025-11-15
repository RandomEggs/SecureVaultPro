# 🔐 SecureVault Pro

<div align="center">

![SecureVault Pro](https://img.shields.io/badge/SecureVault-Pro-6b0f8a?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Flask](https://img.shields.io/badge/Flask-3.1-000000?style=for-the-badge&logo=flask)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)

**A modern, secure password manager with military-grade encryption**

[Features](#features) • [Installation](#installation) • [Security](#security) • [License](#license)

</div>

---

## About

SecureVault Pro is a full-stack password management application built with Flask, featuring enterprise-grade security, beautiful UI, and comprehensive password management capabilities.

## Features

- 🔒 **Secure Storage** - Fernet symmetric encryption for all passwords
- 🔐 **Two-Factor Authentication** - TOTP-based 2FA with QR codes and backup codes
- 📧 **Email Verification** - Secure account activation
- 🔑 **Password Generator** - Generate strong, random passwords
- 📥 **Import/Export** - Bulk password management via CSV
- 🎨 **Modern UI** - Responsive design with smooth animations
- 🛡️ **Security Headers** - CSRF protection, rate limiting, and secure headers
- 🔍 **Search & Filter** - Quick password lookup

## Tech Stack

- **Backend**: Flask, SQLAlchemy, PostgreSQL
- **Security**: bcrypt, Fernet encryption, Flask-WTF, Flask-Limiter
- **Authentication**: Flask-Login, PyOTP
- **Frontend**: Bootstrap 5, Font Awesome, jQuery
- **Deployment**: Gunicorn, Render.com

## Installation

### Prerequisites
- Python 3.12+
- PostgreSQL
- Gmail account (for SMTP)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/securevault-pro.git
cd securevault-pro/backend
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Initialize database**
```bash
python init_db.py
```

6. **Run the application**
```bash
python app.py
```

Visit http://localhost:5000

## Configuration

Create a `.env` file with the following variables:

```env
FLASK_SECRET_KEY=your-secret-key
JWT_SECRET=your-jwt-secret
DATABASE_URL=postgresql://user:pass@host:port/db
ENCRYPTION_KEY=your-fernet-key
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
```

## Security

SecureVault Pro implements industry-standard security practices:

- ✅ Fernet encryption (AES-128) for password storage
- ✅ bcrypt password hashing with salt
- ✅ CSRF protection on all forms
- ✅ Rate limiting to prevent brute force
- ✅ Security headers (CSP, HSTS, X-Frame-Options)
- ✅ HTTPOnly and Secure session cookies
- ✅ Input validation and sanitization
- ✅ Two-factor authentication support

## Deployment

### Render.com

1. Create a new Web Service
2. Connect your GitHub repository
3. Set environment variables in Render dashboard
4. Deploy with: `gunicorn app:app`

For detailed deployment instructions, see [RENDER_DEPLOYMENT.md](RENDER_DEPLOYMENT.md)

## Usage

### Creating an Account
1. Navigate to `/signup`
2. Enter email and password
3. Verify email address
4. Login at `/login`

### Managing Passwords
- Add new passwords with the "Add Password" button
- View, edit, or delete existing passwords
- Use the search function to find passwords quickly
- Export passwords to CSV for backup

### Two-Factor Authentication
1. Go to "Setup 2FA" in the dashboard
2. Scan QR code with authenticator app
3. Enter verification code
4. Save backup codes securely

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For issues and questions, please open an issue on GitHub.

---

<div align="center">

**Built with ❤️ using Flask and Python**

⭐ Star this repository if you find it useful!

</div>
