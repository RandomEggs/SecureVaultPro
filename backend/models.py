from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
import secrets
import string
import pyotp
import qrcode
from io import BytesIO
import base64

from database import Base

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Email verification fields
    is_email_verified = Column(Boolean, default=False)
    email_verification_token = Column(String(32))
    email_verification_expires = Column(DateTime)
    
    # Password reset fields
    password_reset_token = Column(String(32))
    password_reset_expires = Column(DateTime)
    
    # Relationship with passwords
    passwords = relationship("Password", back_populates="user", cascade="all, delete-orphan")
    
    # Relationship with 2FA
    mfa_totp = relationship("MFATOTP", back_populates="user", uselist=False, cascade="all, delete-orphan")

class Password(Base):
    __tablename__ = 'passwords'
    
    id = Column(Integer, primary_key=True)
    website_name = Column(String(255), nullable=False)
    username = Column(String(255), nullable=False)
    encrypted_password = Column(Text, nullable=False)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Relationship with user
    user = relationship("User", back_populates="passwords")

class MFATOTP(Base):
    __tablename__ = 'mfa_totp'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False, unique=True)
    secret_encrypted = Column(String(255), nullable=False)
    secret_salt = Column(String(32), nullable=False)
    issuer = Column(String(100), nullable=False, default='Kali Password Manager')
    algorithm = Column(String(10), nullable=False, default='SHA1')
    digits = Column(Integer, nullable=False, default=6)
    period = Column(Integer, nullable=False, default=30)
    backup_codes_encrypted = Column(Text)
    is_enabled = Column(Boolean, nullable=False, default=False)
    is_verified = Column(Boolean, nullable=False, default=False)
    last_used = Column(DateTime)
    usage_count = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    enabled_at = Column(DateTime)
    
    # Relationship with user
    user = relationship("User", back_populates="mfa_totp")
    
    def __init__(self, user_id, issuer='SecureVault Pro'):
        self.user_id = user_id
        self.issuer = issuer
        self.secret_salt = secrets.token_hex(16)
        self.secret = pyotp.random_base32()
        self.generate_backup_codes()
    
    @property
    def secret(self):
        from security import decrypt_password
        return decrypt_password(self.secret_encrypted.encode())
    
    @secret.setter
    def secret(self, value):
        from security import encrypt_password
        self.secret_encrypted = encrypt_password(value).decode()
    
    @property
    def backup_codes(self):
        from security import decrypt_password
        if self.backup_codes_encrypted:
            return decrypt_password(self.backup_codes_encrypted.encode()).split(',')
        return []
    
    @backup_codes.setter
    def backup_codes(self, codes_list):
        from security import encrypt_password
        codes_string = ','.join(codes_list)
        self.backup_codes_encrypted = encrypt_password(codes_string).decode()
    
    def generate_backup_codes(self):
        """Generate 10 backup codes"""
        codes = []
        for _ in range(10):
            code = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
            codes.append(code)
        self.backup_codes = codes
    
    def get_totp_uri(self, email):
        """Generate TOTP URI for QR code"""
        totp = pyotp.TOTP(self.secret, issuer=self.issuer, name=email)
        return totp.provisioning_uri(name=email, issuer_name=self.issuer)
    
    def generate_qr_code(self, email):
        """Generate QR code for TOTP setup"""
        uri = self.get_totp_uri(email)
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="purple", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        img_str = base64.b64encode(buffer.getvalue()).decode()
        
        return f"data:image/png;base64,{img_str}"
    
    def verify_token(self, token):
        """Verify TOTP token"""
        if not token or len(token) != self.digits:
            return False
        
        totp = pyotp.TOTP(self.secret, issuer=self.issuer, digits=self.digits, interval=self.period)
        return totp.verify(token)
    
    def verify_backup_code(self, code):
        """Verify backup code"""
        if not code or len(code) != 8:
            return False
        
        codes = self.backup_codes
        if code.upper() in codes:
            # Remove used backup code
            codes.remove(code.upper())
            self.backup_codes = codes
            return True
        return False
    
    def enable(self):
        """Enable 2FA"""
        self.is_enabled = True
        self.is_verified = True
        self.enabled_at = datetime.utcnow()
    
    def disable(self):
        """Disable 2FA"""
        self.is_enabled = False
        self.is_verified = False
        self.enabled_at = None
    
    def record_usage(self):
        """Record when 2FA is used"""
        self.last_used = datetime.utcnow()
        self.usage_count += 1
