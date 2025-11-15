import os
import logging
import resend
from datetime import datetime, timezone
from dotenv import load_dotenv
from pathlib import Path

# Configure logging
logger = logging.getLogger(__name__)

env_path = Path('.') / '.env'
load_dotenv(dotenv_path=env_path)

class EmailService:
    def __init__(self):
        # Use Resend API (works on Render - uses HTTPS, not blocked SMTP ports)
        self.resend_api_key = os.getenv("RESEND_API_KEY")
        self.from_email = os.getenv("FROM_EMAIL", "onboarding@resend.dev")
        self.app_url = os.getenv("APP_URL", "http://localhost:5000")
        
        # Configure Resend
        if self.resend_api_key:
            resend.api_key = self.resend_api_key
        else:
            logger.warning('RESEND_API_KEY not set, email functionality disabled')
    
    def send_email(self, to_email: str, subject: str, body: str, is_html: bool = False):
        """Send an email using Resend API"""
        try:
            if not self.resend_api_key:
                logger.warning('Resend API key not configured, email not sent')
                return False
            
            logger.info(f'Attempting to send email via Resend to {to_email}')
            
            params = {
                "from": self.from_email,
                "to": [to_email],
                "subject": subject,
            }
            
            if is_html:
                params["html"] = body
            else:
                params["text"] = body
            
            response = resend.Emails.send(params)
            
            logger.info(f'Email sent successfully via Resend. ID: {response.get("id")}')
            return True
            
        except Exception as e:
            logger.error(f'Failed to send email via Resend: {str(e)}')
            logger.error(f'Error type: {type(e).__name__}')
            return False
    
    def send_verification_email(self, to_email, token):
        subject = "Verify Your SecureVault Pro Account"
        
        verification_url = f"{os.getenv('APP_URL')}/verify-email/{token}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #1a1a1a;
                    color: #ffffff;
                    margin: 0;
                    padding: 20px;
                }}
                .container {{
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #2a2a2a;
                    border-radius: 10px;
                    border: 1px solid #6b0f8a;
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #6b0f8a 0%, #4a0763 100%);
                    padding: 30px;
                    text-align: center;
                }}
                .header h1 {{
                    color: #ffffff;
                    margin: 0;
                    font-size: 28px;
                }}
                .content {{
                    padding: 30px;
                }}
                .button {{
                    display: inline-block;
                    background: linear-gradient(135deg, #6b0f8a 0%, #8e44ad 100%);
                    color: #ffffff;
                    padding: 15px 30px;
                    text-decoration: none;
                    border-radius: 5px;
                    font-weight: bold;
                    margin: 20px 0;
                }}
                .footer {{
                    background-color: #1a1a1a;
                    padding: 20px;
                    text-align: center;
                    font-size: 12px;
                    color: #888888;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔐 SecureVault Pro</h1>
                </div>
                <div class="content">
                    <h2>Welcome to SecureVault Pro!</h2>
                    <p>Thank you for creating an account with us. To complete your registration and start using our secure password manager, please verify your email address.</p>
                    
                    <p style="text-align: center;">
                        <a href="{verification_url}" class="button">Verify Email Address</a>
                    </p>
                    
                    <p><strong>Or copy and paste this link:</strong></p>
                    <p style="word-break: break-all; background-color: #1a1a1a; padding: 10px; border-radius: 5px;">{verification_url}</p>
                    
                    <p><em>This link will expire in 24 hours.</em></p>
                    <p>If you didn't create an account with SecureVault Pro, please ignore this email.</p>
                </div>
                <div class="footer">
                    <p>&copy; 2025 SecureVault Pro - Your Digital Security Partner</p>
                    <p>This is an automated message. Please do not reply to this email.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, html_content, is_html=True)
    
    def send_password_reset_email(self, to_email: str, reset_token: str):
        """Send password reset email"""
        reset_url = f"{self.app_url}/reset-password/{reset_token}"
        
        subject = "Reset Your Password - SecureVault Pro"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #1a1a1a; color: #ffffff; padding: 20px;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #2d2d2d; padding: 30px; border-radius: 10px; border: 1px solid #6b0f8a;">
                <h1 style="color: #8e44ad; text-align: center;">🔐 SecureVault Pro</h1>
                <h2 style="color: #ffffff; text-align: center;">Password Reset</h2>
                
                <p style="color: #cccccc; font-size: 16px;">Hello,</p>
                <p style="color: #cccccc; font-size: 16px;">We received a request to reset your password. Click the button below to reset it:</p>
                
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" style="background-color: #6b0f8a; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-size: 18px; display: inline-block;">
                        Reset Password
                    </a>
                </div>
                
                <p style="color: #cccccc; font-size: 14px;">Or copy and paste this link into your browser:</p>
                <p style="color: #8e44ad; font-size: 12px; word-break: break-all;">{reset_url}</p>
                
                <hr style="border: 1px solid #6b0f8a; margin: 30px 0;">
                
                <p style="color: #999999; font-size: 12px; text-align: center;">
                    This link will expire in 1 hour. If you didn't request this reset, please ignore this email.
                </p>
            </div>
        </body>
        </html>
        """
        
        return self.send_email(to_email, subject, body, is_html=True)

# Create a global email service instance
email_service = EmailService()
