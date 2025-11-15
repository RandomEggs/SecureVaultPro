"""
Gmail API Service for SecureVault Pro
Uses OAuth2 authentication to send emails via Gmail API
"""

import os
import base64
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

logger = logging.getLogger(__name__)


class GmailService:
    """Gmail API service for sending emails using OAuth2"""
    
    def __init__(self):
        """Initialize Gmail API service with OAuth2 credentials"""
        self.client_id = os.getenv('GMAIL_CLIENT_ID')
        self.client_secret = os.getenv('GMAIL_CLIENT_SECRET')
        self.refresh_token = os.getenv('GMAIL_REFRESH_TOKEN')
        self.sender_email = os.getenv('GMAIL_SENDER_EMAIL')
        
        if not all([self.client_id, self.client_secret, self.refresh_token, self.sender_email]):
            logger.warning('Gmail API credentials not fully configured')
            self.service = None
        else:
            try:
                self.service = self._get_gmail_service()
                logger.info('Gmail API service initialized successfully')
            except Exception as e:
                logger.error(f'Failed to initialize Gmail API service: {str(e)}')
                self.service = None
    
    def _get_gmail_service(self):
        """Create and return Gmail API service with OAuth2 credentials"""
        try:
            creds = None
            
            # Check if token.json exists (from generate_gmail_token.py)
            if os.path.exists('token.json'):
                logger.debug('Loading credentials from token.json')
                creds = Credentials.from_authorized_user_file('token.json', 
                    scopes=['https://www.googleapis.com/auth/gmail.send'])
            
            # If no token.json, create from environment variables
            if not creds:
                logger.debug('Creating credentials from environment variables')
                creds = Credentials(
                    token=None,
                    refresh_token=self.refresh_token,
                    token_uri='https://oauth2.googleapis.com/token',
                    client_id=self.client_id,
                    client_secret=self.client_secret,
                    scopes=['https://www.googleapis.com/auth/gmail.send']
                )
            
            # Refresh the access token if needed
            if not creds.valid:
                if creds.expired and creds.refresh_token:
                    logger.debug('Refreshing expired access token')
                    creds.refresh(Request())
                    logger.debug('Access token refreshed successfully')
                    
                    # Save updated token
                    if os.path.exists('token.json'):
                        with open('token.json', 'w') as token:
                            token.write(creds.to_json())
            
            # Build Gmail API service
            service = build('gmail', 'v1', credentials=creds)
            return service
            
        except Exception as e:
            logger.error(f'Error creating Gmail service: {str(e)}')
            raise
    
    def _create_message(self, to_email, subject, html_content):
        """Create a MIME message for Gmail API"""
        try:
            message = MIMEMultipart('alternative')
            message['to'] = to_email
            message['from'] = self.sender_email
            message['subject'] = subject
            
            # Add HTML content
            html_part = MIMEText(html_content, 'html')
            message.attach(html_part)
            
            # Encode the message
            raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode('utf-8')
            return {'raw': raw_message}
            
        except Exception as e:
            logger.error(f'Error creating email message: {str(e)}')
            raise
    
    def send_email(self, to_email, subject, html_content):
        """
        Send an email using Gmail API
        
        Args:
            to_email (str): Recipient email address
            subject (str): Email subject
            html_content (str): HTML email body
            
        Returns:
            bool: True if email sent successfully, False otherwise
        """
        if not self.service:
            logger.error('Gmail API service not initialized')
            return False
        
        try:
            logger.info(f'Attempting to send email via Gmail API to {to_email}')
            
            # Create message
            message = self._create_message(to_email, subject, html_content)
            
            # Send message
            result = self.service.users().messages().send(
                userId='me',
                body=message
            ).execute()
            
            message_id = result.get('id')
            logger.info(f'Email sent successfully via Gmail API. Message ID: {message_id}')
            return True
            
        except HttpError as error:
            logger.error(f'Gmail API HTTP error: {error}')
            logger.error(f'Error details: {error.error_details if hasattr(error, "error_details") else "N/A"}')
            return False
            
        except Exception as e:
            logger.error(f'Failed to send email via Gmail API: {str(e)}')
            logger.error(f'Error type: {type(e).__name__}')
            return False


# Create a global Gmail service instance
gmail_service = GmailService()
