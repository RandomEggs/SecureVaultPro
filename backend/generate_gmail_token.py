"""
Gmail OAuth2 Token Generator
Generates refresh token for Gmail API access
"""

import os
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

# Gmail API scope for sending emails
SCOPES = ['https://www.googleapis.com/auth/gmail.send']

def generate_gmail_credentials():
    """
    Generate Gmail API credentials with refresh token
    
    Steps:
    1. Go to Google Cloud Console: https://console.cloud.google.com/
    2. Create a new project or select existing
    3. Enable Gmail API
    4. Create OAuth 2.0 Client ID (Desktop app)
    5. Download credentials JSON
    6. Save as 'credentials.json' in this directory
    7. Run this script
    """
    
    print("=" * 70)
    print("🔐 Gmail API OAuth2 Token Generator - SecureVault Pro")
    print("=" * 70)
    
    # Check if credentials.json exists
    if not os.path.exists('credentials.json'):
        print("\n❌ ERROR: credentials.json not found!")
        print("\n📋 Setup Instructions:")
        print("1. Go to: https://console.cloud.google.com/")
        print("2. Create new project: 'SecureVault Pro Email'")
        print("3. Enable Gmail API")
        print("4. Go to: APIs & Services → Credentials")
        print("5. Create OAuth 2.0 Client ID (Desktop app)")
        print("6. Download JSON and save as 'credentials.json' in backend folder")
        print("7. Run this script again")
        print("=" * 70)
        return
    
    creds = None
    
    # Check for existing token
    if os.path.exists('token.json'):
        print("\n📄 Found existing token.json")
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    
    # If no valid credentials, let user log in
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            print("\n🔄 Refreshing expired token...")
            creds.refresh(Request())
        else:
            print("\n🌐 Opening browser for OAuth2 authorization...")
            print("Please sign in with your Gmail account")
            flow = InstalledAppFlow.from_client_secrets_file(
                'credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        
        # Save credentials for next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    
    print("\n✅ SUCCESS! Gmail API credentials generated")
    print("\n" + "=" * 70)
    print("📝 ADD THESE TO YOUR .env FILE:")
    print("=" * 70)
    print(f"\nGMAIL_CLIENT_ID={creds.client_id}")
    print(f"GMAIL_CLIENT_SECRET={creds.client_secret}")
    print(f"GMAIL_REFRESH_TOKEN={creds.refresh_token}")
    print(f"GMAIL_SENDER_EMAIL=your-gmail@gmail.com")
    print("\n" + "=" * 70)
    print("⚠️  SECURITY WARNINGS:")
    print("1. Never commit credentials.json or token.json to version control")
    print("2. Add them to .gitignore")
    print("3. Keep refresh token secret")
    print("4. For Render, add these as environment variables")
    print("=" * 70)


if __name__ == '__main__':
    generate_gmail_credentials()
