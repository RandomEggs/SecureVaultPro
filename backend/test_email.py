import resend
import os
from dotenv import load_dotenv

load_dotenv()

# Configure Resend
resend.api_key = os.getenv("RESEND_API_KEY")

print(f"API Key: {resend.api_key[:10]}...")
print(f"FROM_EMAIL: {os.getenv('FROM_EMAIL')}")

# Test sending email
try:
    params = {
        "from": "onboarding@resend.dev",
        "to": ["ddeathgod20@gmail.com"],
        "subject": "Test Email from SecureVault Pro",
        "html": "<h1>Test Email</h1><p>This is a test email from Resend API.</p>",
    }
    
    response = resend.Emails.send(params)
    print(f"✅ Email sent successfully!")
    print(f"Response: {response}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    print(f"Error type: {type(e).__name__}")
