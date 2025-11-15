# 📧 Gmail API Setup Guide for SecureVault Pro

## ✅ Why Gmail API?

- ✅ **No SMTP port blocking** (Render blocks ports 25, 587, 465)
- ✅ **No domain verification needed**
- ✅ **Send to ANY email address**
- ✅ **No DMARC issues**
- ✅ **Free (15GB quota/day)**
- ✅ **Works everywhere** (local, Render, any cloud)

---

## 🚀 Quick Setup (5 minutes)

### Step 1: Google Cloud Console Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. **Create new project**:
   - Name: `SecureVault Pro Email`
   - Click "Create"

3. **Enable Gmail API**:
   - Go to: `APIs & Services` → `Library`
   - Search: `Gmail API`
   - Click `Enable`

4. **Configure OAuth Consent Screen**:
   - Go to: `APIs & Services` → `OAuth consent screen`
   - User Type: `External`
   - App name: `SecureVault Pro`
   - User support email: Your email
   - Developer contact: Your email
   - Click `Save and Continue`
   - Scopes: Skip (click `Save and Continue`)
   - Test users: Add your Gmail address
   - Click `Save and Continue`

5. **Create OAuth2 Credentials**:
   - Go to: `APIs & Services` → `Credentials`
   - Click: `Create Credentials` → `OAuth client ID`
   - Application type: `Desktop app`
   - Name: `SecureVault Pro Desktop`
   - Click `Create`
   - **Download JSON** → Save as `credentials.json` in `backend/` folder

---

### Step 2: Generate Refresh Token

Run the token generator script:

```bash
cd backend
python generate_gmail_token.py
```

This will:
1. Open your browser
2. Ask you to sign in to Gmail
3. Generate OAuth2 tokens
4. Display credentials to copy

---

### Step 3: Update Environment Variables

Copy the output from Step 2 to your `.env` file:

```env
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-client-secret
GMAIL_REFRESH_TOKEN=your-refresh-token
GMAIL_SENDER_EMAIL=youremail@gmail.com
```

---

### Step 4: Test Locally

```bash
python app.py
```

Sign up with any email - verification emails will now be sent via Gmail API! ✅

---

## 🚀 Render Deployment

### Add Environment Variables in Render Dashboard:

1. Go to your Render service
2. Click `Environment`
3. Add these variables:

```
GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GMAIL_CLIENT_SECRET=your-client-secret
GMAIL_REFRESH_TOKEN=your-refresh-token
GMAIL_SENDER_EMAIL=youremail@gmail.com
```

4. Save and redeploy

---

## 🔒 Security Best Practices

### ✅ DO:
- ✅ Keep `credentials.json` and `token.json` in `.gitignore`
- ✅ Use environment variables for production
- ✅ Rotate refresh tokens periodically
- ✅ Enable 2FA on your Gmail account
- ✅ Use a dedicated Gmail account for sending (not your personal)

### ❌ DON'T:
- ❌ Commit credentials to Git
- ❌ Share refresh tokens
- ❌ Use your personal Gmail (create a new one)
- ❌ Leave OAuth consent screen in testing mode for production

---

## 📊 Gmail API Limits

| Metric | Limit |
|--------|-------|
| Daily sending quota | **2,000 emails/day** (free Gmail) |
| Daily sending quota | **10,000 emails/day** (Google Workspace) |
| Batch size | 100 recipients per message |
| Message size | 35 MB |

**Note:** 2,000 emails/day is more than enough for a password manager!

---

## 🐛 Troubleshooting

### Error: "The Gmail API has not been used in project..."
**Solution:** Wait 1-2 minutes after enabling the API, then try again.

### Error: "invalid_grant"
**Solution:** Refresh token expired. Re-run `generate_gmail_token.py`.

### Error: "Access blocked: This app's request is invalid"
**Solution:** Make sure you added your email to Test Users in OAuth consent screen.

### Error: "insufficient authentication scopes"
**Solution:** Delete `token.json` and re-run `generate_gmail_token.py`.

---

## ✅ Verification

Test email sending:

```bash
python -c "from email_service import email_service; print(email_service.send_verification_email('test@example.com', 'test-token'))"
```

Should return `True` and send an email! 🎉

---

## 📝 Notes

- **Refresh tokens don't expire** (unless revoked)
- **No monthly fees** (completely free)
- **No domain verification** required
- **Works on all hosting platforms**
- **Better deliverability** than SMTP

---

## 🆘 Need Help?

1. Check [Gmail API Documentation](https://developers.google.com/gmail/api/guides/sending)
2. Verify credentials are correct
3. Check Render logs for errors
4. Ensure Gmail account has "Less secure app access" OFF (OAuth2 is more secure)

---

**That's it! Your password manager now sends emails using Gmail API! 🚀**
