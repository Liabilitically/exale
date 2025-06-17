from fastapi import FastAPI, Request, HTTPException, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from google import genai
import requests
import base64
import os
import logging
from dotenv import load_dotenv
from firestore_database import is_user_allowed, is_msg_classified, store_new_classified_message, set_message_to_drafted, get_all_stored_leads, get_user_industry

# Load environment variables
load_dotenv()

# Initialize app
app = FastAPI()

# Secure cookie settings
COOKIE_OPTIONS = {
    "httponly": True,
    "samesite": "None",
    "secure": True  # Change to True in production when using HTTPS
}

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Env config
GEMINI_API_KEY = os.getenv("GOOGLE_API_KEY")
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = "http://localhost:3000/oauth/callback"
TOKEN_URI = "https://oauth2.googleapis.com/token"

NUMBER_OF_FETCHED_EMAILS = 10

# Gemini client
client = genai.Client(api_key=GEMINI_API_KEY)

# Utility: Get Gmail Credentials
def get_gmail_creds(access_token, refresh_token):
    return Credentials(
        token=access_token,
        refresh_token=refresh_token,
        token_uri=TOKEN_URI,
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
    )

# Utility: Create or get Gmail label
def get_or_create_label(service, label_name):
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    for label in labels:
        if label['name'].lower() == label_name.lower():
            return label['id']
    body = {"name": label_name, "labelListVisibility": "labelShow", "messageListVisibility": "show"}
    new_label = service.users().labels().create(userId='me', body=body).execute()
    return new_label['id']

# Utility: Refresh token and retry
async def retry_with_refresh(request_func, refresh_token):
    token_res = requests.post(TOKEN_URI, data={
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    }).json()

    new_token = token_res.get("access_token")
    if not new_token:
        raise HTTPException(status_code=401, detail="Failed to refresh token")

    creds = get_gmail_creds(new_token, refresh_token)
    return request_func(creds), new_token

# Utility: Get the user email from access and refresh tokens
def get_user_email(creds):
    service = build('gmail', 'v1', credentials=creds)
    profile = service.users().getProfile(userId='me').execute()
    email_address = profile['emailAddress']
    return email_address

# ==================== AUTH ====================

@app.post("/auth/callback")
async def auth_callback(request: Request):
    data = await request.json()
    code = data.get("code")

    token_res = requests.post(TOKEN_URI, data={
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code',
    }).json()

    access_token, refresh_token = token_res.get("access_token"), token_res.get("refresh_token")
    if not access_token or not refresh_token:
        raise HTTPException(status_code=400, detail="Missing token(s)")

    response = JSONResponse({"message": "Authenticated"})
    response.set_cookie("access_token", access_token, **COOKIE_OPTIONS)
    response.set_cookie("refresh_token", refresh_token, **COOKIE_OPTIONS)
    return response

@app.post("/logout")
async def logout():
    response = JSONResponse({"message": "Logged out"})
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return response

@app.post("/refresh-token")
async def refresh_token(refresh_token: str = Cookie(None)):
    if not refresh_token:
        raise HTTPException(status_code=401, detail="No refresh token")

    token_res = requests.post(TOKEN_URI, data={
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'refresh_token': refresh_token,
        'grant_type': 'refresh_token',
    }).json()

    new_token = token_res.get("access_token")
    if not new_token:
        raise HTTPException(status_code=401, detail="Refresh failed")

    response = JSONResponse({"message": "Token refreshed"})
    response.set_cookie("access_token", new_token, **COOKIE_OPTIONS)
    return response

@app.get("/check-user")
def check_user(access_token: str = Cookie(None), refresh_token: str = Cookie(None)):
    if not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Missing cookies")
    
    creds = get_gmail_creds(access_token, refresh_token)
    user_email = get_user_email(creds)
    
    if not is_user_allowed(user_email):
        raise HTTPException(status_code=403, detail="User not allowed")
    
    return {"status": "ok"}

# ==================== READ EMAILS ====================

@app.post("/read-emails") # ❌❌❌
async def read_emails(access_token: str = Cookie(None), refresh_token: str = Cookie(None)):
    if not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Missing cookies")
    
    def fetch(creds):
        self_email_address = get_user_email(creds)
        service = build('gmail', 'v1', credentials=creds)
        raw_msgs = service.users().messages().list(userId='me', maxResults=NUMBER_OF_FETCHED_EMAILS).execute().get('messages', [])
        emails = []
        for msg in raw_msgs:
            detail = service.users().messages().get(userId='me', id=msg['id']).execute()
            headers = detail.get("payload", {}).get("headers", [])
            subject = next((h['value'] for h in headers if h['name'] == 'Subject'), '')
            sender = next((h['value'] for h in headers if h['name'] == 'From'), '')
            snippet = detail.get("snippet", '')
            if self_email_address not in sender and not is_msg_classified(self_email_address, msg['id']):
                emails.append({"id": msg['id'], "subject": subject, "sender": sender, "snippet": snippet})
        return emails

    try:
        creds = get_gmail_creds(access_token, refresh_token)
        emails = fetch(creds)
    except Exception:
        emails, new_token = await retry_with_refresh(fetch, refresh_token)
        response = JSONResponse(content=emails)
        response.set_cookie("access_token", new_token, **COOKIE_OPTIONS)
        return response

    self_email_address = get_user_email(creds)
    
    if len(emails) > 0:
        # Classify with Gemini
        prompt = f"""
        I have given below a list of emails from my inbox. Check if any of them are from potential leads for my {get_user_industry(self_email_address)} business.
        Your response should only be a single-line-CSV of indexes of emails that are from leads (indexes start at 0).

        Emails:
        {str(emails)}
        """
        result = client.models.generate_content(model='gemini-2.0-flash-001', contents=prompt).text.strip()
        indexes = [int(i.strip()) for i in result.split(',') if i.strip().isdigit()]
        leads = [emails[i] for i in indexes]

        for email in emails:
            if email in leads:
                store_new_classified_message(
                    user_email=self_email_address,
                    message_id=email["id"],
                    lead=True,
                    subject=email["subject"],
                    sender=email["sender"],
                    snippet=email["snippet"],
                )
            else:
                store_new_classified_message(
                    user_email=self_email_address,
                    message_id=email["id"],
                    lead=False,
                    subject=email["subject"],
                    sender=email["sender"],
                    snippet=email["snippet"],
                )

        # Label leads
        service = build('gmail', 'v1', credentials=get_gmail_creds(access_token, refresh_token))
        label_id = get_or_create_label(service, "Leads")
        for lead in leads:
            service.users().messages().modify(userId='me', id=lead['id'], body={'addLabelIds': [label_id]}).execute()
    
    leads = get_all_stored_leads(self_email_address)

    return leads

# ==================== DRAFT ====================

@app.post("/draft")
async def create_draft(request: Request, access_token: str = Cookie(None), refresh_token: str = Cookie(None)):
    if not access_token or not refresh_token:
        raise HTTPException(status_code=401, detail="Missing cookies")

    data = await request.json()
    email, msg_id = data.get("email"), data.get("msg_id")
    if not email or not msg_id:
        raise HTTPException(status_code=400, detail="Missing email data")

    # AI draft
    prompt = f"""
    You're an AI assistant. Given this email from a lead, write a professional reply. ONLY include the body.
    Email: "{email}"
    """
    reply = client.models.generate_content(model='gemini-2.0-flash-001', contents=prompt).text.strip()

    try:
        creds = get_gmail_creds(access_token, refresh_token)
        self_email_address = get_user_email(creds)
        service = build('gmail', 'v1', credentials=creds)

        original = service.users().messages().get(userId='me', id=msg_id, format='metadata').execute()
        headers = original.get('payload', {}).get('headers', [])
        sender = next((h['value'] for h in headers if h['name'].lower() == 'from'), '')
        subject = next((h['value'] for h in headers if h['name'].lower() == 'subject'), 'Re: Lead')
        thread_id = original.get('threadId')

        message_text = f"To: {sender}\nSubject: Re: {subject}\nIn-Reply-To: {msg_id}\nReferences: {msg_id}\n\n{reply}"
        raw = base64.urlsafe_b64encode(message_text.encode()).decode()

        draft = {
            'message': {
                'raw': raw,
                'threadId': thread_id,
            }
        }
        service.users().drafts().create(userId='me', body=draft).execute()

        set_message_to_drafted(self_email_address, msg_id)

    except Exception as e:
        logging.error("Draft creation failed", exc_info=True)
        raise HTTPException(status_code=500, detail="Draft creation failed")

    return reply