# gmail_to_markdown_catchup.py

import os
import base64
import email
import re
import json
import logging
from datetime import datetime
import requests
from dotenv import load_dotenv
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# --- ENV SETUP ---
load_dotenv()

# --- CONFIGURATION ---
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
GMAIL_QUERY = 'from:sfsulliv@gmail.com'
LOG_FILE = "pipeline.log"
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# --- LOGGING SETUP ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# --- AUTH GMAIL ---
def authenticate_gmail():
    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        with open('token.json', 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

# --- FETCH EMAILS ---
def fetch_emails(service):
    messages = []
    next_page_token = None

    while True:
        response = service.users().messages().list(
            userId='me',
            q=GMAIL_QUERY,
            pageToken=next_page_token
        ).execute()

        messages.extend(response.get('messages', []))
        next_page_token = response.get('nextPageToken')
        if not next_page_token:
            break

    logging.info(f"Total emails fetched: {len(messages)}")
    return messages

# --- PARSE EMAIL ---
def parse_email(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()
    headers = {h['name']: h['value'] for h in msg['payload'].get('headers', [])}
    subject = headers.get('Subject', 'No Subject')
    date = headers.get('Date', datetime.utcnow().isoformat())

    parts = msg['payload'].get('parts', [])
    body = ''
    for part in parts:
        if part.get('mimeType') == 'text/plain':
            data = part['body'].get('data')
            if data:
                body = base64.urlsafe_b64decode(data).decode('utf-8', errors='replace')
                break
    return subject, date, body

# --- CATEGORY EXTRACTION ---
CATEGORIES = ["coding data science", "crypto", "carbon"]

def extract_category(subject):
    subject_lower = subject.lower()
    for cat in CATEGORIES:
        if subject_lower.startswith(cat):
            return cat
    return "other"

# --- EXTRACT LINKS ---
def extract_links(text):
    return re.findall(r'(https?://\S+)', text)

# --- SAVE AS MARKDOWN ---
def save_markdown(subject, date, category, links):
    safe_title = re.sub(r'[^a-zA-Z0-9]+', '-', subject.lower())[:50]
    filename = f"{date[:10]}_{safe_title}.md"
    markdown_content = f"# {subject}\n\n**Date:** {date}\n\n**Category:** {category}\n\n"
    for url in links:
        markdown_content += f"- {url}\n"
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(markdown_content)
    return filename, markdown_content

# --- CHECK FOR DUPLICATE IN SUPABASE ---
def already_in_supabase(date):
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}"
    }
    params = {
        "timestamp": f"eq.{date}"
    }
    response = requests.get(SUPABASE_URL, headers=headers, params=params)
    if response.status_code == 200:
        return len(response.json()) > 0
    return False

# --- UPLOAD TO SUPABASE ---
def upload_to_supabase(subject, category, date, markdown, links):
    headers = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "subject": subject,
        "category": category,
        "timestamp": date,
        "markdown": markdown,
        "links": links
    }
    try:
        response = requests.post(SUPABASE_URL, headers=headers, json=[payload])
        if response.status_code == 201:
            logging.info(f"✅ Uploaded: {subject}")
        elif response.status_code == 409:
            logging.info(f"⚠️ Skipped duplicate (409): {subject}")
        else:
            logging.error(f"❌ Upload failed: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"❌ Exception uploading to Supabase: {e}")

# --- MAIN ---
def main():
    service = authenticate_gmail()
    messages = fetch_emails(service)

    for msg in messages:
        subject, date, body = parse_email(service, msg['id'])
        category = extract_category(subject)
        links = extract_links(body)

        if not links:
            logging.info(f"Skipped (no links): {subject}")
            continue

        if already_in_supabase(date):
            logging.info(f"Skipped (already in Supabase): {subject} ({date})")
            continue

        filename, markdown = save_markdown(subject, date, category, links)
        logging.info(f"Saved markdown file: {filename}")
        upload_to_supabase(subject, category, date, markdown, links)

if __name__ == '__main__':
    main()
