# gmail_to_markdown_pipeline.py

import os
import base64
import email
import re
from datetime import datetime
import requests
from bs4 import BeautifulSoup
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# --- CONFIGURATION ---
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
GMAIL_QUERY = 'from:me label:to-process is:unread'
OUTPUT_DIR = "output_md_files"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

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
    results = service.users().messages().list(userId='me', q=GMAIL_QUERY).execute()
    messages = results.get('messages', [])
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
                body = base64.urlsafe_b64decode(data).decode('utf-8')
                break
    return subject, date, body

# --- EXTRACT LINKS ---
def extract_links(text):
    return re.findall(r'(https?://\S+)', text)

# --- FETCH PAGE TEXT ---
def fetch_page_text(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.text, 'html.parser')
        return soup.get_text(separator=' ', strip=True)[:4000]  # truncate to fit token limit
    except Exception as e:
        return f"[Error fetching {url}]: {e}"

# --- SUMMARIZE TEXT USING OPENROUTER ---
def summarize_text(text):
    try:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "google/gemini-2.0-flash-001",  # or another OpenRouter-supported model
            "messages": [
                {"role": "system", "content": "Summarize the following webpage or email content."},
                {"role": "user", "content": text}
            ],
            "max_tokens": 300
        }
        response = requests.post(OPENROUTER_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception as e:
        return f"[Error summarizing content]: {e}"

# --- SAVE AS MARKDOWN ---
def save_markdown(subject, date, links, summaries):
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    safe_title = re.sub(r'[^a-zA-Z0-9]+', '-', subject.lower())[:50]
    filename = f"{date[:10]}_{safe_title}.md"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, 'w') as f:
        f.write(f"# {subject}\n\n")
        f.write(f"**Date:** {date}\n\n")
        for url, summary in zip(links, summaries):
            f.write(f"## {url}\n\n")
            f.write(f"{summary}\n\n")
    return path

# --- MAIN LOGIC ---
def main():
    service = authenticate_gmail()
    messages = fetch_emails(service)
    for msg in messages:
        subject, date, body = parse_email(service, msg['id'])
        links = extract_links(body)
        summaries = []
        for url in links:
            text = fetch_page_text(url)
            summary = summarize_text(text)
            summaries.append(summary)
        save_markdown(subject, date, links, summaries)

if __name__ == '__main__':
    main()
