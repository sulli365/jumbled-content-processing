# gmail_to_markdown_pipeline.py

import os
import base64
import email
import re
import json
import logging
from datetime import datetime
import requests
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# --- CONFIGURATION ---
SCOPES = ['https://www.googleapis.com/auth/gmail.modify']
GMAIL_QUERY = 'from:sfsulliv@gmail.com label:to-process is:unread'
TRACK_FILE = "processed_links.json"
LOG_FILE = "pipeline.log"
SUPABASE_URL = os.getenv("SUPABASE_URL")  # e.g. https://yourproject.supabase.co/rest/v1/email_entries
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
TOKEN_PATH = "/data/token.json"  # this will persist across runs
CREDENTIALS_PATH = "/app/credentials.json"  # this can stay in /app or /data


# --- LOGGING SETUP ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

# --- HELPER FUNCTION TO WRITE FILES FROM ENV VARIABLES ---
def write_file_from_env(var_name, filename):
    encoded = os.getenv(var_name)
    if encoded:
        with open(filename, 'wb') as f:
            f.write(base64.b64decode(encoded))
        logging.info(f"Successfully wrote {filename} from {var_name}.")
    else:
        logging.error(f"Environment variable {var_name} is not set.")
        raise Exception(f"Environment variable {var_name} is not set.")


# --- AUTH GMAIL ---
def authenticate_gmail():
    try:
        creds = None
        if os.path.exists(TOKEN_PATH):
            creds = Credentials.from_authorized_user_file(TOKEN_PATH, SCOPES)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
                logging.info("Refreshed expired Gmail token.")
            else:
                logging.error("No valid token available and no refresh token. Re-authentication required.")
                raise Exception("Gmail credentials invalid and re-auth not possible in headless mode.")

            with open(TOKEN_PATH, 'w') as token:
                token.write(creds.to_json())
                logging.info("Updated token.json after refresh.")
        else:
            logging.info("Loaded valid Gmail credentials from token.json.")
        return build('gmail', 'v1', credentials=creds)

    except Exception as e:
        logging.error(f"Gmail authentication failed: {str(e)}")
        raise


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

# --- EXTRACT CATEGORY FROM SUBJECT ---
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

# --- LOAD TRACK FILE ---
def load_processed_links():
    if os.path.exists(TRACK_FILE):
        with open(TRACK_FILE, 'r') as f:
            return json.load(f)
    return {}

# --- SAVE TRACK FILE ---
def save_processed_links(data):
    with open(TRACK_FILE, 'w') as f:
        json.dump(data, f, indent=2)

# --- SAVE AS MARKDOWN ---
def save_markdown(subject, date, category, links):
    safe_title = re.sub(r'[^a-zA-Z0-9]+', '-', subject.lower())[:50]
    filename = f"{date[:10]}_{safe_title}.md"
    markdown_content = f"# {subject}\n\n**Date:** {date}\n\n**Category:** {category}\n\n"
    for url in links:
        markdown_content += f"- {url}\n"
    with open(filename, 'w') as f:
        f.write(markdown_content)
    return filename, markdown_content

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
            logging.info(f"Uploaded to Supabase: {subject}")
        elif response.status_code == 409:
            logging.info(f"Skipped duplicate: {subject} ({date})")
        else:
            logging.error(f"Failed Supabase upload: {response.status_code} - {response.text}")
    except Exception as e:
        logging.error(f"Exception during Supabase upload: {e}")

# --- MODIFY LABELS ---
def modify_labels(service, msg_id, remove_labels, add_labels):
    body = {
        "removeLabelIds": remove_labels,
        "addLabelIds": add_labels
    }
    service.users().messages().modify(userId='me', id=msg_id, body=body).execute()

# --- GET LABEL IDS ---
def get_label_ids(service):
    labels = service.users().labels().list(userId='me').execute().get('labels', [])
    return {label['name'].lower(): label['id'] for label in labels}

# --- MAIN LOGIC ---
def main():
    # Decode credentials and token files if running from Railway
    # These environment variables should be set in Railway as base64 encoded strings
    if os.getenv('CREDENTIALS_JSON_B64'):
        write_file_from_env('CREDENTIALS_JSON_B64', CREDENTIALS_PATH)
    if os.getenv('TOKEN_JSON_B64') and not os.path.exists(TOKEN_PATH):
        write_file_from_env('TOKEN_JSON_B64', TOKEN_PATH)

        
    service = authenticate_gmail()
    label_ids = get_label_ids(service)
    messages = fetch_emails(service)
    processed_links = load_processed_links()

    for msg in messages:
        subject, date, body = parse_email(service, msg['id'])
        category = extract_category(subject)
        key = f"{date[:10]}_{subject}"

        links = extract_links(body)
        if key not in processed_links:
            processed_links[key] = []

        new_links = [url for url in links if url not in processed_links[key]]
        if not new_links:
            logging.info(f"No new links for '{subject}' on {date[:10]}")
            continue

        processed_links[key].extend(new_links)

        filename, markdown = save_markdown(subject, date, category, new_links)
        logging.info(f"Saved markdown file: {filename}")

        upload_to_supabase(subject, category, date, markdown, new_links)

        remove = [label_ids.get('to-process')]
        add = [label_ids.get(category.lower(), label_ids.get('other'))]
        modify_labels(service, msg['id'], remove, add)
        logging.info(f"Updated labels for message: {subject} → {category}")

    save_processed_links(processed_links)

if __name__ == '__main__':
    main()
