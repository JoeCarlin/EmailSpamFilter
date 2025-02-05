import hashlib
import re
import ssl
import socket
import os
from exchangelib import Credentials, Account, DELEGATE

# List of known spam email hashes (consider making this dynamic)
spam_hashes = [
    "hash1", "hash2", "hash3", "hash4", "hash5",
    "hash6", "hash7", "hash8", "hash9", "hash10"
]

# Generate a SHA-256 hash of the email content
def generate_hash(email_content):
    return hashlib.sha256(email_content.encode()).hexdigest()

# Check if the email content matches any known spam hashes
def check_signature(email_content):
    email_hash = generate_hash(email_content)
    return email_hash in spam_hashes

# Extract all hyperlinks from the email content
def extract_links(email_content):
    return re.findall(r'(https?://\S+)', email_content)

# Check if the domain has a valid SSL certificate
def check_certificate(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            s.getpeercert()
        return True
    except Exception:
        return False

# Check if any hyperlinks in the email content have invalid SSL certificates
def check_hyperlinks(email_content):
    links = extract_links(email_content)
    for link in links:
        domain = re.findall(r'https?://([^/]+)', link)[0]
        if not check_certificate(domain):
            return True
    return False

# Check if the email content lacks an unsubscribe link
def check_unsubscribe_link(email_content):
    unsubscribe_patterns = ["unsubscribe", "opt-out", "manage preferences", "click here to unsubscribe"]
    return not any(pattern.lower() in email_content.lower() for pattern in unsubscribe_patterns)

# Classify the email as "Spam" or "Not Spam" based on various checks
def classify_email(email_content):
    if check_signature(email_content):
        return "Spam"
    if check_hyperlinks(email_content):
        return "Spam"
    if check_unsubscribe_link(email_content):
        return "Spam"
    return "Not Spam"

# Fetch emails from the Outlook inbox
def fetch_emails():
    # Replace with your Outlook email and password
    email = 'JoeCarlin30@outlook.com'
    password = 'Jncarlin98720!'

    credentials = Credentials(email, password)
    account = Account(email, credentials=credentials, autodiscover=True, access_type=DELEGATE)

    for item in account.inbox.all().order_by('-datetime_received')[:10]:
        email_content = item.body
        result = classify_email(email_content)
        print(f"Email ID: {item.message_id} - {result}")

if __name__ == "__main__":
    fetch_emails()