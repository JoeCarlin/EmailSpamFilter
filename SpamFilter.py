import imaplib
import email
import hashlib
import re
from email.header import decode_header
from bs4 import BeautifulSoup
import requests

def generate_email_hash(email_content):
    """
    Generate a hash of the email content.

    Args:
        email_content (str): The content of the email.

    Returns:
        str: The hash of the email content.
    """
    return hashlib.md5(email_content.encode()).hexdigest()

def is_known_spam(email_hash, spam_hashes):
    """
    Check if the email hash matches any known spam hashes.

    Args:
        email_hash (str): The hash of the email content.
        spam_hashes (set): A set of known spam hashes.

    Returns:
        bool: True if the email hash is in the set of known spam hashes, False otherwise.
    """
    return email_hash in spam_hashes

def extract_links(email_content):
    """
    Extract links from the email content.

    Args:
        email_content (str): The content of the email.

    Returns:
        list: A list of links found in the email content.
    """
    soup = BeautifulSoup(email_content, "html.parser")
    return [a['href'] for a in soup.find_all('a', href=True)]

def is_trustworthy_link(link):
    """
    Check if the domain name in the link possesses a digital certificate.

    Args:
        link (str): The URL to check.

    Returns:
        bool: True if the link is trustworthy, False otherwise.
    """
    try:
        response = requests.get(link, timeout=5)
        return response.url.startswith("https")
    except requests.RequestException:
        return False

def has_unsubscribe_link(email_content):
    """
    Check if the email contains an unsubscribe link.

    Args:
        email_content (str): The content of the email.

    Returns:
        bool: True if the email contains an unsubscribe link, False otherwise.
    """
    return "unsubscribe" in email_content.lower()

def fetch_emails(username, password):
    """
    Fetch emails from Gmail.

    Args:
        username (str): The email address to login.
        password (str): The app-specific password for the email account.

    Returns:
        list: A list of tuples containing the subject, sender, and body of each email.
    """
    imap = imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(username, password)
    imap.select("inbox")
    status, messages = imap.search(None, "ALL")
    email_ids = messages[0].split()
    emails = []
    for email_id in email_ids[-10:]:
        status, msg_data = imap.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                from_ = msg.get("From")
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        content_disposition = str(part.get("Content-Disposition"))
                        try:
                            body = part.get_payload(decode=True).decode()
                        except:
                            pass
                        if content_type == "text/plain" and "attachment" not in content_disposition:
                            emails.append((subject, from_, body))
                else:
                    content_type = msg.get_content_type()
                    body = msg.get_payload(decode=True).decode()
                    if content_type == "text/plain":
                        emails.append((subject, from_, body))
    imap.close()
    imap.logout()
    return emails

def classify_emails(username, password, spam_hashes):
    """
    Classify emails as spam or not spam.

    Args:
        username (str): The email address to login.
        password (str): The app-specific password for the email account.
        spam_hashes (set): A set of known spam hashes.
    """
    emails = fetch_emails(username, password)
    for subject, from_, body in emails:
        email_hash = generate_email_hash(body)
        if is_known_spam(email_hash, spam_hashes):
            print(f"Spam: {subject} from {from_}")
            continue
        links = extract_links(body)
        if any(not is_trustworthy_link(link) for link in links):
            print(f"Spam: {subject} from {from_}")
            continue
        if not has_unsubscribe_link(body):
            print(f"Spam: {subject} from {from_}")
            continue
        print(f"Not Spam: {subject} from {from_}")

if __name__ == "__main__":
    username = 'joecarlin30@gmail.com'
    password = 'xvzc uxri rdfv msvg'
    spam_hashes = set()  # Add known spam hashes here
    classify_emails(username, password, spam_hashes)