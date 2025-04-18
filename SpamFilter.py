import imaplib
import email
import hashlib
import csv
from email.header import decode_header
from bs4 import BeautifulSoup
import requests
import logging

# Set up logging for better debugging and progress tracking
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def generate_email_hash(email_content):
    """
    Generate a hash for the given email content.
    
    Args:
        email_content (str): The content of the email.
    
    Returns:
        str: The MD5 hash of the email content.
    """
    return hashlib.md5(email_content.encode()).hexdigest()

def is_known_spam(email_hash, spam_hashes):
    """
    Check if the email hash is in the list of known spam hashes.
    
    Args:
        email_hash (str): The hash of the email content.
        spam_hashes (set): A set of known spam hashes.
    
    Returns:
        bool: True if the email is known spam, False otherwise.
    """
    return email_hash in spam_hashes

def extract_links(email_content):
    """
    Extract all links from the email content.
    
    Args:
        email_content (str): The content of the email.
    
    Returns:
        list: A list of URLs found in the email content.
    """
    soup = BeautifulSoup(email_content, "html.parser")
    return [a['href'] for a in soup.find_all('a', href=True)]

def is_trustworthy_link(link):
    """
    Check if the link is trustworthy by verifying if it starts with "https".
    
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

def link_analysis_score(links):
    """
    Score email based on the ratio of trustworthy links.

    Args:
        links (list): List of URLs.

    Returns:
        float: Ratio of trustworthy links (0 to 1).
    """
    if not links:
        return 1.0  # No links = no threat
    good_links = sum(is_trustworthy_link(link) for link in links)
    return good_links / len(links)

def smart_unsubscribe_check(email_content):
    """
    Look for actual unsubscribe links (not just the word).
    
    Args:
        email_content (str): The HTML content of the email.
    
    Returns:
        bool: True if an unsubscribe link is found.
    """
    soup = BeautifulSoup(email_content, "html.parser")
    for a in soup.find_all("a", href=True):
        if "unsubscribe" in a.text.lower() or "unsubscribe" in a['href'].lower():
            return True
    return False

def has_unsubscribe_link(email_content):
    """
    Check if the email content contains an unsubscribe link.
    
    Args:
        email_content (str): The content of the email.
    
    Returns:
        bool: True if the email contains an unsubscribe link, False otherwise.
    """
    return smart_unsubscribe_check(email_content)

def contains_threat_keywords(email_content):
    """
    Check if the email content contains any threat keywords.
    
    Args:
        email_content (str): The content of the email.
    
    Returns:
        bool: True if the email contains threat keywords, False otherwise.
    """
    threat_keywords = ["urgent", "immediate action", "password", "account", "security"]
    return any(keyword in email_content.lower() for keyword in threat_keywords)

def fetch_emails(username, password, mailbox="[Gmail]/Spam"):
    """
    Fetch emails from the specified mailbox.
    
    Args:
        username (str): The email account username.
        password (str): The email account password.
        mailbox (str): The mailbox to fetch emails from.
    
    Returns:
        list: A list of tuples containing the subject, sender, and body of each email.
    """
    imap = imaplib.IMAP4_SSL('imap.gmail.com')
    imap.login(username, password)
    imap.select(mailbox)
    status, messages = imap.search(None, "ALL")
    email_ids = messages[0].split()
    emails = []
    
    # Fetch the last 100 emails
    for email_id in email_ids[-50:]:
        status, msg_data = imap.fetch(email_id, "(RFC822)")
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject = msg["Subject"]
                if subject is None:
                    subject = "No Subject"
                else:
                    subject, encoding = decode_header(subject)[0]
                    if isinstance(subject, bytes):
                        if encoding == 'unknown-8bit':
                            subject = subject.decode('latin1')
                        else:
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
    
def classify_emails(username, password, spam_hashes, output_csv):
    """
    Classify emails into Not Spam, Spam, and Threats categories and write to a CSV file.
    
    Args:
        username (str): The email account username.
        password (str): The email account password.
        spam_hashes (set): A set of known spam hashes.
        output_csv (str): The path to the output CSV file.
    """
    logging.info("Fetching emails for classification...")
    emails = fetch_emails(username, password)
    
    not_spam_count = 0
    spam_count = 0
    threats_count = 0
    
    with open(output_csv, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        
        # Write Not Spam section
        writer.writerow(["Not Spam"])
        writer.writerow(["Subject", "From"])
        for subject, from_, body in emails:
            email_hash = generate_email_hash(body)
            if not is_known_spam(email_hash, spam_hashes):
                links = extract_links(body)
                link_score = link_analysis_score(links)
                if link_score > 0.7 and has_unsubscribe_link(body):  # Updated threshold
                    writer.writerow([subject, from_])
                    not_spam_count += 1
        
        # Write Spam section
        writer.writerow([])
        writer.writerow(["Spam"])
        writer.writerow(["Subject", "From"])
        for subject, from_, body in emails:
            email_hash = generate_email_hash(body)
            if is_known_spam(email_hash, spam_hashes) or link_analysis_score(extract_links(body)) < 0.5 or not has_unsubscribe_link(body):
                writer.writerow([subject, from_])
                spam_count += 1
        
        # Write Threats section
        writer.writerow([])
        writer.writerow(["Threats"])
        writer.writerow(["Subject", "From"])
        for subject, from_, body in emails:
            if contains_threat_keywords(body):
                writer.writerow([subject, from_])
                threats_count += 1
        
        # Write counts
        writer.writerow([])
        writer.writerow(["Counts"])
        writer.writerow(["Not Spam", not_spam_count])
        writer.writerow(["Spam", spam_count])
        writer.writerow(["Threats", threats_count])
        
    logging.info("Classification complete. Output written to: " + output_csv)

if __name__ == "__main__":
    username = 'JoeCarlin30@gmail.com'  # Replace with your email address
    password = 'xvzc uxri rdfv msvg'  # Replace with your app-specific password in order to connect
    spam_hashes = set()  # Add known spam hashes here
    output_csv = 'emails.csv'
    classify_emails(username, password, spam_hashes, output_csv)