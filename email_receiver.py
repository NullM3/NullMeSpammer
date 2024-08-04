# email_receiver.py
import imaplib
import email
from email.header import decode_header
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def receive_email(imap_server, imap_port, email_address, password, use_starttls, key_file=None, cert_file=None):
    emails = []
    try:
        logging.info(f"Connecting to IMAP server {imap_server}")
        if use_starttls:
            mail = imaplib.IMAP4(imap_server, imap_port)
            mail.starttls(keyfile=key_file, certfile=cert_file)
        else:
            mail = imaplib.IMAP4_SSL(imap_server, imap_port, keyfile=key_file, certfile=cert_file)
        
        mail.login(email_address, password)
        mail.select("inbox")
        status, messages = mail.search(None, "ALL")
        email_ids = messages[0].split()

        logging.info(f"Fetching emails for {email_address}")
        for email_id in email_ids:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            msg = email.message_from_bytes(msg_data[0][1])
            subject, encoding = decode_header(msg["Subject"])[0]

            if isinstance(subject, bytes):
                subject = subject.decode(encoding if encoding else "utf-8")

            email_content = f"Subject: {subject}\n"

            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))

                    if "attachment" in content_disposition:
                        continue

                    if content_type == "text/plain" or content_type == "text/html":
                        body = part.get_payload(decode=True).decode()
                        email_content += f"Body: {body}\n"
            
            emails.append(email_content)

        mail.logout()
        logging.info(f"Emails fetched successfully for {email_address}")
        return True, emails

    except imaplib.IMAP4.error:
        logging.error(f"Authentication error when fetching emails for {email_address}")
        return False, "Authentication error. Please check your email and password."
    except Exception as e:
        logging.error(f"Failed to fetch emails for {email_address}: {e}")
        return False, str(e)
