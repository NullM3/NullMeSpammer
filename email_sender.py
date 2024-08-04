# email_sender.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email import encoders
import os
import logging
from jinja2 import Template
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def render_template(template_path, context):
    if not os.path.exists(template_path):
        logging.error(f"Template file not found: {template_path}")
        raise FileNotFoundError(f"Template file not found: {template_path}")
    with open(template_path) as file:
        template = Template(file.read())
    return template.render(context)

def authenticate_gmail():
    SCOPES = ['https://www.googleapis.com/auth/gmail.send']
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
    return creds

def send_email(smtp_server, smtp_port, sender_email, password, receiver_email, subject, body, use_starttls, attachment_paths, key_file=None, cert_file=None, is_html=False, inline_images=None, tracking_id=None):
    try:
        logging.info(f"Sending email to {receiver_email}")
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = receiver_email
        msg['Subject'] = subject

        if tracking_id:
            tracking_pixel = f'<img src="http://yourserver.com/track/{tracking_id}" width="1" height="1" />'
            body += tracking_pixel
        
        msg.attach(MIMEText(body, 'html' if is_html else 'plain'))

        if inline_images:
            for cid, image_path in inline_images.items():
                if os.path.isfile(image_path):
                    with open(image_path, 'rb') as img:
                        part = MIMEImage(img.read(), _subtype="jpeg")
                        part.add_header('Content-ID', f'<{cid}>')
                        part.add_header('Content-Disposition', 'inline', filename=cid)
                        msg.attach(part)
                else:
                    logging.error(f"Inline image not found: {image_path}")

        for attachment_path in attachment_paths:
            if os.path.isfile(attachment_path):
                with open(attachment_path, 'rb') as attachment:
                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(attachment.read())
                encoders.encode_base64(part)
                part.add_header('Content-Disposition', f'attachment; filename={os.path.basename(attachment_path)}')
                msg.attach(part)
            else:
                logging.error(f"Attachment not found: {attachment_path}")

        server = smtplib.SMTP(smtp_server, smtp_port)
        if use_starttls:
            server.starttls(keyfile=key_file, certfile=cert_file)
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()

        logging.info(f"Email sent to {receiver_email}")
        return True, "Email sent successfully!"

    except Exception as e:
        logging.error(f"Failed to send email to {receiver_email}: {e}")
        return False, str(e)
