#!/usr/bin/env python3
"""
send_mail.py

Usage examples:
  # basic send (no encryption)
  python send_mail.py --from EMAIL --to target@example.com --subject "Hello" --message-file message.txt --attachment image.jpg

  # encrypt attachments but not body (you must share the key separately)
  python send_mail.py --from EMAIL --to target@example.com --subject "Hello" --message-file message.txt --attachment secret.pdf --encrypt-attachments

  # encrypt both body and attachments (attaches encrypted message as message.enc)
  python send_mail.py --from EMAIL --to target@example.com --subject "Encrypted" --message-file message.txt --attachment secret.pdf --encrypt-all

Important:
- Set environment variables EMAIL_PASSWORD (Gmail app password) and optionally FERNET_KEY.
- For Gmail: enable 2FA and create an App Password (do not use your main Google password).
"""
from __future__ import annotations

import os
import sys
import argparse
import mimetypes
import logging
from email import encoders
from email.utils import formataddr
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
import smtplib
from cryptography.fernet import Fernet
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present (optional convenience)
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 465


def get_fernet(key: str | None) -> Fernet | None:
    if not key:
        return None
    try:
        return Fernet(key)
    except Exception:
        logging.error("Invalid FERNET_KEY. It must be a valid 32-byte base64 urlsafe key.")
        return None


def read_file_bytes(path: Path) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def make_attachment_from_bytes(data: bytes, filename: str, maintype: str = "application", subtype: str = "octet-stream") -> MIMEBase:
    part = MIMEBase(maintype, subtype)
    part.set_payload(data)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", f'attachment; filename="{filename}"')
    return part


def attach_file(msg: MIMEMultipart, filepath: Path, encryptor: Fernet | None, encrypt_attachments: bool):
    """
    Attach a file to msg. If encrypt_attachments is True and encryptor provided,
    attach encrypted bytes and append .enc to filename.
    """
    if not filepath.exists():
        logging.warning("Attachment '%s' not found; skipping.", filepath)
        return

    ctype, encoding = mimetypes.guess_type(str(filepath))
    if ctype is None:
        ctype = "application/octet-stream"
    maintype, subtype = ctype.split("/", 1)

    data = read_file_bytes(filepath)

    if encryptor and encrypt_attachments:
        data = encryptor.encrypt(data)
        filename = filepath.name + ".enc"
        # Attach as generic octet-stream
        part = make_attachment_from_bytes(data, filename)
        msg.attach(part)
        logging.info("Attached encrypted file: %s", filename)
        return

    # Not encrypted: use appropriate MIME class for images
    if maintype == "image":
        part = MIMEImage(data, _subtype=subtype)
        part.add_header("Content-Disposition", f'attachment; filename="{filepath.name}"')
        msg.attach(part)
    else:
        part = MIMEBase(maintype, subtype)
        part.set_payload(data)
        encoders.encode_base64(part)
        part.add_header("Content-Disposition", f'attachment; filename="{filepath.name}"')
        msg.attach(part)

    logging.info("Attached file: %s", filepath.name)


def create_message(from_name: str, from_addr: str, to_addrs: list[str], subject: str, body: str, body_encrypted: bool, encryptor: Fernet | None) -> MIMEMultipart:
    msg = MIMEMultipart()
    msg["From"] = formataddr((from_name, from_addr))
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject

    if body_encrypted and encryptor:
        # encrypt body and attach as message.enc
        encrypted_body = encryptor.encrypt(body.encode("utf-8"))
        attached = make_attachment_from_bytes(encrypted_body, "message.txt.enc")
        msg.attach(attached)
        # put a short notice in the email body telling recipient how to get the key (do NOT include key)
        notice = ("This email has an encrypted message and/or attachments. "
                  "Please obtain the decryption key from the sender (not via this email). "
                  "An encrypted payload is attached as message.txt.enc.")
        msg.attach(MIMEText(notice, "plain"))
    else:
        msg.attach(MIMEText(body, "plain"))

    return msg


def send_email(username: str, password: str, msg: MIMEMultipart, recipients: list[str]):
    logging.info("Connecting to SMTP server %s:%s", SMTP_HOST, SMTP_PORT)
    try:
        with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT) as server:
            server.ehlo()
            server.login(username, password)
            server.sendmail(username, recipients, msg.as_string())
        logging.info("Email sent to %s", ", ".join(recipients))
    except smtplib.SMTPAuthenticationError:
        logging.error("Authentication failed. Check your EMAIL_PASSWORD (app password for Gmail).")
        raise
    except Exception as e:
        logging.exception("Failed to send email: %s", e)
        raise


def main():
    parser = argparse.ArgumentParser(description="Send email with optional encryption of body/attachments.")
    parser.add_argument("--from", dest="from_addr", required=True, help="Sender email address")
    parser.add_argument("--from-name", dest="from_name", default="", help="Sender name")
    parser.add_argument("--to", dest="to", required=True, help="Comma-separated list of recipient emails")
    parser.add_argument("--subject", dest="subject", default="(no subject)")
    parser.add_argument("--message-file", dest="message_file", required=True, help="Path to plaintext message file")
    parser.add_argument("--attachment", dest="attachment", action="append", help="File to attach (can repeat)")
    parser.add_argument("--encrypt-attachments", dest="encrypt_attachments", action="store_true", help="Encrypt attachments before sending (FERNET_KEY required)")
    parser.add_argument("--encrypt-body", dest="encrypt_body", action="store_true", help="Encrypt message body and attach as message.txt.enc (FERNET_KEY required)")
    parser.add_argument("--fernet-key", dest="fernet_key", default=os.environ.get("FERNET_KEY"), help="Optional Fernet key (base64 urlsafe). If omitted and encryption flags used, a key will be generated and printed (not recommended for production).")
    parser.add_argument("--password", dest="password", default=os.environ.get("EMAIL_PASSWORD"), help="SMTP password/app-password (recommended to set in env var EMAIL_PASSWORD)")
    args = parser.parse_args()

    # Validate recipients
    to_addrs = [addr.strip() for addr in args.to.split(",") if addr.strip()]
    if not to_addrs:
        logging.error("No recipient addresses provided.")
        sys.exit(1)

    if not args.password:
        logging.error("No SMTP password provided. Set EMAIL_PASSWORD env var or pass --password.")
        sys.exit(1)

    # Read message body
    message_path = Path(args.message_file)
    if not message_path.exists():
        logging.error("Message file not found: %s", message_path)
        sys.exit(1)
    body_text = message_path.read_text(encoding="utf-8")

    # Setup Fernet if needed
    encrypt_requested = args.encrypt_body or args.encrypt_attachments
    encryptor = None
    if encrypt_requested:
        if not args.fernet_key:
            # generate a key and warn the user: if generated here, and you don't record it, you can't decrypt later
            generated_key = Fernet.generate_key().decode()
            logging.warning("FERNET_KEY not provided. Generated one for this run. Save it securely! Key:\n%s", generated_key)
            encryptor = Fernet(generated_key.encode())
        else:
            encryptor = get_fernet(args.fernet_key)
            if encryptor is None:
                logging.error("Invalid FERNET_KEY; aborting.")
                sys.exit(1)

    # Create message (body will be encrypted/attached if requested)
    msg = create_message(args.from_name or args.from_addr, args.from_addr, to_addrs, args.subject, body_text, args.encrypt_body, encryptor)

    # Attach files
    if args.attachment:
        for path_str in args.attachment:
            attach_file(msg, Path(path_str), encryptor, args.encrypt_attachments)

    # Send
    send_email(args.from_addr, args.password, msg, to_addrs)


if __name__ == "__main__":
    main()
