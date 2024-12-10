from random import shuffle
from typing import defaultdict
from cryptography.fernet import Fernet
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import os.path
import base64

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import test

# If modifying these SCOPES, delete the file token.json.
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]
EMAIL_ADDRESSES = {
    "Gosia": "broguski1@gmail.com",
    "Krzychu": "broguski1@gmail.com",
    "Babcia": "broguski1@gmail.com",
    "Dziadek": "broguski1@gmail.com",
    "Agusia": "broguski1@gmail.com",
    "Kornel": "broguski1@gmail.com",
    "Bartek": "broguski1@gmail.com",
}


def authenticate_gmail():
    """Authenticates the user and returns the Gmail API service."""
    creds = None
    # The file token.json stores the user's access and refresh tokens.
    if os.path.exists("token.json"):
        creds = Credentials.from_authorized_user_file("token.json", SCOPES)
    # If no valid credentials are available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file("credentials.json", SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run.
        with open("token.json", "w") as token:
            token.write(creds.to_json())

    service = build("gmail", "v1", credentials=creds)
    return service


def create_message(sender, to, subject, message_text):
    """Creates a MIME message for email."""
    message = MIMEMultipart()
    message["To"] = to
    message["From"] = sender
    message["Subject"] = subject

    message.attach(MIMEText(message_text, "plain"))

    raw_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
    return {"raw": raw_message}


def send_email(service, user_id, message):
    """Sends an email message."""
    try:
        sent_message = (
            service.users().messages().send(userId=user_id, body=message).execute()
        )
        print(f'Email sent successfully. Message Id: {sent_message["id"]}\n')
        return sent_message
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def generate_key() -> str:
    return Fernet.generate_key().decode()


def encrypt_string(s: str, key: str) -> str:
    f = Fernet(key.encode())
    return f.encrypt(s.encode()).decode()


def decrypt_string(s: str, key: str) -> str:
    f = Fernet(key.encode())
    return f.decrypt(s.encode()).decode()


def losuj():
    osoby = ["Gosia", "Krzychu", "Babcia", "Dziadek", "Agusia", "Kornel", "Bartek"]
    pula = osoby.copy()
    pary = defaultdict(str)
    klucze = {osoba: generate_key() for osoba in osoby}
    shuffle(pula)
    for idx, osoba in enumerate(osoby):
        wylosowana = pula.pop()
        if wylosowana == osoba:
            pula.insert(0, wylosowana)
            wylosowana = pula.pop()
        zaszyfrowana_wylosowana = encrypt_string(wylosowana, klucze[osoba])
        pary[osoba] = zaszyfrowana_wylosowana
    return pary, klucze


# for every person in osoby send an email with the encrypted name and the key
def send_emails_to_all(pary, klucze):
    # Authenticate and build the service
    service = authenticate_gmail()

    # Email details
    sender = "bozenarodzenie2024@gmail.com"  # Replace with sender's email

    for osoba, zaszyfrowana in pary.items():
        subject = f"Świąteczne losowanie 2024 - {osoba} 🎄"
        body = f"Osoba wylosowana:\n{zaszyfrowana}\n\nKlucz:\n{klucze[osoba]}"
        to = EMAIL_ADDRESSES[osoba]
        # Create the email message
        message = create_message(sender, to, subject, body)

        # Send the email
        print(f"Sending email to {osoba} ({to})...")
        send_email(service, "me", message)


def main():
    pary, klucze = losuj()
    send_emails_to_all(pary, klucze)


def test_decrypt_string():
    key = generate_key()
    s = "test"
    encrypted = encrypt_string(s, key)
    decrypted = decrypt_string(encrypted, key)
    assert decrypted == s


def test_losuj():
    pary, klucze = losuj()

    wylosowani = [
        decrypt_string(zaszyfrowana, klucze[osoba])
        for osoba, zaszyfrowana in pary.items()
    ]
    assert len(set(wylosowani)) == 7

    assert len(pary) == 7
    assert len(klucze) == 7

    for osoba, zaszyfrowana in pary.items():
        assert osoba in klucze
        assert zaszyfrowana
        assert decrypt_string(zaszyfrowana, klucze[osoba]) in pary.keys()


if __name__ == "__main__":
    main()
