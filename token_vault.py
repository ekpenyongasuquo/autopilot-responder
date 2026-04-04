import os
import aiohttp
from dotenv import load_dotenv

load_dotenv()

DOMAIN = os.getenv("AUTH0_DOMAIN")
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")

async def get_gmail_token_from_vault(auth0_access_token: str) -> str:
    """
    Use Auth0 Token Vault to retrieve a Gmail access token
    on behalf of the authenticated user.
    """
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"https://{DOMAIN}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "subject_token": auth0_access_token,
                "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
                "connection": "google-oauth2",
                "scope": "https://www.googleapis.com/auth/gmail.readonly"
            }
        ) as resp:
            data = await resp.json()
            if "access_token" in data:
                print("Token Vault: Gmail token retrieved successfully!")
                return data["access_token"]
            else:
                print("Token Vault error:", data)
                return None

async def read_gmail_emails(gmail_token: str) -> list:
    """
    Use the Gmail token from Token Vault to read latest emails.
    """
    async with aiohttp.ClientSession() as session:
        # Get list of latest messages
        async with session.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": f"Bearer {gmail_token}"},
            params={"maxResults": 5, "q": "is:unread"}
        ) as resp:
            data = await resp.json()
            messages = data.get("messages", [])

        emails = []
        for msg in messages:
            async with session.get(
                f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg['id']}",
                headers={"Authorization": f"Bearer {gmail_token}"},
                params={"format": "metadata", "metadataHeaders": ["Subject", "From"]}
            ) as resp:
                msg_data = await resp.json()
                headers = msg_data.get("payload", {}).get("headers", [])
                subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
                sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
                emails.append({"subject": subject, "from": sender, "id": msg["id"]})

        return emails

def analyze_threat(email: dict) -> dict:
    """
    Simple threat analyzer - checks for suspicious keywords.
    """
    suspicious_keywords = [
        "urgent", "password", "verify", "account suspended",
        "click here", "wire transfer", "bitcoin", "suspicious login",
        "unauthorized", "blocked", "confirm your identity"
    ]
    subject_lower = email["subject"].lower()
    sender_lower = email["from"].lower()

    is_threat = any(keyword in subject_lower for keyword in suspicious_keywords)
    threat_level = "HIGH" if is_threat else "LOW"
    reason = f"Subject contains suspicious keywords" if is_threat else "Email appears normal"

    return {
        "email": email,
        "threat_level": threat_level,
        "reason": reason,
        "simulated_malicious_ip": "192.168.1.100" if is_threat else None
    }