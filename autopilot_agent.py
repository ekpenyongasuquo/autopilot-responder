import os
import asyncio
import aiohttp
from dotenv import load_dotenv
from token_vault import get_gmail_token_from_vault, read_gmail_emails, analyze_threat

load_dotenv()

DOMAIN = os.getenv("AUTH0_DOMAIN")
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
USER_ID = os.getenv("AUTH0_USER_ID")

async def get_auth0_access_token() -> str:
    """Get an Auth0 access token using client credentials."""
    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"https://{DOMAIN}/oauth/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "grant_type": "client_credentials",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "audience": f"https://{DOMAIN}/api/v2/"
            }
        ) as resp:
            data = await resp.json()
            return data.get("access_token")

async def send_ciba_push(threat: dict) -> bool:
    """Send CIBA push notification for threat approval."""
    hint = '{"format":"iss_sub","iss":"https://' + DOMAIN + '/","sub":"' + USER_ID + '"}'
    message = f"AutoPilot: {threat['threat_level']} threat detected. Block IP?"

    async with aiohttp.ClientSession() as session:
        async with session.post(
            f"https://{DOMAIN}/bc-authorize",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "login_hint": hint,
                "scope": "openid",
                "binding_message": "AutoPilot: Confirm threat response",
                "request_expiry": "300"
            }
        ) as resp:
            data = await resp.json()
            if "auth_req_id" not in data:
                print("CIBA failed:", data)
                return False
            auth_req_id = data["auth_req_id"]
            interval = data.get("interval", 5)
            print(f"Push sent! CHECK YOUR PHONE and approve...")

        for attempt in range(20):
            await asyncio.sleep(interval)
            print(f"Polling attempt {attempt + 1}...")
            async with session.post(
                f"https://{DOMAIN}/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "urn:openid:params:grant-type:ciba",
                    "auth_req_id": auth_req_id
                }
            ) as token_resp:
                token_data = await token_resp.json()
                if "access_token" in token_data:
                    return True
                elif token_data.get("error") == "authorization_pending":
                    print("Waiting for approval...")
                else:
                    print("Push denied or error:", token_data)
                    return False
    return False

def simulate_block_ip(ip: str):
    """Simulate blocking a malicious IP address."""
    print(f"\n🔒 SIMULATING IP BLOCK: {ip}")
    print(f"✅ Firewall rule added: DENY ALL traffic from {ip}")
    print(f"✅ Incident logged to security dashboard")
    print(f"✅ Team alert sent via Slack")

async def run_autopilot():
    print("=" * 50)
    print("🤖 AutoPilot Security Responder - STARTED")
    print("=" * 50)

    # Step 1: Get Auth0 access token
    print("\n[1/4] Getting Auth0 access token...")
    auth0_token = await get_auth0_access_token()
    if not auth0_token:
        print("Failed to get Auth0 token")
        return
    print("Auth0 token obtained!")

    # Step 2: Use Token Vault to get Gmail token
    print("\n[2/4] Fetching Gmail token from Auth0 Token Vault...")
    gmail_token = await get_gmail_token_from_vault(auth0_token)
    if not gmail_token:
        print("Could not get Gmail token from Token Vault")
        print("Make sure Google connection is set up in Auth0")
        return
    print("Gmail token retrieved via Token Vault!")

    # Step 3: Read and analyze emails
    print("\n[3/4] Reading emails and analyzing threats...")
    emails = await read_gmail_emails(gmail_token)
    if not emails:
        print("No unread emails found")
        return

    print(f"Found {len(emails)} unread emails")
    threats = [analyze_threat(email) for email in emails]
    high_threats = [t for t in threats if t["threat_level"] == "HIGH"]

    if not high_threats:
        print("No threats detected. All emails look safe.")
        return

    print(f"\n⚠️  {len(high_threats)} THREAT(S) DETECTED:")
    for threat in high_threats:
        print(f"   From: {threat['email']['from']}")
        print(f"   Subject: {threat['email']['subject']}")
        print(f"   Reason: {threat['reason']}")

    # Step 4: Send CIBA push for human approval
    print("\n[4/4] Requesting human approval via Auth0 CIBA...")
    for threat in high_threats:
        approved = await send_ciba_push(threat)
        if approved:
            print("\n✅ APPROVED! Executing response...")
            if threat["simulated_malicious_ip"]:
                simulate_block_ip(threat["simulated_malicious_ip"])
        else:
            print("\n❌ DENIED or timed out. No action taken.")

    print("\n" + "=" * 50)
    print("🤖 AutoPilot Security Responder - COMPLETE")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(run_autopilot())