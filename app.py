import os
import json
import httpx
import asyncio
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from dotenv import load_dotenv
from urllib.parse import urlencode

load_dotenv()

app = FastAPI(title="AutoPilot Security Responder")
templates = Jinja2Templates(directory="templates")

DOMAIN = os.getenv("AUTH0_DOMAIN")
CLIENT_ID = os.getenv("AUTH0_CLIENT_ID")
CLIENT_SECRET = os.getenv("AUTH0_CLIENT_SECRET")
USER_ID = os.getenv("AUTH0_USER_ID")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
APP_BASE_URL = "http://localhost:8000"
CALLBACK_URL = APP_BASE_URL + "/callback"
TOKEN_FILE = "google_token.json"

sessions = {}

def save_google_token(refresh_token):
    with open(TOKEN_FILE, "w") as f:
        json.dump({"refresh_token": refresh_token}, f)
    print("Google token saved to " + TOKEN_FILE)

def load_google_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as f:
            data = json.load(f)
            return data.get("refresh_token")
    return None

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    session_id = request.cookies.get("session_id")
    user = sessions.get(session_id)
    return templates.TemplateResponse(request=request, name="index.html", context={"user": user})

@app.get("/login")
async def login():
    params = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK_URL,
        "scope": "openid profile email offline_access",
        "audience": "https://" + DOMAIN + "/api/v2/",
        "connection": "google-oauth2",
        "access_type": "offline",
        "prompt": "consent"
    }
    return RedirectResponse("https://" + DOMAIN + "/authorize?" + urlencode(params))

@app.get("/callback")
async def callback(request: Request, code: str = None, error: str = None):
    if error:
        return HTMLResponse("Login error: " + error)
    if not code:
        return HTMLResponse("No code received")
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://" + DOMAIN + "/oauth/token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "redirect_uri": CALLBACK_URL
            }
        )
        tokens = token_resp.json()
        if "access_token" not in tokens:
            return HTMLResponse("Token error: " + str(tokens))
        user_resp = await client.get(
            "https://" + DOMAIN + "/userinfo",
            headers={"Authorization": "Bearer " + tokens["access_token"]}
        )
        user_info = user_resp.json()
    session_id = str(uuid.uuid4())
    sessions[session_id] = {
        "user": user_info,
        "access_token": tokens["access_token"],
        "refresh_token": tokens.get("refresh_token"),
    }
    response = RedirectResponse("/dashboard")
    response.set_cookie("session_id", session_id)
    return response

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session_id = request.cookies.get("session_id")
    session = sessions.get(session_id)
    if not session:
        return RedirectResponse("/login")
    google_connected = os.path.exists(TOKEN_FILE)
    return templates.TemplateResponse(request=request, name="dashboard.html", context={
        "user": session["user"],
        "google_connected": google_connected
    })

@app.get("/connect-google")
async def connect_google(request: Request):
    params = {
        "response_type": "code",
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": APP_BASE_URL + "/connect-callback",
        "scope": "https://www.googleapis.com/auth/gmail.readonly email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    return RedirectResponse("https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params))

@app.get("/connect-callback")
async def connect_callback(request: Request, code: str = None, error: str = None):
    if error:
        return HTMLResponse("Connect error: " + error)
    if not code:
        return HTMLResponse("No code received")
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "grant_type": "authorization_code",
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "code": code,
                "redirect_uri": APP_BASE_URL + "/connect-callback"
            }
        )
        tokens = token_resp.json()
        print("=== GOOGLE CONNECT TOKENS ===")
        print("KEYS:", list(tokens.keys()))
        print("REFRESH TOKEN:", tokens.get("refresh_token"))
        print("=============================")
        if "refresh_token" in tokens:
            save_google_token(tokens["refresh_token"])
            print("Google token saved to file!")
            return RedirectResponse("/dashboard")
        else:
            print("No refresh token! Full response:", tokens)
            return HTMLResponse("No refresh token received. Response: " + str(tokens))

async def get_google_access_token(refresh_token):
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "client_id": GOOGLE_CLIENT_ID,
                "client_secret": GOOGLE_CLIENT_SECRET,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            }
        )
        data = resp.json()
        print("=== TOKEN VAULT: Google Token Exchange ===")
        print("Keys:", list(data.keys()))
        print("Has access token:", "access_token" in data)
        if "error" in data:
            print("Error:", data)
        print("==========================================")
        return data.get("access_token")

@app.get("/scan", response_class=HTMLResponse)
async def scan_emails(request: Request):
    session_id = request.cookies.get("session_id")
    session = sessions.get(session_id)
    if not session:
        return RedirectResponse("/login")
    google_refresh_token = load_google_token()
    results = []
    if not google_refresh_token:
        return templates.TemplateResponse(request=request, name="results.html", context={
            "error": "Please connect your Google account first.",
            "results": []
        })
    print("=== TOKEN VAULT: Exchanging refresh token for Gmail access token ===")
    gmail_token = await get_google_access_token(google_refresh_token)
    if not gmail_token:
        return templates.TemplateResponse(request=request, name="results.html", context={
            "error": "Failed to get Gmail token. Please reconnect your Google account.",
            "results": []
        })
    print("Gmail token obtained via Token Vault!")
    async with httpx.AsyncClient() as client:
        msgs_resp = await client.get(
            "https://gmail.googleapis.com/gmail/v1/users/me/messages",
            headers={"Authorization": "Bearer " + gmail_token},
            params={"maxResults": 5, "q": "is:unread"}
        )
        msgs_data = msgs_resp.json()
        print("=== GMAIL RESPONSE ===")
        print(msgs_data)
        print("======================")
        messages = msgs_data.get("messages", [])
        suspicious_keywords = [
            "urgent", "password", "verify", "suspended",
            "click here", "wire transfer", "bitcoin",
            "suspicious login", "unauthorized", "confirm your identity"
        ]
        for msg in messages:
            msg_resp = await client.get(
                "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + msg["id"],
                headers={"Authorization": "Bearer " + gmail_token},
                params={"format": "metadata", "metadataHeaders": ["Subject", "From"]}
            )
            msg_data = msg_resp.json()
            headers = msg_data.get("payload", {}).get("headers", [])
            subject = next((h["value"] for h in headers if h["name"] == "Subject"), "No Subject")
            sender = next((h["value"] for h in headers if h["name"] == "From"), "Unknown")
            is_threat = any(k in subject.lower() for k in suspicious_keywords)
            results.append({
                "subject": subject,
                "from": sender,
                "threat": "HIGH" if is_threat else "LOW",
                "ip": "192.168.1.100" if is_threat else None
            })
    return templates.TemplateResponse(request=request, name="results.html", context={"results": results, "error": None})

@app.get("/approve/{ip}")
async def approve_block(request: Request, ip: str):
    session_id = request.cookies.get("session_id")
    session = sessions.get(session_id)
    if not session:
        return RedirectResponse("/login")
    hint = chr(123) + chr(34) + "format" + chr(34) + ":" + chr(34) + "iss_sub" + chr(34) + "," + chr(34) + "iss" + chr(34) + ":" + chr(34) + "https://" + DOMAIN + "/" + chr(34) + "," + chr(34) + "sub" + chr(34) + ":" + chr(34) + USER_ID + chr(34) + chr(125)
    async with httpx.AsyncClient() as client:
        ciba_resp = await client.post(
            "https://" + DOMAIN + "/bc-authorize",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "login_hint": hint,
                "scope": "openid",
                "binding_message": "AutoPilot: Block malicious IP",
                "request_expiry": "300"
            }
        )
        ciba_data = ciba_resp.json()
        if "auth_req_id" not in ciba_data:
            return HTMLResponse("CIBA error: " + str(ciba_data))
        auth_req_id = ciba_data["auth_req_id"]
        interval = ciba_data.get("interval", 5)
        for _ in range(20):
            await asyncio.sleep(interval)
            poll_resp = await client.post(
                "https://" + DOMAIN + "/oauth/token",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "client_id": CLIENT_ID,
                    "client_secret": CLIENT_SECRET,
                    "grant_type": "urn:openid:params:grant-type:ciba",
                    "auth_req_id": auth_req_id
                }
            )
            poll_data = poll_resp.json()
            if "access_token" in poll_data:
                return templates.TemplateResponse(request=request, name="blocked.html", context={"ip": ip})
            elif poll_data.get("error") != "authorization_pending":
                return HTMLResponse("Approval failed: " + str(poll_data))
    return HTMLResponse("Timed out waiting for approval")

@app.get("/logout")
async def logout(request: Request):
    session_id = request.cookies.get("session_id")
    if session_id in sessions:
        del sessions[session_id]
    response = RedirectResponse("/")
    response.delete_cookie("session_id")
    return response
