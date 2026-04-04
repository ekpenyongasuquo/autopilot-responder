# AutoPilot Responder: Zero-Trust AI Gateway

An AI-powered security analyst that monitors Gmail for threats and requires human approval before taking action — built with Auth0 Token Vault and CIBA.

## How It Works

1. User logs in via Auth0 (Google OAuth)
2. Auth0 Token Vault securely stores and exchanges Gmail tokens
3. AI agent scans Gmail inbox for security threats
4. When a threat is detected, Auth0 CIBA sends a push notification to the user's phone
5. User approves or denies the action on Okta Verify
6. Only after approval does the agent execute the response (block IP, alert team)

## Features

- Auth0 Token Vault for secure Gmail token management
- Auth0 CIBA (Client-Initiated Backchannel Authentication) for human-in-the-loop approval
- Real-time Gmail threat detection
- Simulated IP blocking after phone approval
- Zero-trust architecture — AI never acts without human approval

## Tech Stack

- Python + FastAPI
- Auth0 (Token Vault + CIBA + Okta Verify)
- Gmail API
- LangChain / LangGraph

## Setup

1. Clone the repo
2. Create `.env` file with your credentials:
3. Install dependencies: `pip install -r requirements.txt`
4. Run: `python -m uvicorn app:app --reload --port 8000`
5. Open `http://localhost:8000`

## Demo Flow

1. Click Login
2. Click Connect Google Account (Token Vault)
3. Click Scan Gmail for Threats
4. Click Block IP on any HIGH threat
5. Approve on your phone via Okta Verify