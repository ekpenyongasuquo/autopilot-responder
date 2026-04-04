# AutoPilot Responder: Zero-Trust AI Gateway
**Built for the "Authorized to Act: Auth0 for AI Agents" Hackathon**

## 🚀 Overview
AutoPilot Responder is a security gateway designed to solve the "Secret Zero" problem for autonomous AI agents. Instead of giving an AI agent permanent, long-lived API keys to sensitive infrastructure (like DigitalOcean), this project implements a **Human-in-the-Loop** architecture. 

The agent must request permission via **Auth0 CIBA** (Client Initiated Backchannel Authentication). Only after a human approves the action via a biometric push notification (Okta Verify) does the agent receive a scoped, short-lived token from the **Auth0 Token Vault**.

## 🛠️ Key Features & Tech Stack
- **Auth0 CIBA:** Out-of-band biometric authentication for non-interactive agents.
- **Auth0 Token Vault:** Secure exchange of Auth0 session tokens for third-party (DigitalOcean) resource tokens.
- **Python (Asyncio/Aiohttp):** High-performance polling and request handling.
- **Zero-Trust Security:** No static API keys are stored within the agent's environment.

## 📂 Project Structure
- `test_ciba.py`: The core logic containing the CIBA request and the **Token Vault Exchange**.
- `.env.example`: Template for required environment variables.
- `requirements.txt`: Python dependencies.

## ⚙️ Setup & Installation
1. **Clone the repository:**
   ```bash
   git clone [https://github.com/ekpenyongasuquo/autopilot-responder.git](https://github.com/ekpenyongasuquo/autopilot-responder.git)
   cd autopilot-responder