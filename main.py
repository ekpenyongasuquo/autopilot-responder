import os
from dotenv import load_dotenv

# This loads the .env file you just updated
load_dotenv()

client_id = os.getenv("AUTH0_CLIENT_ID")
user_id = os.getenv("AUTH0_USER_ID")

print("--- Auth0 Connection Check ---")
if client_id and user_id:
    print(f"✅ Found Client ID: {client_id[:5]}***")
    print(f"✅ Found User ID: {user_id}")
    print("------------------------------")
    print("🚀 Ready to test the notification!")
else:
    print("❌ Error: Missing credentials in .env file.")
    print(f"Current Client ID: {client_id}")
    print(f"Current User ID: {user_id}")