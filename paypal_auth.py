"""Exchange the sandbox client ID + secret for a short-lived access token."""
import base64
import json
import os
import urllib.parse
import urllib.request

from dotenv import load_dotenv

load_dotenv()

BASE = {
    "SANDBOX": "https://api-m.sandbox.paypal.com",
    "PRODUCTION": "https://api-m.paypal.com",
}


def get_access_token() -> str:
    env = os.getenv("PAYPAL_ENVIRONMENT", "SANDBOX").upper()
    client_id = os.environ["PAYPAL_CLIENT_ID"]
    secret = os.environ["PAYPAL_SECRET"]
    basic = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    req = urllib.request.Request(
        f"{BASE[env]}/v1/oauth2/token",
        data=urllib.parse.urlencode({"grant_type": "client_credentials"}).encode(),
        headers={
            "Authorization": f"Basic {basic}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.load(resp)["access_token"]


if __name__ == "__main__":
    token = get_access_token()
    print(f"OK: got an access token ({len(token)} characters). Credentials work.")
