"""Force PayPal to issue a fresh access token.

PayPal hands back the same cached token for hours, and that token keeps the
permissions the app had when it was issued. After changing an app's features
in the dashboard, run this once so the next token picks up the new ones.
"""
import base64
import os
import urllib.error
import urllib.parse
import urllib.request

from paypal_auth import BASE, get_access_token

env = os.getenv("PAYPAL_ENVIRONMENT", "SANDBOX").upper()
old = get_access_token()
basic = base64.b64encode(
    f"{os.environ['PAYPAL_CLIENT_ID']}:{os.environ['PAYPAL_SECRET']}".encode()
).decode()
req = urllib.request.Request(
    f"{BASE[env]}/v1/oauth2/token/terminate",
    data=urllib.parse.urlencode({"token": old, "token_type_hint": "ACCESS_TOKEN"}).encode(),
    headers={
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
    },
)
try:
    urllib.request.urlopen(req, timeout=30)
    print("Old token ended.")
except urllib.error.HTTPError as exc:
    print(f"PayPal refused to end the old token (HTTP {exc.code}): {exc.read().decode()[:200]}")

new = get_access_token()
print("New token issued." if new != old else "PayPal returned the same token again; wait a few minutes and retry.")
