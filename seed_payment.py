"""Create one real sandbox payment, through the firewall, so there is
something to refund later.

Step A:  python seed_payment.py            -> creates a $40 order, prints a link
         (open the link, log in as your sandbox PERSONAL account, approve)
Step B:  python seed_payment.py ORDER_ID   -> captures the payment, prints the capture ID
"""
import asyncio
import json
import re
import sys

from fastmcp import Client

from proxy import build_proxy


def text_of(result) -> str:
    return "\n".join(getattr(part, "text", "") for part in result.content)


async def main():
    async with Client(build_proxy()) as client:
        if len(sys.argv) == 1:
            result = await client.call_tool(
                "create_order",
                {
                    "currencyCode": "USD",
                    "items": [
                        {
                            "name": "Test widget",
                            "quantity": 1,
                            "itemCost": 40,
                            "itemTotal": 40,
                        }
                    ],
                    "returnUrl": "https://example.com/return",
                    "cancelUrl": "https://example.com/cancel",
                },
            )
            out = text_of(result)
            print(out)
            links = re.findall(r"https://www\.sandbox\.paypal\.com/[^\s\"\\]+", out)
            order_ids = re.findall(r'"id"\s*:\s*"([A-Z0-9]{17,32})"', out)
            print("\n--- next ---")
            if links:
                print("1. Open this link and approve as your sandbox PERSONAL account:")
                print("  ", links[0])
            if order_ids:
                print(f"2. Then run:  python seed_payment.py {order_ids[0]}")
        else:
            order_id = sys.argv[1]
            print(text_of(await client.call_tool("pay_order", {"id": order_id})))
            details = text_of(await client.call_tool("get_order", {"id": order_id}))
            captures = re.findall(r'"captures"\s*:\s*\[\s*\{[^\]]*?"id"\s*:\s*"([A-Za-z0-9_-]{15,32})"', details, re.S)
            print("\n--- result ---")
            if captures:
                print("Capture ID (save this, refunds need it):", captures[0])
            else:
                print("Could not find a capture ID automatically. Full order details:")
                print(details)


asyncio.run(main())
