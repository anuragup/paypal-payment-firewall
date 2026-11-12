"""Run this to check the proxy end to end against the PayPal sandbox."""
import asyncio
import os

from fastmcp import Client

from proxy import build_proxy


async def main():
    proxy = build_proxy(os.getenv("TEST_FAKE_TOKEN"))
    async with Client(proxy) as client:
        tools = await client.list_tools()
        print(f"1. Proxy lists {len(tools)} PayPal tools, e.g. "
              f"{', '.join(t.name for t in tools[:5])}")

        print("2. Read-only call through the proxy (list_invoices):")
        try:
            result = await client.call_tool("list_invoices", {})
            print("   OK:", str(result.content[0].text)[:300])
        except Exception as exc:
            print("   FAILED:", exc)

        print("3. Over-limit refund should be blocked before reaching PayPal:")
        try:
            await client.call_tool(
                "create_refund",
                {"capture_id": "TEST", "amount": {"value": "500.00", "currency_code": "USD"}},
            )
            print("   NOT BLOCKED - firewall rule did not fire")
        except Exception as exc:
            print("   BLOCKED:", exc)


asyncio.run(main())
