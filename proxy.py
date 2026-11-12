"""Payment firewall: a drop-in proxy in front of PayPal's MCP server.

Point any MCP-capable agent at this instead of PayPal's server. Every tool
call is checked against policy.yaml and written to the audit log before it
can reach PayPal.
"""
import os
import sys

from fastmcp.exceptions import ToolError
from fastmcp.server import create_proxy
from fastmcp.server.middleware import Middleware, MiddlewareContext

import policy
from paypal_auth import get_access_token


def log(line: str) -> None:
    print(f"[firewall] {line}", file=sys.stderr)


class FirewallMiddleware(Middleware):
    async def on_call_tool(self, context: MiddlewareContext, call_next):
        tool = context.message.name
        args = context.message.arguments or {}
        decision = policy.evaluate(tool, args)
        log(f"{decision.verdict:5} {tool}: {decision.reason}")

        if decision.verdict == policy.DENY:
            raise ToolError(f"Blocked by payment firewall. {decision.reason}")
        if decision.verdict == policy.HOLD:
            raise ToolError(f"Held by payment firewall. {decision.reason}")

        # Forward the request in the exact shape PayPal expects.
        context.message.arguments = policy.normalise(tool, args)

        def give_back_approval():
            # The call never succeeded, so the human's approval was not spent.
            if decision.approval_id is not None:
                policy.set_status(decision.approval_id, "approved")

        try:
            result = await call_next(context)
        except Exception as exc:
            policy.set_status(decision.log_id, "failed", str(exc)[:500])
            give_back_approval()
            raise
        text = " ".join(getattr(p, "text", "") for p in getattr(result, "content", []) or [])
        failed = '"ok":false' in text.replace(" ", "")
        policy.set_status(decision.log_id, "failed" if failed else "done", text[:500])
        if failed:
            give_back_approval()
        return result


def build_proxy(access_token: str | None = None):
    token = access_token or get_access_token()
    backend = {
        "mcpServers": {
            "paypal": {
                "command": "npx",
                "args": ["-y", "@paypal/mcp", "--tools=all"],
                "env": {
                    **os.environ,
                    "PAYPAL_ACCESS_TOKEN": token,
                    "PAYPAL_ENVIRONMENT": os.getenv("PAYPAL_ENVIRONMENT", "SANDBOX"),
                },
            }
        }
    }
    proxy = create_proxy(backend, name="PayPal Payment Firewall", mode="legacy")
    proxy.add_middleware(FirewallMiddleware())
    return proxy


if __name__ == "__main__":
    build_proxy().run()  # stdio, so any MCP client can launch it
