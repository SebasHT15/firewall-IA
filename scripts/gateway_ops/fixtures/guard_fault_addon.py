"""TEST FIXTURE. Simulates the egress guard's listener stopping while the gateway runs, which no
external signal can do because the guard shares the mitmdump process. When the file named by
FIREWALL_GUARD_FAULT_FILE appears, it is removed and the guard is closed once. It injects the failure
only: detecting it and restarting the guard is the gateway's own job."""
import asyncio
import os

from mitmproxy import ctx


class GuardFault:
    def __init__(self):
        self.path = os.environ.get("FIREWALL_GUARD_FAULT_FILE")
        self.task = None

    def running(self):
        if self.path:
            self.task = asyncio.ensure_future(self.watch())

    async def watch(self):
        while True:
            if os.path.exists(self.path):
                os.unlink(self.path)
                gateway = ctx.master.addons.get("cascadefirewallgateway")
                await gateway.cascade.guard.aclose()
            await asyncio.sleep(0.05)


addons = [GuardFault()]
