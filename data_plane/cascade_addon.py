"""
firewall-IA — mitmproxy entry point of the cascade gateway.

    FIREWALL_CASCADE_CONFIG=<config.yaml> .venv-dataplane/bin/mitmdump -s data_plane/cascade_addon.py ...

Use `scripts/gateway_ops/launch.py`, which validates the configuration and passes the exact options
of `gateway-framing/v1`.

`data_plane.py` stays the V4 gateway and is not modified. `CascadeFirewallGateway` subclasses it, so
the V4 path of every mode IS that code: rendering, the `/classify` call, fail-closed, the shadow
observers and the unload protection of `done()`. With `mode: V4_ONLY`, or without
`FIREWALL_CASCADE_CONFIG`, no runtime exists and the subclass only delegates.

A configuration or manifest that cannot be enabled in an authoritative mode raises while the script
loads, which makes mitmdump exit before it listens: a misconfigured gateway never runs.
"""

import logging
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import cascade as C  # noqa: E402
import cascade_gateway as CG  # noqa: E402
import cascade_manifest as CM  # noqa: E402
import data_plane as dp  # noqa: E402
import fast_path  # noqa: E402

log = logging.getLogger("firewall.data_plane.cascade")

CONFIG_ENV = "FIREWALL_CASCADE_CONFIG"


class CascadeFirewallGateway(dp.FirewallGateway):
    def __init__(self, *args, cascade=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.cascade = cascade

    async def running(self) -> None:
        super().running()
        if self.cascade is None:
            log.info("cascade: off (V4 path only)")
            return
        log.info("cascade: mode=%s profile=%s manifest=%s framing=%s", self.cascade.cfg.mode,
                 self.cascade.cfg.deployment_profile,
                 getattr(self.cascade.manifest, "manifest_id", None), CG.GF.CONTRACT_ID)
        await self.cascade.start()

    def configure(self, updated) -> None:
        super().configure(updated)
        if self.cascade is not None:
            self.cascade.configure(dp.ctx.options, dp.MITMPROXY_VERSION)

    async def enforce(self, flow) -> None:
        runtime = self.cascade
        if runtime is None or not runtime.authoritative():
            await super().enforce(flow)
            if runtime is not None:
                runtime.after_v4(flow)
            return
        await runtime.enforce(flow)

    def done(self) -> None:
        if self.cascade is not None:
            self.cascade.close()
        super().done()


def build_addon() -> CascadeFirewallGateway:
    classifier_url, timeout = dp.load_config()
    shadow_fast_path = dp.load_shadow_fast_path()
    runtime = None
    config_path = os.environ.get(CONFIG_ENV)
    if config_path:
        cfg = CM.load_gateway_config(config_path)
        classifier_url = cfg.v4_url.rstrip("/") + "/classify"
        timeout = cfg.v4_timeout_seconds
        if cfg.mode != C.V4_ONLY:
            runtime = CG.build_runtime(cfg)
    return CascadeFirewallGateway(
        classifier_url, timeout, shadow_features=dp.load_shadow_feature_extraction(),
        shadow_analyzer=dp.build_shadow_analyzer(dp.load_shadow_analyzer()),
        shadow_fast_path=shadow_fast_path[0], fast_path_policy_file=shadow_fast_path[1],
        canonical_observer=dp.build_canonical_observer(dp.load_canonical_observer()),
        framing_observer=dp.load_shadow_framing_observer(), cascade=runtime)


addons = [build_addon()]
