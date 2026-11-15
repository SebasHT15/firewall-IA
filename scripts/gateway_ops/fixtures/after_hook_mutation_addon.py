"""TEST FIXTURE. Loaded after the cascade addon, so its `request` hook runs after the decision, the
same position as mitmproxy's own modify_headers/map_remote. It changes the request the way such an
addon would, to prove the egress guard refuses bytes that are not the ones that were decided."""


def request(flow):
    flow.request.headers["X-Added-After-Decision"] = "1"
