"""
Open-loop load generation and accounting for the gateway load checks. Standard library only.

OPEN LOOP. Arrivals follow a seeded Poisson schedule and never wait for earlier responses. A closed
loop slows down with the system, which hides queues (coordinated omission). Latency is measured from
the SCHEDULED arrival, so time a request spends waiting is never lost. The generator's own lag is
reported, and a step where it is large is not valid evidence.

NO CORRELATION HEADER. Every header is model input, so a client cannot mark its requests. Under
concurrency a request is matched with its reception by the hash of its bytes, as a multiset. That
proves the same set of messages was answered 200 and received, not a one-to-one pairing of identical
messages.

USEFUL WORK. A fast 503 is an answer, not capacity. `useful` counts only authoritative decisions (200
forwarded, 403 blocked). `rejected` counts fail-closed 503. Neither is ever added to the other.
"""
import asyncio
import collections
import hashlib
import math
import random
import re
import time

# Descriptive saturation criteria, fixed before measuring. They are not an SLO.
MIN_USEFUL_FRACTION = 0.95
MAX_USEFUL_P95_MS = 2000.0
LOW_SAMPLE_P99 = 100


def nearest_rank(values, p):
    ordered = sorted(values)
    return ordered[max(1, math.ceil(p / 100 * len(ordered))) - 1] if ordered else None


def dist(values):
    values = [v for v in values if v is not None]
    if not values:
        return {"n": 0}
    out = {"n": len(values), "mean": sum(values) / len(values), "p50": nearest_rank(values, 50),
           "p95": nearest_rank(values, 95), "p99": nearest_rank(values, 99), "min": min(values),
           "max": max(values)}
    if len(values) < LOW_SAMPLE_P99:
        out["p99_low_confidence"] = True
    return out


def poisson_offsets(rate, seconds, seed):
    """Arrival offsets in seconds for a Poisson process, reproducible from the seed."""
    rng = random.Random(seed)
    offsets, t = [], 0.0
    while True:
        t += rng.expovariate(rate)
        if t >= seconds:
            return offsets
        offsets.append(t)


class TrafficOrder:
    """A fixed, seeded order over the DEV cases, cycled. `sha256` identifies the order."""

    def __init__(self, cases, seed):
        self.cases = sorted(cases, key=lambda c: c["id"])
        random.Random(seed).shuffle(self.cases)
        self.sha256 = hashlib.sha256("\n".join(c["id"] for c in self.cases).encode()).hexdigest()
        self.position = 0

    def take(self, count):
        out = []
        for _ in range(count):
            out.append(self.cases[self.position % len(self.cases)])
            self.position += 1
        return out


async def _read_status(reader):
    """Status of one response, reading exactly its Content-Length. None if it closes before one."""
    head = bytearray()
    while b"\r\n\r\n" not in head:
        data = await reader.read(65536)
        if not data:
            return None
        head += data
    raw_head, _, rest = bytes(head).partition(b"\r\n\r\n")
    status = int(raw_head.split(b" ", 2)[1])
    length = 0
    for line in raw_head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            length = int(value)
    remaining = length - len(rest)
    while remaining > 0:
        data = await reader.read(remaining)
        if not data:
            break
        remaining -= len(data)
    return status


async def _one(host, port, case, scheduled, timeout, kind):
    loop = asyncio.get_running_loop()
    start = loop.time()
    row = {"case": case["id"], "kind": kind, "lag_ms": (start - scheduled) * 1000,
           "t_sched": time.time() - (start - scheduled), "wire_sha256": case["wire_sha256"]}
    writer = None
    try:
        async with asyncio.timeout(timeout):
            reader, writer = await asyncio.open_connection(host, port)
            writer.write(case["wire_bytes"])
            await writer.drain()
            row["status"] = await _read_status(reader)
        row["outcome"] = "response" if row["status"] is not None else "closed_without_response"
    except TimeoutError:
        row.update(status=None, outcome="client_timeout")
    except (OSError, ValueError, IndexError) as exc:
        row.update(status=None, outcome=f"connection_error:{type(exc).__name__}")
    finally:
        if writer is not None:
            writer.close()
    row["latency_ms"] = (loop.time() - scheduled) * 1000
    return row


async def launch(host, port, cases, offsets, timeout, kind="dev"):
    """Start every request on its schedule. Returns the tasks when the last one has started, so a
    caller can do something else while the tail finishes (a recovery probe, for example)."""
    loop = asyncio.get_running_loop()
    origin = loop.time()
    tasks = []
    for case, offset in zip(cases, offsets):
        scheduled = origin + offset
        delay = scheduled - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        tasks.append(asyncio.ensure_future(_one(host, port, case, scheduled, timeout, kind)))
    return tasks


async def open_loop(host, port, cases, offsets, timeout, kind="dev"):
    tasks = await launch(host, port, cases, offsets, timeout, kind)
    return list(await asyncio.gather(*tasks))


def useful(row):
    return row.get("status") in (200, 403)


def client_accounting(rows, seconds):
    """Offered, completed, useful and rejected for one window. Rates use the arrival window, or the
    time the tail really took if that was longer."""
    outcomes = collections.Counter(r["outcome"].split(":")[0] for r in rows)
    statuses = collections.Counter(str(r["status"]) for r in rows if r["status"] is not None)
    span = max(seconds, max((r["latency_ms"] / 1000 + r["t_sched"] for r in rows), default=0)
               - min((r["t_sched"] for r in rows), default=0))
    good = [r for r in rows if useful(r)]
    return {
        "offered": len(rows), "offered_per_s": len(rows) / seconds,
        "completed": sum(1 for r in rows if r["status"] is not None),
        "useful": len(good), "useful_per_s": len(good) / span, "span_s": span,
        "useful_fraction": len(good) / len(rows) if rows else None,
        "useful_within_1s_per_s": sum(1 for r in good if r["latency_ms"] <= 1000) / span,
        "useful_within_3s_per_s": sum(1 for r in good if r["latency_ms"] <= 3000) / span,
        "rejected_503": statuses.get("503", 0), "bad_gateway_502": statuses.get("502", 0),
        "client_timeouts": outcomes.get("client_timeout", 0),
        "connection_errors": outcomes.get("connection_error", 0),
        "closed_without_response": outcomes.get("closed_without_response", 0),
        "other_status": {k: v for k, v in statuses.items() if k not in ("200", "403", "503", "502")},
        "statuses": dict(statuses), "outcomes": dict(outcomes),
        "latency_useful_ms": dist([r["latency_ms"] for r in good]),
        "latency_forwarded_ms": dist([r["latency_ms"] for r in rows if r["status"] == 200]),
        "latency_blocked_ms": dist([r["latency_ms"] for r in rows if r["status"] == 403]),
        "latency_rejected_ms": dist([r["latency_ms"] for r in rows if r["status"] == 503]),
        "generator_lag_ms": dist([r["lag_ms"] for r in rows]),
    }


def is_saturated(accounting):
    """Fixed before measuring: a step is saturated when under 95% of offered requests got a useful
    answer, or the P95 of those answers exceeds 2 s. Fast rejection can never make a step pass."""
    fraction = accounting["useful_fraction"]
    p95 = accounting["latency_useful_ms"].get("p95")
    return fraction is None or fraction < MIN_USEFUL_FRACTION or p95 is None \
        or p95 > MAX_USEFUL_P95_MS


def l2_multiset(rows, sink_rows):
    """L2 by message. Forwarded answers and independent reception must be the same multiset of byte
    hashes. A request the client gave up on may still have been delivered: that is indeterminate, not
    a contradiction, and is reported apart."""
    forwarded = collections.Counter(r["wire_sha256"] for r in rows if r["status"] == 200)
    denied = collections.Counter(r["wire_sha256"] for r in rows
                                 if r["status"] is not None and r["status"] != 200)
    unknown = collections.Counter(r["wire_sha256"] for r in rows if r["status"] is None)
    received = collections.Counter(r["wire_sha256"] for r in sink_rows)
    answered_not_received = forwarded - received
    received_not_answered = received - forwarded
    explained_by_unknown = received_not_answered & unknown
    contradiction = received_not_answered - explained_by_unknown
    denied_but_received = contradiction & denied
    return {
        "forwarded": sum(forwarded.values()), "received": sum(received.values()),
        "answered_200_not_received": sum(answered_not_received.values()),
        "received_after_client_gave_up": sum(explained_by_unknown.values()),
        "denied_but_received": sum(denied_but_received.values()),
        "received_without_any_request": sum((contradiction - denied_but_received).values()),
        "conformant": not answered_not_received and not contradiction,
    }


def recovery_seconds(probes, load_end, limit_ms, run=10):
    """Time from the end of the load to the start of the first `run` consecutive probes that were all
    useful and within `limit_ms`. None if that never happened."""
    streak = 0
    for i, row in enumerate(sorted(probes, key=lambda r: r["t_sched"])):
        streak = streak + 1 if useful(row) and row["latency_ms"] <= limit_ms else 0
        if streak == run:
            first = sorted(probes, key=lambda r: r["t_sched"])[i - run + 1]
            return max(0.0, first["t_sched"] - load_end)
    return None


class LogTail:
    """New complete lines of a growing log since the last read."""

    def __init__(self, path):
        self.path, self.position = path, 0

    def read(self):
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self.position)
                data = fh.read()
        except OSError:
            return []
        end = data.rfind(b"\n") + 1
        self.position += end
        return data[:end].decode("utf-8", "replace").splitlines()


_V4_CLASSIFIER = re.compile(r"\((?:classifier|after) (\d+) ms\)")
_V4_MODEL = re.compile(r"model_latency_ms=([0-9.]+)")
_V5_GENERATE = re.compile(r"classify: (?:ok decision=\w+ )?.*generate_ms=([0-9.]+)")


def gateway_v4_ms(lines):
    """Gateway-side V4 time, from the V4 path's own decision lines. Numbers only leave this function:
    those lines hold request paths."""
    return [float(m.group(1)) for m in map(_V4_CLASSIFIER.search, lines) if m]


def v4_model_ms(lines):
    return [float(m.group(1)) for m in map(_V4_MODEL.search, lines) if m]


def v5_service_counts(lines):
    return {"generate_ms": [float(m.group(1)) for m in map(_V5_GENERATE.search, lines) if m],
            "saturated": sum("saturated" in line for line in lines),
            "lock_timeouts": sum("GPU lock wait exceeded" in line for line in lines),
            "invalid": sum("classify: invalid" in line for line in lines)}


_METRIC = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(\{[^}]*\})? ([0-9.eE+\-]+)$")


def parse_metrics(text):
    """Counters and gauges of a /metrics page. Histograms are left out: the records carry the times."""
    out = {}
    for line in text.splitlines():
        match = _METRIC.match(line)
        if match and not re.search(r"_(bucket|sum|count)$", match.group(1)):
            out[match.group(1) + (match.group(2) or "")] = float(match.group(3))
    return out


def metric_delta(before, after):
    return {k: after[k] - before.get(k, 0.0) for k in sorted(after)
            if k.endswith("}") or k.endswith("_total")
            if after[k] != before.get(k, 0.0)}


def decision_accounting(records):
    """Per route and stage, from the gateway's decision records. Queue, inference and service time are
    what the V5 service reported for that same request; `v5_hop_outside_service` is the rest of the
    hop as the router saw it."""
    decisions = [r for r in records if r.get("kind") == "decision" and "applied" in r]
    routes = collections.defaultdict(list)
    for record in decisions:
        routes[record.get("cascade_stage") or record.get("deciding_stage")].append(record)
    out = {"records": len(decisions), "routes": {}}
    for route, rows in sorted(routes.items(), key=lambda kv: str(kv[0])):
        stages = collections.defaultdict(list)
        decoder = collections.defaultdict(list)
        for record in rows:
            for name, value in (record.get("stage_ms") or {}).items():
                stages[name].append(value)
            hop = (record.get("timings_ms") or {}).get("v5_ms")
            service = record.get("v5_service") or {}
            if hop is not None:
                stages["v5_hop"].append(hop)
            if service.get("service_ms") is not None:
                stages["v5_queue"].append(service.get("queue_wait_ms"))
                stages["v5_inference"].append(service.get("pipeline_ms"))
                stages["v5_service"].append(service["service_ms"])
                stages["v5_hop_outside_service"].append(max(0.0, hop - service["service_ms"]))
                if service.get("decoder_fallback") is not None:
                    path = "fallback" if service["decoder_fallback"] else "verified"
                    decoder[path].append(service.get("pipeline_ms"))
            model2 = (record.get("timings_ms") or {}).get("model2_ms")
            if model2 is not None:
                stages["model2"].append(model2)
        out["routes"][str(route)] = {
            "n": len(rows), "gateway_ms": dist([r.get("gateway_ms") for r in rows]),
            "reasons": dict(collections.Counter(str(r.get("reason")) for r in rows)),
            "stages_ms": {k: dist(v) for k, v in sorted(stages.items())},
            "decoder_pipeline_ms": {k: dist(v) for k, v in sorted(decoder.items())}}
    return out
