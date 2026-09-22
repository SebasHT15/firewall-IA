"""External Test v1 — capture-fidelity verification.

Answers one question, and must answer it BEFORE the final DRAFT is built:

    when a captured request is replayed, does the proxy hand the classifier
    byte-for-byte the same text that was captured?

If it does not, every frozen case is a case whose label describes something other than
what V4 is scored on, and the whole evaluation is invalid.

Procedure (no model in the path at any point):

    1. real clients -> capture proxy -> lab-app        => capture_original.jsonl
    2. replay.py --target capture (same capture proxy) => capture_replayed.jsonl
    3. this script compares the two by SHA-256

Reports per-request match, and the exact diff of the first mismatches so a failure is
actionable rather than just a number.
"""

import argparse
import json
import sys


def load(path):
    out = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def select(records, only_host, limit):
    """Apply the replay's own selection rule to a set of captured records.

    replay.py picks cases with `--only-host HOST` then `--limit N`, in that order and in
    file order. The checker must select the originals THE SAME WAY, or it compares a
    different set of requests than the one that was replayed — and can then agree or
    disagree by luck.
    """
    chosen = [r for r in records if not only_host or r.get("host") == only_host]
    dropped_by_host = len(records) - len(chosen)
    if limit is not None:
        chosen = chosen[:limit]
    return chosen, dropped_by_host


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", help="capture JSONL from the client run")
    ap.add_argument("--replayed", help="capture JSONL from the replay run")
    ap.add_argument("--capture", help="ONE capture JSONL holding both passes, in order; "
                                      "use with --split-after")
    ap.add_argument("--split-after", type=int,
                    help="number of records belonging to the ORIGINAL pass in --capture; "
                         "the replayed pass is everything after them")
    ap.add_argument("--expect", type=int, default=None,
                    help="SUBSET MODE: the predeclared number of requests that were "
                         "replayed. Without it, every captured request must be replayed.")
    ap.add_argument("--only-host", default=None,
                    help="the host filter replay.py was given; must match it exactly so "
                         "both sides select the same requests")
    ap.add_argument("--show", type=int, default=3, help="mismatches to print in full")
    args = ap.parse_args(argv)

    if args.capture:
        # The capture proxy appends to one file for as long as it runs, so a replay through
        # the SAME proxy lands after the original pass instead of in a second file. Reading
        # both halves out of one file keeps the operator handoff to a single command.
        if args.split_after is None:
            ap.error("--capture requires --split-after")
        rows = load(args.capture)
        captured_pass = rows[:args.split_after]
        replayed_pass = rows[args.split_after:]
        print(f"capture file: {len(rows)} record(s), split after {args.split_after}")
    else:
        if not (args.original and args.replayed):
            ap.error("give --original and --replayed, or --capture with --split-after")
        captured_pass, replayed_pass = load(args.original), load(args.replayed)

    subset_mode = args.expect is not None

    # Select from BOTH passes with the identical rule replay.py used.
    original, orig_off_host = select(captured_pass, args.only_host,
                                     args.expect if subset_mode else None)
    replayed, rep_off_host = select(replayed_pass, args.only_host, None)

    print(f"captured pass: {len(captured_pass)} record(s)")
    print(f"replayed pass: {len(replayed_pass)} record(s)")
    if args.only_host:
        print(f"host filter {args.only_host!r}: dropped {orig_off_host} captured, "
              f"{rep_off_host} replayed")

    problems = []

    if subset_mode:
        # A subset was replayed BY DESIGN. Requests outside it were never meant to be
        # replayed, so their absence is not a mismatch — but the selected subset must be
        # exactly the predeclared size on both sides.
        eligible = len([r for r in captured_pass
                        if not args.only_host or r.get("host") == args.only_host])
        print(f"predeclared subset: first {args.expect} of {eligible} eligible captured "
              f"request(s); {max(eligible - args.expect, 0)} not replayed by design")
        if len(original) != args.expect:
            problems.append(f"selected only {len(original)} original record(s), "
                            f"predeclared subset is {args.expect}")
        if len(replayed) != args.expect:
            problems.append(f"found {len(replayed)} replayed record(s), "
                            f"predeclared subset is {args.expect}")
    else:
        # Full-replay contract: every captured request must come back exactly once.
        if len(original) != len(replayed):
            problems.append(f"COUNT MISMATCH: {len(original)} captured vs "
                            f"{len(replayed)} replayed. Replay must re-emit every "
                            f"captured request exactly once.")

    print(f"comparing: {len(original)} original vs {len(replayed)} replayed")

    n = min(len(original), len(replayed))
    matches, mismatches = 0, []
    for a, b in zip(original[:n], replayed[:n]):
        if a["request_sha256"] == b["request_sha256"]:
            matches += 1
        else:
            mismatches.append((a, b))

    print(f"\nbyte-exact matches: {matches}/{n}")
    if n:
        print(f"fidelity: {100.0 * matches / n:.2f}%  ({matches}/{n})")
    if matches != n:
        problems.append(f"{n - matches} of {n} compared record(s) are not byte-exact")
    if n == 0:
        problems.append("nothing was compared")

    for a, b in mismatches[:args.show]:
        print("\n--- MISMATCH ---")
        print(f"  seq {a.get('seq')} {a.get('method')} {a.get('path')}")
        print(f"  original sha256: {a['request_sha256']}")
        print(f"  replayed sha256: {b['request_sha256']}")
        ta, tb = a["request_text"].split("\n"), b["request_text"].split("\n")
        for i in range(max(len(ta), len(tb))):
            la = ta[i] if i < len(ta) else "<absent>"
            lb = tb[i] if i < len(tb) else "<absent>"
            if la != lb:
                print(f"    line {i}: original={la!r}")
                print(f"    line {i}: replayed={lb!r}")

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print(f"  - {p}")
    print("\nRESULT: " + ("PASS — replay is byte-exact, DRAFT may be built"
                          if not problems else
                          "FAIL — do NOT build the DRAFT until replay is byte-exact"))
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main())
