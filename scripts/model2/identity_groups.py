"""Connect already gated TRAIN/VALIDATION rows sharing any declared identity.

Conservative diagnostic grouping; not proof of independent components.
No files, payloads, labels or predictions read. Tokens remain in memory only.
"""
IDENTITY_KEYS = ("text_sha256", "pair_id", "payload_family_id", "payload_record_id",
                 "struct_cluster_id", "template_id", "value_entries")
GROUP_DEFINITION = "connected_exchange_identities/proposal-v1"


def connected_groups(examples):
    if type(examples) is not dict or set(examples) != {"TRAIN", "VALIDATION"}:
        raise ValueError("only separate TRAIN and VALIDATION examples supported")
    parents, tokens, roles = {}, {}, {}

    def find(key):
        while parents[key] != key:
            parents[key] = parents[parents[key]]
            key = parents[key]
        return key

    for split in ("TRAIN", "VALIDATION"):
        if not examples[split]:
            raise ValueError("both splits must be nonempty")
        for example in examples[split]:
            index = example.get("row_index")
            if example.get("split") != split or type(index) is not int or index < 0:
                raise ValueError("example split/index mismatch")
            key = (split, index)
            if key in parents:
                raise ValueError("duplicate example index")
            parents[key] = key
            identities = example.get("identities")
            if type(identities) is not dict or set(identities) != set(IDENTITY_KEYS):
                raise ValueError("identity schema mismatch")
            for name in IDENTITY_KEYS:
                value = identities[name]
                if value is None and name in ("payload_family_id", "payload_record_id"):
                    continue
                if name == "value_entries":
                    if type(value) is not list:
                        raise ValueError("value entries must be a list")
                    values = []
                    for entry in value:
                        if (type(entry) not in (list, tuple) or len(entry) != 2
                                or any(type(v) is not str or not v.strip() for v in entry)):
                            raise ValueError("invalid value-entry identity")
                        values.append(tuple(entry))
                else:
                    if type(value) is not str or not value.strip():
                        raise ValueError("required identity missing")
                    values = [value]
                for value in values:
                    token = (name, value)
                    if roles.setdefault(token, split) != split:
                        raise ValueError("identity crosses TRAIN/VALIDATION")
                    other = tokens.setdefault(token, key)
                    a, b = find(key), find(other)
                    parents[max(a, b)] = min(a, b)
    roots = sorted({find(k) for k in parents})
    names = {root: f"component-{i}" for i, root in enumerate(roots)}
    return {key: names[find(key)] for key in sorted(parents)}
