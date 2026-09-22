# External Test v1 — ground-truth rules (Phase C DRAFT)

**Status: DRAFT. Assigned before any V4 exposure (protocol §8).** Ground truth is attached
to the **case**, from the intent of the flow that produced it — never from a V4 prediction,
which does not exist yet. This file records the labelling rules and the resolved
disagreements so the labels are reproducible and auditable.

> "BLOCK ground truth" means: **this request contains an intentionally security-relevant
> pattern the firewall is expected to block.** It does **not** mean the lab application was
> exploited. The lab app is inert by design (protocol §5.1); attack success is out of scope.

---

## 1. Rules

### ALLOW (benign, 5 slices)
A captured request is **ALLOW** iff it is a legitimate interaction the lab application is
designed — or would reasonably be expected — to serve.

| Slice | Rule | Notes |
|---|---|---|
| `browser-navigation` | any real Chromium page load / navigation / sub-resource against a lab alias | sub-resources (favicon, static assets) are ALLOW too, declared before exposure (§4.2) |
| `browser-forms-session` | any real Chromium form submission or session-continuity request | login/search/cart/checkout, cookies carried |
| `api-json` | httpx JSON GET/POST/PUT against the API routes | a PUT the app answers 405 is still a benign real API request |
| `api-query` | curl query-parameter GETs: filters, pagination, sorting, encodings | empty/boundary params are benign |
| `unseen-structure` | a benign request whose **structure** has zero/near-zero support in `datasets/v4_clean/` | OPTIONS/HEAD, unseen header names, unseen content types — see `build/unseen_structure_support.json` |

`unseen-structure` is **unseen-input robustness (RQ4), not OOD detection.** No novelty score
or calibrated uncertainty is claimed. The structural axes are chosen from direct counts over
the V4 corpus (31,340 rows): methods outside {GET,POST,PUT,PATCH,DELETE,HEAD}; header names
outside the 15 observed; content types outside the 4 observed; ports outside {none,8000,8080}.

### BLOCK (malicious, 5 categories)
A request is **BLOCK** iff it carries an intentionally security-relevant pattern of its
category, placed in an inert location (query value, form field, JSON value, path segment,
cookie or header). Each records `attack_category`, `technique`, `payload_placement`, the
decoded `payload`, and a `ground_truth_basis`.

| Category | Signal that justifies BLOCK |
|---|---|
| `sqli` | SQL syntax intended to alter a query (tautology, UNION, error/time/stacked, metadata) |
| `cmdi` | shell metacharacters / substitution / interpreter invocation intended to run a command |
| `xss` | HTML/JS intended to execute in a victim browser (tags, event handlers, `javascript:` URIs) |
| `path-traversal` | `../`-style navigation intended to escape the intended directory |
| `ssrf` | a URL/host intended to make the server fetch an internal/loopback/metadata target |

Every BLOCK request is **local-lab only** (destination is a lab alias) and **inert**: lab-app
never interpolates the payload into a query, shell, path, template sink or outbound fetch.

---

## 2. Confidence and review

- `label_confidence`: `high` (unambiguous), `medium` (structurally unusual / placement makes
  the intent less clear-cut), `review` (must be adjudicated before freeze).
- `review_status`: `auto-accepted` or `needs-review`. Any `review` confidence ⇒ `needs-review`.
- **Ambiguous cases are marked for review, not silently accepted**, and — per protocol §8 —
  ambiguous cases are **excluded** (not guessed) during the Phase D trim, with the exclusion
  logged. Exclusions happen only in DRAFT.

### Candidates currently flagged `needs-review` (Phase C)
These are authored at `medium` confidence because the security-relevant content sits in a
**header** (or an unusual host form), where benign/malicious intent is less clear-cut than in
a query/body, and a firewall's treatment of headers is worth adjudicating explicitly:

| case_id | cell | technique | why flagged |
|---|---|---|---|
| `cmdi-0031` | cmdi | header-ua-shellshock | Shellshock function in `User-Agent`; recognised as CmdI, but header-borne |
| `xss-0050` | xss | referer-xss | script payload in `Referer`; reflected-XSS intent depends on a sink |
| `ssrf-0050` | ssrf | header-forwarded-host | internal host in `X-Forwarded-Host`; SSRF-adjacent, header-borne |
| `ssrf-0051` | ssrf | header-forwarded-for | internal address in `X-Forwarded-For`; often benign metadata |
| `unseen-structure-0042` | unseen-structure | host-trailing-dot | benign, but the FQDN-trailing-dot + port-9100 structure is genuinely unusual |

Two-pass review (a second independent pass over every label) is a **Phase D** step; its
disagreements and resolutions will be appended here before freeze. No two-pass adjudication
has been performed yet.

---

## 3. Provenance, not relabelling

Text divergence between what a driver intended and what the client transmitted (e.g. a client
adding `Proxy-Connection`) is recorded as **provenance**, never as a relabel (§8). Ground
truth stays attached to the case. The frozen `request_text` is the captured text, verbatim.
