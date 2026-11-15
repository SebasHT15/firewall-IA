# Minimal-pair protocol for V4 — DRAFT (`v5-minimal-pairs-v1`)

**STATUS: DRAFT — not anchored, not executed, no case generated.** Before any request is scored
it must be revised by the owner, its cases generated, and the SHA-256 of this file and of the
cases anchored on an issue (as in #59).

## 1. Purpose

The coverage audit (`README.md` §6) found that the observational data cannot separate four
candidate mechanisms behind V4's benign false blocks:

| ID | Mechanism | Why the existing data cannot separate it |
|---|---|---|
| M-content | benign content coverage gaps | in #60, body structure is perfectly confounded with `Content-Length` and an unseen port |
| M-envelope | envelope train/serve skew (`Content-Length` on bodies, unseen ports, `Proxy-Connection`, loopback-IP Host) | same confound; #57 S1 covers GET only |
| M-token | a token learned in one position applied in another (`127.0.0.1`) | never isolated |
| M-instability | decision instability near the boundary | seen in #60 (login usernames) but never measured against a control |

This protocol changes **one variable at a time** on new benign requests. It measures which
changes flip V4 from ALLOW to BLOCK more often than a control that changes only a well-covered
dimension. The same suite, frozen, later serves as a **V5 acceptance diagnostic**: does V5 remove
the flips, or only memorize texts?

## 2. Data role and independence (fixed before generation)

- **New development diagnostic.** Never a test set, and never training or checkpoint-selection
  data for V5.
- **Disjoint from the V5 generator.**
  - Templates, endpoint names, parameter names and value pools are written for this suite only.
  - The V5 generator must not reuse them. Each pool's SHA-256 is recorded so the V5 builder can
    assert disjointness.
- **Copies nothing from:**
  - `fwlab.test` or the lab-app routes (`/login`, `/checkout`, `/search`, `/products`,
    `/static`, `/api/orders`, `/api/me`, `/cart`, `/profile`);
  - any #57/#60 text or value;
  - External Test v1 (never opened).
  
  INTERNAL TEST is not used.
- **Host names** use reserved example domains (RFC 2606/6761, e.g. `portal.example.net`) except
  where the Host itself is the independent variable.
- **Fictitious application:** a municipal library and events portal. Endpoints are illustrative
  and fixed in the case manifest, for example:
  - `/session/new`, `/members/settings`, `/catalog/find`;
  - `/events/{id}/signup`, `/api/v2/reservations`, `/hooks/subscriptions`, `/media/{path}`.

## 3. Units and size

- **Independent unit:** one *base* benign request, i.e. one value tuple drawn once from the
  suite's pools.
- **Levels** of a factor applied to the same base are **dependent** and are never counted as
  independent.
- **≥ 30 bases per factor** where a conclusion is drawn (D18). Otherwise report INSUFFICIENT
  DATA.
- **Estimated size:** about 15 factors × 2–5 levels × 30 bases plus controls, roughly 1,500
  classifications, a few minutes of GPU (inference only).

## 4. Factors (independent variable → everything else held identical)

| Factor | Independent variable | Levels (first = reference) | Tests |
|---|---|---|---|
| F-CL | `Content-Length` on a body request (form and JSON bases) | absent · present (correct value) | M-envelope |
| F-PORT | Host port | none · 8080 · 9100 · 30000 | M-envelope |
| F-HOSTIP | Host value | DNS name · `127.0.0.1` · `10.0.0.5` | M-token / M-envelope |
| F-PXY | `Proxy-Connection: keep-alive` | absent · present | M-envelope |
| F-NFIELDS | form field count (neutral extra fields appended) | 1 · 2 · 3 · 5 | M-content |
| F-NQUERY | query parameter count | 1 · 2 · 4 | M-content |
| F-PWD | password character class (same length) | alphanumeric · with `!` · with `#` · with `-` | M-content |
| F-APOS | apostrophe in a surname | `oneil` · `o'neil` | M-content |
| F-ADDR | address punctuation | none · `#` · `,` · `&` | M-content |
| F-WORD | one word in a fixed prose note, same position | neutral word · one level per homonym: select, union, from, where, table, call, match, include, order, drop | M-content |
| F-JSON | JSON body shape (matching Content-Type) | 1 string key · 3 keys · 3 keys + number · nested object · array | M-content |
| F-CTB | Content-Type / body consistency | JSON body + JSON type · JSON body + form type · form body + JSON type | M-content (reverse shortcut, audit §3.3) |
| F-ENC | encoding of the same value | `%20` · `+` · `%2F` vs `/` in a path segment | M-content |
| F-URL | URL-valued parameter | https same host · https external host · http external host | M-content |
| F-NAME | parameter name with an identical benign value | neutral (`note`) · `template` · `callback` · `file` | M-content (name semantics) |

**Controls:**
- **CONTROL-COV (instability):** change only a well-covered dimension, e.g. a username drawn
  from covered classes (letters, digits, `.`, `-`) on body and GET bases. Every factor is
  compared against it.
- **CONTROL-REP (determinism):** 10% of all texts repeated 3 times. Any non-determinism voids the
  run (greedy decoding is expected to be deterministic).

## 5. Hypotheses, expected observations, falsification

For each factor level vs its reference, over its bases, build the paired 2×2 table (ALLOW/BLOCK
at the reference × ALLOW/BLOCK at the level).

- **H(level): the change makes V4 flip ALLOW → BLOCK more often than BLOCK → ALLOW.** Test:
  exact McNemar test (binomial on discordant pairs), one-sided. The family of comparisons
  declared in §4, controls included, uses Holm correction at α = 0.05.
- **Expected if M-content holds:** F-PWD(`!`), F-APOS, F-ADDR(`#`/`&`), F-WORD(homonyms),
  F-NFIELDS(2), F-JSON(≥3 keys) are significant.
- **Expected if M-envelope holds:** F-CL(present), F-PORT(30000/9100), F-PXY are significant.
- **Expected if M-token holds:** F-HOSTIP(`127.0.0.1`) is significant while F-HOSTIP(`10.0.0.5`)
  is not.
- **M-instability is material** if CONTROL-COV has discordant pairs with an exact 95% lower
  bound above 0.
- **Falsification:**
  - A mechanism is **not supported** if none of its factor levels is significant after Holm.
  - A content factor that is significant is still only **"not distinguishable from
    instability"** if its discordance does not exceed CONTROL-COV's (both counts reported).
  - If the content factors are not significant while F-CL is, the §5.1 correlation in the audit
    is attributed to the envelope confound, and V5 priorities change: envelope realism (F7)
    first.

All results are diagnostic counts on an author-chosen composition, never rates (D42).

## 6. Measurements per classification

- V4 decision, reason, status.
- `model_latency_ms` as an observation only.
- Adapter SHA-256 (`7bf16875…`), checked before and after.
- **Recommended, not required:** the first-decision-token log-probability margin
  (log P(`B`) − log P(`AL`)). It needs the shadow instrumentation designed by the verdict-only
  research and is a separate, opt-in change to `inference_core`. It turns binary flips into a
  continuous shift and is **not** a calibrated probability.

## 7. Execution constraints

- **Path:** direct `inference_core` / `/classify` on the frozen V4. The envelope is part of the
  text, so the gateway is not needed. Optionally, a 10% subset goes through the lab gateway to
  confirm rendering.
- **Integrity:** cases are generated deterministically from a recorded seed. Cases, pools and
  this protocol are hashed and anchored before scoring. Scoring runs once; the analysis is
  offline and deterministic.
- **Training firewall:** no result of this suite changes V5's generator *except at the level of
  mechanism priorities* (which family is built first). That rule is recorded with the anchor.

## 8. Non-claims

No FPR, recall or operational rate. No cause beyond "this isolated change flipped this many
bases in this suite". No claim about V5, External Test v1 or deployment traffic.
