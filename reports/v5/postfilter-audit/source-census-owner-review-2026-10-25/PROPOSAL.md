# Four unresolved census units: owner decision packet

The 166-unit census is complete and its three model votes remain immutable. The
four cases below are `UNRESOLVED_THREE_WAY`; the frozen rule does not convert a
third reviewer's `PROBABLY_CORRECT` vote into a resolved label. This packet
proposes `RESOLVE_WITH_EVIDENCE` → `UNCERTAIN` for each. It is **not an owner
decision**. The cited source is the pinned PayloadsAllTheThings clone at
`/home/sebas/PayloadsAllTheThings` (`e961fef231d8327bae83b563fab50aec2e6b77c0`).

| ID prefix | Category | Evidence for conservative `UNCERTAIN` |
| --- | --- | --- |
| `1d97fda6` | SSTI | PHP.md line 147 has two complete Twig expressions and calls `registerUndefinedFilterCallback("exec")`; execution depends on the Twig version, callback availability, and server configuration. No engine render was recorded. |
| `1f67c0ff` | SSTI | Python.md line 312 has a complete Jinja2 `attr` expression assembled with `join`; whether `request` exists in the render context and attribute access is permitted is untested. |
| `56d6707a` | SSTI | Java.md lines 222–229 contain a full Velocity block that invokes `Runtime.exec`; the `$class` helper and reflection access depend on host configuration. No Velocity render was recorded. |
| `5e2a31d3` | XSS | 3 - XSS Common WAF Bypass.md line 58 contains a full HTML anchor using character references in `href`. Its proposed sink is `...?param={INPUT}`; that context alone does not prove HTML parsing or execution. No browser render was recorded. |

The proposal acknowledges a real payload mechanism but does not assert that
execution was verified in the proposed sink. It avoids treating source presence
as ground truth. The source hashes, byte ranges, reviewer votes, and full IDs
remain in `validation-prepared/population.jsonl` and the immutable consumer
result (`sha256:119c7fd47931230f2263306abfcb4684cf91d5066416481345c66626403321e8`).

If the owner accepts these four evidence-backed dispositions, both categories
would meet the existing r4 thresholds **without changing a vote or denominator**:
SSTI n=60, INCORRECT=0, UNCERTAIN=5, C1=0.0602, C2=0.1807;
XSS n=58, INCORRECT=1, UNCERTAIN=4, C1=0.0914, C2=0.1864.
These are conditional calculations, not an admission. The decision must cite
this packet and be recorded separately before an overlay consumer may run.
