# Evidence matrix — challenge-app integration (V5 double, gateway 16m)

Generated from the sealed smoke JSONs by `scripts/local_stack/challenges/evidence_matrix.py`. V5 DOUBLE only (BLOCK on the literal word `evil`): integration and attribution, not quality. No real V5.1, attack campaign, load or latency here; the gateway limit was fixed at 16m before the run.

**24/24 runs pass.** apps commit matches pin for every run: yes.

## App × arm

| App | direct | v5only | guarded | crs |
|---|---|---|---|---|
| An0nB0ard | ✅ 9/9 | ✅ 10/10 | ✅ 10/10 | ✅ 9/9 |
| CatP1cs | ✅ 10/10 | ✅ 11/11 | ✅ 11/11 | ✅ 10/10 |
| D33pTh0ught | ✅ 7/7 | ✅ 8/8 | ✅ 8/8 | ✅ 7/7 |
| Inf3ct | ✅ 8/8 | ✅ 9/9 | ✅ 9/9 | ✅ 8/8 |
| ObC00ki3s | ✅ 9/9 | ✅ 10/10 | ✅ 10/10 | ✅ 9/9 |
| ag3ncy | ✅ 7/7 | ✅ 8/8 | ✅ 8/8 | ✅ 7/7 |

✅ = all checks pass. Each run checks: startup, benign flows + reception, the no-server-session fact, state reset, block attribution for the arm, large-response handling (where an asset > 64 KiB exists), teardown and check-clean.

## Failures and causes

None — every run passed every check.

## Large-response delivery

The cascade gateway uses `body_size_limit=16m` in both directions; the front keeps its 64 KiB request-body cap. The CRS comparator and the direct arm do not use the cascade response limit.

| App | arm | asset | size (B) | status | capped 502? |
|---|---|---|---|---|---|
| An0nB0ard | crs | `/static/css/bootstrap.min.css` | 82972 | 200 | no |
| An0nB0ard | direct | `/static/css/bootstrap.min.css` | 82972 | 200 | no |
| An0nB0ard | guarded | `/static/css/bootstrap.min.css` | 82972 | 200 | no |
| An0nB0ard | v5only | `/static/css/bootstrap.min.css` | 82972 | 200 | no |
| CatP1cs | crs | `/show?img=alba.jpg` | 76673 | 200 | no |
| CatP1cs | crs | `/static/img/blackcat.gif` | 8106213 | 200 | no |
| CatP1cs | direct | `/show?img=alba.jpg` | 76673 | 200 | no |
| CatP1cs | direct | `/static/img/blackcat.gif` | 8106213 | 200 | no |
| CatP1cs | guarded | `/show?img=alba.jpg` | 76673 | 200 | no |
| CatP1cs | guarded | `/static/img/blackcat.gif` | 8106213 | 200 | no |
| CatP1cs | v5only | `/show?img=alba.jpg` | 76673 | 200 | no |
| CatP1cs | v5only | `/static/img/blackcat.gif` | 8106213 | 200 | no |
| ObC00ki3s | crs | `/static/img/bunchofcookies.jpeg` | 135981 | 200 | no |
| ObC00ki3s | direct | `/static/img/bunchofcookies.jpeg` | 135981 | 200 | no |
| ObC00ki3s | guarded | `/static/img/bunchofcookies.jpeg` | 135981 | 200 | no |
| ObC00ki3s | v5only | `/static/img/bunchofcookies.jpeg` | 135981 | 200 | no |

