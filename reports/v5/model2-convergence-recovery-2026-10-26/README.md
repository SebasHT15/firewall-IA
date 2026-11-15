# Model 2 convergence recovery — D82

The owner's original baseline34 FINAL attempt stopped at the D73 max_iter=500 cap with
ConvergenceWarning. No artifact was saved. Its directory
`model-output-model2/final/v4-20261027T022627Z/` and empty redirected report are preserved.

D82 records the owner go-ahead for the disclosed numerical repair. Two successor recipes use
max_iter=5000, with C=1, tol=1e-6, lbfgs, seed=0 and every feature/scaling/data/label rule unchanged.
ConvergenceWarning remains fatal. Both candidates remain offline research candidates without
an operating threshold or winner. Original D73/D81 recipes, protocol and authorizations remain
byte-untouched in their original paths. V5 and its completed training remain unchanged.

`diagnostic-train-only.json` records one ephemeral numerical diagnostic: baseline34 converged at
825 iterations and path-ablation32 at 478, with finite coefficients and no convergence warnings.
Its 5000 budget was fixed before fitting. The authorized loader opened TRAIN and VALIDATION;
only TRAIN was fit, with no VALIDATION prediction, scoring or selection. Weights were discarded.
No FINAL artifact or protected-set evaluation was produced. Its wall times are diagnostic, not
a controlled inference/training benchmark.

`recipe-differences.json` records every recipe change: max_iter and the D82 decision reference.
`selection-protocol.md` preserves the D73 protocol and appends the explicit numerical amendment.
Each authorization separately binds its successor recipe, this protocol, original C1 contract,
v4 freeze/preregistration/AI authorization, and unchanged code/library pins.

After committing these records with a clean tracked tree, run the actual FINAL gate for each
successor using `Entrenar_Model2.sh`'s arguments plus `--gate-only`, saving results outside the
tracked tree. This README does not claim a fit or gate result merely because the records exist.
The owner launch command then checks gates and creates a new `v4-d82-<UTC timestamp>` directory,
fits both candidates, writes their reports/artifacts and verifies JSON reloads. The owner runs it;
the repair work stops at gate-only. No new V5 run is needed.
