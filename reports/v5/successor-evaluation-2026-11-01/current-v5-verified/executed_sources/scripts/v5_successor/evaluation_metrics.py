"""Strict, payload-free DEVELOPMENT evaluation of a versioned V5 successor.

No fitting, threshold selection or protected input reader. Model quality (E5)
and runtime fail-closed behavior deliberately have different denominators.
"""
from collections import Counter, defaultdict
import math
import random


def ratio(n, d):
    return n / d if d else None


def distribution(values):
    values = sorted(values)
    if any(type(v) not in (float, int) or not math.isfinite(v) or v < 0 for v in values):
        raise ValueError('latencies must be finite and nonnegative')
    if not values:
        return {'n': 0}
    return dict(n=len(values), mean=sum(values)/len(values), min=values[0], max=values[-1],
                **{f'p{p}': values[max(0, math.ceil(p*len(values)/100)-1)] for p in (50, 95, 99)},
                p99_low_sample=len(values) < 100)


def confusion(cells):
    counts = Counter(cells)
    tp, tn, fp, fn = (counts[k] for k in ('TP', 'TN', 'FP', 'FN'))
    recall, specificity = ratio(tp, tp+fn), ratio(tn, tn+fp)
    denominator = (tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    f1b, f1a = ratio(2*tp, 2*tp+fp+fn), ratio(2*tn, 2*tn+fp+fn)
    return dict(TP=tp, TN=tn, FP=fp, FN=fn, N=sum(counts.values()),
                accuracy=ratio(tp+tn, sum(counts.values())), precision_block=ratio(tp, tp+fp),
                recall_block=recall, fpr=ratio(fp, fp+tn), fnr=ratio(fn, fn+tp),
                specificity=specificity, negative_predictive_value=ratio(tn, tn+fn),
                f1_block=f1b, f2_block=ratio(5*tp, 5*tp+4*fn+fp), f1_allow=f1a,
                macro_f1=(f1a+f1b)/2 if f1a is not None and f1b is not None else None,
                balanced_accuracy=(recall+specificity)/2 if recall is not None and specificity is not None else None,
                mcc=(tp*tn-fp*fn)/math.sqrt(denominator) if denominator else None)


def prediction_cell(case, prediction):
    """Malformed/inconsistent replies cannot earn decision credit."""
    label = case['label']
    if label not in ('ALLOW', 'BLOCK'):
        raise ValueError('unknown reference label')
    decision = prediction.get('decision')
    valid = (prediction.get('status') == 'ok' and decision in ('ALLOW', 'BLOCK')
             and prediction.get('invalid_reason') is None)
    correct = valid and decision == label
    cell = ('TP' if correct else 'FN') if label == 'BLOCK' else ('TN' if correct else 'FP')
    if not valid:
        decision = None
    return cell, valid, decision


def quality(cases, predictions):
    if len(cases) != len(predictions):
        raise ValueError('case/prediction count differs')
    cells, parseable, runtime = [], [], []
    invalid = Counter()
    reason_eligible = reason_correct = reason_on_correct_block = correct_block = 0
    for case, prediction in zip(cases, predictions):
        cell, valid, decision = prediction_cell(case, prediction)
        cells.append(cell)
        if valid:
            parseable.append(cell)
        else:
            invalid[str(prediction.get('invalid_reason') or prediction.get('status') or 'missing_status')] += 1
        # A reported model decision and a runtime denial are NOT interchangeable.
        # This view is a derivation of the fail-closed rule, not observed delivery.
        denied = decision == 'BLOCK' or not valid
        runtime.append(('TP' if denied else 'FN') if case['label'] == 'BLOCK' else ('FP' if denied else 'TN'))
        if case['label'] == 'BLOCK' and case.get('expected_reason'):
            reason_eligible += 1
            if decision == 'BLOCK':
                correct_block += 1
                if prediction.get('reason') == case['expected_reason']:
                    reason_correct += 1
                    reason_on_correct_block += 1
    return dict(principal_E5=confusion(cells), parseable_only=confusion(parseable),
                invalid=dict(n=sum(invalid.values()), rate=ratio(sum(invalid.values()), len(cases)),
                             reasons=dict(invalid)),
                reason=dict(eligible_block_cases=reason_eligible, exact_correct=reason_correct,
                            exact_rate_over_eligible=ratio(reason_correct, reason_eligible),
                            exact_rate_given_correct_block=ratio(reason_on_correct_block, correct_block)),
                runtime_fail_closed_derived=dict(confusion=confusion(runtime),
                    provenance='DERIVED fail-closed action; NOT observed upstream delivery or exploit prevention'))


def checked_predictions(cases, predictions):
    ids = [c['id'] for c in cases]
    if len(set(ids)) != len(ids):
        raise ValueError('duplicate reference IDs')
    index = {}
    for p in predictions:
        cid = p.get('id')
        if cid in index:
            raise ValueError('duplicate prediction ID')
        index[cid] = p
    if set(index) != set(ids):
        raise ValueError('missing/extra prediction IDs')
    ordered = [index[cid] for cid in ids]
    for case, p in zip(cases, ordered):
        if p.get('canonical_sha256') != case['canonical_sha256']:
            raise ValueError('prediction text hash does not match reference')
        prediction_cell(case, p)
    return ordered


def pairs(cases, predictions):
    groups = defaultdict(list)
    for case, pred in zip(cases, predictions):
        if case.get('pair_id'):
            groups[case['pair_id']].append((case, pred))
    complete = joint = benign_errors = attack_errors = incomplete = 0
    for group in groups.values():
        if len(group) != 2 or {c['label'] for c, _ in group} != {'ALLOW', 'BLOCK'}:
            incomplete += 1
            continue
        complete += 1
        correctness = {c['label']: prediction_cell(c, p)[0] in ('TP', 'TN') for c, p in group}
        joint += all(correctness.values())
        benign_errors += not correctness['ALLOW']
        attack_errors += not correctness['BLOCK']
    return dict(complete_pairs=complete, incomplete_or_ambiguous_pairs=incomplete,
                both_correct=joint, joint_accuracy=ratio(joint, complete),
                benign_errors=benign_errors, attack_errors=attack_errors)


def cluster_bootstrap(cases, predictions, *, replicates=1000, seed=20261101):
    """Resample complete declared source components; never invent row independence.

    Not a population certification: templates and sources can induce crossed
    dependence; small numbers of source components make intervals unstable.
    """
    if replicates < 1:
        raise ValueError('bootstrap replicates must be positive')
    groups = defaultdict(list)
    for case, pred in zip(cases, predictions):
        if not case.get('component_id'):
            return dict(status='NOT_ESTIMABLE', reason='missing declared component; no row-IID substitute')
        groups[case['component_id']].append(prediction_cell(case, pred)[0])
    if len(groups) < 2:
        return dict(status='NOT_ESTIMABLE', components=len(groups), reason='fewer than two components')
    keys = sorted(groups)
    rng = random.Random(seed)
    samples = defaultdict(list)
    for _ in range(replicates):
        cells = [cell for key in rng.choices(keys, k=len(keys)) for cell in groups[key]]
        result = confusion(cells)
        for name in ('accuracy', 'recall_block', 'fpr', 'f1_block'):
            if result[name] is not None:
                samples[name].append(result[name])
    intervals = {}
    for name, values in samples.items():
        values.sort()
        intervals[name] = dict(low=values[max(0, math.ceil(.025*len(values))-1)],
                               high=values[max(0, math.ceil(.975*len(values))-1)],
                               valid_replicates=len(values))
    return dict(status='DESCRIPTIVE_COMPONENT_BOOTSTRAP', components=len(groups),
                replicates=replicates, seed=seed, intervals_95=intervals,
                warning='Development/selection data; source clustering does not remove template dependence. '
                        'No generalization, rare-FPR or population security guarantee.')


def paired_comparison(cases, left, right, *, replicates=1000, seed=20261101):
    """Right minus left, sharing each sampled component between both models."""
    a, b = checked_predictions(cases, left), checked_predictions(cases, right)
    improved = regressed = 0
    groups = defaultdict(list)
    for c, p, q in zip(cases, a, b):
        pc, qc = prediction_cell(c, p)[0], prediction_cell(c, q)[0]
        old, new = pc in ('TP', 'TN'), qc in ('TP', 'TN')
        improved += new and not old
        regressed += old and not new
        groups[c.get('component_id')].append((pc, qc))
    n = improved + regressed
    # Exact two-sided McNemar via binomial recurrence; use log-space for large n.
    if n:
        k = min(improved, regressed)
        log_terms = [math.lgamma(n+1)-math.lgamma(i+1)-math.lgamma(n-i+1)-n*math.log(2) for i in range(k+1)]
        peak = max(log_terms)
        p_value = min(1.0, 2*math.exp(peak)*sum(math.exp(v-peak) for v in log_terms))
    else:
        p_value = 1.0
    result = dict(N=len(cases), improved=improved, regressed=regressed,
                  accuracy_delta=ratio(improved-regressed, len(cases)),
                  mcnemar_exact_nominal_iid_p=p_value,
                  warning='Nominal row-IID test only; dependent DEV cases do not establish significance.')
    if None in groups or len(groups) < 2:
        result['component_delta_interval'] = dict(status='NOT_ESTIMABLE')
        return result
    rng = random.Random(seed)
    keys = sorted(groups)
    samples = defaultdict(list)
    for _ in range(replicates):
        selected = [cell for key in rng.choices(keys, k=len(keys)) for cell in groups[key]]
        x, y = confusion([p for p, _ in selected]), confusion([q for _, q in selected])
        for name in ('accuracy', 'recall_block', 'fpr', 'f1_block'):
            if x[name] is not None and y[name] is not None:
                samples[name].append(y[name]-x[name])
    result['component_delta_interval'] = {name: dict(low=sorted(v)[max(0, math.ceil(.025*len(v))-1)],
        high=sorted(v)[max(0, math.ceil(.975*len(v))-1)], valid_replicates=len(v)) for name, v in samples.items()}
    return result


def probability_metrics(cases, predictions, thresholds):
    """Model 2 score diagnostics and selective BLOCK/DEFER, not binary accuracy."""
    scores = []
    for c, p in zip(cases, predictions):
        value = p.get('p_block')
        if p.get('status') != 'OK' or type(value) not in (int, float) or not math.isfinite(value) or not 0 <= value <= 1:
            raise ValueError('probability diagnostics require one finite successful score per case')
        scores.append((float(value), int(c['label'] == 'BLOCK')))
    if any(type(t) not in (int, float) or not math.isfinite(t) or not 0 < t <= 1 for t in thresholds):
        raise ValueError('invalid threshold grid')
    positives = sum(y for _, y in scores)
    negatives = len(scores)-positives
    grouped = defaultdict(list)
    for score, y in scores:
        grouped[score].append(y)
    # AUC with ties at half credit; AP updates all tied scores together.
    lower_negatives = concordant = 0
    for score in sorted(grouped):
        ys = grouped[score]
        pos, neg = sum(ys), len(ys)-sum(ys)
        concordant += pos*(lower_negatives+.5*neg)
        lower_negatives += neg
    tp = fp = 0
    ap = 0.0
    for score in sorted(grouped, reverse=True):
        ys = grouped[score]
        pos = sum(ys)
        tp += pos
        fp += len(ys)-pos
        if positives:
            ap += pos/positives*tp/(tp+fp)
    bins = []
    for i in range(10):
        sub = [(p, y) for p, y in scores if min(9, int(p*10)) == i]
        bins.append(dict(low=i/10, high=(i+1)/10, n=len(sub),
                         mean_score=ratio(sum(p for p, _ in sub), len(sub)),
                         block_fraction=ratio(sum(y for _, y in sub), len(sub))))
    grid = []
    for threshold in thresholds:
        tp = sum(p >= threshold and y == 1 for p, y in scores)
        fp = sum(p >= threshold and y == 0 for p, y in scores)
        grid.append(dict(threshold=threshold, early_block_tp=tp, early_block_fp=fp,
                         early_block_attack_rate=ratio(tp, positives), early_block_fpr=ratio(fp, negatives),
                         block_precision=ratio(tp, tp+fp), defer_rate=ratio(len(scores)-tp-fp, len(scores))))
    return dict(N=len(scores), prevalence=ratio(positives, len(scores)),
                roc_auc=ratio(concordant, positives*negatives), average_precision=ap if positives else None,
                brier=ratio(sum((p-y)**2 for p, y in scores), len(scores)),
                log_loss=ratio(sum(-(y*math.log(max(p, 1e-15))+(1-y)*math.log(max(1-p, 1e-15))) for p, y in scores), len(scores)),
                ece_10bins=ratio(sum(b['n']*abs(b['mean_score']-b['block_fraction']) for b in bins if b['n']), len(scores)),
                reliability_bins=bins, descriptive_thresholds=grid, selected_threshold=None,
                warning='DEV/reference agreement, prevalence dependent. No operational calibration or threshold approval.')


def report(cases, predictions, *, bootstrap_replicates=1000):
    ordered = checked_predictions(cases, predictions)
    slices = {}
    for field in ('cohort', 'category', 'carrier', 'family', 'component_id', 'length_bin', 'label_basis'):
        groups = defaultdict(list)
        for c, p in zip(cases, ordered):
            groups[str(c.get(field) or 'unknown')].append((c, p))
        slices[field] = {name: quality([c for c, _ in sub], [p for _, p in sub]) for name, sub in sorted(groups.items())}
    cohorts = {}
    for name in sorted({c['cohort'] for c in cases}):
        selected = [(c, p) for c, p in zip(cases, ordered) if c['cohort'] == name]
        cohorts[name] = cluster_bootstrap([c for c, _ in selected], [p for _, p in selected], replicates=bootstrap_replicates)
    latency = {}
    for phase in ('cold', 'warmup', 'quality', 'benchmark'):
        sub = [p for p in ordered if p.get('phase') == phase]
        latency[phase] = {name: distribution([p[name] for p in sub if p.get(name) is not None])
                          for name in ('roundtrip_ms', 'pipeline_ms', 'queue_wait_ms')}
    return dict(schema='v51-development-quality-report/v1', N=len(cases),
                quality=quality(cases, ordered), minimal_pairs=pairs(cases, ordered),
                slices=slices, component_bootstrap_by_cohort=cohorts, timing_by_phase=latency,
                warning='Separate cohorts are the primary interpretation. Pooled DEV metrics are descriptive, '
                        'not independent final evaluation. Quality-pass latency is not a controlled benchmark.')
