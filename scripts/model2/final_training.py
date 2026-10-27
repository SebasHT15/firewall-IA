"""Model 2 FINAL adapter over the shared V5 dataset reader.

D73 ratifies the authorization schema, recipes and C1 contract. Every FINAL run
still needs a separate complete committed permission and eligible frozen data. No runtime policy or operating threshold.
"""
import argparse
from dataclasses import dataclass
import json
from pathlib import Path
import sys

from . import training as T
from .v5_fixture_integration import exchange

PROPOSED_AUTH_SCHEMA = 'model2-final-training-authorization/v1-PROPOSED'
FINAL_AUTH_SCHEMA = PROPOSED_AUTH_SCHEMA  # D73; concrete committed permission still mandatory.
EVIDENCE_SCHEMA = 'model2-final-training-evidence/proposal-v1'


class FinalRefused(ValueError):
    pass


def library_versions():
    import numpy
    import sklearn
    return {'python': sys.version.split()[0], 'numpy': numpy.__version__, 'sklearn': sklearn.__version__}


def reader_hashes():
    # Pin the shared implementation and its local source modules, not V5 library requirements.
    paths = set(T.READER_SOURCES)
    for folder in ('scripts/training', 'scripts/dataset'):
        paths.update(str(p.relative_to(T.ROOT)) for p in (T.ROOT/folder).glob('*.py'))
    paths.add('control_plane/v5_tokenization.py')
    return {name: T.digest((T.ROOT/name).read_bytes()) for name in sorted(paths)}


def guarded_path(path):
    p = Path(path).resolve()
    try:
        exchange.D.C.assert_not_protected(str(p))
    except SystemExit as e:
        raise FinalRefused('protected input path') from e
    if any('e6_reserve' in s.lower() or 'stab-held' in s.lower() or 'stab_held' in s.lower()
           for s in p.parts):
        raise FinalRefused('protected input path')
    return p


def capture(path, *, committed=False):
    p = guarded_path(path)
    if committed and not exchange.D.git_committed_unmodified(str(p)):
        raise FinalRefused(f'record must be committed and unmodified: {p.name}')
    raw = p.read_bytes()
    return p, raw, T.digest(raw)


def _require_text(obj, key):
    if type(obj.get(key)) is not str or not obj[key].strip():
        raise FinalRefused(f'missing text field: {key}')


def _hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def validate_c1(contract, recipe):
    if type(contract) is not dict or contract.get('schema') != 'model2-c1-training-input/proposal-v1':
        raise FinalRefused('C1 contract schema mismatch')
    if contract.get('status') != 'RATIFIED':
        raise FinalRefused('C1 contract is not ratified')
    _require_text(contract, 'owner_decision')
    expected = list(T.features.FEATURES)
    ablated = [x for x in expected if x not in T.features.DIRECT_PATH_FIELDS]
    if (contract.get('baseline_fields') != expected or contract.get('ablated_fields') != ablated
            or contract.get('representation') != T.features.REPRESENTATION
            or contract.get('canonical_outcome_required') != 'ACCEPT'
            or contract.get('c1_extension_fields') != 'metadata_only; no learned admission'):
        raise FinalRefused('C1 contract differs from implemented feature semantics')
    return expected if recipe['feature_view'] == 'baseline_34' else ablated


def validate_evidence(evidence, recipe, manifest_sha):
    if type(evidence) is not dict or evidence.get('schema') != EVIDENCE_SCHEMA:
        raise FinalRefused('FINAL evidence missing')
    auth = evidence.get('authorization')
    if type(auth) is not dict or FINAL_AUTH_SCHEMA is None or auth.get('schema') != FINAL_AUTH_SCHEMA:
        raise FinalRefused('FINAL authorization schema is not ratified')
    if auth.get('scope') != 'FINAL_OFFLINE_MODEL2' or auth.get('status') != 'AUTHORIZED':
        raise FinalRefused('FINAL authorization scope/status mismatch')
    for key in ('owner_decision', 'authorized_by', 'date'):
        _require_text(auth, key)
    if auth.get('recipe_sha256') != T.digest(T.encode(recipe)) or auth.get('dataset_manifest_sha256') != manifest_sha:
        raise FinalRefused('FINAL authorization recipe/dataset binding mismatch')
    hashes = evidence.get('record_sha256')
    if type(hashes) is not dict or not _hash(hashes.get('authorization')):
        raise FinalRefused('FINAL record evidence missing')
    for name in ('recipe_file', 'c1_contract', 'selection_protocol', 'dataset_preregistration',
                 'freeze_record', 'vocabulary_recipe'):
        if not _hash(hashes.get(name)) or auth.get(name+'_sha256') != hashes[name]:
            raise FinalRefused(f'FINAL record binding mismatch: {name}')
    ai = hashes.get('ai_audit_authorization')
    if (ai is not None and not _hash(ai)) or auth.get('ai_audit_authorization_sha256') != ai:
        raise FinalRefused('FINAL AI authorization binding mismatch')
    ds = evidence.get('dataset_final_evidence')
    if (type(ds) is not dict or ds.get('mode') != 'FINAL' or ds.get('manifest_sha256') != manifest_sha
            or ds.get('splits_opened') != ['TRAIN', 'VALIDATION']):
        raise FinalRefused('shared FINAL dataset evidence mismatch')
    for field, name in (('preregistration_sha256','dataset_preregistration'),
                        ('freeze_record_sha256','freeze_record'),
                        ('ai_audit_authorization_sha256','ai_audit_authorization')):
        if ds.get(field) != hashes.get(name):
            raise FinalRefused(f'shared FINAL record evidence mismatch: {field}')
    if ds.get('vocabulary_bound_to_preregistration') is not True or not ds.get('vocabulary_id'):
        raise FinalRefused('shared FINAL vocabulary is not bound to the dataset preregistration')
    if ds.get('audit_type') == 'ai_audited' and ai is None:
        raise FinalRefused('AI audit requires its separate dataset authorization')
    if auth.get('source_sha256') != T.source_hashes() or auth.get('reader_source_sha256') != reader_hashes():
        raise FinalRefused('FINAL source binding mismatch')
    if auth.get('library_versions') != library_versions():
        raise FinalRefused('FINAL library versions mismatch')


@dataclass
class PreparedFinal:
    examples: dict
    recipe: dict
    evidence: dict
    captures: dict
    manifest_path: Path
    manifest_sha256: str


def _unchanged(prepared):
    for name, (path, expected) in prepared.captures.items():
        if T.digest(path.read_bytes()) != expected or not exchange.D.git_committed_unmodified(str(path)):
            raise FinalRefused(f'record changed during FINAL: {name}')
    if T.digest(prepared.manifest_path.read_bytes()) != prepared.manifest_sha256:
        raise FinalRefused('manifest changed during FINAL')
    if not exchange.D.git_state().get('clean'):
        raise FinalRefused('FINAL requires a clean tracked tree')
    validate_evidence(prepared.evidence, prepared.recipe, prepared.manifest_sha256)


def prepare_final(dataset, *, recipe_path, c1_contract, selection_protocol, authorization,
                  dataset_prereg, freeze_record, vocabulary_recipe, ai_audit_authorization=None):
    # This deliberate default-off gate runs before opening any caller input.
    if FINAL_AUTH_SCHEMA is None:
        raise FinalRefused('FINAL authorization schema is not ratified; owner decision pending')
    files = dict(recipe_file=recipe_path, c1_contract=c1_contract, selection_protocol=selection_protocol,
                 authorization=authorization, dataset_preregistration=dataset_prereg,
                 freeze_record=freeze_record, vocabulary_recipe=vocabulary_recipe)
    if ai_audit_authorization is not None:
        files['ai_audit_authorization'] = ai_audit_authorization
    captures, parsed, hashes = {}, {}, {'ai_audit_authorization': None}
    for name, path in files.items():
        p, raw, sha = capture(path, committed=True)
        captures[name] = (p, sha)
        hashes[name] = sha
        if name in ('recipe_file', 'c1_contract', 'authorization'):
            parsed[name] = json.loads(raw)
        elif name == 'selection_protocol' and not raw.strip():
            raise FinalRefused('selection protocol is empty')
    recipe, auth = parsed['recipe_file'], parsed['authorization']
    T.validate_recipe(recipe, 'FINAL')
    validate_c1(parsed['c1_contract'], recipe)
    if type(auth) is not dict or auth.get('schema') != FINAL_AUTH_SCHEMA:
        raise FinalRefused('FINAL authorization schema mismatch')
    for name, sha in hashes.items():
        if name != 'authorization' and auth.get(name+'_sha256') != sha:
            raise FinalRefused(f'FINAL record binding mismatch: {name}')
    if auth.get('recipe_sha256') != T.digest(T.encode(recipe)):
        raise FinalRefused('FINAL recipe binding mismatch')
    if auth.get('scope') != 'FINAL_OFFLINE_MODEL2' or auth.get('status') != 'AUTHORIZED':
        raise FinalRefused('FINAL authorization scope/status mismatch')
    for key in ('owner_decision', 'authorized_by', 'date'):
        _require_text(auth, key)
    if auth.get('source_sha256') != T.source_hashes() or auth.get('reader_source_sha256') != reader_hashes():
        raise FinalRefused('FINAL source binding mismatch')
    if auth.get('library_versions') != library_versions():
        raise FinalRefused('FINAL library versions mismatch')
    if not exchange.D.git_state().get('clean'):
        raise FinalRefused('FINAL requires a clean tracked tree')
    for name in set(auth['source_sha256']) | set(auth['reader_source_sha256']):
        if not exchange.D.git_committed_unmodified(str(T.ROOT/name)):
            raise FinalRefused(f'FINAL source not committed: {name}')
    root = guarded_path(dataset)
    manifest_path, raw, manifest_sha = capture(root/'manifest.json')
    manifest = json.loads(raw)
    if (manifest.get('fixture') is True or manifest.get('status') != 'REAL'
            or manifest.get('generator_config', {}).get('mode') != 'real'):
        raise FinalRefused('FINAL refuses fixture or provisional datasets')
    if manifest_sha != auth.get('dataset_manifest_sha256'):
        raise FinalRefused('FINAL dataset binding mismatch')
    # Resolve only the four permitted row/meta paths. Never open a protected role.
    for split in ('TRAIN', 'VALIDATION'):
        for pattern in (exchange.D.ROWS_FILE, exchange.D.META_FILE):
            path = guarded_path(root/pattern.format(split=split))
            if not path.is_relative_to(root):
                raise FinalRefused('row artifact escapes dataset directory')
    bundle = exchange.load_final_examples(str(root), dataset_prereg=str(captures['dataset_preregistration'][0]),
        freeze_record=str(captures['freeze_record'][0]), recipe_path=str(captures['vocabulary_recipe'][0]),
        ai_audit_authorization=str(captures['ai_audit_authorization'][0]) if ai_audit_authorization else None)
    examples, ds = bundle['examples'], bundle['dataset_final_evidence']
    _, consumed_manifest = T._validate_examples(examples)
    if consumed_manifest != manifest_sha or ds.get('rows') != {s: len(rs) for s,rs in examples.items()}:
        raise FinalRefused('shared FINAL examples/evidence binding mismatch')
    evidence = {'schema': EVIDENCE_SCHEMA, 'authorization': auth, 'record_sha256': hashes,
                'dataset_final_evidence': ds}
    prepared = PreparedFinal(examples, recipe, evidence, captures, manifest_path, manifest_sha)
    _unchanged(prepared)
    return prepared


def train_final(dataset, **kwargs):
    prepared = prepare_final(dataset, **kwargs)
    artifact, report = T._fit(prepared.examples, prepared.recipe, 'FINAL', final_evidence=prepared.evidence)
    _unchanged(prepared)  # No artifact returned or written if records/code changed during fitting.
    report['final_training_evidence'] = prepared.evidence
    return artifact, report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--dataset', type=Path, required=True)
    for flag in ('recipe-path', 'c1-contract', 'selection-protocol', 'authorization',
                 'dataset-prereg', 'freeze-record', 'vocabulary-recipe'):
        ap.add_argument('--'+flag, type=Path, required=True)
    ap.add_argument('--ai-audit-authorization', type=Path)
    ap.add_argument('--gate-only', action='store_true')
    ap.add_argument('--output', type=Path)
    args = vars(ap.parse_args())
    gate_only, output, dataset = args.pop('gate_only'), args.pop('output'), args.pop('dataset')
    if output and output.exists():
        ap.error('output already exists')
    if not gate_only and output is None:
        ap.error('--output required for training')
    if output:
        guarded_path(output)
    try:
        if gate_only:
            prepared = prepare_final(dataset, **args)
            print(json.dumps({'status': 'FINAL_GATES_PASSED', 'trained': False,
                              'evidence': prepared.evidence}, indent=2))
        else:
            artifact, report = train_final(dataset, **args)
            sha = T.save_artifact(artifact, output)
            T.load_artifact(output, expected_sha256=sha)
            print(json.dumps({**report, 'artifact_sha256': sha}, indent=2))
    except (OSError, ValueError) as e:
        print(json.dumps({'status': 'REFUSED', 'reason': str(e)}, indent=2))
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
