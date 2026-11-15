"""D72-ratified #80 row-contract addendum; no dataset permission is implicit.

TRAINING_REFERENCE is a training reference admitted under an explicit contract.
Its provenance lives in label_status_basis; category audit outcomes stay separate.
Existing policy IDs and M-3 retain their meaning.
"""
SCHEMA = 'v5-training-reference-contract/v1-PROPOSED'
TRAINING_REFERENCE = 'TRAINING_REFERENCE'


def is_reference(meta, *, contract=None):
    return (contract == SCHEMA and meta.get('label_status') == TRAINING_REFERENCE
            and meta.get('label') == 'BLOCK' and meta.get('label_status_basis') == 'ai_audit'
            and meta.get('policy_id') is None and meta.get('label_rule') == 'ATTACK_POOL_LEAF')

RATIFICATION = 'D72'
