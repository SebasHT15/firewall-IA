"""Hash-bound inference overrides. Does not change the training/template recipe."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

SCHEMA = 'v5-inference-profile/v1'
DECODER_SCHEMA = 'v5-inference-profile/v2'


class RuntimeProfileError(ValueError):
    pass


@dataclass(frozen=True)
class RuntimeProfile:
    profile_id: str
    sha256: str
    status: str
    precision: str
    double_quant: bool
    recipe_sha256: str
    adapter_sha256: str
    schema: str = SCHEMA
    decoder: str = 'native'
    decoder_sha256: str | None = None

    def summary(self):
        result = {
            'schema': self.schema, 'profile_id': self.profile_id, 'sha256': self.sha256,
            'status': self.status, 'precision': self.precision,
            'double_quant': self.double_quant,
            'recipe_sha256': self.recipe_sha256, 'adapter_sha256': self.adapter_sha256,
        }
        if self.schema == DECODER_SCHEMA:
            result.update(decoder=self.decoder,decoder_sha256=self.decoder_sha256)
        return result


def load_decoder(profile):
    """Load only the locally measured implementation, from the bytes just hashed."""
    if profile.decoder == 'native':return None
    import types
    path=Path(__file__).resolve().parents[1]/'scripts/v5_successor/verified_suffix.py'
    raw=path.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=profile.decoder_sha256:
        raise RuntimeProfileError('decoder implementation SHA-256 mismatch')
    module=types.ModuleType('v5_bound_verified_suffix')
    module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    return module


def load_profile(path, *, expected_sha256, recipe_sha256, adapter_sha256,
                 allow_experimental=False):
    """Refuse unknown/unbound profiles before allocating GPU memory."""
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise RuntimeProfileError('explicit full profile SHA-256 is required')
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise RuntimeProfileError('runtime profile SHA-256 mismatch')
    obj = json.loads(raw)
    if not isinstance(obj, dict) or obj.get('schema') not in (SCHEMA,DECODER_SCHEMA):
        raise RuntimeProfileError('unknown runtime profile schema')
    if obj.get('recipe_sha256') != recipe_sha256 or obj.get('adapter_sha256') != adapter_sha256:
        raise RuntimeProfileError('profile is not bound to this recipe and adapter')
    for name in ('recipe_sha256', 'adapter_sha256'):
        if not isinstance(obj.get(name), str) or not re.fullmatch('[0-9a-f]{64}', obj[name]):
            raise RuntimeProfileError('invalid artifact hash')
    status = obj.get('status')
    if status == 'EXPERIMENTAL':
        if allow_experimental is not True:
            raise RuntimeProfileError('experimental runtime requires explicit opt-in')
    elif status == 'APPROVED':
        if not all(isinstance(obj.get(k), str) and obj[k].strip()
                   for k in ('owner_decision', 'approved_by', 'approval_date')):
            raise RuntimeProfileError('approved runtime lacks owner decision provenance')
    else:
        raise RuntimeProfileError('runtime profile is not enabled')
    precision = obj.get('precision')
    double_quant = obj.get('double_quant')
    if precision not in ('nf4', 'bf16') or type(double_quant) is not bool:
        raise RuntimeProfileError('unsupported precision or double_quant type')
    if precision == 'bf16' and double_quant:
        raise RuntimeProfileError('BF16 cannot request 4-bit double quantization')
    pid = obj.get('profile_id')
    if not isinstance(pid, str) or not pid.strip():
        raise RuntimeProfileError('profile_id is required')
    decoder,decoder_sha='native',None
    if obj['schema']==SCHEMA:
        if 'decoder' in obj or 'decoder_sha256' in obj:
            raise RuntimeProfileError('decoder selection requires profile schema v2')
    else:
        decoder,decoder_sha=obj.get('decoder'),obj.get('decoder_sha256')
        if decoder!='verified_suffix/v1' or not isinstance(decoder_sha,str) or not re.fullmatch('[0-9a-f]{64}',decoder_sha):
            raise RuntimeProfileError('unknown or unbound decoder')
        if precision!='nf4' or double_quant:
            raise RuntimeProfileError('verified suffix currently requires measured NF4 without double quantization')
    return RuntimeProfile(pid, expected_sha256, status, precision, double_quant,
                          recipe_sha256, adapter_sha256,obj['schema'],decoder,decoder_sha)
