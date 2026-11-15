"""Runtime profile identity and admission failures, without GPU dependencies."""
import hashlib,json,sys,tempfile,unittest
from types import SimpleNamespace
from unittest.mock import Mock,patch
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'control_plane'))
from v5_runtime_profile import load_profile,load_decoder,RuntimeProfileError
import v5_inference_core as core

class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.path=Path(self.tmp.name)/'profile.json'
        self.obj=dict(schema='v5-inference-profile/v1',profile_id='test',status='EXPERIMENTAL',precision='nf4',double_quant=False,recipe_sha256='a'*64,adapter_sha256='b'*64)
    def load(self,**overrides):
        self.path.write_text(json.dumps(self.obj));digest=hashlib.sha256(self.path.read_bytes()).hexdigest()
        args=dict(expected_sha256=digest,recipe_sha256='a'*64,adapter_sha256='b'*64,allow_experimental=True);args.update(overrides)
        return load_profile(self.path,**args)
    def test_explicit_experimental_profile(self):
        p=self.load();self.assertEqual(p.precision,'nf4');self.assertFalse(p.double_quant);self.assertEqual(p.summary()['status'],'EXPERIMENTAL')
    def test_experiment_is_not_enabled_by_default(self):
        with self.assertRaisesRegex(RuntimeProfileError,'opt-in'):self.load(allow_experimental=False)
    def test_full_digest_required(self):
        with self.assertRaisesRegex(RuntimeProfileError,'full profile'):self.load(expected_sha256=None)
    def test_tampered_profile_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError,'mismatch'):self.load(expected_sha256='c'*64)
    def test_wrong_recipe_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError,'not bound'):self.load(recipe_sha256='c'*64)
    def test_wrong_adapter_rejected(self):
        with self.assertRaisesRegex(RuntimeProfileError,'not bound'):self.load(adapter_sha256='c'*64)
    def test_unknown_schema_rejected(self):
        self.obj['schema']='other'
        with self.assertRaisesRegex(RuntimeProfileError,'schema'):self.load()
    def test_bf16_double_quant_is_invalid(self):
        self.obj.update(precision='bf16',double_quant=True)
        with self.assertRaisesRegex(RuntimeProfileError,'BF16'):self.load()
    def test_unknown_precision_rejected(self):
        self.obj['precision']='int4-new'
        with self.assertRaisesRegex(RuntimeProfileError,'unsupported'):self.load()
    def test_string_boolean_rejected(self):
        self.obj['double_quant']='false'
        with self.assertRaisesRegex(RuntimeProfileError,'type'):self.load()
    def test_false_approval_rejected(self):
        self.obj['status']='APPROVED'
        with self.assertRaisesRegex(RuntimeProfileError,'owner decision'):self.load()
    def test_draft_cannot_enable_service(self):
        self.obj['status']='DRAFT_PENDING_OWNER'
        with self.assertRaisesRegex(RuntimeProfileError,'not enabled'):self.load()


    def decoder_profile(self):
        self.obj.update(schema='v5-inference-profile/v2',decoder='verified_suffix/v1',decoder_sha256='d'*64)
    def test_decoder_is_explicit_and_hash_bound(self):
        self.decoder_profile();p=self.load()
        self.assertEqual(p.summary()['decoder'],'verified_suffix/v1')
        with self.assertRaisesRegex(RuntimeProfileError,'implementation SHA'):load_decoder(p)
    def test_decoder_intent_cannot_be_silently_ignored_by_v1(self):
        self.obj['decoder']='verified_suffix/v1'
        with self.assertRaisesRegex(RuntimeProfileError,'schema v2'):self.load()
    def test_unbound_decoder_is_rejected(self):
        self.decoder_profile();self.obj.pop('decoder_sha256')
        with self.assertRaisesRegex(RuntimeProfileError,'unbound decoder'):self.load()
    def test_decoder_cannot_select_unmeasured_bf16(self):
        self.decoder_profile();self.obj['precision']='bf16'
        with self.assertRaisesRegex(RuntimeProfileError,'measured NF4'):self.load()
    def test_decoder_cannot_implicitly_select_double_quant(self):
        self.decoder_profile();self.obj['double_quant']=True
        with self.assertRaisesRegex(RuntimeProfileError,'measured NF4'):self.load()


class ArtifactRaceTests(unittest.TestCase):
    def modules(self):
        factory=Mock()
        return factory,{'torch':SimpleNamespace(bfloat16='bf16'),
            'peft':SimpleNamespace(PeftModel=Mock()),
            'transformers':SimpleNamespace(AutoModelForCausalLM=factory,
                AutoTokenizer=Mock(),BitsAndBytesConfig=Mock())}
    def test_recipe_change_refused_before_model_allocation(self):
        factory,modules=self.modules()
        with patch.dict(sys.modules,modules),patch.object(core.D,'load_recipe',return_value=({},'a'*64)),patch.object(core,'load_contract',return_value=SimpleNamespace(recipe_sha256='b'*64)):
            with self.assertRaisesRegex(core.V5ContractError,'recipe changed'):core.load_v5()
        factory.from_pretrained.assert_not_called()
    def test_changed_weight_file_never_becomes_ready(self):
        factory,modules=self.modules()
        contract=SimpleNamespace(recipe_sha256='a'*64,base_model='base',base_revision='rev')
        with patch.dict(sys.modules,modules),patch.object(core.D,'load_recipe',return_value=({'quantization':{}},'a'*64)),patch.object(core,'load_contract',return_value=contract),patch.object(core,'adapter_fingerprint',side_effect=['b'*64,'c'*64]):
            with self.assertRaisesRegex(core.V5ContractError,'weights changed'):core.load_v5()

if __name__=='__main__':unittest.main()
