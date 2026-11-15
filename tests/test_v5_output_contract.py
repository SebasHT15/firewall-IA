"""Tests for `control_plane/v5_output_contract.py` (V5 stage 2; PROPOSED contract, not wired).

Pure tests run everywhere; tokenizer tests skip without transformers or the local base snapshot.

    python3 -m unittest tests.test_v5_output_contract -v
    HF_HUB_OFFLINE=1 python3.12 -m unittest tests.test_v5_output_contract -v
"""

import ast
import glob
import os
import sys
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "control_plane"))
sys.path.insert(0, os.path.join(REPO, "data_plane"))
sys.path.insert(0, os.path.join(REPO, "scripts", "dataset"))

import v5_output_contract as oc  # noqa: E402
import v5_tokenization as v5  # noqa: E402

ALT_A_FP = "b845921fb410563edfb7a0f2e60565ba9c0cdab15f6cafaa7599ced95d77b400"
ALT_B_FP = "ad93d3b6d0a115ddb313c2dcda37c9f4fb87b11e66914761c92509fb5df4c7e3"


class Vocabulary(unittest.TestCase):
    def test_allow_string_is_the_existing_v4_contract_string(self):
        import parse_dataset_v4
        self.assertEqual(oc.ALLOW_OUTPUT, parse_dataset_v4.ALLOW_LABEL)

    def test_block_strings_come_from_the_v4_d47_reason_vocabulary(self):
        with open(os.path.join(REPO, "scripts", "dataset", "parse_dataset_v4.py"), encoding="utf-8") as fh:
            src = fh.read()
        for s in oc.VOCABULARY_ALT_A[1:]:
            self.assertIn(f'"{s[len("BLOCK | "):]}"', src, s)

    def test_alternatives(self):
        self.assertEqual(len(oc.VOCABULARY_ALT_A), 12)
        self.assertEqual(len(oc.VOCABULARY_ALT_B), 7)
        self.assertTrue(set(oc.VOCABULARY_ALT_B) < set(oc.VOCABULARY_ALT_A))
        self.assertEqual(oc.VOCABULARY_ALT_A, v5.V5_CANDIDATE_OUTPUTS)  # stage-1 candidate unchanged
        for v in (oc.VOCABULARY_ALT_A, oc.VOCABULARY_ALT_B):
            oc.check_vocabulary(v)

    def test_pilot_vocabulary_is_alternative_b(self):
        self.assertEqual(oc.PILOT_VOCABULARY, oc.VOCABULARY_ALT_B)
        self.assertEqual(oc.fingerprint(v5.V5_CANDIDATE_TEMPLATE, oc.PILOT_VOCABULARY)[0], ALT_B_FP)

    def test_check_vocabulary_rejects_malformed(self):
        for bad in ((oc.ALLOW_OUTPUT, oc.ALLOW_OUTPUT), ("ALLOW|x",), ("BLOCK | x",),
                    (oc.ALLOW_OUTPUT, "ALLOW | other"), (oc.ALLOW_OUTPUT, "BLOCK | a\nb"),
                    (oc.ALLOW_OUTPUT, "BLOCK | x ")):
            with self.assertRaises(ValueError, msg=bad):
                oc.check_vocabulary(bad)

    def test_fingerprints_pinned(self):
        # Changing one byte of the template or the vocabulary changes the fingerprint.
        self.assertEqual(oc.fingerprint(v5.V5_CANDIDATE_TEMPLATE, oc.VOCABULARY_ALT_A)[0], ALT_A_FP)
        self.assertEqual(oc.fingerprint(v5.V5_CANDIDATE_TEMPLATE, oc.VOCABULARY_ALT_B)[0], ALT_B_FP)
        changed = v5.PromptTemplate(v5.V5_CANDIDATE_TEMPLATE.system + " ", "\n<|user|>\n", "\n<|assistant|>\n")
        self.assertNotEqual(oc.fingerprint(changed, oc.VOCABULARY_ALT_A)[0], ALT_A_FP)


class StrictParser(unittest.TestCase):
    V = oc.VOCABULARY_ALT_A

    def p(self, text, eos=True):
        return oc.parse_v5_output(text, self.V, ended_with_eos=eos)

    def test_every_vocabulary_string_parses(self):
        for s in self.V:
            r = self.p(s)
            self.assertEqual((r.status, r.decision), (oc.OK, s.split(" | ")[0]))
            self.assertEqual(f"{r.decision} | {r.reason}", s)

    def test_outer_ascii_whitespace_only_is_tolerated(self):
        self.assertEqual(self.p("\n" + self.V[1] + " \n").status, oc.OK)

    def test_invalid_cases_carry_no_decision(self):
        cases = {
            "no_eos": (self.V[0], False),
            "empty": ("  \n", True),
        }
        for reason, (text, eos) in cases.items():
            r = self.p(text, eos)
            self.assertEqual((r.status, r.decision, r.reason, r.invalid_reason), (oc.INVALID, None, None, reason))
        for text in ("ALLOW", "allow | Normal HTTP request with no attack patterns detected.",
                     "ALLOW | Normal HTTP request with no attack patterns detected",
                     "BLOCK | LDAP injection payload detected.",          # V4 string, not in V5 vocabulary
                     "BLOCK | SQL injection payload detected.\nALLOW | x",
                     "Sure! " + self.V[1], self.V[1] + " Explanation follows.",
                     "BLOCK | SQL injection payload detected.  ", "BLOCK |SQL injection payload detected."):
            r = self.p(text)
            if text.strip(" \t\r\n") in self.V:
                continue
            self.assertEqual((r.status, r.decision, r.invalid_reason), (oc.INVALID, None, "not_in_vocabulary"), text)

    def test_vocabulary_alternative_changes_acceptance(self):
        ssrf = "BLOCK | Server-side request forgery attack detected."
        self.assertEqual(oc.parse_v5_output(ssrf, oc.VOCABULARY_ALT_A, ended_with_eos=True).status, oc.OK)
        self.assertEqual(oc.parse_v5_output(ssrf, oc.VOCABULARY_ALT_B, ended_with_eos=True).status, oc.INVALID)

    def test_module_is_stdlib_only_and_not_wired(self):
        with open(os.path.join(REPO, "control_plane", "v5_output_contract.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        mods = {a.name.split(".")[0] for n in tree.body if isinstance(n, ast.Import) for a in n.names}
        mods |= {n.module.split(".")[0] for n in tree.body if isinstance(n, ast.ImportFrom)}
        self.assertTrue(mods <= set(sys.stdlib_module_names), mods)
        for f in ("inference_core.py", "classifier_api.py"):
            with open(os.path.join(REPO, "control_plane", f), encoding="utf-8") as fh:
                self.assertNotIn("v5_output_contract", fh.read())


class WithTokenizer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            from transformers import AutoTokenizer
        except Exception as exc:
            raise unittest.SkipTest(f"transformers unavailable ({type(exc).__name__})")
        snaps = sorted(glob.glob(os.path.expanduser(
            "~/.cache/huggingface/hub/models--TinyLlama--TinyLlama-1.1B-Chat-v1.0/snapshots/*")))
        if not snaps:
            raise unittest.SkipTest("base TinyLlama snapshot not in the local cache")
        os.environ.setdefault("HF_HUB_OFFLINE", "1")
        cls.tok = AutoTokenizer.from_pretrained(snaps[-1])

    def test_training_target_decodes_back_to_the_exact_vocabulary_string(self):
        T = v5.V5_CANDIDATE_TEMPLATE
        prompt = v5.encode_prompt(self.tok, T, "GET /search?q=O%27Neil HTTP/1.1\n")
        for s in oc.VOCABULARY_ALT_A:
            full = v5.encode_prompt(self.tok, T, "GET /search?q=O%27Neil HTTP/1.1\n", s)
            gen = full[len(prompt):]
            self.assertEqual(full[:len(prompt)], prompt)  # training prompt == inference prompt
            self.assertEqual(gen[-1], self.tok.eos_token_id)
            text = self.tok.decode(gen, skip_special_tokens=True)
            self.assertEqual(oc.parse_v5_output(text, oc.VOCABULARY_ALT_A, ended_with_eos=True).status, oc.OK)
            self.assertEqual(text, s)

    def test_label_budget_is_the_same_for_both_alternatives(self):
        T = v5.V5_CANDIDATE_TEMPLATE
        a = v5.label_budget(self.tok, T, oc.VOCABULARY_ALT_A)
        b = v5.label_budget(self.tok, T, oc.VOCABULARY_ALT_B)
        self.assertEqual((a, b), (13, 13))  # the ALLOW string is the longest (13 incl. EOS)
        self.assertEqual(v5.template_overhead(self.tok, T), 76)


if __name__ == "__main__":
    unittest.main()
