import itertools
import unittest
import adjudicate as a


class AuditTests(unittest.TestCase):
    def test_agreement_never_overridden(self):
        for x,y in itertools.product(a.LABELS, (*a.LABELS,None)):
            self.assertEqual(a.adjudicate(x,x,y)[0],x)

    def test_vp_rule_independent_of_r3(self):
        for x,y in [('VERIFIABLE','PROBABLY_CORRECT'),('PROBABLY_CORRECT','VERIFIABLE')]:
            for z in (*a.LABELS,None):
                self.assertEqual(a.adjudicate(x,y,z)[0],'PROBABLY_CORRECT')

    def test_majority_requires_three_valid_votes(self):
        self.assertIsNone(a.adjudicate('INCORRECT','UNCERTAIN',None)[0])
        self.assertIsNone(a.adjudicate('INCORRECT',None,'INCORRECT')[0])
        self.assertEqual(a.adjudicate('INCORRECT','UNCERTAIN','UNCERTAIN')[0],'UNCERTAIN')
        self.assertIsNone(a.adjudicate('INCORRECT','UNCERTAIN','VERIFIABLE')[0])

    def test_wilson_preregistered_boundary(self):
        self.assertLessEqual(a.wilson_upper(4,50,1.96),.20)
        self.assertGreater(a.wilson_upper(5,50,1.96),.20)
        self.assertLessEqual(a.wilson_upper(10,50,1.96),.35)
        self.assertGreater(a.wilson_upper(11,50,1.96),.35)
        self.assertGreater(a.wilson_upper(1,22,1.96),.20)

    def test_missing_duplicate_order_and_schema_rejected(self):
        inputs=[{'sample_id':'a'},{'sample_id':'b'}]
        outputs=[{'sample_id':s,'status':'UNEVALUATED','reason':'not evaluated'} for s in ('a','b')]
        a.validate_responses(inputs,outputs)
        for bad in (outputs[:1],outputs[::-1],[outputs[0],outputs[0]],
                    [{**outputs[0],'label':'INCORRECT'},outputs[1]]):
            with self.assertRaises(ValueError): a.validate_responses(inputs,bad)

    def test_no_default_label_for_unevaluated(self):
        row={'sample_id':'a','status':'UNEVALUATED','reason':'not evaluated'}
        a.validate_responses([{'sample_id':'a'}],[row])
        self.assertIsNone(a.adjudicate('VERIFIABLE','UNCERTAIN',row.get('label'))[0])


if __name__ == '__main__': unittest.main()
