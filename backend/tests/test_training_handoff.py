"""Offline target linkage and split isolation must hold before any fitting."""
import copy,json
from pathlib import Path
import tempfile,unittest
from backend.input_contract import ROOT,CONTRACT,FILES,validate_inputs
from backend.training_handoff import group_plan,prepare_training

class HandoffTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.paths={k:CONTRACT/"example"/n for k,n in FILES.items()}
        self.labels=[json.loads(s) for s in (CONTRACT/"example/training_labels.jsonl").read_text().splitlines()]
    def prepare(self):
        label=self.root/"labels.jsonl"
        label.write_text("".join(json.dumps(r)+"\n" for r in self.labels))
        return prepare_training(self.paths,label,self.root/"prepared")
    def test_seven_class_example_exports_23_features_but_is_not_fit_ready(self):
        report=self.prepare()
        self.assertEqual((report["sessions"],report["features"]),(7,23))
        self.assertFalse(report["model1_ready_for_reviewed_synthetic_fitting"])
        rows=[json.loads(s) for s in (self.root/"prepared/supervised_records.jsonl").read_text().splitlines()]
        self.assertEqual(len({r["scenario_class"] for r in rows}),7)
        self.assertFalse(any("scenario_class" in r["features"] or "recommended_control_ids" in r["features"] for r in rows))
    def test_missing_event_label_blocks_preparation(self):
        self.labels[0]["event_ids"].pop()
        with self.assertRaisesRegex(ValueError,"without offline annotations"):self.prepare()
    def test_annotations_cannot_span_two_observed_sessions(self):
        self.labels[0]["event_ids"]+=self.labels[1]["event_ids"]
        self.labels.pop(1)
        with self.assertRaisesRegex(ValueError,"exactly one prepared session"):self.prepare()
    def test_runtime_qualification_ignores_even_invalid_label_file(self):
        for key,p in self.paths.items():
            dst=self.root/FILES[key];dst.write_bytes(p.read_bytes())
        (self.root/"training_labels.jsonl").write_text("not-json-at-all")
        self.assertTrue(validate_inputs({k:self.root/n for k,n in FILES.items()})["valid"])
    def test_copied_templates_and_identical_features_do_not_cross_partitions(self):
        rows=[{"campaign_id":f"C{i}","template_group":f"T{i}","features":{"x":i}} for i in range(20)]
        rows[1]["template_group"]=rows[0]["template_group"]
        rows[3]["features"]=dict(rows[2]["features"])
        plan=group_plan(rows)
        cg=plan["campaign_group"]
        self.assertEqual(cg["C0"],cg["C1"])
        self.assertEqual(cg["C2"],cg["C3"])
        self.assertEqual(plan["independent_groups"],18)
        self.assertEqual(set(plan["assignments"].values()),{"fit","selection","calibration","threshold","test"})
    def test_unreviewed_llm_cannot_mark_its_own_labels_verified(self):
        self.labels[0]["label_verified"]=True
        with self.assertRaisesRegex(ValueError,"review_status"):self.prepare()
