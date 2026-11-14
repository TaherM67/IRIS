"""Exercise correlation after the old 2,000-case cutoff without fitting a model."""
from datetime import datetime,timedelta,timezone
import hashlib,json
from pathlib import Path
import tempfile,unittest
from unittest import mock
from backend.config import ROOT,Settings
from backend.core import INPUTS
from demo_app.engine import DemoEngine

class FixedTestAdapter:
    profile="coverage-test"
    artifact_identity="coverage-test"
    metadata={"package_version":"coverage-test","model_sha256":"0"*64,
              "aggregation_schema":"iris-three-source-session-v1-window60","model1":{"categorical_vocab":{}}}
    def predict(self,session):
        return {"soc_assessment":{"scenario_class":None,"status":"ABSTAINED","confidence":None,"method":"no_usable_evidence"},
                "shadow_candidate":None,"grc_control_review":{"recommendations":[]},"warnings":[],
                "automatic_execution":False,"official_risk_register_write":False}

class CompleteReviewTests(unittest.TestCase):
    def make_engine(self,count):
        temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup)
        root=Path(temp.name);data=root/"data";data.mkdir()
        base=ROOT/"contracts/expanded-v1/example"
        asset=json.loads((base/"asset_inventory.json").read_text())["records"][0]
        risk=next(r for r in json.loads((base/"risk_register.json").read_text())["records"] if r["asset_id"]==asset["asset_id"])
        a=json.loads((base/"siem_alerts.jsonl").read_text().splitlines()[0])
        start=datetime(2026,11,8,6,tzinfo=timezone.utc)
        alerts=[{**a,"event_id":f"EVT-{i:05d}","run_id":f"RUN-{i:05d}","campaign_id":"GROUP-ONE",
                 "timestamp":(start+timedelta(seconds=i)).isoformat(),"asset_id":asset["asset_id"],
                 "agent_name":asset["hostname"],"source_ip":"198.51.100.1","destination_ip":asset["ip_addresses"][0],
                 "network_direction":"inbound","remote_destination_ip":None,"event_family":"network","protocol":"TCP"}
                for i in range(count)]
        for name,record,schema in [("asset_inventory",asset,"iris-asset-inventory-v1"),("risk_register",risk,"iris-risk-register-v1")]:
            (data/(name+".json")).write_text(json.dumps({"schema_version":schema,"data_provenance":"synthetic","records":[record]}))
        (data/"siem_alerts.jsonl").write_text("".join(json.dumps(r)+"\n" for r in alerts))
        manifest={"name":"Large complete processing fixture","data_provenance":"synthetic","unique_assets":1,"unique_risks":1,
                  "inputs":[{"upload_field":k,"sha256":hashlib.sha256((data/name).read_bytes()).hexdigest()} for k,name in INPUTS.items()]}
        (data/"demo_manifest.json").write_text(json.dumps(manifest))
        keys={r:("TEST-COVERAGE-"+r).ljust(48,"0") for r in ["admin","soc","grc"]}
        return DemoEngine(Settings(root/"state",keys),data_dir=data,adapter=FixedTestAdapter())
    def test_all_2001_cases_reach_working_alert_correlation(self):
        engine=self.make_engine(2001);result=engine.analyze("admin")
        self.assertEqual(result["sessions"],2001)
        with engine.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM demo_alerts WHERE case_id IS NOT NULL").fetchone()[0],2001)
            self.assertEqual(db.execute("SELECT COUNT(DISTINCT case_id) FROM demo_alerts").fetchone()[0],2001)
    def test_incomplete_read_fails_before_working_records_change(self):
        engine=self.make_engine(2)
        with mock.patch.object(engine.store,"cases",return_value={"total":2,"items":[]}):
            with self.assertRaisesRegex(ValueError,"Incomplete analysis case retrieval"):engine.analyze("admin")
        with engine.store.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM demo_alerts WHERE case_id IS NOT NULL").fetchone()[0],0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM demo_proposals").fetchone()[0],0)

