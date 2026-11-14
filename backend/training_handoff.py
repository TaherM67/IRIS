"""Prepare seven-class supervised records; never train or activate a model."""
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random

from .input_contract import CONTRACT, _json, _schema, validate_inputs


def group_plan(rows, seed=20261114):
    """Join reused campaign/template identities before assigning experimental roles."""
    parent={}
    def find(x):
        parent.setdefault(x,x)
        if parent[x]!=x:parent[x]=find(parent[x])
        return parent[x]
    def union(a,b):
        a,b=find(a),find(b)
        if a!=b:parent[b]=a
    for row in rows:
        campaign="campaign:"+row["campaign_id"]
        union(campaign,"template:"+row["template_group"])
        if row.get("features"):
            digest=hashlib.sha256(json.dumps(row["features"],sort_keys=True,allow_nan=False).encode()).hexdigest()
            union(campaign,"features:"+digest)
    components=defaultdict(list)
    for node in list(parent):components[find(node)].append(node)
    identifiers={node:"GROUP-"+hashlib.sha256("|".join(sorted(nodes)).encode()).hexdigest()[:16]
                 for nodes in components.values() for node in nodes}
    groups=sorted(set(identifiers.values()))
    assignments={}
    if len(groups)>=10:
        random.Random(seed).shuffle(groups)
        holdout=max(1,len(groups)//10)
        roles=(["fit"]*(len(groups)-4*holdout)+["selection"]*holdout+["calibration"]*holdout+
               ["threshold"]*holdout+["test"]*holdout)
        assignments=dict(zip(groups,roles))
    return {"seed":seed,"independent_groups":len(groups),"assignments":assignments,
            "campaign_group":{k.split(":",1)[1]:v for k,v in identifiers.items() if k.startswith("campaign:")},
            "method":"Connected campaigns, reused templates and identical observed feature vectors stay together; no target labels choose the split."}


def prepare_training(paths, labels_path, output_dir):
    report=validate_inputs(paths)
    if not report["valid"]:
        raise ValueError("Runtime input agreement failed; correct its errors before preparing training data")
    if report["readiness"]["model1_input_ready_sessions"]!=report["counts"]["prepared_sessions"]:
        raise ValueError("Training handoff requires complete, healthy observed measurements")
    schema=_json((CONTRACT/"schemas/training_label.schema.json").read_text())
    labels=[];errors=[]
    label_path=Path(labels_path)
    if not 0<label_path.stat().st_size<=20*1024*1024:
        raise ValueError("Offline annotation file must contain 1..20 MiB")
    for i,line in enumerate(label_path.read_text(encoding="utf-8").splitlines(),1):
        if not line.strip():raise ValueError("Blank annotation line "+str(i))
        label=_json(line)
        _schema(label,schema,f"labels#L{i}",lambda p,m:errors.append(p+": "+m))
        labels.append(label)
    if errors:raise ValueError("; ".join(errors[:10]))
    if not labels:raise ValueError("Offline annotations are required for supervised targets")
    case_ids=set();by_event={}
    for label in labels:
        if label["case_id"] in case_ids:raise ValueError("Duplicate offline case_id")
        case_ids.add(label["case_id"])
        for eid in label["event_ids"]:
            if eid in by_event:raise ValueError("An event occurs in multiple offline annotations")
            by_event[eid]=label
        reviewed=label["review_status"]=="independently_reviewed"
        if label["label_verified"] != reviewed or (reviewed and not label["reviewer"]):
            raise ValueError("Label verification and reviewer must agree with review_status")
        if label["controls_reviewed"] and not label["control_reviewer"]:
            raise ValueError("Reviewed control targets need a named reviewer")
    from iris_models.three_sources import integrate
    from iris_models.contracts import FEATURES
    from .scenarios import attach_evidence,feature_row,CLASSES
    _,sessions,_=integrate(Path(paths["asset_inventory"]),Path(paths["risk_register"]),Path(paths["siem_alerts"]),window_seconds=60)
    sessions=attach_evidence(sessions,{k:Path(v) for k,v in paths.items()})
    used=set();rows=[]
    for session in sessions:
        ids=session["source_event_ids"]
        annotations=[by_event.get(eid) for eid in ids]
        if any(x is None for x in annotations):raise ValueError("Observed session has events without offline annotations")
        label=annotations[0]
        if any(x is not label for x in annotations) or set(label["event_ids"])!=set(ids):
            raise ValueError("Offline annotation must match exactly one prepared session; no label voting or fragmentation")
        if label["campaign_id"]!=session["campaign_id"] or label["run_id"]!=session["run_id"]:
            raise ValueError("Offline campaign/run identifiers disagree with observed events")
        used.update(ids)
        rows.append({"session_id":session["session_id"],"source_event_ids":ids,"campaign_id":session["campaign_id"],
          "run_id":session["run_id"],"template_group":label["template_group"],"scenario_class":label["scenario_class"],
          "label_source":label["label_source"],"label_verified":label["label_verified"],"reviewer":label["reviewer"],
          "recommended_control_ids":label["recommended_control_ids"],"controls_reviewed":label["controls_reviewed"],
          "control_reviewer":label["control_reviewer"],"features":feature_row(session,FEATURES)})
    if set(by_event)!=used:raise ValueError("Offline annotations reference absent or unprepared observed events")
    plan=group_plan(rows)
    for row in rows:
        row["experimental_group"]=plan["campaign_group"][row["campaign_id"]]
        row["partition"]=plan["assignments"].get(row["experimental_group"],"unassigned")
    class_support={role:{c:sum(r["partition"]==role and r["scenario_class"]==c for r in rows) for c in CLASSES}
                   for role in ("fit","selection","calibration","threshold","test")}
    support_ok=all(all(n>=10 for n in counts.values()) for counts in class_support.values()) if plan["assignments"] else False
    reviewed=all(r["label_verified"] and r["reviewer"] for r in rows)
    manifest={"contract_id":"iris-expanded-input-v1","sessions":len(rows),"features":len(rows[0]["features"]),
              "classes":list(CLASSES),"independent_campaign_template_groups":plan["independent_groups"],
              "source_sha256":report["source_sha256"],
              "labels_sha256":hashlib.sha256(label_path.read_bytes()).hexdigest(),
              "model1_ready_for_reviewed_synthetic_fitting":bool(reviewed and support_ok),
              "all_scenario_labels_independently_reviewed":bool(reviewed),
              "minimum_10_per_class_in_each_role":support_ok,"class_support_by_partition":class_support,
              "model2_control_targets_reviewed":all(r["controls_reviewed"] and r["control_reviewer"] for r in rows),
              "model_weights_fitted":False,"production_release_eligible":False,
              "note":"Preparation is not fitting or independent validation. The legacy train-three CLI is three-class; do not use it for these seven-class records."}
    out=Path(output_dir)
    out.mkdir(parents=True,exist_ok=False)
    (out/"supervised_records.jsonl").write_text("".join(json.dumps(r,allow_nan=False)+"\n" for r in rows))
    (out/"split_plan.json").write_text(json.dumps(plan,indent=2)+"\n")
    (out/"preparation.json").write_text(json.dumps(manifest,indent=2)+"\n")
    return manifest
