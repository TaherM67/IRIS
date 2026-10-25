"""Bounded synchronous batch adapter: three files in, persisted shadow cases out."""
from __future__ import annotations

import hashlib
import json
import shutil
import threading
import uuid
from collections import Counter
from pathlib import Path

from .config import Settings
from .model_adapter import ModelAdapter, SAMPLES, digest, prepare_three, utc_now
from .policy import VERSION, evaluate, primary_controls
from .storage import Store

INPUTS = {"asset_inventory": "asset_inventory.json", "risk_register": "risk_register.json", "siem_alerts": "siem_alerts.jsonl"}


class BusyError(RuntimeError):
    pass


class Engine:
    def __init__(self, settings: Settings, adapter=None):
        self.settings = settings
        self.adapter = adapter or ModelAdapter()
        self.store = Store(settings.state_dir / "iris.sqlite3")
        self.lock = threading.Lock()

    def run(self, paths: dict[str, Path], actor: str) -> dict:
        if actor not in {"admin", "soc"}:
            raise PermissionError("Only Admin or SOC may submit a batch")
        if set(paths) != set(INPUTS):
            raise ValueError("Exactly asset_inventory, risk_register and siem_alerts are required; no labels or model uploads")
        if not self.lock.acquire(blocking=False):
            raise BusyError("A batch is already running; retry after it finishes")
        run_id = None
        try:
            for key, path in paths.items():
                maximum = (20 if key == "siem_alerts" else 5) * 1024 * 1024
                if not path.is_file() or not 0 < path.stat().st_size <= maximum:
                    raise ValueError(f"{key}: empty file or upload-size limit exceeded")
            with paths["siem_alerts"].open(encoding="utf-8") as stream:
                alert_rows = sum(1 for line in stream if line.strip())
                if alert_rows > self.settings.max_alert_rows:
                    raise ValueError("Batch alert-row limit exceeded")
            hashes = {key: digest(path) for key, path in sorted(paths.items())}
            fingerprint = hashlib.sha256(json.dumps({"inputs": hashes, "model": self.adapter.metadata["model_sha256"],
                                                     "artifact_manifest": self.adapter.artifact_identity,
                                                     "policy": VERSION, "window": 60}, sort_keys=True).encode()).hexdigest()
            previous = self.store.previous(fingerprint)
            if previous:
                return {**previous, "reused_existing_run": True}
            run_id = "RUN-" + uuid.uuid4().hex
            directory = self.settings.state_dir / "runs" / run_id
            inputs = directory / "inputs"
            inputs.mkdir(parents=True, exist_ok=False)
            self.store.begin(run_id, fingerprint, actor)
            local = {}
            for key, path in paths.items():
                local[key] = inputs / INPUTS[key]
                shutil.copyfile(path, local[key])
                if digest(local[key]) != hashes[key]:
                    raise ValueError("Input changed during processing; submit an immutable export")
            # Bound enrichment expansion before allocating or serializing nested
            # risk context on every alert. Byte limits alone do not bound this.
            risks_by_asset = {}
            for key in ("asset_inventory", "risk_register"):
                payload = json.loads(local[key].read_text(encoding="utf-8"))
                records = payload.get("records") if isinstance(payload, dict) else None
                if not isinstance(records, list) or len(records) > 5000:
                    raise ValueError(f"{key}: records array required, with at most 5000 snapshots")
                if key == "risk_register":
                    for record in records:
                        if not isinstance(record, dict) or not isinstance(record.get("asset_id"), str) or not isinstance(record.get("risk_id"), str):
                            raise ValueError("Risk identifiers must be explicit strings")
                        risks_by_asset.setdefault(record["asset_id"], set()).add(record["risk_id"])
            maximum_risks = max(map(len, risks_by_asset.values()), default=0)
            if maximum_risks > 10 or alert_rows * maximum_risks > 200000:
                raise ValueError("Risk-context expansion limit exceeded; use a smaller coherent batch")
            report = prepare_three(local["asset_inventory"], local["risk_register"], local["siem_alerts"], directory / "prepared", window_seconds=60)
            if not 0 < report["model_sessions"] <= self.settings.max_sessions:
                raise ValueError("Batch must produce 1..2000 model sessions")
            sessions = [json.loads(line) for line in (directory / "prepared/model_sessions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            cases, labels = [], Counter()
            for session in sessions:
                prediction = self.adapter.predict(session)
                candidate = prediction.get("shadow_candidate")
                labels[(candidate.get("scenario_class") or "ABSTAINED") if candidate else "ML_UNAVAILABLE"] += 1
                risk = evaluate(session, prediction)
                cases.append({
                    "case_id": "CASE-" + hashlib.sha256(f"{run_id}:{session['session_id']}".encode()).hexdigest()[:24],
                    "run_id": run_id, "created_at_utc": utc_now(), "session": session,
                    "prediction": prediction, "risk_review": risk,
                    "primary_controls": primary_controls(session, prediction, risk),
                })
            summary = {
                "run_id": run_id, "status": "completed", "created_at_utc": utc_now(), "mode": "shadow",
                "model_sha256": self.adapter.metadata["model_sha256"], "sessions": len(cases),
                "shadow_class_counts": dict(labels), "integration": report,
                "reused_existing_run": False, "training_labels_read": False,
                "automatic_execution": False, "official_risk_register_write": False,
                "delivery": "LOCAL_ONLY_NO_EXTERNAL_CONNECTORS",
            }
            self.store.complete(run_id, cases, summary, actor)
            return summary
        except Exception as exc:
            if run_id:
                self.store.fail(run_id, actor, f"{type(exc).__name__}: {exc}")
            raise
        finally:
            self.lock.release()

    def sample(self, actor):
        return self.run({key: SAMPLES / filename for key, filename in INPUTS.items()}, actor)


def view(case: dict, role: str) -> dict:
    session, prediction = case["session"], case["prediction"]
    common = {
        "case_id": case["case_id"], "run_id": case["run_id"], "session_id": session["session_id"],
        "asset": session["asset_snapshot"], "data_provenance": session["data_provenance"],
        "context_as_of_utc": session["context_as_of_utc"], "primary_assessment": prediction["soc_assessment"],
        "priority": case["risk_review"]["priority"], "review": case.get("review"),
        "shadow_only": True, "automatic_execution": False, "official_risk_register_write": False,
        "warnings": prediction["warnings"],
    }
    if role == "soc":
        common.update(evidence_features=session["features"], source_event_ids=session["source_event_ids"],
                      evidence_refs=session["evidence_refs"], risk_review=case["risk_review"],
                      primary_controls=case["primary_controls"], shadow_candidate=prediction["shadow_candidate"])
    elif role == "grc":
        common.update(risk_snapshots=session["risk_snapshots"], risk_review=case["risk_review"],
                      primary_controls=case["primary_controls"], shadow_candidate=prediction["shadow_candidate"],
                      shadow_model_context=session["context"],
                      shadow_context_note="Model 2 uses the same representative prior-risk context as training; it is not an official matched risk or effectiveness estimate.")
    else:
        raise ValueError("Unknown result view")
    return common
