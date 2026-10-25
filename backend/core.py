# IRIS EXPLAIN: File purpose: Loads one model adapter and turns exactly three source files into immutable, persisted cases with
# IRIS EXPLAIN: explicit policy advice; repeated identical batches reuse saved results.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Bounded synchronous batch adapter: three files in, persisted shadow cases out."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import hashlib to compute deterministic byte identities and content fingerprints.
import hashlib
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import shutil to copy immutable inputs or clean test-owned temporary directories.
import shutil
# IRIS EXPLAIN: Import threading to coordinate the batch/approval lock or run a local HTTP test server.
import threading
# IRIS EXPLAIN: Import uuid to generate independent run, case-proposal and exercise identities.
import uuid
# IRIS EXPLAIN: Import Counter from collections to count values and build efficient grouping/history containers.
from collections import Counter
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import Settings from .config to reuse the shared project contract/implementation rather than duplicate it.
from .config import Settings
# IRIS EXPLAIN: Import ModelAdapter, SAMPLES, digest, prepare_three, utc_now from .model_adapter to reuse the shared project
# IRIS EXPLAIN: contract/implementation rather than duplicate it.
from .model_adapter import ModelAdapter, SAMPLES, digest, prepare_three, utc_now
# IRIS EXPLAIN: Import VERSION, evaluate, primary_controls from .policy to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .policy import VERSION, evaluate, primary_controls
# IRIS EXPLAIN: Import Store from .storage to reuse the shared project contract/implementation rather than duplicate it.
from .storage import Store

# IRIS EXPLAIN: Store a mapping containing asset_inventory, risk_register, siem_alerts in INPUTS; later lines use this named
# IRIS EXPLAIN: result.
INPUTS = {"asset_inventory": "asset_inventory.json", "risk_register": "risk_register.json", "siem_alerts": "siem_alerts.jsonl"}


# IRIS EXPLAIN: Class BusyError: Marker exception for a rejected overlapping batch; it adds no custom execution logic.
class BusyError(RuntimeError):
    # IRIS EXPLAIN: Intentionally do nothing in this existing placeholder/no-op branch; no new behavior is added.
    pass


# IRIS EXPLAIN: Class Engine: Reusable three-input batch coordinator with immutable SQLite case persistence.
class Engine:
    # IRIS EXPLAIN: Function Engine.__init__: Create one reusable model adapter, SQLite store and batch lock; incoming requests
    # IRIS EXPLAIN: do not retrain or reload the models.
    # IRIS EXPLAIN: Inputs: settings: validated local credentials, state path and processing bounds; adapter: optional existing
    # IRIS EXPLAIN: trusted model adapter, reused by tests rather than retrained.
    def __init__(self, settings: Settings, adapter=None):
        # IRIS EXPLAIN: Store settings in self.settings; later lines use this named result.
        self.settings = settings
        # IRIS EXPLAIN: Store adapter or ModelAdapter() in self.adapter; later lines use this named result.
        self.adapter = adapter or ModelAdapter()
        # IRIS EXPLAIN: Store the result of Store(settings.state_dir / 'iris.sqlite3') in self.store; later lines use this named
        # IRIS EXPLAIN: result.
        self.store = Store(settings.state_dir / "iris.sqlite3")
        # IRIS EXPLAIN: Store the result of threading.Lock() in self.lock; later lines use this named result.
        self.lock = threading.Lock()

    # IRIS EXPLAIN: Function Engine.run: Bound, fingerprint and copy exactly three inputs, reuse identical completed runs,
    # IRIS EXPLAIN: prepare sessions, run shadow inference and explicit policy, then atomically persist cases.
    # IRIS EXPLAIN: Inputs: paths: the exact three named operational input paths; actor: the server-authenticated role; tests
    # IRIS EXPLAIN: use explicit synthetic fixture roles.
    # IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
    def run(self, paths: dict[str, Path], actor: str) -> dict:
        # IRIS EXPLAIN: Enter this branch only when actor not in {'admin', 'soc'}.
        if actor not in {"admin", "soc"}:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising PermissionError('Only Admin or SOC may submit a
            # IRIS EXPLAIN: batch'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise PermissionError("Only Admin or SOC may submit a batch")
        # IRIS EXPLAIN: Enter this branch only when set(paths) != set(INPUTS).
        if set(paths) != set(INPUTS):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Exactly asset_inventory,
            # IRIS EXPLAIN: risk_register and siem_alerts are required; no labels or model uploads'); the caller's existing
            # IRIS EXPLAIN: boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Exactly asset_inventory, risk_register and siem_alerts are required; no labels or model uploads")
        # IRIS EXPLAIN: Enter this branch only when not self.lock.acquire(blocking=False).
        if not self.lock.acquire(blocking=False):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising BusyError('A batch is already running; retry
            # IRIS EXPLAIN: after it finishes'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise BusyError("A batch is already running; retry after it finishes")
        # IRIS EXPLAIN: Store None (no result/value) in run_id; later lines use this named result.
        run_id = None
        # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
        # IRIS EXPLAIN: decide fallback and cleanup.
        try:
            # IRIS EXPLAIN: Iterate paths.items(), binding each item to (key, path); process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for key, path in paths.items():
                # IRIS EXPLAIN: Store the computed value (20 if key == 'siem_alerts' else 5) * 1024 * 1024 in maximum; later
                # IRIS EXPLAIN: lines use this named result.
                maximum = (20 if key == "siem_alerts" else 5) * 1024 * 1024
                # IRIS EXPLAIN: Enter this branch only when not path.is_file() or not 0 < path.stat().st_size <= maximum.
                if not path.is_file() or not 0 < path.stat().st_size <= maximum:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{key}: empty file or
                    # IRIS EXPLAIN: upload-size limit exceeded'); the caller's existing boundary determines rollback or the HTTP
                    # IRIS EXPLAIN: diagnostic.
                    raise ValueError(f"{key}: empty file or upload-size limit exceeded")
            # IRIS EXPLAIN: Enter paths['siem_alerts'].open(encoding='utf-8') as stream; its context manager supplies the
            # IRIS EXPLAIN: existing cleanup/transaction/expected-exception behavior.
            with paths["siem_alerts"].open(encoding="utf-8") as stream:
                # IRIS EXPLAIN: Store sum((1 for line in stream if line.strip())) in alert_rows; later lines use this named
                # IRIS EXPLAIN: result.
                alert_rows = sum(1 for line in stream if line.strip())
                # IRIS EXPLAIN: Enter this branch only when alert_rows > self.settings.max_alert_rows.
                if alert_rows > self.settings.max_alert_rows:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Batch alert-row limit
                    # IRIS EXPLAIN: exceeded'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                    raise ValueError("Batch alert-row limit exceeded")
            # IRIS EXPLAIN: Store the comprehension {key: digest(path) for key, path in sorted(paths.items())} in hashes; later
            # IRIS EXPLAIN: lines use this named result.
            hashes = {key: digest(path) for key, path in sorted(paths.items())}
            # IRIS EXPLAIN: Store the result of hashlib.sha256(json.dumps({'inputs': hashes, 'model':
            # IRIS EXPLAIN: self.adapter.metadata['model_sha256'], 'artifact_manifest': self.adapter.artif... (return the
            # IRIS EXPLAIN: hexadecimal content digest) in fingerprint; later lines use this named result.
            fingerprint = hashlib.sha256(json.dumps({"inputs": hashes, "model": self.adapter.metadata["model_sha256"],
                                                     # IRIS EXPLAIN: Continue the current record with artifact_manifest; each value
                                                     # IRIS EXPLAIN: comes from the expression shown on this unchanged line.
                                                     "artifact_manifest": self.adapter.artifact_identity,
                                                     # IRIS EXPLAIN: Continue the current record with policy, window; each value comes
                                                     # IRIS EXPLAIN: from the expression shown on this unchanged line.
                                                     "policy": VERSION, "window": 60}, sort_keys=True).encode()).hexdigest()
            # IRIS EXPLAIN: Store the result of self.store.previous(fingerprint) in previous; later lines use this named result.
            previous = self.store.previous(fingerprint)
            # IRIS EXPLAIN: Enter this branch only when previous.
            if previous:
                # IRIS EXPLAIN: Return a mapping containing reused_existing_run to the caller; this ends the current function
                # IRIS EXPLAIN: path.
                return {**previous, "reused_existing_run": True}
            # IRIS EXPLAIN: Store the computed value 'RUN-' + uuid.uuid4().hex in run_id; later lines use this named result.
            run_id = "RUN-" + uuid.uuid4().hex
            # IRIS EXPLAIN: Store the computed value self.settings.state_dir / 'runs' / run_id in directory; later lines use
            # IRIS EXPLAIN: this named result.
            directory = self.settings.state_dir / "runs" / run_id
            # IRIS EXPLAIN: Store the computed value directory / 'inputs' in inputs; later lines use this named result.
            inputs = directory / "inputs"
            # IRIS EXPLAIN: Call inputs.mkdir(parents=True, exist_ok=False): create the required directory if permitted by the
            # IRIS EXPLAIN: existing flags.
            inputs.mkdir(parents=True, exist_ok=False)
            # IRIS EXPLAIN: Call self.store.begin(run_id, fingerprint, actor) using the existing explicit arguments.
            self.store.begin(run_id, fingerprint, actor)
            # IRIS EXPLAIN: Store a mapping containing  in local; later lines use this named result.
            local = {}
            # IRIS EXPLAIN: Iterate paths.items(), binding each item to (key, path); process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for key, path in paths.items():
                # IRIS EXPLAIN: Store the computed value inputs / INPUTS[key] in local[key]; later lines use this named result.
                local[key] = inputs / INPUTS[key]
                # IRIS EXPLAIN: Call shutil.copyfile(path, local[key]) using the existing explicit arguments.
                shutil.copyfile(path, local[key])
                # IRIS EXPLAIN: Enter this branch only when digest(local[key]) != hashes[key].
                if digest(local[key]) != hashes[key]:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Input changed during
                    # IRIS EXPLAIN: processing; submit an immutable export'); the caller's existing boundary determines rollback
                    # IRIS EXPLAIN: or the HTTP diagnostic.
                    raise ValueError("Input changed during processing; submit an immutable export")
            # Bound enrichment expansion before allocating or serializing nested
            # risk context on every alert. Byte limits alone do not bound this.
            # IRIS EXPLAIN: Store a mapping containing  in risks_by_asset; later lines use this named result.
            risks_by_asset = {}
            # IRIS EXPLAIN: Iterate ('asset_inventory', 'risk_register'), binding each item to key; process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for key in ("asset_inventory", "risk_register"):
                # IRIS EXPLAIN: Store the result of json.loads(local[key].read_text(encoding='utf-8')) (decode the existing JSON
                # IRIS EXPLAIN: text) in payload; later lines use this named result.
                payload = json.loads(local[key].read_text(encoding="utf-8"))
                # IRIS EXPLAIN: Store the result of payload.get('records') (read an optional mapping field using its stated
                # IRIS EXPLAIN: fallback) when isinstance(payload, dict); otherwise None (no result/value) in records; later
                # IRIS EXPLAIN: lines use this named result.
                records = payload.get("records") if isinstance(payload, dict) else None
                # IRIS EXPLAIN: Enter this branch only when not isinstance(records, list) or len(records) > 5000.
                if not isinstance(records, list) or len(records) > 5000:
                    # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'{key}: records array
                    # IRIS EXPLAIN: required, with at most 5000 snapshots'); the caller's existing boundary determines rollback
                    # IRIS EXPLAIN: or the HTTP diagnostic.
                    raise ValueError(f"{key}: records array required, with at most 5000 snapshots")
                # IRIS EXPLAIN: Enter this branch only when key == 'risk_register'.
                if key == "risk_register":
                    # IRIS EXPLAIN: Iterate records, binding each item to record; process only the existing observed/fixture
                    # IRIS EXPLAIN: collection.
                    for record in records:
                        # IRIS EXPLAIN: Enter this branch only when not isinstance(record, dict) or not
                        # IRIS EXPLAIN: isinstance(record.get('asset_id'), str) or (not isinstance(record.get('risk_id'), str)).
                        if not isinstance(record, dict) or not isinstance(record.get("asset_id"), str) or not isinstance(record.get("risk_id"), str):
                            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Risk identifiers
                            # IRIS EXPLAIN: must be explicit strings'); the caller's existing boundary determines rollback or
                            # IRIS EXPLAIN: the HTTP diagnostic.
                            raise ValueError("Risk identifiers must be explicit strings")
                        # IRIS EXPLAIN: Call risks_by_asset.setdefault(record['asset_id'], set()).add(record['risk_id']): record
                        # IRIS EXPLAIN: membership in the set.
                        risks_by_asset.setdefault(record["asset_id"], set()).add(record["risk_id"])
            # IRIS EXPLAIN: Store max(map(len, risks_by_asset.values()), default=0) in maximum_risks; later lines use this named
            # IRIS EXPLAIN: result.
            maximum_risks = max(map(len, risks_by_asset.values()), default=0)
            # IRIS EXPLAIN: Enter this branch only when maximum_risks > 10 or alert_rows * maximum_risks > 200000.
            if maximum_risks > 10 or alert_rows * maximum_risks > 200000:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Risk-context expansion limit
                # IRIS EXPLAIN: exceeded; use a smaller coherent batch'); the caller's existing boundary determines rollback or
                # IRIS EXPLAIN: the HTTP diagnostic.
                raise ValueError("Risk-context expansion limit exceeded; use a smaller coherent batch")
            # IRIS EXPLAIN: Store the result of prepare_three(local['asset_inventory'], local['risk_register'],
            # IRIS EXPLAIN: local['siem_alerts'], directory / 'prepared... in report; later lines use this named result.
            report = prepare_three(local["asset_inventory"], local["risk_register"], local["siem_alerts"], directory / "prepared", window_seconds=60)
            # IRIS EXPLAIN: Enter this branch only when not 0 < report['model_sessions'] <= self.settings.max_sessions.
            if not 0 < report["model_sessions"] <= self.settings.max_sessions:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Batch must produce 1..2000
                # IRIS EXPLAIN: model sessions'); the caller's existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Batch must produce 1..2000 model sessions")
            # IRIS EXPLAIN: Store the comprehension [json.loads(line) for line in (directory /
            # IRIS EXPLAIN: 'prepared/model_sessions.jsonl').read_text(encoding='utf-8').splitlines() if line.strip()] in
            # IRIS EXPLAIN: sessions; later lines use this named result.
            sessions = [json.loads(line) for line in (directory / "prepared/model_sessions.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
            # IRIS EXPLAIN: Store ([], Counter()) in (cases, labels); later lines use this named result.
            cases, labels = [], Counter()
            # IRIS EXPLAIN: Iterate sessions, binding each item to session; process only the existing observed/fixture
            # IRIS EXPLAIN: collection.
            for session in sessions:
                # IRIS EXPLAIN: Store the result of self.adapter.predict(session) (obtain the configured prediction result
                # IRIS EXPLAIN: without training on this call) in prediction; later lines use this named result.
                prediction = self.adapter.predict(session)
                # IRIS EXPLAIN: Store the result of prediction.get('shadow_candidate') (read an optional mapping field using its
                # IRIS EXPLAIN: stated fallback) in candidate; later lines use this named result.
                candidate = prediction.get("shadow_candidate")
                # IRIS EXPLAIN: Update labels[candidate.get('scenario_class') or 'ABSTAINED' if candidate else 'ML_UNAVAILABLE']
                # IRIS EXPLAIN: using the existing Add operation and 1.
                labels[(candidate.get("scenario_class") or "ABSTAINED") if candidate else "ML_UNAVAILABLE"] += 1
                # IRIS EXPLAIN: Store the result of evaluate(session, prediction) in risk; later lines use this named result.
                risk = evaluate(session, prediction)
                # IRIS EXPLAIN: Call cases.append({'case_id': 'CASE-' +
                # IRIS EXPLAIN: hashlib.sha256(f"{run_id}:{session['session_id']}".encode()).hexdigest()[:24], 'run_id': run_id,
                # IRIS EXPLAIN: 'created_at_utc': utc_now...: append one item to the working list.
                cases.append({
                    # IRIS EXPLAIN: Continue the current record with case_id; each value comes from the expression shown on this
                    # IRIS EXPLAIN: unchanged line.
                    "case_id": "CASE-" + hashlib.sha256(f"{run_id}:{session['session_id']}".encode()).hexdigest()[:24],
                    # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance retained for
                    # IRIS EXPLAIN: traceability; not a hidden attack-label feature.
                    "run_id": run_id, "created_at_utc": utc_now(), "session": session,
                    # IRIS EXPLAIN: Continue the current record with prediction, risk_review; each value comes from the
                    # IRIS EXPLAIN: expression shown on this unchanged line.
                    "prediction": prediction, "risk_review": risk,
                    # IRIS EXPLAIN: Continue the current record with primary_controls; each value comes from the expression
                    # IRIS EXPLAIN: shown on this unchanged line.
                    "primary_controls": primary_controls(session, prediction, risk),
                # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
                # IRIS EXPLAIN: unchanged.
                })
            # IRIS EXPLAIN: Store a mapping containing run_id, status, created_at_utc, mode, model_sha256, sessions,
            # IRIS EXPLAIN: shadow_class_counts and additional fields in summary; later lines use this named result.
            summary = {
                # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance retained for
                # IRIS EXPLAIN: traceability; not a hidden attack-label feature; status: the stated assessment/proposal/run
                # IRIS EXPLAIN: state; an abstention must not be relabeled benign.
                "run_id": run_id, "status": "completed", "created_at_utc": utc_now(), "mode": "shadow",
                # IRIS EXPLAIN: Set/describe these existing record fields: model_sha256: content identity of the saved trusted
                # IRIS EXPLAIN: model bundle.
                "model_sha256": self.adapter.metadata["model_sha256"], "sessions": len(cases),
                # IRIS EXPLAIN: Continue the current record with shadow_class_counts, integration; each value comes from the
                # IRIS EXPLAIN: expression shown on this unchanged line.
                "shadow_class_counts": dict(labels), "integration": report,
                # IRIS EXPLAIN: Set/describe these existing record fields: reused_existing_run: identical completed evidence was
                # IRIS EXPLAIN: reused rather than re-inferred or duplicated; training_labels_read: runtime provenance flag
                # IRIS EXPLAIN: proving labels are not operational inputs.
                "reused_existing_run": False, "training_labels_read": False,
                # IRIS EXPLAIN: Set/describe these existing record fields: automatic_execution: safety flag separating
                # IRIS EXPLAIN: recommendations from automatic control execution; official_risk_register_write: safety flag:
                # IRIS EXPLAIN: model inference does not change an official company register.
                "automatic_execution": False, "official_risk_register_write": False,
                # IRIS EXPLAIN: Continue the current record with delivery; each value comes from the expression shown on this
                # IRIS EXPLAIN: unchanged line.
                "delivery": "LOCAL_ONLY_NO_EXTERNAL_CONNECTORS",
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            }
            # IRIS EXPLAIN: Call self.store.complete(run_id, cases, summary, actor) using the existing explicit arguments.
            self.store.complete(run_id, cases, summary, actor)
            # IRIS EXPLAIN: Return summary to the caller; this ends the current function path.
            return summary
        # IRIS EXPLAIN: Catch Exception as exc; execute the existing error/fallback path rather than silently treating it as
        # IRIS EXPLAIN: success.
        except Exception as exc:
            # IRIS EXPLAIN: Enter this branch only when run_id.
            if run_id:
                # IRIS EXPLAIN: Call self.store.fail(run_id, actor, f'{type(exc).__name__}: {exc}') using the existing explicit
                # IRIS EXPLAIN: arguments.
                self.store.fail(run_id, actor, f"{type(exc).__name__}: {exc}")
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising NoneType; the caller's existing boundary
            # IRIS EXPLAIN: determines rollback or the HTTP diagnostic.
            raise
        # IRIS EXPLAIN: Run this cleanup regardless of whether the attempted operation succeeded or raised an error.
        finally:
            # IRIS EXPLAIN: Call self.lock.release(): release the acquired lock.
            self.lock.release()

    # IRIS EXPLAIN: Function Engine.sample: Run the original bundled 900-session synthetic sample through the exact same
    # IRIS EXPLAIN: three-input batch path.
    # IRIS EXPLAIN: Inputs: actor: the server-authenticated role; tests use explicit synthetic fixture roles.
    def sample(self, actor):
        # IRIS EXPLAIN: Return the result of self.run({key: SAMPLES / filename for key, filename in INPUTS.items()}, actor) to
        # IRIS EXPLAIN: the caller; this ends the current function path.
        return self.run({key: SAMPLES / filename for key, filename in INPUTS.items()}, actor)


# IRIS EXPLAIN: Function view: Project a saved case into the SOC technical view or GRC registered-risk view while preserving
# IRIS EXPLAIN: common priority, provenance and review state.
# IRIS EXPLAIN: Inputs: case: the explicit case input used by the unchanged statements below; role: the authenticated role or
# IRIS EXPLAIN: explicitly constructed test fixture role.
# IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
def view(case: dict, role: str) -> dict:
    # IRIS EXPLAIN: Store (case['session'], case['prediction']) in (session, prediction); later lines use this named result.
    session, prediction = case["session"], case["prediction"]
    # IRIS EXPLAIN: Store a mapping containing case_id, run_id, session_id, asset, data_provenance, context_as_of_utc,
    # IRIS EXPLAIN: primary_assessment and additional fields in common; later lines use this named result.
    common = {
        # IRIS EXPLAIN: Set/describe these existing record fields: run_id: run/batch provenance retained for traceability; not a
        # IRIS EXPLAIN: hidden attack-label feature; session_id: deterministic observed session identity linking evidence to
        # IRIS EXPLAIN: separate reviews/cases.
        "case_id": case["case_id"], "run_id": case["run_id"], "session_id": session["session_id"],
        # IRIS EXPLAIN: Set/describe these existing record fields: data_provenance: explicit synthetic/cyber_range/operational
        # IRIS EXPLAIN: source identity.
        "asset": session["asset_snapshot"], "data_provenance": session["data_provenance"],
        # IRIS EXPLAIN: Continue the current record with context_as_of_utc, primary_assessment; each value comes from the
        # IRIS EXPLAIN: expression shown on this unchanged line.
        "context_as_of_utc": session["context_as_of_utc"], "primary_assessment": prediction["soc_assessment"],
        # IRIS EXPLAIN: Set/describe these existing record fields: priority: explicit policy priority; in the active demo it is
        # IRIS EXPLAIN: written only after SOC approval.
        "priority": case["risk_review"]["priority"], "review": case.get("review"),
        # IRIS EXPLAIN: Set/describe these existing record fields: automatic_execution: safety flag separating recommendations
        # IRIS EXPLAIN: from automatic control execution; official_risk_register_write: safety flag: model inference does not
        # IRIS EXPLAIN: change an official company register.
        "shadow_only": True, "automatic_execution": False, "official_risk_register_write": False,
        # IRIS EXPLAIN: Continue the current record with warnings; each value comes from the expression shown on this unchanged
        # IRIS EXPLAIN: line.
        "warnings": prediction["warnings"],
    # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain unchanged.
    }
    # IRIS EXPLAIN: Enter this branch only when role == 'soc'.
    if role == "soc":
        # IRIS EXPLAIN: Call common.update(evidence_features=session['features'], source_event_ids=session['source_event_ids'],
        # IRIS EXPLAIN: evidence_refs=session['evidence_refs'], risk_review=case['...: merge the supplied fields into this
        # IRIS EXPLAIN: existing mapping.
        common.update(evidence_features=session["features"], source_event_ids=session["source_event_ids"],
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: evidence_refs=session["evidence_refs"], risk_review=case["risk_review"],.
                      evidence_refs=session["evidence_refs"], risk_review=case["risk_review"],
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: primary_controls=case["primary_controls"],
                      # IRIS EXPLAIN: shadow_candidate=prediction["shadow_candidate"]).
                      primary_controls=case["primary_controls"], shadow_candidate=prediction["shadow_candidate"])
    # IRIS EXPLAIN: Check this alternative branch when role == 'grc'.
    elif role == "grc":
        # IRIS EXPLAIN: Call common.update(risk_snapshots=session['risk_snapshots'], risk_review=case['risk_review'],
        # IRIS EXPLAIN: primary_controls=case['primary_controls'], shadow_candidate=predicti...: merge the supplied fields into
        # IRIS EXPLAIN: this existing mapping.
        common.update(risk_snapshots=session["risk_snapshots"], risk_review=case["risk_review"],
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: primary_controls=case["primary_controls"],
                      # IRIS EXPLAIN: shadow_candidate=prediction["shadow_candidate"],.
                      primary_controls=case["primary_controls"], shadow_candidate=prediction["shadow_candidate"],
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: shadow_model_context=session["context"],.
                      shadow_model_context=session["context"],
                      # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                      # IRIS EXPLAIN: arguments/items: shadow_context_note="Model 2 uses the same representative prior-risk
                      # IRIS EXPLAIN: context as training; it is not an official matched risk or effectiveness estimate.").
                      shadow_context_note="Model 2 uses the same representative prior-risk context as training; it is not an official matched risk or effectiveness estimate.")
    # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
    else:
        # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Unknown result view'); the caller's
        # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
        raise ValueError("Unknown result view")
    # IRIS EXPLAIN: Return common to the caller; this ends the current function path.
    return common
