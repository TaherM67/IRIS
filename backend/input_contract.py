"""Executable synthetic expanded-input agreement.

Only the three supplied runtime sources are read. No model weights, training
labels, credentials, saved demo state or database are opened.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import math
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "expanded-v1"
FILES = {"asset_inventory": "asset_inventory.json", "risk_register": "risk_register.json",
         "siem_alerts": "siem_alerts.jsonl"}
ML_ROOT = str(ROOT / "IRIS_Models_v2")
if ML_ROOT not in sys.path:
    sys.path.insert(0, ML_ROOT)


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON object key: " + key)
        result[key] = value
    return result


def _json(text):
    def invalid(value):
        raise ValueError("Non-finite JSON token: " + value)
    return json.loads(text, object_pairs_hook=_object, parse_constant=invalid)


def _time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _schema(value, schema, path, issue):
    """Evaluate exactly the JSON Schema vocabulary used by the bundled schemas."""
    allowed = {"$schema", "$id", "title", "description", "type", "const", "enum",
               "minimum", "maximum", "minLength", "maxLength", "pattern", "format",
               "items", "minItems", "maxItems", "uniqueItems", "properties", "required",
               "additionalProperties", "maxProperties"}
    if set(schema) - allowed:
        raise ValueError("Unsupported contract schema keywords: " + str(sorted(set(schema)-allowed)))
    if "const" in schema and (value != schema["const"] or type(value) is not type(schema["const"])):
        issue(path, "Expected constant " + repr(schema["const"]))
    if "enum" in schema and not any(value == v and type(value) is type(v) for v in schema["enum"]):
        issue(path, "Value is outside the declared allowed values")
    kinds = schema.get("type")
    if isinstance(kinds, str):
        kinds = [kinds]
    matches = {"object": type(value) is dict, "array": type(value) is list,
               "string": type(value) is str, "null": value is None,
               "integer": type(value) is int,
               "number": type(value) is int or (type(value) is float and math.isfinite(value)),
               "boolean": type(value) is bool}
    if kinds and not any(matches[k] for k in kinds):
        issue(path, "Expected JSON type " + "/".join(kinds))
        return
    if value is None:
        return
    if type(value) in (int, float):
        if type(value) is float and not math.isfinite(value):
            issue(path, "A finite number is required")
        for bound, op in (("minimum", lambda a,b:a<b), ("maximum", lambda a,b:a>b)):
            if bound in schema and op(value, schema[bound]):
                issue(path, f"Value violates {bound}={schema[bound]}")
    if type(value) is str:
        for bound, op in (("minLength", lambda a,b:a<b), ("maxLength", lambda a,b:a>b)):
            if bound in schema and op(len(value), schema[bound]):
                issue(path, f"String violates {bound}={schema[bound]}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            issue(path, "String does not match the declared pattern")
        try:
            if schema.get("format") == "ipv4":
                ipaddress.IPv4Address(value)
            elif schema.get("format") == "date-time":
                _time(value)
        except (ValueError, OverflowError):
            issue(path, "Invalid " + schema["format"])
    if type(value) is list:
        for bound, op in (("minItems", lambda a,b:a<b), ("maxItems", lambda a,b:a>b)):
            if bound in schema and op(len(value), schema[bound]):
                issue(path, f"Array violates {bound}={schema[bound]}")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(x, sort_keys=True, allow_nan=False) for x in value]
            if len(encoded) != len(set(encoded)):
                issue(path, "Array items must be unique")
        for i, child in enumerate(value):
            _schema(child, schema.get("items", {}), f"{path}[{i}]", issue)
    if type(value) is dict:
        props = schema.get("properties", {})
        for key in schema.get("required", []):
            if key not in value:
                issue(path + "." + key, "Required field is missing; do not invent a default")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            issue(path, "Too many object properties")
        for key, child in value.items():
            if key in props:
                _schema(child, props[key], path+"."+key, issue)
            elif schema.get("additionalProperties") is False:
                issue(path+"."+key, "Unknown or forbidden field; target labels are offline only")
            elif isinstance(schema.get("additionalProperties"), dict):
                _schema(child, schema["additionalProperties"], path+"."+key, issue)


def validate_inputs(paths, *, contract_dir=CONTRACT):
    """Check the strict new agreement, links and actual prepared session readiness."""
    report = {"contract_id": "iris-expanded-input-v1", "valid": False, "status": "REJECTED",
              "errors": [], "warnings": [], "issues_omitted": 0, "source_sha256": {},
              "counts": {}, "readiness": None, "sessions": [],
              "model_weights_loaded": False, "training_labels_read": False,
              "accuracy_evaluated": False}
    def add(kind, location, message):
        if len(report[kind]) < 200:
            report[kind].append({"path": location, "message": message})
        else:
            report["issues_omitted"] += 1
    error = lambda p,m: add("errors",p,m)
    warning = lambda p,m: add("warnings",p,m)
    if set(paths) != set(FILES):
        error("inputs", "Exactly asset_inventory, risk_register and siem_alerts are required")
        return report
    contract_dir = Path(contract_dir)
    manifest = _json((contract_dir/"contract.json").read_text())
    reference_path = contract_dir/"control_catalogue_reference.json"
    if hashlib.sha256(reference_path.read_bytes()).hexdigest() != manifest["catalogue_reference_sha256"]:
        error("catalogue", "Pinned catalogue reference changed; review and version the contract")
        return report
    catalogue = {c["control_id"]:c for c in _json(reference_path.read_text())}
    raw = {}
    for key, name in FILES.items():
        path = Path(paths[key])
        try:
            size = path.stat().st_size
            if not 0 < size <= manifest["maximum_file_bytes"][key]:
                raise ValueError("Empty file or contract byte limit exceeded")
            data = path.read_bytes()
            report["source_sha256"][key] = hashlib.sha256(data).hexdigest()
            text = data.decode("utf-8")
            if text.startswith("\ufeff"):
                raise ValueError("UTF-8 without a byte-order mark is required")
            if key == "siem_alerts":
                raw[key] = []
                rows = text.splitlines()
                if len(rows) > manifest["maximum_alert_rows"]:
                    raise ValueError("Alert row limit exceeded")
                for i, line in enumerate(rows, 1):
                    if not line.strip():
                        error(f"{name}#L{i}", "Blank JSONL lines are not permitted")
                        continue
                    try:
                        raw[key].append(_json(line))
                    except (ValueError, TypeError) as exc:
                        error(f"{name}#L{i}", str(exc))
            else:
                raw[key] = _json(text)
            schema_name = "siem_alert" if key == "siem_alerts" else key
            schema = _json((contract_dir/"schemas"/(schema_name+".schema.json")).read_text())
            if key == "siem_alerts":
                for i, event in enumerate(raw[key], 1):
                    _schema(event, schema, f"{name}#L{i}", error)
            else:
                _schema(raw[key], schema, name, error)
        except (ValueError, TypeError, OSError, UnicodeError) as exc:
            error(name, str(exc))
    if report["errors"]:
        return report
    assets, risks, alerts = raw["asset_inventory"]["records"], raw["risk_register"]["records"], raw["siem_alerts"]
    report["counts"] = {"asset_snapshots": len(assets), "logical_assets": len({a["asset_id"] for a in assets}),
                        "risk_snapshots": len(risks), "logical_risks": len({r["risk_id"] for r in risks}),
                        "alert_rows": len(alerts), "campaigns": len({a["campaign_id"] for a in alerts}),
                        "source_runs": len({(a["campaign_id"],a["run_id"]) for a in alerts})}
    for name, rows, vid in (("asset_inventory",assets,"asset_version_id"),("risk_register",risks,"risk_version_id")):
        seen = set()
        for i, row in enumerate(rows):
            if row[vid] in seen:
                error(f"{name}.records[{i}].{vid}", "Duplicate version identifier")
            seen.add(row[vid])
            if row["valid_to"] and _time(row["valid_to"]) <= _time(row["valid_from"]):
                error(f"{name}.records[{i}].valid_to", "Must be later than valid_from")
    asset_ids = {a["asset_id"] for a in assets}
    category_histories = defaultdict(list)
    for i, risk in enumerate(risks):
        loc=f"risk_register.records[{i}]"
        if risk["asset_id"] not in asset_ids:
            error(loc+".asset_id", "Risk references an absent inventory asset")
        existing, planned = set(risk["existing_control_ids"]), set(risk["planned_control_ids"])
        members = existing | planned
        if existing & planned:
            error(loc, "Existing and planned control membership must be disjoint")
        if not set(risk["control_states"]) <= members:
            error(loc+".control_states", "State keys must be registered existing/planned controls")
        if not set(risk["active_exception_control_ids"]) <= members:
            error(loc+".active_exception_control_ids", "Exceptions must be registered controls")
        if not members:
            warning(loc, "No registered candidate controls; no recommendation must be fabricated")
        category_histories[(risk["asset_id"],risk["risk_category"])].append(risk)
    for key, history in category_histories.items():
        history.sort(key=lambda x:_time(x["valid_from"]))
        for before, after in zip(history, history[1:]):
            if before["risk_id"] != after["risk_id"] and (before["valid_to"] is None or _time(before["valid_to"])>_time(after["valid_from"])):
                error("risk_register."+str(key), "Multiple active risks in one asset/category would make primary mapping ambiguous")
    seen = set()
    for i, event in enumerate(alerts,1):
        loc=f"siem_alerts.jsonl#L{i}"
        if event["event_id"] in seen:
            error(loc+".event_id", "Duplicate event identifier; remove redelivery rows from the clean bundle")
        seen.add(event["event_id"])
        if event["asset_id"] not in asset_ids:
            error(loc+".asset_id", "Event references an absent inventory asset")
        if event["network_direction"] in {"outbound","local"} and event["destination_ip"] is not None:
            error(loc+".destination_ip", "Must be null for outbound/local events; this field resolves the monitored destination")
        if event["network_direction"]=="inbound" and event["destination_ip"] is None:
            error(loc+".destination_ip", "Inbound observations require the monitored destination address")
        if event["network_direction"]=="outbound" and event["remote_destination_ip"] is None:
            error(loc+".remote_destination_ip", "Outbound observations require their explicit remote recipient")
        if event["network_direction"]!="outbound" and event["remote_destination_ip"] is not None:
            error(loc+".remote_destination_ip", "Only outbound observations carry a remote recipient")
        if event["event_family"] in {"process","privilege"} and event["bytes_sent"] != 0:
            error(loc+".bytes_sent", "A local process/privilege event is not a network byte measurement")
        if not event["sensor_healthy"]:
            warning(loc+".sensor_healthy", "This session will remain unassessed by the current experimental models")
    if report["errors"]:
        return report
    try:
        from iris_models.three_sources import integrate
        from iris_models.contracts import FEATURES
        from .grounded_context import GroundedContext
        from .scenarios import attach_evidence, feature_row
        unified, sessions, integration = integrate(Path(paths["asset_inventory"]),Path(paths["risk_register"]),Path(paths["siem_alerts"]),window_seconds=60)
        if not 0 < len(sessions) <= manifest["maximum_sessions"]:
            error("sessions", "Prepared session count must be 1..5000")
        if integration["quarantine"] or integration["conflicting_event_ids_excluded"] or integration["unresolved_asset_events"] or integration["exact_duplicate_rows_removed"]:
            error("integration", "Clean input agreement forbids excluded, unresolved, quarantined or duplicated events")
        members = [eid for s in sessions for eid in s["source_event_ids"]]
        if len(members)!=len(set(members)) or set(members)!=seen:
            error("integration", "Every supplied event must belong to exactly one prepared session")
        raw_alert_by_id = {a["event_id"]:a for a in alerts}
        for event in unified:
            asset = event["asset"]
            if asset:
                original = raw_alert_by_id[event["event_id"]]
                if original["agent_name"] != asset["hostname"]:
                    error("event."+event["event_id"]+".agent_name","Hostname disagrees with the selected asset version")
                if original["network_direction"] in {"outbound","local"} and original["source_ip"] not in asset["ip_addresses"]:
                    error("event."+event["event_id"]+".source_ip","Local/outbound source must be the monitored asset address")
        context = GroundedContext({k:Path(v) for k,v in paths.items()})
        enriched = attach_evidence([context.attach(s) for s in sessions],{k:Path(v) for k,v in paths.items()})
        ready1=ready2=0
        for session in enriched:
            row=feature_row(session,FEATURES)
            eligible = session["sensor_healthy"] is True and session["scenario_evidence_complete"] is True
            missing=session["model2_context"]["missing_fields"]
            m2_eligible=eligible and not missing
            ready1+=int(eligible);ready2+=int(m2_eligible)
            report["sessions"].append({"session_id":session["session_id"],"event_count":len(session["source_event_ids"]),
               "asset_id":session["asset_id"],"asset_version_id":session["asset_snapshot"]["asset_version_id"],
               "risk_version_ids":[r["risk_version_id"] for r in session["risk_snapshots"]],
               "campaign_id":session["campaign_id"],"run_id":session["run_id"],
               "model1_input_ready":eligible,"model2_context_ready":m2_eligible,"model2_missing_fields":missing,
               "event_family":row["event_family"],"primary_protocol":row["primary_protocol"]})
        report["counts"]["prepared_sessions"]=len(sessions)
        report["readiness"]={"model1_input_ready_sessions":ready1,"model1_total_sessions":len(sessions),
           "model2_complete_context_sessions":ready2,"model2_total_sessions":len(sessions),
           "model2_missing_field_counts":dict(Counter(f for s in report["sessions"] for f in s["model2_missing_fields"])),
           "all_events_accounted_for":len(members)==len(alerts) and len(set(members))==len(members),
           "prediction_coverage_measured":False}
        if ready1<len(sessions):
            warning("model1","Some sessions cannot run; inspect their explicit health/evidence flags")
        if ready2<len(sessions):
            warning("model2","Some sessions have no complete control context. A missing technique is not evidence of benign activity")
    except (ValueError, KeyError, TypeError, OverflowError) as exc:
        error("integration",str(exc))
    report["valid"]=not report["errors"]
    report["status"]="REJECTED" if report["errors"] else "VALID_WITH_LIMITATIONS" if report["warnings"] else "VALID"
    return report

