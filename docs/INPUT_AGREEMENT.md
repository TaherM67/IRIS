# IRIS Input Agreement

Expanded seven class analysis and synthetic data generation

Contract iris-expanded-input-v1 | Version 1.0.0 | Issued 14 November 2026

Supply exactly three operational files: asset_inventory.json, risk_register.json and siem_alerts.jsonl. This agreement fixes their fields, meanings, joins, time rules and acceptance checks for the expanded IRIS profile. An optional offline label file supports later reviewed model refinement and is never a runtime input.

The refinement strengthens input diagnostics, complete review processing and evidence-grounded control advice. The learned weights and frozen confidence thresholds are unchanged. New fitting and performance claims require the supplied dataset, reviewed labels and a held-out evaluation.

## 1 Contract scope and deliverables

| Item | Role and exact requirement |
| --- | --- |
| asset_inventory.json | Required runtime JSON object. schema_version is iris-asset-inventory-v1; data_provenance is synthetic; records contains inventory snapshots. |
| risk_register.json | Required runtime JSON object. schema_version is iris-risk-register-v1; data_provenance is synthetic; control_membership_basis is versioned_runtime_risk_snapshots; records contains risk snapshots. |
| siem_alerts.jsonl | Required runtime JSON Lines file. One complete observed event object per line, with every required alert field. No enclosing array and no blank lines. |
| training_labels.jsonl | Optional for inference; required before supervised refinement. Offline event-to-session annotations with explicit provenance and review status. |
| Catalogue reference | Fixed supplied file control_catalogue_reference.json, containing 120 control IDs, names, applicability and technique mappings. Do not generate or replace it. It is not a fourth uploaded runtime source. |
| Schemas and contract.json | Normative machine-readable definitions. Schema field names, nullability, enum values, string bounds and the pinned profile/catalogue identities control acceptance. |

Serving profile: iris_scenarios_20261109. Model 1 uses 23 observed session features and seven scenario classes. Grounded Model 2 evaluates 120 control candidates using observed technique, asset and registered-risk context. Primary risk policy and human approval remain separate from the learned scores.

This agreement is for clearly declared LLM-generated synthetic data. The current experimental models do not become approved for real operational data by changing a provenance flag. The separate older three-class/v2 input adapters remain available; they are not the schema for this generation request.

## 2 Shared encoding and data integrity rules

Use UTF-8 without a byte-order mark, exact case-sensitive field names, finite JSON numbers and standard JSON true, false and null. Integer fields use integer notation, such as 3 rather than 3.0. Duplicate JSON keys, extra fields, placeholders and ellipses are rejected.

Every field listed in the relevant schema is required. Null is permitted only when its type explicitly includes null. Zero and false mean an observed zero/false value, never a substitute for missing evidence.

Use UTC timestamps ending Z, for example 2026-11-01T09:00:00Z. Optional fractional seconds may have one to six digits. valid_to may be null. Historical intervals are half-open: valid_from <= event time < valid_to.

recorded_at is the time the snapshot became known. A selected asset/risk snapshot must be both valid and known at the event timestamp. Do not use later records to explain earlier observations.

Keep stable logical asset_id and risk_id values across changes. Each snapshot has its own unique version ID. A risk_id belongs to one asset throughout its history. Versions of one logical record must not overlap.

Provide one unambiguous active registered risk per asset and risk category. Ambiguous categories block primary risk mapping rather than choosing an arbitrary record.

Use unique event IDs and explicit monitored asset IDs. A remote sender or recipient is not the monitored victim merely because its IP occurs in an alert.

Do not include scenario_class, ground_truth, label, target, recommended_control_ids, desired priorities or post-decision risk values in the operational sources. Business criticality and registered likelihood/impact are pre-existing context, not model truth.

| Bound | Maximum per batch |
| --- | --- |
| Inventory file / risk file | 5 MiB each; 5,000 snapshots in each records array |
| SIEM file | 20 MiB; 50,000 event rows |
| Prepared sessions | 5,000; excess batches are rejected, not silently truncated |
| Time grouping | 60-second inactivity boundary; asset/risk version changes can also split a run |
| Clean nominal bundle | Every supplied event must belong to exactly one prepared session. No duplicate, quarantined or unresolved events. |

## 3 Asset inventory fields

The top-level envelope has exactly schema_version, data_provenance and records. The following fields are required in every records element. Array sizes and identifier/string limits are specified in asset_inventory.schema.json.

| Field | Type | Meaning and allowed values |
| --- | --- | --- |
| asset_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| asset_version_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| hostname | string | Lowercase exact hostname; keep consistent with alert.agent_name. |
| ip_addresses | array<string> | Addresses of this monitored asset in this version. |
| asset_type | string | Asset kind used for organizational context. Allowed: server, workstation, network_device, identity_service, web_application, database, cloud_resource, iot_device. |
| criticality | integer; 1 to 5 | Pre-existing business criticality, 1 low to 5 highest; not an attack target. |
| zone | string | Network or business zone. |
| owner | string | Fictional accountable team. |
| control_groups | array<string> | Only groups that actually apply to this asset. Allowed items: all, cloud, db, endpoint, identity, iot, network, server, web. |
| valid_from | string | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |
| valid_to | string / null | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |
| recorded_at | string | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |

Control groups must describe actual applicability, for example server and identity for an identity server. Do not put every group on every asset. The all value is a catalogue group, not permission to assume every control is relevant. Use only fictional owners, hostnames and addresses.

## 4 Risk register fields

The top-level envelope has schema_version, data_provenance, control_membership_basis and records. The membership basis is versioned_runtime_risk_snapshots. The following fields are required in every risk snapshot.

| Field | Type | Meaning and allowed values |
| --- | --- | --- |
| risk_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| risk_version_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| asset_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| risk_category | string | Exact business-risk category, with one active risk per asset/category. Allowed: Unauthorized Access, Reconnaissance, Malware Execution, Privilege Escalation, Web Application Compromise, Data Exfiltration. |
| likelihood | integer; 1 to 5 | Pre-decision likelihood from this historical risk version; never a model output. |
| impact | integer; 1 to 5 | Pre-decision impact, 1 lowest to 5 highest. |
| existing_control_ids | array<string> | Explicit registered membership, not inferred recommendation targets. Use only the 120 supplied catalogue IDs. |
| planned_control_ids | array<string> | Explicit planned membership; disjoint from existing_control_ids. Use only the 120 supplied catalogue IDs. |
| mitre_attack_techniques | array<string> | Technique links registered before analysis, not oracle alert labels. |
| control_states | object | Implementation state per linked control; use unknown when unobserved. |
| active_exception_control_ids | array<string> | Active exceptions; each must belong to existing or planned membership. Use only the 120 supplied catalogue IDs. |
| valid_from | string | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |
| valid_to | string / null | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |
| recorded_at | string | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |

Allowed control state values are implemented, partial, missing, not_assessed, compensating, exception and unknown. Every state key and every active exception must refer to an explicitly existing/planned control in that same risk version. Existing and planned ID sets are disjoint.

Use exact catalogue IDs. A useful registered control must have an observed-technique match and an applicability match for the asset. A high learned score does not override either requirement. Unknown implementation remains unknown; no control-effectiveness percentage or causal risk reduction is inferred.

## 5 SIEM event fields

Write one complete event object per line in siem_alerts.jsonl. Include every field below. In particular, the six observed booleans and bytes_sent must be explicit. A missing boolean is not interpreted as false.

| Field | Type | Meaning and allowed values |
| --- | --- | --- |
| event_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| timestamp | string | UTC timestamp ending Z; valid RFC 3339 calendar time. Use UTC Z. |
| asset_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| agent_name | string | Exact monitored-asset hostname at event time. |
| destination_ip | string / null | Monitored destination asset IP for inbound observations. Null for local or outbound events. |
| remote_destination_ip | string / null | Actual remote recipient for outbound events; null for local/inbound observations. |
| network_direction | string | Explicit observation direction. Allowed: inbound, outbound, local. |
| source_ip | string | Syntactically valid IPv4 address; generated lab data uses fictional addresses. |
| account | string / null | Observed fictional account or null when unavailable. |
| event_family | string | Supported expanded telemetry family. Allowed: authentication, network, privilege, process, web. |
| protocol | string | Exact case-sensitive supported protocol; never rewrite SSH to TCP. Allowed: HTTPS, LOCAL, SSH, TCP. |
| rule_id | string | Observed detector/rule identifier; opaque, never a truth label. |
| rule_level | integer; 0 to 15 | Normalized observed rule severity, 0 to 15. |
| outcome | string | Observed event outcome. Allowed: failed, success, unknown. |
| bytes_sent | integer; 0 to 1000000000000 | Measured outbound bytes for this event only; do not repeat a session total. |
| process_unsigned | boolean | Observed unsigned-process evidence, not a scenario label. |
| privilege_change | boolean | Observed privilege-change evidence. |
| web_attack_signal | boolean | Observed web sensor signature or alert flag. |
| sensitive_data_access | boolean | Observed access to a fictional sensitive resource. |
| destination_untrusted | boolean | Observed untrusted destination evidence. |
| malicious_indicator | boolean | Observed match to a fictional known indicator, not ground-truth attack status. |
| mitre_technique | string / null | Technique explicitly observed in this event; null if none is observed. |
| sensor_healthy | boolean | True only when sensor-health evidence is available and healthy. False produces an explicit model abstention. |
| campaign_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| run_id | string | Opaque stable identifier. Never encode a class, true label or target. |
| data_provenance | constant | Required declaration on every LLM-generated alert. Required value: synthetic. |

### Monitored and remote endpoints

For inbound traffic, destination_ip is an IP of the monitored asset. For local or outbound observations, destination_ip is null and source_ip is the monitored asset address. For outbound observations, remote_destination_ip is the remote recipient; otherwise it is null. agent_name must equal the selected inventory hostname. Process/privilege observations have zero network bytes.

### Session identity and feature meaning

Sessions are grouped by campaign_id, run_id, asset, account, source IP and event family. Gaps over 60 seconds or changes in historical context split a group. For the nominal request, hold these grouping values, the protocol and the snapshot context fixed inside one source run; use another run_id for another activity.

Supported event families are authentication, network, privilege, process and web. Supported protocol values are HTTPS, LOCAL, SSH and TCP. Do not disguise an unsupported protocol as a supported one. A new protocol vocabulary or attack class needs a reviewed contract/profile update.

Detector flags are observations, not target labels. An unsigned process, web alert or known-indicator match can be noisy or legitimate. bytes_sent measures this event only. Do not repeat a total-session byte count on every event, and do not infer missing measurements from the true class.

## 6 Expected analysis and explicit limitations

| Condition | Required behavior |
| --- | --- |
| Healthy compatible observations | All clean events are accounted for, sessions receive model attempts, and the audit preserves source event IDs. Confidence thresholding can still cause an explained abstention. |
| No observed attack technique | Model 1 can still classify the session. Model 2 records missing technique context rather than inventing a control assessment. Missing technique is not proof of benign activity. |
| Unknown / conflicting implementation state | Return unknown and require review. Do not claim the control is effective or choose a made-up implementation state. |
| Unsupported control advice | Withhold candidates that lack a registered-risk/observed-technique link, a catalogue technique match or an asset-applicability match. Retain reason codes for inspection. |
| Ambiguous model prediction | Report probabilities, top-two margin and normalized entropy. These describe ambiguity, not correctness or control effectiveness. |
| Rule / model disagreement | Expose the disagreement for review. Do not silently promote the experimental model to the primary risk policy. |
| Large accepted case batch | The demo must retrieve every accepted case up to its configured limit before producing reviews. An incomplete case read fails before working-record updates. |

The complete included example has 7 assets, 42 registered risks, 95 observations and 7 prepared sessions. Its qualification has 7 input-ready Model 1 sessions and 6 sessions with complete Model 2 context; the routine session has no attack technique. The isolated inference check produced 7 Model 1 assessments and 6 Model 2 assessments. These are coverage checks, not accuracy measurements.

## 7 Offline annotations for supervised refinement

Keep training_labels.jsonl outside all runtime feature inputs. Every annotation must cover exactly the events in one prepared session and must agree with its campaign/run. Every observed event has one annotation; annotations may not overlap or refer to absent events. No majority vote or target-driven session merging is allowed.

| Field | Type | Meaning and allowed values |
| --- | --- | --- |
| case_id; event_ids | string; array<string> | Unique annotation ID and exact source event membership. |
| campaign_id; run_id | strings | Exactly match the observed activity, not a renamed evaluation split. |
| template_group | string | Identity of a copied/derived base scenario. Reused stories retain this identity. |
| scenario_class | string | One of the seven expanded classes. This field exists only offline. |
| label_source | string | llm_synthetic or deterministic_synthetic_generator. |
| review_status | string | unreviewed initially; independently_reviewed only after an actual independent review. |
| label_verified; reviewer | boolean; string/null | LLM generation sets false and null. Verification and reviewer identity must agree with review_status. |
| recommended_control_ids | array<string> | Offline reference targets, using catalogue IDs only. Leave empty when unsupported; do not derive targets from the model output. |
| controls_reviewed; control_reviewer | boolean; string/null | Initially false and null. A reviewed control target needs an actual reviewer. |

The generating LLM cannot certify its own targets as independent expert judgments. Template groups, shared campaigns and identical observed feature vectors are connected before experimental roles are assigned, so copied examples cannot cross the fit, selection, calibration, threshold and final-audit boundaries.

The preparation tool exports seven-class records with 23 observed features. It performs no fitting or activation. It marks fitting readiness false until labels are independently reviewed, there are enough independent groups and every experimental role has at least 10 sessions per class. The older train-three command is a three-class trainer and must not be used for this seven-class handoff.

Control-target review is tracked separately. Matching synthetic associations is not proof that a recommendation prevents an attack. Future Model 2 evaluations must include the deterministic catalogue baseline and controls with adequate positive support.

## 8 Exact generation request and acceptance

| Requested property | Value |
| --- | --- |
| Logical assets / current risks | 40 assets and 240 current risks, six risk categories per asset |
| Historical coverage | At least 8 assets and their 48 risks have two non-overlapping versions; include sessions on both sides of the change |
| Activity balance | 60 varied campaigns x 3 sessions per class x 7 classes = 1,260 nominal sessions |
| Routine / attack sessions | 180 routine sessions; 1,080 sessions across the six attack classes |
| Expected technique coverage | Routine activity normally has null technique. Do not invent techniques to claim 100% Model 2 coverage. |
| Variation | 36 routine sessions are benign lookalikes; 216 attack sessions are subtle/noisy variants (20% in each group). Vary timing, counts, detector levels and business context |
| Generator / provenance | Prefer a reproducible Python generator, seed 20261114, fictional data only, with generator source included |
| Partition intent | Separate connected campaign/template/identical-feature groups; approximately 60/10/10/10/10 when enough groups exist |
| Initial review status | All LLM-supplied scenario and control labels start unreviewed; no claimed expert certification |

The full copyable request is LLM_GENERATION_PROMPT.txt. Give the data-generating LLM this agreement, all four schemas and the supplied catalogue reference. Ask for executable generator code when a chat response cannot safely contain all records. Never accept a truncated file as a complete dataset.

### Acceptance commands from the updated IRIS repository

python tools/validate_inputs.py --input-dir DATA_DIRECTORY --out NEW_qualification.json

python tools/prepare_expanded_training.py --input-dir DATA_DIRECTORY --labels DATA_DIRECTORY/training_labels.jsonl --out NEW_REVIEW_DIRECTORY

python tools/check_input_coverage.py --assets DATA_DIRECTORY/asset_inventory.json --risks DATA_DIRECTORY/risk_register.json --alerts DATA_DIRECTORY/siem_alerts.jsonl --model-profile auto --out NEW_COVERAGE_DIRECTORY

The qualifier must report zero contract errors and account for every nominal event. Inspect every warning, prepared-session count, readiness count and actual inference outcome. A valid schema is not a promise of a confident prediction. Keep negative tests in a separate bundle with expected diagnostics.

Return the three operational files, optional offline labels, generator source and validation outputs together. The next model-refinement step is review of these actual data and labels, followed by a fresh versioned fit, calibration and sealed evaluation. Existing model versions, saved approvals and original inputs remain traceable; no performance figure is invented before that work.
