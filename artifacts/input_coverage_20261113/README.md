# Input compatibility verification - 13 November 2026

The serving code was checked against GitHub commit
`5901aed1e462568d07a11983cf9f81fed8d9e27d`. The seven-class model was already
present. This update fixes runtime schema/profile pairing, not model fitting.

| Dataset | Retained fragments checked | Model 1 predictions | Grounded Model 2 assessments | Explicit remaining outcome |
| --- | ---: | ---: | ---: | --- |
| Expanded demo | 84 | 84 | 72 | 12 without an observed technique |
| Original demo, matching SSH model | 132 | 131 | Different original advisor/catalogue | 1 blocked by missing healthy-sensor evidence |
| Supplied v2 JSON files | 2,985 | 2,985 | 2,388 | 597 without an observed technique |

Every retained fragment was processed and read back from an isolated backend
database. Original operational files and the existing website state were not
changed. The v2 source's 1,340 original session identifiers split into 2,985
fragments; this is not evidence of 2,985 independent attacks. The 131 events with
unresolved assets remain held aside rather than receiving invented asset context.

Each dataset folder contains an aggregate `coverage.json` and a line-by-line
`session_outcomes.jsonl`. Check `verification.json` for environment, tests and
the evidence boundary. All 6,665 retained v2 telemetry mappings matched the
existing offline training adapter. Model 2 receives the separately retained,
explicit technique and registered-control context.

301 Python tests: 286 passed, 15 existing TLS/LAN setup-dependent checks skipped,
zero failures/errors. JavaScript controller checks passed. No browser visual
rehearsal or production control-efficacy assessment is claimed.

These are **coverage**, not new accuracy/F1 results. No weights were retrained,
runtime labels read, security controls executed or official risk records changed.

Run `python tools/check_input_coverage.py --dataset v2` from the repository root
to produce a new isolated result folder. For the smaller demonstration use
`--dataset expanded`. See [full instructions](../../docs/INPUT_COVERAGE.md).
