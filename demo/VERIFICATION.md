# Active demo verification

Verified 25 October 2026. This record applies to `demo.py` and `demo_app/`, not the separately prepared FastAPI server.

## Executed

```bash
python -m unittest demo_app.tests.test_demo -v
```

**52 tests passed**, including 32 active-core tests and 20 real loopback HTTP tests. These use the actual pinned user Colab models, not a dummy classifier. The 79 original model tests and 33 earlier backend-core tests also pass: **164 Python regression tests in total**.

The additional optional developer command `node demo_app/tests/test_ui_controller.js` passed all three role flows. It executes the actual frontend controller against deliberate DOM/API doubles, checking login, role-only reads, summary rendering, approval/read-only behavior and logout. It is not a real-browser or visual-layout test, and Node is not required to run the demo.

Verified:

- Three exact source hashes; 30 assets, 60 risks, 2,367 source alert rows.
- 132 cases; 2,355 clean, matched working alerts; cleaning/ambiguity handling.
- Initial analysis creates 123 SOC and 63 GRC proposals without changing working records.
- Actual fresh HTTP analysis through the demo server, followed by both team approvals and current-state exports.
- GRC approval changes `DEMO-R001-1`: likelihood 3 → 4, impact remains 5, score 0.60 → 0.80, revision 1 → 2.
- SOC approval changes 19 of the newest identity-server session's 29 alert priorities to Critical; ten already-Critical alerts are left unchanged.
- Database-backed queue sorting, before/after change entries, audit, rejection, role separation, idempotent retry and persistence on restart.
- Optimistic revision checks and atomic SOC group updates; no partial target mutation if one target is stale.
- Same-risk stale proposal protection; one old evidence batch cannot repeatedly increase a risk.
- A new rehearsal preserves previous records/history while isolating new approvals; old-exercise proposals cannot alter the new exercise.
- Original input bytes remain unchanged; no external writes, control execution or model release.
- Authentication before command-body parsing, local host/origin restriction, bounded JSON bodies, role-restricted exports and no static-file path traversal.
- SOC state/proposals omit GRC counters, risk values and control recommendations; GRC state/proposals omit SOC counters, raw telemetry and model confidence/metrics. Admin retains the full evidence and both teams' working records.
- Actual served SOC/GRC HTML omits other-team and Admin panels/links rather than merely hiding them. Template slots resolve, element IDs are unique and partial templates are not publicly served as static pages.
- Only Admin can run analysis or create a rehearsal; team approvals and stale-revision protections remain unchanged. Role/query parameters cannot expand authenticated-key access.

The Python source compiles; JavaScript syntax checks pass; HTML IDs and script references match; UI values use text nodes rather than untrusted HTML; all frontend assets are local.

## Not executed / not established

No real browser executable was available, so browser click-through, visual rendering and download interactions need a local rehearsal. Serving HTML/JS successfully is not a browser execution test.

No external SOC/GRC vendor APIs, company systems, cloud deployment, production security assessment or new real-world ML evaluation were tested. This is a local, synthetic-system demonstration. The original ML artifact/release gates are unchanged.

The older FastAPI HTTP tests still require its unavailable web dependencies and are not included in the executed test counts above.
