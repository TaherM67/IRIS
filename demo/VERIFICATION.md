# Restored active demo verification

Verified 25 October 2026. Applies to `demo.py` and `demo_app/`, not the separate passive FastAPI prototype.

## Executed

```bash
python -m unittest demo_app.tests.test_demo -v
python -m unittest backend.tests.test_core -v
# From IRIS_Models_v2:
python -m unittest discover -s tests -v
# Optional controller checks, from the repository root:
node demo_app/tests/test_ui_controller.js
```

**54 demo tests** (32 core and 22 real loopback HTTP), **33 backend-core tests**, and **79 model tests** pass: **166 Python regressions** total. The demo core/HTTP fixtures use the actual pinned user Colab model. Nine controller scenarios execute the actual restored JavaScript against deliberate DOM/API doubles, not a real browser.

## Original UI restoration

- Restores the original annotated dark stylesheet rules byte-for-byte; only a team-only three-counter rule is appended.
- Restores the original hero, login form, five-card Admin strip, proposal summary/evidence, working tables and applied-change history. No sidebar or redesigned before/after card.
- Restores direct `/state` key login. No `/info`, version/profile or separate `/session` prerequisite.
- Omits unrelated blocks from the original served HTML. Team pages contain only their own counters, working table, evidence and history. Admin receives both working tables plus full model/audit/history.
- Keeps the existing API role allowlists, Admin-only analysis, team-only approval authority and query-escalation denial.
- Removes unused redesigned page partials and the redesign-only access helper/commands. They remain recoverable in Git history. Existing keys and runtime records are not removed.
- Controller checks cover role-only reads, working summary/table rendering, approvals, read-only Admin reviews, failed/wrong-role login and logout.

## Engine and persistence

- Original source hashes, pinned models, explicit policy and database schema unchanged.
- Three operational inputs, 132 saved cases, 2,355 clean matched alerts, 60 current risks.
- Analysis creates 123 SOC and 63 GRC proposals without prematurely changing records.
- GRC approval changes likelihood 3→4, keeps impact 5, changes score 0.60→0.80 and revision 1→2.
- SOC approval changes 19 alert priorities to Critical; ten already-Critical records are not rewritten.
- Atomic writes, stale-revision denial, idempotent retry, rejection, audit, current-state exports, queue sorting and restart persistence.
- New rehearsals preserve history and isolate old proposals.
- Original inputs remain unchanged; no external system writes, control execution or model release.
- Exact local host/origin, authentication before body parsing, bounded commands and forbidden cross-team exports preserved.

## Limits

No real browser executable was available. Layout/click-through and download interaction still need a local rehearsal. Static HTML/controller tests are not visual browser verification.

No vendor integrations, cloud deployment, production security assessment or real-world ML effectiveness were established. The separately prepared FastAPI HTTP tests remain unexecuted because its web dependencies were unavailable and are not included in the 166 tests above.
