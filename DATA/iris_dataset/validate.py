import json, sys, collections
d = sys.argv[1]
L = lambda f, k: json.load(open(f"{d}/{f}"))[k]
assets, risks, ctrls, alerts, labels = L("asset_inventory.json","assets"), L("risk_register.json","risks"), L("security_controls.json","controls"), L("siem_alerts.json","alerts"), L("training_labels.json","labels")
err = []
def uniq(rows, k, name):
    c = collections.Counter(r[k] for r in rows); bad = [x for x, n in c.items() if n > 1]
    if bad: err.append(f"{name}: duplicate ids {bad[:3]}")
uniq(assets,"asset_id","assets"); uniq(risks,"risk_id","risks"); uniq(ctrls,"control_id","controls"); uniq(alerts,"alert_id","alerts")
ips = collections.Counter(a["ip_address"] for a in assets)
if any(n > 1 for n in ips.values()): err.append("duplicate asset IPs")
A = {a["asset_id"]: a for a in assets}; Rk = {r["risk_id"]: r for r in risks}; C = {c["control_id"] for c in ctrls}
for r in risks:
    if r["asset_id"] not in A: err.append(f"risk {r['risk_id']} bad asset")
    for c in r["existing_control_ids"] + r["planned_control_ids"]:
        if c not in C: err.append(f"risk {r['risk_id']} bad control {c}")
    if r["inherent"]["score"] != r["inherent"]["likelihood"] * r["inherent"]["impact"]: err.append(f"score {r['risk_id']}")
    if r["history"][-1]["likelihood"] != r["inherent"]["likelihood"]: err.append(f"history mismatch {r['risk_id']}")
    if r["history"] != sorted(r["history"], key=lambda h: h["valid_from"]): err.append(f"history order {r['risk_id']}")
sessions = set()
for x in alerts:
    sessions.add(x["session_id"])
    s = x["associations"]; aid = s["asset_id"]
    if aid is None:
        if x["dst_ip"] in ips: err.append(f"{x['alert_id']} unlinked but IP known")
        continue
    a = A.get(aid)
    if not a: err.append(f"{x['alert_id']} bad asset"); continue
    if a["ip_address"] != x["dst_ip"]: err.append(f"{x['alert_id']} dst_ip mismatch")
    if x["timestamp"] < a["valid_from"]: err.append(f"{x['alert_id']} before asset valid_from")
    if a["status"] == "retired": err.append(f"{x['alert_id']} on retired asset")
    for r in s["risk_ids"]:
        if r not in Rk or Rk[r]["asset_id"] != aid: err.append(f"{x['alert_id']} bad risk link {r}")
    for c in s["control_ids"]:
        if c not in C: err.append(f"{x['alert_id']} bad control link")
lab = {l["session_id"] for l in labels}
if lab != sessions: err.append(f"label/session mismatch: {len(lab ^ sessions)}")
ts = [x["timestamp"] for x in alerts]
print("alerts per session  min/avg/max:", min(collections.Counter(x["session_id"] for x in alerts).values()), round(len(alerts)/len(sessions),1), max(collections.Counter(x["session_id"] for x in alerts).values()))
print("time range:", min(ts), "->", max(ts))
print("risk ratings:", dict(collections.Counter(r["inherent"]["rating"] for r in risks)))
print("control status:", dict(collections.Counter(c["implementation_status"] for c in ctrls)))
print("alert sources:", dict(collections.Counter(x["source"] for x in alerts)), "severity:", dict(collections.Counter(x["severity"] for x in alerts)))
print("risks re-assessed in window:", sum(1 for r in risks if r["history"][-1]["valid_from"] >= "2026-09-28"))
print("ERRORS:", len(err)); print("\n".join(err[:15]))
