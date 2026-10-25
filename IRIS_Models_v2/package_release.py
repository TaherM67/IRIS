# IRIS EXPLAIN: File purpose: Packages the model project and writes a content-hash manifest when explicitly run;
# IRIS EXPLAIN: importing/running this packaging script has file-writing side effects.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Create a clean source/demo ZIP and a reproducible content-hash inventory."""
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path
# IRIS EXPLAIN: Import hashlib to compute deterministic byte identities and content fingerprints.
import hashlib
# IRIS EXPLAIN: Import zipfile to inspect/package ZIP contents with explicit source-path checks.
import zipfile

# IRIS EXPLAIN: Store Path(__file__).resolve().parent in root; later lines use this named result.
root = Path(__file__).resolve().parent
# IRIS EXPLAIN: Store the computed value root.parent / 'IRIS_Model_Code_v2.zip' in output; later lines use this named result.
output = root.parent / "IRIS_Model_Code_v2.zip"
# IRIS EXPLAIN: Store {'__pycache__', '.git', '.venv', 'build', 'dist'} in excluded; later lines use this named result.
excluded = {"__pycache__", ".git", ".venv", "build", "dist"}
# IRIS EXPLAIN: Store sorted((p for p in root.rglob('*') if p.is_file() and (not any((part in excluded or
# IRIS EXPLAIN: part.endswith('.egg-inf... in paths; later lines use this named result.
paths = sorted(p for p in root.rglob("*") if p.is_file()
               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
               # IRIS EXPLAIN: and not any(part in excluded or part.endswith(".egg-info") for part in
               # IRIS EXPLAIN: p.relative_to(root).parts).
               and not any(part in excluded or part.endswith(".egg-info") for part in p.relative_to(root).parts)
               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
               # IRIS EXPLAIN: and p.suffix != ".pyc" and p.name != "MANIFEST.sha256".
               and p.suffix != ".pyc" and p.name != "MANIFEST.sha256"
               # Raw unified event audits are large and quickly reproducible.
               # Ship the complete model sessions, inputs, reports and weights.
               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
               # IRIS EXPLAIN: and not (p.name == "unified_events.jsonl" and p.relative_to(root).parts[0] == "examples").
               and not (p.name == "unified_events.jsonl" and p.relative_to(root).parts[0] == "examples")
               # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing arguments/items:
               # IRIS EXPLAIN: and "examples/three_input_prediction/prepared" not in p.relative_to(root).as_posix()).
               and "examples/three_input_prediction/prepared" not in p.relative_to(root).as_posix())
# IRIS EXPLAIN: Store the result of ''.join((f'{hashlib.sha256(p.read_bytes()).hexdigest()} {p.relative_to(root).as_posix()}\n'
# IRIS EXPLAIN: for p in paths)) (wait within the existing limit for the test thread to end) in inventory; later lines use this
# IRIS EXPLAIN: named result.
inventory = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n" for p in paths)
# IRIS EXPLAIN: Store the computed value root / 'MANIFEST.sha256' in manifest; later lines use this named result.
manifest = root / "MANIFEST.sha256"
# IRIS EXPLAIN: Call manifest.write_text(inventory, encoding='utf-8'): write the existing text payload.
manifest.write_text(inventory, encoding="utf-8")
# IRIS EXPLAIN: Enter zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive; its context manager supplies
# IRIS EXPLAIN: the existing cleanup/transaction/expected-exception behavior.
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    # IRIS EXPLAIN: Iterate [*paths, manifest], binding each item to path; process only the existing observed/fixture
    # IRIS EXPLAIN: collection.
    for path in [*paths, manifest]:
        # IRIS EXPLAIN: Call archive.write(path, (Path(root.name) / path.relative_to(root)).as_posix()): write the already
        # IRIS EXPLAIN: prepared payload.
        archive.write(path, (Path(root.name) / path.relative_to(root)).as_posix())
# IRIS EXPLAIN: Enter zipfile.ZipFile(output) as archive; its context manager supplies the existing
# IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
with zipfile.ZipFile(output) as archive:
    # IRIS EXPLAIN: Assert archive.testzip() is None; a failure indicates the demonstrated invariant did not hold.
    assert archive.testzip() is None
# IRIS EXPLAIN: Call print(f'{output}\n{len(paths) + 1} files; {output.stat().st_size} bytes') using the existing explicit
# IRIS EXPLAIN: arguments.
print(f"{output}\n{len(paths) + 1} files; {output.stat().st_size} bytes")
