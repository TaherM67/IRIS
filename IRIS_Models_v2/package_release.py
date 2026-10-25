"""Create a clean source/demo ZIP and a reproducible content-hash inventory."""
from pathlib import Path
import hashlib
import zipfile

root = Path(__file__).resolve().parent
output = root.parent / "IRIS_Model_Code_v2.zip"
excluded = {"__pycache__", ".git", ".venv", "build", "dist"}
paths = sorted(p for p in root.rglob("*") if p.is_file()
               and not any(part in excluded or part.endswith(".egg-info") for part in p.relative_to(root).parts)
               and p.suffix != ".pyc" and p.name != "MANIFEST.sha256"
               # Raw unified event audits are large and quickly reproducible.
               # Ship the complete model sessions, inputs, reports and weights.
               and not (p.name == "unified_events.jsonl" and p.relative_to(root).parts[0] == "examples")
               and "examples/three_input_prediction/prepared" not in p.relative_to(root).as_posix())
inventory = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(root).as_posix()}\n" for p in paths)
manifest = root / "MANIFEST.sha256"
manifest.write_text(inventory, encoding="utf-8")
with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in [*paths, manifest]:
        archive.write(path, (Path(root.name) / path.relative_to(root)).as_posix())
with zipfile.ZipFile(output) as archive:
    assert archive.testzip() is None
print(f"{output}\n{len(paths) + 1} files; {output.stat().st_size} bytes")
