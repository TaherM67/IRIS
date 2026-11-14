"""Validate an LLM-generated expanded bundle before inference. Never fits/loads weights."""
import argparse
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.input_contract import FILES, validate_inputs

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir",type=Path,required=True)
    parser.add_argument("--out",type=Path,help="Optional new diagnostics JSON; existing files are never replaced")
    args=parser.parse_args()
    report=validate_inputs({k:args.input_dir/name for k,name in FILES.items()})
    text=json.dumps(report,indent=2,allow_nan=False)+"\n"
    if args.out:
        args.out.parent.mkdir(parents=True,exist_ok=True)
        with args.out.open("x",encoding="utf-8") as f:f.write(text)
    compact={k:v for k,v in report.items() if k not in {"sessions","source_sha256"}}
    print(json.dumps(compact,indent=2,allow_nan=False))
    raise SystemExit(0 if report["valid"] else 2)

if __name__=="__main__":
    main()

