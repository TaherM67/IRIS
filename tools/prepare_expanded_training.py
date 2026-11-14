"""Join offline seven-class annotations to observed sessions; no weights are fitted."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from backend.input_contract import FILES
from backend.training_handoff import prepare_training

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input-dir",type=Path,required=True)
    p.add_argument("--labels",type=Path,required=True)
    p.add_argument("--out",type=Path,required=True)
    args=p.parse_args()
    try:
        result=prepare_training({k:args.input_dir/n for k,n in FILES.items()},args.labels,args.out)
    except (ValueError,OSError,TypeError,KeyError) as exc:
        p.exit(2,"Training handoff: "+str(exc)+"\n")
    print(json.dumps(result,indent=2))
if __name__=="__main__":main()

