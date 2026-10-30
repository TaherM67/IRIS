"""Inspect repaired read-only control advice without starting any server."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'IRIS_Models_v2'))
from iris_models.grounded_controls import GroundedControlRecommender


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    run = ROOT / 'artifacts/model2_fix_20261029'
    parser.add_argument('--model', type=Path, default=run / 'grounded_model2.joblib')
    parser.add_argument('--request', type=Path, default=run / 'example_request.json')
    parser.add_argument('--json', action='store_true')
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding='utf-8'))
    result = GroundedControlRecommender.load(args.model).recommend(
        **{name: request[name] for name in ('session', 'alerts', 'asset', 'registered_risks', 'catalogue')})
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print('Experimental synthetic control review recommendations')
        for control in result['recommendations']:
            print(f"{control['control_id']}: {control['name']} | action: review | current state: unknown")
        if not result['recommendations']:
            print(result.get('reason', 'No control passed the relevance threshold'))
        print('No controls executed. No risk register or alert priorities changed.')
        print('Synthetic association matching, not proven control effectiveness.')


if __name__ == '__main__':
    main()
