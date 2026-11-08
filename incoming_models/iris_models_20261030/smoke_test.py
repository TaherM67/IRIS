"""Load both trusted trained components; no server or database is touched."""
import hashlib
import json
from pathlib import Path
import joblib
import numpy as np
import pandas as pd
import sklearn
from reference_code.grounded_controls import GroundedControlRecommender

folder = Path(__file__).resolve().parent
metadata = json.loads((folder / 'model1_metadata.json').read_text())
if sklearn.__version__ != metadata['sklearn_version']:
    raise RuntimeError('Use the pinned scikit-learn version: ' + metadata['sklearn_version'])
if hashlib.sha256((folder / 'model1_scenario.joblib').read_bytes()).hexdigest() != metadata['model_sha256']:
    raise RuntimeError('Model 1 checksum mismatch')
request = json.loads((folder / 'smoke_test_request.json').read_text())
scenario = joblib.load(folder / 'model1_scenario.joblib')
frame = pd.DataFrame([request['session']['features']], columns=metadata['features'])
probabilities = scenario.predict_proba(frame)[0]
assert np.isfinite(probabilities).all() and np.isclose(probabilities.sum(), 1)
label = str(scenario.classes_[probabilities.argmax()])
if probabilities.max() < metadata['threshold']:
    label = 'ABSTAINED'
print('Model 1 loaded. Example scenario:', label)
request['catalogue'] = json.loads((folder / 'control_catalogue.json').read_text())
recommendations = GroundedControlRecommender.load(folder / 'grounded_model2.joblib').recommend(**request)
for item in recommendations['recommendations']:
    print(item['control_id'] + ': ' + item['name'] + ' | review only')
print('Both components loaded. No website, keys, database or GitHub files changed.')
print('Model 2 remains synthetic association matching, not proven control efficacy.')
