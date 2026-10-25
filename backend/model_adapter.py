# IRIS EXPLAIN: File purpose: Checks the pinned trusted Colab bundle and catalogue before deserialization, then exposes
# IRIS EXPLAIN: shadow-only inference and model status.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Load the operator-approved Colab bundle once; never train on an API request."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import sys to inspect the Python version or select the same executable/import path.
import sys
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import ROOT from .config to reuse the shared project contract/implementation rather than duplicate it.
from .config import ROOT

# IRIS EXPLAIN: Store the computed value ROOT / 'IRIS_Models_v2' in MODEL_PROJECT; later lines use this named result.
MODEL_PROJECT = ROOT / "IRIS_Models_v2"
# IRIS EXPLAIN: Enter this branch only when str(MODEL_PROJECT) not in sys.path.
if str(MODEL_PROJECT) not in sys.path:
    # IRIS EXPLAIN: Call sys.path.insert(0, str(MODEL_PROJECT)) using the existing explicit arguments.
    sys.path.insert(0, str(MODEL_PROJECT))

# IRIS EXPLAIN: Import digest, utc_now from iris_models.contracts to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from iris_models.contracts import digest, utc_now  # noqa: E402
# IRIS EXPLAIN: Import ModelService from iris_models.runtime to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from iris_models.runtime import ModelService  # noqa: E402
# IRIS EXPLAIN: Import prepare_three from iris_models.three_sources to reuse the shared project contract/implementation rather
# IRIS EXPLAIN: than duplicate it.
from iris_models.three_sources import prepare_three  # noqa: E402

# IRIS EXPLAIN: Store the computed value ROOT / 'artifacts' / 'user_colab_run' / 'models' in MODEL_DIR; later lines use this
# IRIS EXPLAIN: named result.
MODEL_DIR = ROOT / "artifacts" / "user_colab_run" / "models"
# IRIS EXPLAIN: Store the computed value MODEL_PROJECT / 'iris_models' / 'data' / 'control_catalog.csv' in CATALOGUE; later
# IRIS EXPLAIN: lines use this named result.
CATALOGUE = MODEL_PROJECT / "iris_models" / "data" / "control_catalog.csv"
# IRIS EXPLAIN: Store the result of Path(__file__).with_name('model_manifest.json') in MANIFEST; later lines use this named
# IRIS EXPLAIN: result.
MANIFEST = Path(__file__).with_name("model_manifest.json")
# IRIS EXPLAIN: Store the computed value MODEL_PROJECT / 'samples' / 'three_inputs' in SAMPLES; later lines use this named
# IRIS EXPLAIN: result.
SAMPLES = MODEL_PROJECT / "samples" / "three_inputs"


# IRIS EXPLAIN: Class ModelAdapter: Fixed shadow-only wrapper around the user-approved, checksum-pinned Colab models.
class ModelAdapter:
    # IRIS EXPLAIN: Function ModelAdapter.__init__: Verify all pinned model files and catalogue bytes before trusted loading,
    # IRIS EXPLAIN: require both trained components and the exact session contract, and retain one loaded service.
    # IRIS EXPLAIN: Inputs: model_dir: operator-trusted model bundle directory; manifest_path: server-owned artifact integrity
    # IRIS EXPLAIN: manifest.
    def __init__(self, model_dir: Path = MODEL_DIR, manifest_path: Path = MANIFEST):
        # IRIS EXPLAIN: Store the result of json.loads(manifest_path.read_text(encoding='utf-8')) (decode the existing JSON
        # IRIS EXPLAIN: text) in manifest; later lines use this named result.
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        # IRIS EXPLAIN: Iterate manifest['files'].items(), binding each item to (name, expected); process only the existing
        # IRIS EXPLAIN: observed/fixture collection.
        for name, expected in manifest["files"].items():
            # IRIS EXPLAIN: Enter this branch only when Path(name).name != name or digest(model_dir / name) != expected.
            if Path(name).name != name or digest(model_dir / name) != expected:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Pinned model artifact mismatch;
                # IRIS EXPLAIN: do not load or silently replace it'); the caller's existing boundary determines rollback or the
                # IRIS EXPLAIN: HTTP diagnostic.
                raise ValueError("Pinned model artifact mismatch; do not load or silently replace it")
        # IRIS EXPLAIN: Enter this branch only when digest(CATALOGUE) != manifest['catalogue_sha256'].
        if digest(CATALOGUE) != manifest["catalogue_sha256"]:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Pinned control catalogue
            # IRIS EXPLAIN: mismatch'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Pinned control catalogue mismatch")
        # IRIS EXPLAIN: Store the result of ModelService(model_dir, CATALOGUE) in self.service; later lines use this named
        # IRIS EXPLAIN: result.
        self.service = ModelService(model_dir, CATALOGUE)
        # IRIS EXPLAIN: Enter this branch only when self.service.load_error.
        if self.service.load_error:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError(f'Model cannot load:
            # IRIS EXPLAIN: {self.service.load_error}'); the caller's existing boundary determines rollback or the HTTP
            # IRIS EXPLAIN: diagnostic.
            raise ValueError(f"Model cannot load: {self.service.load_error}")
        # IRIS EXPLAIN: Enter this branch only when not self.service.bundle.get('scenario_model') or not
        # IRIS EXPLAIN: self.service.bundle.get('control_model').
        if not self.service.bundle.get("scenario_model") or not self.service.bundle.get("control_model"):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Both trained model components are
            # IRIS EXPLAIN: required'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Both trained model components are required")
        # IRIS EXPLAIN: Enter this branch only when self.service.metadata['aggregation_schema'] !=
        # IRIS EXPLAIN: manifest['aggregation_schema'].
        if self.service.metadata["aggregation_schema"] != manifest["aggregation_schema"]:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Model/session contract mismatch');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Model/session contract mismatch")
        # IRIS EXPLAIN: Store self.service.metadata in self.metadata; later lines use this named result.
        self.metadata = self.service.metadata
        # IRIS EXPLAIN: Store the result of digest(manifest_path) (compute the selected file content hash) in
        # IRIS EXPLAIN: self.artifact_identity; later lines use this named result.
        self.artifact_identity = digest(manifest_path)
        # IRIS EXPLAIN: Store the result of utc_now() in self.loaded_at; later lines use this named result.
        self.loaded_at = utc_now()

    # IRIS EXPLAIN: Function ModelAdapter.predict: Call the shared service in fixed shadow mode and reject outputs that promote
    # IRIS EXPLAIN: an ML candidate or claim automatic/official writes.
    # IRIS EXPLAIN: Inputs: session: observed session features plus time-valid asset/risk context.
    # IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
    def predict(self, session: dict) -> dict:
        # IRIS EXPLAIN: Store the result of self.service.predict(session, mode='shadow') (obtain the configured prediction
        # IRIS EXPLAIN: result without training on this call) in prediction; later lines use this named result.
        prediction = self.service.predict(session, mode="shadow")
        # IRIS EXPLAIN: Enter this branch only when prediction['soc_assessment']['method'] == 'calibrated_model1'.
        if prediction["soc_assessment"]["method"] == "calibrated_model1":
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising RuntimeError('Shadow result must not become the
            # IRIS EXPLAIN: primary assessment'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise RuntimeError("Shadow result must not become the primary assessment")
        # IRIS EXPLAIN: Enter this branch only when prediction['automatic_execution'] or
        # IRIS EXPLAIN: prediction['official_risk_register_write'].
        if prediction["automatic_execution"] or prediction["official_risk_register_write"]:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising RuntimeError('Unsafe model output'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise RuntimeError("Unsafe model output")
        # IRIS EXPLAIN: Return prediction to the caller; this ends the current function path.
        return prediction

    # IRIS EXPLAIN: Function ModelAdapter.status: Return loaded artifact identity, metrics, release checks and coverage limits
    # IRIS EXPLAIN: for dashboards, without exposing role secrets.
    # IRIS EXPLAIN: Declared return type: dict; the return statements below show each actual result/fallback.
    def status(self) -> dict:
        # IRIS EXPLAIN: Return a mapping containing loaded, loaded_at_utc, mode, model_sha256, artifact_manifest_sha256,
        # IRIS EXPLAIN: package_version, aggregation_schema and additional fields to the caller; this ends the current function
        # IRIS EXPLAIN: path.
        return {
            # IRIS EXPLAIN: Continue the current record with loaded, loaded_at_utc, mode; each value comes from the expression
            # IRIS EXPLAIN: shown on this unchanged line.
            "loaded": True, "loaded_at_utc": self.loaded_at, "mode": "shadow_only",
            # IRIS EXPLAIN: Set/describe these existing record fields: model_sha256: content identity of the saved trusted model
            # IRIS EXPLAIN: bundle.
            "model_sha256": self.metadata["model_sha256"],
            # IRIS EXPLAIN: Continue the current record with artifact_manifest_sha256; each value comes from the expression
            # IRIS EXPLAIN: shown on this unchanged line.
            "artifact_manifest_sha256": self.artifact_identity,
            # IRIS EXPLAIN: Continue the current record with package_version; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "package_version": self.metadata["package_version"],
            # IRIS EXPLAIN: Set/describe these existing record fields: aggregation_schema: the exact
            # IRIS EXPLAIN: normalization/session-window contract used for training and inference.
            "aggregation_schema": self.metadata["aggregation_schema"],
            # IRIS EXPLAIN: Continue the current record with synthetic_training; each value comes from the expression shown on
            # IRIS EXPLAIN: this unchanged line.
            "synthetic_training": self.metadata["data_quality"]["synthetic"],
            # IRIS EXPLAIN: Continue the current record with algorithm; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "algorithm": self.metadata["model1"]["algorithm"],
            # IRIS EXPLAIN: Continue the current record with model1_metrics; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "model1_metrics": self.metadata["model1"]["metrics"],
            # IRIS EXPLAIN: Continue the current record with model1_checks; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "model1_checks": self.metadata["model1"]["checks"],
            # IRIS EXPLAIN: Continue the current record with model2_metrics; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "model2_metrics": {k: v for k, v in self.metadata["model2"]["metrics"].items() if k != "per_control"},
            # IRIS EXPLAIN: Continue the current record with model2_controls_with_positive_test_examples; each value comes from
            # IRIS EXPLAIN: the expression shown on this unchanged line.
            "model2_controls_with_positive_test_examples": [
                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                # IRIS EXPLAIN: arguments/items: control for control, metrics in
                # IRIS EXPLAIN: self.metadata["model2"]["metrics"]["per_control"].items().
                control for control, metrics in self.metadata["model2"]["metrics"]["per_control"].items()
                # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                # IRIS EXPLAIN: arguments/items: if metrics["test_positive_support"] > 0.
                if metrics["test_positive_support"] > 0
            # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
            # IRIS EXPLAIN: unchanged.
            ],
            # IRIS EXPLAIN: Continue the current record with model1_released; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "model1_released": self.service.released("model1"),
            # IRIS EXPLAIN: Continue the current record with model2_released; each value comes from the expression shown on this
            # IRIS EXPLAIN: unchanged line.
            "model2_released": self.service.released("model2"),
            # IRIS EXPLAIN: Set/describe these existing record fields: automatic_execution: safety flag separating
            # IRIS EXPLAIN: recommendations from automatic control execution; official_risk_register_write: safety flag: model
            # IRIS EXPLAIN: inference does not change an official company register.
            "automatic_execution": False, "official_risk_register_write": False,
        # IRIS EXPLAIN: Finish the existing grouped expression/call or collection; any trailing fields/call chain remain
        # IRIS EXPLAIN: unchanged.
        }
