"""Load the operator-approved Colab bundle once; never train on an API request."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from .config import ROOT

MODEL_PROJECT = ROOT / "IRIS_Models_v2"
if str(MODEL_PROJECT) not in sys.path:
    sys.path.insert(0, str(MODEL_PROJECT))

from iris_models.contracts import digest, utc_now  # noqa: E402
from iris_models.runtime import ModelService  # noqa: E402
from iris_models.three_sources import prepare_three  # noqa: E402

MODEL_DIR = ROOT / "artifacts" / "user_colab_run" / "models"
CATALOGUE = MODEL_PROJECT / "iris_models" / "data" / "control_catalog.csv"
MANIFEST = Path(__file__).with_name("model_manifest.json")
SAMPLES = MODEL_PROJECT / "samples" / "three_inputs"


class ModelAdapter:
    def __init__(self, model_dir: Path = MODEL_DIR, manifest_path: Path = MANIFEST):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name, expected in manifest["files"].items():
            if Path(name).name != name or digest(model_dir / name) != expected:
                raise ValueError("Pinned model artifact mismatch; do not load or silently replace it")
        if digest(CATALOGUE) != manifest["catalogue_sha256"]:
            raise ValueError("Pinned control catalogue mismatch")
        self.service = ModelService(model_dir, CATALOGUE)
        if self.service.load_error:
            raise ValueError(f"Model cannot load: {self.service.load_error}")
        if not self.service.bundle.get("scenario_model") or not self.service.bundle.get("control_model"):
            raise ValueError("Both trained model components are required")
        if self.service.metadata["aggregation_schema"] != manifest["aggregation_schema"]:
            raise ValueError("Model/session contract mismatch")
        self.metadata = self.service.metadata
        self.artifact_identity = digest(manifest_path)
        self.loaded_at = utc_now()

    def predict(self, session: dict) -> dict:
        prediction = self.service.predict(session, mode="shadow")
        if prediction["soc_assessment"]["method"] == "calibrated_model1":
            raise RuntimeError("Shadow result must not become the primary assessment")
        if prediction["automatic_execution"] or prediction["official_risk_register_write"]:
            raise RuntimeError("Unsafe model output")
        return prediction

    def status(self) -> dict:
        return {
            "loaded": True, "loaded_at_utc": self.loaded_at, "mode": "shadow_only",
            "model_sha256": self.metadata["model_sha256"],
            "artifact_manifest_sha256": self.artifact_identity,
            "package_version": self.metadata["package_version"],
            "aggregation_schema": self.metadata["aggregation_schema"],
            "synthetic_training": self.metadata["data_quality"]["synthetic"],
            "algorithm": self.metadata["model1"]["algorithm"],
            "model1_metrics": self.metadata["model1"]["metrics"],
            "model1_checks": self.metadata["model1"]["checks"],
            "model2_metrics": {k: v for k, v in self.metadata["model2"]["metrics"].items() if k != "per_control"},
            "model2_controls_with_positive_test_examples": [
                control for control, metrics in self.metadata["model2"]["metrics"]["per_control"].items()
                if metrics["test_positive_support"] > 0
            ],
            "model1_released": self.service.released("model1"),
            "model2_released": self.service.released("model2"),
            "automatic_execution": False, "official_risk_register_write": False,
        }
