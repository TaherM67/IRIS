# User-provided Colab training artifact

The four files in `models/` were copied without modification from the user's `IRIS_Colab_Training.zip`. The backend pins their hashes in `backend/model_manifest.json` and loads this bundle, not the earlier example weights.

- Both scenario and control models are in `models/models.joblib`.
- Training provenance is synthetic; this is a shadow-only research artifact.
- No `release.json` is provided and no release gate is bypassed.
- Keep metadata and the matching control catalogue with the model.
- Do not upload replacement model files through HTTP. A future replacement needs an operator-reviewed manifest and validation.

`joblib`/pickle can execute code while loading. Only load artifacts you trained or independently trust. Checksums detect a change against this trusted manifest; they are not an independent publisher signature.
