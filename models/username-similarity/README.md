# Username Similarity Model

This directory contains the reproducible synthetic-data baseline for local
username similarity inference.

## Train

Create an isolated Python environment and install the pinned dependencies:

```powershell
npm install
python -m venv .venv-model
.venv-model\Scripts\python.exe -m pip install -r models\username-similarity\requirements.txt
```

The trainer uses the repository's pinned Prettier installation to format the
generated JSON artifact before returning.

Run the contract tests and regenerate both artifacts:

```powershell
.venv-model\Scripts\python.exe -m unittest discover -s models\username-similarity -p test_*.py
.venv-model\Scripts\python.exe models\username-similarity\train.py
```

Training uses a fixed seed and 4,000 balanced synthetic pairs by default. It
compares logistic regression with a small random forest, records holdout
precision and recall, and exports logistic regression because its coefficients
can be audited and evaluated by the Rust client without a native runtime.

## Artifacts

- `model.json` is the versioned coefficient format consumed by `agent-core`.
- `model.onnx` is an ONNX export for interoperability and future runtime tests.

The feature order is part of the model contract:

1. normalized edit similarity
2. Jaro-Winkler similarity
3. character-bigram Jaccard similarity
4. numeric suffix agreement

Changing feature semantics or order requires incrementing the format version,
retraining, regenerating both artifacts, and updating Rust validation.

### JSON Format Version 1

`model.json` requires:

- `format_version`: integer `1`
- `model_name`: non-empty stable identifier
- `feature_names`: the four names above in exact order
- `weights`: four finite logistic-regression coefficients in feature order
- `bias`: finite logistic-regression intercept
- `threshold`: finite classification threshold in `0.0..=1.0`

The `training` and `metrics` objects record provenance and evaluation metadata.
Rust ignores those metadata objects during inference but preserves their
meaning as part of the generated artifact.

The ONNX graph uses opset 18. Its `features` input is a float32 tensor shaped
`[batch, 4]`; outputs are `label` shaped `[batch]` and `probabilities` shaped
`[batch, 2]`, with class-one probability representing same-persona likelihood.

The recorded synthetic holdout metrics verify pipeline behavior only. They do
not establish accuracy on real usernames or demographic groups. Real labeled
examples must be opt-in, de-identified, reviewed for consent and bias, and kept
out of the repository unless their license explicitly permits redistribution.
