"""Train and export the synthetic username-similarity baseline."""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import subprocess
from pathlib import Path

import numpy as np
from onnx.reference import ReferenceEvaluator
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_score, recall_score
from sklearn.model_selection import train_test_split

SEED = 20260921
FEATURE_NAMES = [
    "normalized_edit",
    "jaro_winkler",
    "bigram",
    "numeric_suffix",
]
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


def format_model_json(path: Path) -> None:
    """Format a generated artifact with the repository's pinned Prettier."""
    executable_name = "prettier.cmd" if os.name == "nt" else "prettier"
    prettier = REPOSITORY_ROOT / "node_modules" / ".bin" / executable_name
    if not prettier.is_file():
        raise RuntimeError("Prettier is unavailable; run npm install before training")
    subprocess.run(
        [
            str(prettier),
            "--config",
            str(REPOSITORY_ROOT / "static-analysis/formatters/prettier.json"),
            "--write",
            str(path),
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def normalize_username(value: str) -> str:
    """Match the normalization contract implemented by agent-core."""
    return "".join(
        character
        for character in value.strip().lower()
        if not character.isspace() and character not in "_-."
    )


def levenshtein_distance(lhs: str, rhs: str) -> int:
    """Return character-level Levenshtein distance."""
    previous = list(range(len(rhs) + 1))
    for lhs_index, lhs_character in enumerate(lhs, start=1):
        current = [lhs_index]
        for rhs_index, rhs_character in enumerate(rhs, start=1):
            current.append(
                min(
                    current[-1] + 1,
                    previous[rhs_index] + 1,
                    previous[rhs_index - 1]
                    + (lhs_character != rhs_character),
                )
            )
        previous = current
    return previous[-1]


def normalized_edit_similarity(lhs: str, rhs: str) -> float:
    """Return normalized edit similarity for normalized usernames."""
    lhs = normalize_username(lhs)
    rhs = normalize_username(rhs)
    if lhs == rhs:
        return 1.0
    if not lhs or not rhs:
        return 0.0
    return 1.0 - (levenshtein_distance(lhs, rhs) / max(len(lhs), len(rhs)))


def jaro_similarity(lhs: str, rhs: str) -> float:
    """Return the Jaro similarity used as the base for Jaro-Winkler."""
    if lhs == rhs:
        return 1.0
    if not lhs or not rhs:
        return 0.0

    match_distance = max(len(lhs), len(rhs)) // 2 - 1
    match_distance = max(0, match_distance)
    lhs_matches = [False] * len(lhs)
    rhs_matches = [False] * len(rhs)

    matches = 0
    for lhs_index, lhs_character in enumerate(lhs):
        start = max(0, lhs_index - match_distance)
        end = min(lhs_index + match_distance + 1, len(rhs))
        for rhs_index in range(start, end):
            if rhs_matches[rhs_index] or lhs_character != rhs[rhs_index]:
                continue
            lhs_matches[lhs_index] = True
            rhs_matches[rhs_index] = True
            matches += 1
            break

    if matches == 0:
        return 0.0

    lhs_sequence = [
        character
        for character, matched in zip(lhs, lhs_matches, strict=True)
        if matched
    ]
    rhs_sequence = [
        character
        for character, matched in zip(rhs, rhs_matches, strict=True)
        if matched
    ]
    transpositions = sum(
        lhs_character != rhs_character
        for lhs_character, rhs_character in zip(
            lhs_sequence, rhs_sequence, strict=True
        )
    ) / 2

    return (
        (matches / len(lhs))
        + (matches / len(rhs))
        + ((matches - transpositions) / matches)
    ) / 3


def jaro_winkler_similarity(lhs: str, rhs: str) -> float:
    """Return Jaro-Winkler similarity after normalization."""
    lhs = normalize_username(lhs)
    rhs = normalize_username(rhs)
    similarity = jaro_similarity(lhs, rhs)
    prefix_length = 0
    for lhs_character, rhs_character in zip(lhs[:4], rhs[:4]):
        if lhs_character != rhs_character:
            break
        prefix_length += 1
    if similarity > 0.7:
        similarity += prefix_length * 0.1 * (1.0 - similarity)
    return similarity


def ngram_similarity(lhs: str, rhs: str, size: int = 2) -> float:
    """Return character n-gram Jaccard similarity after normalization."""
    lhs = normalize_username(lhs)
    rhs = normalize_username(rhs)
    if not lhs or not rhs or size <= 0:
        return 0.0
    lhs_ngrams = {lhs[index : index + size] for index in range(len(lhs) - size + 1)}
    rhs_ngrams = {rhs[index : index + size] for index in range(len(rhs) - size + 1)}
    if not lhs_ngrams or not rhs_ngrams:
        return 0.0
    return len(lhs_ngrams & rhs_ngrams) / len(lhs_ngrams | rhs_ngrams)


def numeric_suffix(value: str) -> str | None:
    """Return a trailing ASCII numeric suffix after normalization."""
    value = normalize_username(value)
    split_at = len(value)
    while split_at > 0 and value[split_at - 1].isascii() and value[split_at - 1].isdigit():
        split_at -= 1
    return value[split_at:] or None


def numeric_suffix_similarity(lhs: str, rhs: str) -> float:
    """Match agent-core numeric suffix agreement semantics."""
    lhs_suffix = numeric_suffix(lhs)
    rhs_suffix = numeric_suffix(rhs)
    if lhs_suffix is None and rhs_suffix is None:
        return 1.0
    return float(lhs_suffix is not None and lhs_suffix == rhs_suffix)


def extract_features(lhs: str, rhs: str) -> list[float]:
    """Extract features in the versioned order consumed by Rust."""
    return [
        normalized_edit_similarity(lhs, rhs),
        jaro_winkler_similarity(lhs, rhs),
        ngram_similarity(lhs, rhs),
        numeric_suffix_similarity(lhs, rhs),
    ]


def synthetic_stems(rng: random.Random, count: int) -> list[str]:
    """Create deterministic, non-personal base handles."""
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    stems: set[str] = set()
    while len(stems) < count:
        length = rng.randint(5, 11)
        stems.add("".join(rng.choice(alphabet) for _ in range(length)))
    return sorted(stems)


def positive_variant(stem: str, rng: random.Random) -> tuple[str, str]:
    """Create a related synthetic username pair."""
    suffix = str(rng.randint(1, 99)) if rng.random() < 0.55 else ""
    lhs = stem + suffix
    rhs = lhs
    operation = rng.choice(["separator", "case", "delete", "substitute"])
    if operation == "separator" and len(rhs) > 2:
        index = rng.randint(1, len(rhs) - 1)
        rhs = rhs[:index] + rng.choice(["_", "-", "."]) + rhs[index:]
    elif operation == "case":
        rhs = "".join(
            character.upper() if rng.random() < 0.4 else character
            for character in rhs
        )
    elif operation == "delete" and len(stem) > 5:
        index = rng.randrange(len(stem))
        rhs = stem[:index] + stem[index + 1 :] + suffix
    elif operation == "substitute":
        index = rng.randrange(len(stem))
        replacement = rng.choice("abcdefghijklmnopqrstuvwxyz")
        rhs = stem[:index] + replacement + stem[index + 1 :] + suffix
    return lhs, rhs


def build_dataset(sample_count: int, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """Build a balanced synthetic feature matrix and labels."""
    rng = random.Random(seed)
    stems = synthetic_stems(rng, max(200, sample_count // 4))
    features: list[list[float]] = []
    labels: list[int] = []

    for index in range(sample_count // 2):
        features.append(extract_features(*positive_variant(stems[index % len(stems)], rng)))
        labels.append(1)

        lhs, rhs = rng.sample(stems, 2)
        if rng.random() < 0.5:
            suffix = str(rng.randint(1, 99))
            lhs += suffix
            rhs += suffix
        features.append(extract_features(lhs, rhs))
        labels.append(0)

    return np.asarray(features, dtype=np.float32), np.asarray(labels, dtype=np.int64)


def evaluate(model: object, features: np.ndarray, labels: np.ndarray) -> dict[str, float]:
    """Return holdout precision and recall for a fitted classifier."""
    predictions = model.predict(features)
    return {
        "precision": round(float(precision_score(labels, predictions)), 6),
        "recall": round(float(recall_score(labels, predictions)), 6),
    }


def train(output_dir: Path, sample_count: int) -> None:
    """Train, evaluate, and export deterministic model artifacts."""
    features, labels = build_dataset(sample_count, SEED)
    train_features, test_features, train_labels, test_labels = train_test_split(
        features,
        labels,
        test_size=0.25,
        random_state=SEED,
        stratify=labels,
    )

    logistic = LogisticRegression(random_state=SEED, max_iter=1_000)
    logistic.fit(train_features, train_labels)
    forest = RandomForestClassifier(
        n_estimators=150,
        max_depth=6,
        random_state=SEED,
        n_jobs=1,
    )
    forest.fit(train_features, train_labels)

    logistic_metrics = evaluate(logistic, test_features, test_labels)
    forest_metrics = evaluate(forest, test_features, test_labels)
    if logistic_metrics["precision"] < 0.8 or logistic_metrics["recall"] < 0.8:
        raise RuntimeError("logistic baseline did not meet minimum holdout metrics")

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "format_version": 1,
        "model_name": "username-similarity-logistic-v1",
        "feature_names": FEATURE_NAMES,
        "weights": [round(float(value), 9) for value in logistic.coef_[0]],
        "bias": round(float(logistic.intercept_[0]), 9),
        "threshold": 0.5,
        "training": {
            "dataset": "synthetic-only",
            "seed": SEED,
            "samples": int(len(labels)),
            "test_samples": int(len(test_labels)),
        },
        "metrics": {
            "logistic_regression": logistic_metrics,
            "random_forest": forest_metrics,
        },
    }
    model_json_path = output_dir / "model.json"
    model_json_path.write_text(
        json.dumps(artifact, indent=2) + "\n", encoding="utf-8"
    )
    format_model_json(model_json_path)

    onnx_model = convert_sklearn(
        logistic,
        initial_types=[("features", FloatTensorType([None, len(FEATURE_NAMES)]))],
        options={id(logistic): {"zipmap": False}},
        target_opset=18,
    )
    onnx_model.graph.name = "username-similarity-logistic-v1"
    onnx_model.producer_name = "Alias username similarity trainer"
    onnx_model.producer_version = "1"
    onnx_probabilities = ReferenceEvaluator(onnx_model).run(
        None, {"features": test_features[:32]}
    )[1]
    expected_probabilities = logistic.predict_proba(test_features[:32])
    if not np.allclose(onnx_probabilities, expected_probabilities, atol=1e-6):
        raise RuntimeError("ONNX probabilities do not match the trained model")
    (output_dir / "model.onnx").write_bytes(
        onnx_model.SerializeToString(deterministic=True)
    )

    print(json.dumps(artifact["metrics"], indent=2))


def main() -> None:
    """Parse command-line arguments and train the model."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples", type=int, default=4_000)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent)
    args = parser.parse_args()
    if args.samples < 200 or args.samples % 2 != 0:
        parser.error("--samples must be an even integer of at least 200")
    train(args.output, args.samples)


if __name__ == "__main__":
    main()
