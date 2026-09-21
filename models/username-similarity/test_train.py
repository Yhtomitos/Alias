"""Contract tests for username model feature extraction and data generation."""

import unittest

from train import build_dataset, extract_features, normalize_username


class TrainingContractTests(unittest.TestCase):
    """Verify deterministic feature and synthetic-data contracts."""

    def test_normalization_matches_rust_contract(self) -> None:
        self.assertEqual(normalize_username("  Dev_Tim-23. "), "devtim23")

    def test_equivalent_usernames_have_maximum_features(self) -> None:
        self.assertEqual(extract_features("dev_tim23", "DevTim23"), [1.0] * 4)

    def test_nontrivial_feature_fixture_matches_rust_contract(self) -> None:
        features = extract_features("martha", "marhta")
        expected = [2 / 3, 0.9611111111111111, 0.25, 1.0]
        for actual, expected_value in zip(features, expected, strict=True):
            self.assertAlmostEqual(actual, expected_value)

    def test_dataset_is_deterministic_and_balanced(self) -> None:
        lhs_features, lhs_labels = build_dataset(200, 42)
        rhs_features, rhs_labels = build_dataset(200, 42)
        self.assertTrue((lhs_features == rhs_features).all())
        self.assertTrue((lhs_labels == rhs_labels).all())
        self.assertEqual(int(lhs_labels.sum()), 100)


if __name__ == "__main__":
    unittest.main()
