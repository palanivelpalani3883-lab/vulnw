from pathlib import Path

import pandas as pd
import pytest

from src.matcher import match_vulnerabilities
from src.profile_schema import validate_profiles
from src.scorer import rank_top_vulnerabilities


def _spearman(actual, expected):
    return pd.Series(actual).rank().corr(pd.Series(expected).rank())


def test_gold_set_rank_correlation():
    gold_path = Path("data/gold_set.csv")
    if not gold_path.exists():
        pytest.skip("data/gold_set.csv is not present in this checkout")
    gold = pd.read_csv(gold_path)
    profiles = validate_profiles(pd.read_json("data/profile.json"))
    vulnerabilities = pd.read_csv("data/vulnerabilities.csv")
    for profile, rank_column in zip(profiles[:2], ("practitioner_rank_bank", "practitioner_rank_startup")):
        expected = gold[rank_column].tolist()
        model = rank_top_vulnerabilities(match_vulnerabilities(vulnerabilities, profile), profile, limit=len(gold))
        positions = {item["cve_id"]: index + 1 for index, item in enumerate(model)}
        actual = [positions.get(cve, len(gold) + 1) for cve in gold["cve_id"]]
        assert _spearman(actual, expected) >= 0.7
