from pathlib import Path
import sys

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.matcher import match_vulnerabilities
from src.profile_schema import validate_profiles
from src.scorer import rank_top_vulnerabilities


def main():
    path = Path("data/gold_set.csv")
    if not path.exists():
        print("Validation unavailable: data/gold_set.csv is not present in this checkout.")
        return
    gold = pd.read_csv(path)
    profiles = validate_profiles(pd.read_json("data/profile.json"))
    vulnerabilities = pd.read_csv("data/vulnerabilities.csv")
    for profile, column in zip(profiles[:2], ("practitioner_rank_bank", "practitioner_rank_startup")):
        ranked = rank_top_vulnerabilities(match_vulnerabilities(vulnerabilities, profile), profile, len(gold))
        positions = {item["cve_id"]: index + 1 for index, item in enumerate(ranked)}
        actual = [positions.get(cve, len(gold) + 1) for cve in gold["cve_id"]]
        correlation = pd.Series(actual).rank().corr(gold[column].rank())
        print(f"{profile['organisation']}: Spearman correlation = {correlation:.3f}")


if __name__ == "__main__":
    main()
