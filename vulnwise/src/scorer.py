from typing import Dict

import pandas as pd

from src.matcher import match_vulnerabilities
from src.scoper import calculate_risk, rank_top_vulnerabilities


DATASET_COLUMNS = {
	"product_name": "product",
	"cvss_base_score": "cvss",
	"cisa_kev": "in_kev",
	"first_epss": "epss",
	"summary": "description",
	"vulnerability_description": "description",
	"details": "description",
	"reference": "reference_url",
	"reference_link": "reference_url",
	"source_url": "reference_url",
	"cve_url": "reference_url",
	"nvd_url": "reference_url",
}


def normalize_dataset(dataset: pd.DataFrame) -> pd.DataFrame:
	"""Accept the public feed schema and convert it to the internal scorer schema."""
	normalized = dataset.copy()
	normalized = normalized.rename(
		columns={
			column: DATASET_COLUMNS.get(str(column).strip().lower(), column)
			for column in normalized.columns
		}
	)
	if "vendor" not in normalized:
		normalized["vendor"] = ""
	if "affected_version_range" not in normalized:
		normalized["affected_version_range"] = "*"
	return normalized


def compare_datasets(datasets: Dict[str, pd.DataFrame], profile: dict) -> pd.DataFrame:
	rows = []
	for name, dataset in datasets.items():
		normalized = normalize_dataset(dataset)
		ranked = rank_top_vulnerabilities(
			match_vulnerabilities(normalized, profile), profile, limit=5
		)
		scores = [item["risk_score"] for item in ranked]
		kev_count = sum(
			str(item.get("in_kev", "")).lower() in ["true", "1", "yes"]
			for item in ranked
		)
		top_scores = scores[:5]
		mean_top = sum(top_scores) / len(top_scores) if top_scores else 0.0
		top_score = max(scores, default=0.0)
		dataset_priority = 0.5 * mean_top + 0.3 * top_score + 0.2 * (kev_count / 5)
		rows.append(
			{
				"Dataset": name,
				"# CVEs": len(normalized),
				"# CISA-KEV": int(normalized["in_kev"].astype(str).str.lower().isin(["true", "1", "yes"]).sum()),
				"Avg EPSS": round(pd.to_numeric(normalized["epss"], errors="coerce").mean(), 3),
				"Avg Score (this profile)": round(mean_top, 1),
				"Top Score": round(top_score, 1),
				"Dataset score": round(dataset_priority, 3),
			}
		)
	result = pd.DataFrame(rows)
	if result.empty:
		return result
	if len(result) == 1:
		result["Priority"] = "High"
	else:
		scores = result["Dataset score"]
		q25, q50, q75 = scores.quantile([0.25, 0.5, 0.75])
		result["Priority"] = [
			"Very High" if score >= q75 else
			"High" if score >= q50 else
			"Medium" if score >= q25 else
			"Low"
			for score in scores
		]
	return result.sort_values(["Dataset score", "Dataset"], ascending=[False, True]).reset_index(drop=True)

__all__ = ["calculate_risk", "rank_top_vulnerabilities", "normalize_dataset", "compare_datasets"]
