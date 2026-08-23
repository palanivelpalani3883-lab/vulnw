from src.reporting import build_pdf_report
from src.scorer import calculate_risk, compare_datasets, rank_top_vulnerabilities
from src.matcher import match_vulnerabilities


def test_rank_top_vulnerabilities_works():
    profile = {
        "organisation": "ABC College",
        "service": "Student Portal",
        "exposure": "Internet-facing",
        "importance": "Critical",
        "technologies": [{"product": "Apache HTTP Server", "version": "2.4"}],
    }
    vuln_df = __import__("pandas").DataFrame(
        [
            {
                "cve_id": "CVE-2024-1234",
                "vendor": "Apache",
                "product": "HTTP Server",
                "cvss": 9.8,
                "affected_version_range": "2.4.*",
                "epss": 0.9,
                "in_kev": True,
                "reference_url": "https://example.com/cve",
                "description": "Test vulnerability",
            }
        ]
    )

    matched = match_vulnerabilities(vuln_df, profile)
    ranked = rank_top_vulnerabilities(matched, profile, limit=1)

    assert ranked
    assert ranked[0]["cve_id"] == "CVE-2024-1234"


def test_build_pdf_report_returns_pdf_bytes():
    profile = {
        "organisation": "ABC College",
        "service": "Student Portal",
        "exposure": "Internet-facing",
        "importance": "Critical",
    }
    top_5 = [
        {
            "cve_id": "CVE-2024-1234",
            "matched_tech": "Apache HTTP Server",
            "risk_score": 92.5,
            "priority": "Urgent",
            "description": "Critical HTTP server issue",
            "score_breakdown": {"KEV (+40)": "Active exploitation confirmed"},
        }
    ]

    pdf_bytes = build_pdf_report(profile, top_5)

    assert isinstance(pdf_bytes, (bytes, bytearray))
    assert pdf_bytes.startswith(b"%PDF")


def test_critical_asset_multiplier_changes_score():
    item = {"cvss": 5, "epss": 0, "in_kev": False, "is_critical_asset": True}
    profile = {
        "exposure": "Internal",
        "importance": "Normal",
        "weight_modifiers": {"criticality_multiplier": 1.2},
    }

    assert calculate_risk(item, profile)["risk_score"] == 18.0


def test_zero_tolerance_keV_is_ranked_first():
    profile = {"risk_appetite": "Zero-Tolerance", "exposure": "Internal", "importance": "Normal"}
    items = [
        {"cve_id": "low-score-kev", "cvss": 1, "epss": 0, "in_kev": True},
        {"cve_id": "high-score", "cvss": 9.8, "epss": 0.9, "in_kev": False},
    ]

    ranked = rank_top_vulnerabilities(items, profile, limit=2)

    assert ranked[0]["cve_id"] == "low-score-kev"
    assert ranked[0]["kev_escalated"] is True


def test_compare_datasets_accepts_public_schema():
    profile = {
        "exposure": "Internet-facing",
        "importance": "Critical",
        "technologies": [{"product": "Apache HTTP Server", "version": "2.4"}],
    }
    dataset = __import__("pandas").DataFrame(
        [{
            "cve_id": "CVE-1",
            "product_name": "Apache HTTP Server",
            "cvss_base_score": 9.8,
            "cisa_kev": True,
            "first_epss": 0.9,
        }]
    )

    comparison = compare_datasets({"feed.csv": dataset}, profile)

    assert comparison.loc[0, "# CISA-KEV"] == 1
    assert comparison.loc[0, "Priority"] == "High"
