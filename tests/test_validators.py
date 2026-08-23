import json
from pathlib import Path

import pandas as pd
import pytest

from app import resolve_bundled_path
from src.validators import validate_profiles_json, validate_vulnerabilities


def test_validators_accept_current_project_schemas(tmp_path):
    vulnerability_file = tmp_path / "vulnerabilities.csv"
    vulnerability_file.write_text("cve_id,vendor,product,cvss,epss,in_kev\nCVE-1,A,B,9.8,0.8,True\n")
    profiles = [{
        "organisation": "Test Org",
        "service": "Portal",
        "exposure": "Internal",
        "importance": "High",
        "technologies": [],
    }]

    assert len(validate_vulnerabilities(vulnerability_file.read_bytes())) == 1
    assert validate_profiles_json(json.dumps(profiles).encode())[0]["organisation"] == "Test Org"


def test_vulnerability_validator_names_missing_columns():
    with pytest.raises(ValueError, match="cvss"):
        validate_vulnerabilities(pd.DataFrame({"cve_id": ["CVE-1"], "product": ["Apache"]}).to_csv(index=False).encode())


def test_profiles_validator_accepts_wrapped_organization_records():
    payload = {
        "organizations": [
            {
                "organization_name": "Uploaded Org",
                "profile": {
                    "service": "Portal",
                    "exposure": "Internet-facing",
                    "importance": "Critical",
                    "technologies": [],
                    "weight_modifiers": {"criticality_multiplier": 1.1},
                },
            }
        ]
    }

    profiles = validate_profiles_json(json.dumps(payload).encode())

    assert profiles[0]["organisation"] == "Uploaded Org"


def test_profiles_validator_accepts_id_keyed_profiles():
    payload = {
        "ORG-001": {
            "org_name": "Keyed Org",
            "service_context": "API",
            "exposure_level": "Internal",
            "service_importance": "High",
            "technologies": [],
        }
    }

    profiles = validate_profiles_json(json.dumps(payload).encode())

    assert profiles[0]["organisation"] == "Keyed Org"


def test_profiles_validator_accepts_nested_context_aliases():
    payload = [{
        "name": "Context Org",
        "context": {
            "service_type": "API",
            "exposure_type": "Internal",
            "importance_level": "High",
            "assets": ["Apache HTTP Server"],
        },
    }]

    profiles = validate_profiles_json(json.dumps(payload).encode())

    assert profiles[0]["organisation"] == "Context Org"
    assert profiles[0]["technologies"][0]["product"] == "Apache HTTP Server"


def test_profiles_validator_uses_critical_products_when_technologies_missing():
    payload = [{
        "organisation": "Asset Org",
        "critical_products": ["Apache HTTP Server", "MySQL"],
    }]

    profiles = validate_profiles_json(json.dumps(payload).encode())

    assert [item["product"] for item in profiles[0]["technologies"]] == [
        "Apache HTTP Server", "MySQL"
    ]


def test_vulnerability_validator_maps_summary_to_description():
    data = pd.DataFrame({
        "cve_id": ["CVE-1"],
        "product_name": ["Apache HTTP Server"],
        "cvss_base_score": [9.8],
        "cisa_kev": [True],
        "first_epss": [0.9],
        "summary": ["Example vulnerability description"],
    })

    vulnerabilities = validate_vulnerabilities(data.to_csv(index=False).encode())

    assert vulnerabilities.loc[0, "description"] == "Example vulnerability description"


def test_vulnerability_validator_maps_source_url():
    data = pd.DataFrame({
        "cve_id": ["CVE-1"],
        "product_name": ["Apache HTTP Server"],
        "cvss_base_score": [9.8],
        "cisa_kev": [True],
        "first_epss": [0.9],
        "source_url": ["https://example.com/CVE-1"],
    })

    vulnerabilities = validate_vulnerabilities(data.to_csv(index=False).encode())

    assert vulnerabilities.loc[0, "reference_url"] == "https://example.com/CVE-1"


def test_bundled_sample_path_prefers_repo_data_when_present():
    bundle = resolve_bundled_path(["data/gold_set.csv", "src/gold_set.csv"])

    assert bundle == Path("data/gold_set.csv")
    assert bundle.exists()