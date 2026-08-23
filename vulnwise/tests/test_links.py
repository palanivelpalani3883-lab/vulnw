from src.links import vulnerability_reference


def test_reference_uses_uploaded_url_first():
    item = {"cve_id": "CVE-2025-1111", "reference_url": "https://example.com/advisory"}

    assert vulnerability_reference(item) == "https://example.com/advisory"


def test_reference_falls_back_to_nvd_for_valid_cve():
    assert vulnerability_reference({"cve_id": "CVE-2025-1111"}) == (
        "https://nvd.nist.gov/vuln/detail/CVE-2025-1111"
    )


def test_reference_is_unavailable_for_invalid_cve_without_url():
    assert vulnerability_reference({"cve_id": "not-a-cve"}) is None