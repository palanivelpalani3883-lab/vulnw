import re
from typing import Any


def vulnerability_reference(item: dict[str, Any]) -> str | None:
    reference = item.get("reference_url")
    if isinstance(reference, str) and reference.strip().lower().startswith(("https://", "http://")):
        return reference.strip()

    cve_id = str(item.get("cve_id", "")).strip().upper()
    if re.fullmatch(r"CVE-\d{4}-\d{4,}", cve_id):
        return f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    return None