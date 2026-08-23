import re
from typing import Dict, List, Tuple

ALIAS_MAP = {
    "apache": "apache http server",
    "http server": "apache http server",
    "mysql": "mysql",
    "windows": "windows server",
    "windows server": "windows server",
    "cisco": "cisco ios",
    "cisco ios": "cisco ios"
}

def normalize_name(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9\s]", "", str(name).lower()).strip()
    return ALIAS_MAP.get(cleaned, cleaned)

def evaluate_version(profile_ver: str, affected_range: str) -> Tuple[bool, str]:
    if not profile_ver or not affected_range:
        return True, "NEEDS VERIFICATION"
    
    clean_prof = profile_ver.strip().lower()
    clean_range = affected_range.strip().lower()

    if clean_range in ["*", "all", "any"]:
        return True, "MATCHED"

    if "*" in clean_range:
        base_prefix = clean_range.replace("*", "").rstrip(".")
        if clean_prof.startswith(base_prefix):
            return True, "MATCHED"

    if clean_prof == clean_range:
        return True, "MATCHED"

    return True, "NEEDS VERIFICATION"

def match_vulnerabilities(vuln_df, profile: Dict) -> List[Dict]:
    matched_records = []
    org_techs = profile.get("technologies", [])
    critical_products = {
        normalize_name(product) for product in profile.get("critical_products", [])
    }
    
    for _, row in vuln_df.iterrows():
        vuln_prod = normalize_name(f"{row['vendor']} {row['product']}")
        
        for tech in org_techs:
            tech_prod = normalize_name(tech.get("product", ""))
            
            if tech_prod in vuln_prod or vuln_prod in tech_prod:
                is_match, ver_status = evaluate_version(
                    tech.get("version", ""), 
                    str(row.get("affected_version_range", ""))
                )
                if is_match:
                    record = row.to_dict()
                    record["matched_tech"] = tech.get("product")
                    record["installed_version"] = tech.get("version", "N/A")
                    record["version_status"] = ver_status
                    record["is_critical_asset"] = normalize_name(tech.get("product", "")) in critical_products
                    matched_records.append(record)
                    break
                    
    return matched_records