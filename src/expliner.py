from typing import Dict

def generate_explanation(item: Dict, profile: Dict) -> Dict:
    org_name = profile.get("organisation", "the organisation")
    service_name = profile.get("service", "core services")
    exposure = profile.get("exposure", "internal")
    product = item.get("matched_tech", "system component")
    
    in_kev = str(item.get("in_kev", "")).strip().lower() in ["true", "1", "yes"]
    epss_pct = int(float(item.get("epss", 0.0)) * 100)
    
    # Why it matters
    kev_text = "actively exploited in the wild" if in_kev else f"has an estimated {epss_pct}% exploitation likelihood"
    why = (
        f"{org_name} runs {product} on its {service_name} ({exposure}). "
        f"This vulnerability is {kev_text} with a base CVSS of {item.get('cvss')}."
    )

    # Next action
    if item.get("version_status") == "NEEDS VERIFICATION":
        next_action = (
            f"Verify if the running version ({item.get('installed_version')}) falls inside "
            f"the affected range ({item.get('affected_version_range')}). If matched, apply the vendor patch."
        )
        confidence = "Medium (Version confirmation required)"
    else:
        next_action = f"Apply security updates provided by {item.get('vendor', 'the vendor')} for {product} immediately."
        confidence = "High (Confirmed technology match)"

    return {
        "why": why,
        "next_action": next_action,
        "confidence": confidence,
        "source": f"Snapshot {item.get('source_date', 'N/A')}",
        "reference": item.get("reference_url", "#")
    }