from typing import Dict, List

import pandas as pd

def calculate_risk(item: Dict, profile: Dict) -> Dict:
    score = 0.0
    breakdown = {}

    # KEV exploitation status (+40)
    in_kev = str(item.get("in_kev", "")).strip().lower() in ["true", "1", "yes"]
    if in_kev:
        score += 40.0
        breakdown["KEV (+40)"] = "Active exploitation confirmed"

    # EPSS exploitation probability (+0 to +20)
    try:
        epss_val = float(item.get("epss", 0.0))
        epss_contrib = round(epss_val * 20.0, 1)
        score += epss_contrib
        breakdown[f"EPSS (+{epss_contrib})"] = f"Exploit probability {int(epss_val * 100)}%"
    except (ValueError, TypeError):
        breakdown["EPSS (+0.0)"] = "No EPSS data"

    # Exposure factor (+20 for Internet-facing)
    is_internet = str(profile.get("exposure", "")).lower() == "internet-facing"
    if is_internet:
        score += 20.0
        breakdown["Exposure (+20)"] = "Internet-facing asset"
    else:
        score += 5.0
        breakdown["Exposure (+5)"] = "Internal asset"

    # Service importance (+15 for Critical, +10 for High, +5 for Normal)
    imp = str(profile.get("importance", "")).lower()
    if imp == "critical":
        score += 15.0
        breakdown["Importance (+15)"] = "Critical service"
    elif imp == "high":
        score += 10.0
        breakdown["Importance (+10)"] = "High importance"
    else:
        score += 5.0
        breakdown["Importance (+5)"] = "Normal importance"

    # CVSS contextual weight (+0 to +10)
    try:
        cvss_val = float(item.get("cvss", 0.0))
        cvss_contrib = round(cvss_val * 1.0, 1)
        score += cvss_contrib
        breakdown[f"CVSS (+{cvss_contrib})"] = f"Base severity {cvss_val}"
    except (ValueError, TypeError):
        pass

    # Confidence penalty
    if item.get("version_status") == "NEEDS VERIFICATION":
        score -= 5.0
        breakdown["Penalty (-5)"] = "Version needs verification"

    multiplier = float(profile.get("weight_modifiers", {}).get("criticality_multiplier", 1.0))
    if item.get("is_critical_asset", False):
        score *= multiplier
        breakdown[f"Criticality (x{multiplier:g})"] = "Critical product asset"

    final_score = round(max(0.0, min(score, 100.0)), 1)

    if final_score >= 80.0:
        priority = "Urgent"
    elif final_score >= 60.0:
        priority = "High"
    elif final_score >= 40.0:
        priority = "Medium"
    else:
        priority = "Low"

    item["risk_score"] = final_score
    item["priority"] = priority
    item["score_breakdown"] = breakdown
    return item

def rank_top_vulnerabilities(matched_items: List[Dict], profile: Dict, limit: int = 5) -> List[Dict]:
    if not matched_items:
        return []

    frame = pd.DataFrame(matched_items).copy()
    frame["cvss_num"] = pd.to_numeric(frame.get("cvss", 0), errors="coerce").fillna(0)
    frame["epss_num"] = pd.to_numeric(frame.get("epss", 0), errors="coerce").fillna(0)
    kev_values = frame["in_kev"] if "in_kev" in frame else pd.Series(False, index=frame.index)
    version_values = frame["version_status"] if "version_status" in frame else pd.Series("", index=frame.index)
    frame["kev_num"] = kev_values.astype(str).str.lower().isin(["true", "1", "yes"])
    frame["verification_penalty"] = version_values.eq("NEEDS VERIFICATION") * 5
    frame["base_score"] = (
        frame["kev_num"].astype(float) * 40
        + frame["epss_num"] * 20
        + (20 if str(profile.get("exposure", "")).lower() == "internet-facing" else 5)
        + {"critical": 15, "high": 10}.get(str(profile.get("importance", "")).lower(), 5)
        + frame["cvss_num"]
        - frame["verification_penalty"]
    )
    multiplier = float(profile.get("weight_modifiers", {}).get("criticality_multiplier", 1.0))
    critical_values = frame["is_critical_asset"] if "is_critical_asset" in frame else pd.Series(False, index=frame.index)
    frame["risk_score"] = frame["base_score"] * critical_values.map(
        lambda is_critical: multiplier if is_critical else 1.0
    )
    frame["risk_score"] = frame["risk_score"].clip(0, 100).round(1)

    scored_items = []
    for record in frame.to_dict("records"):
        record.pop("cvss_num", None)
        record.pop("epss_num", None)
        record.pop("kev_num", None)
        record.pop("verification_penalty", None)
        record.pop("base_score", None)
        scored = calculate_risk(record, profile)
        scored["risk_score"] = record["risk_score"]
        if scored["risk_score"] >= 80:
            scored["priority"] = "Urgent"
        elif scored["risk_score"] >= 60:
            scored["priority"] = "High"
        elif scored["risk_score"] >= 40:
            scored["priority"] = "Medium"
        else:
            scored["priority"] = "Low"
        scored_items.append(scored)
    
    # Deduplicate by CVE and product
    deduped = {}
    for item in scored_items:
        key = f"{item.get('cve_id')}_{item.get('matched_tech')}"
        if key not in deduped or item["risk_score"] > deduped[key]["risk_score"]:
            deduped[key] = item

    zero_tolerance = str(profile.get("risk_appetite", "")).lower() == "zero-tolerance"
    ranked = sorted(
        deduped.values(),
        key=lambda item: (
            zero_tolerance and str(item.get("in_kev", "")).lower() in ["true", "1", "yes"],
            item["risk_score"],
        ),
        reverse=True,
    )
    for item in ranked:
        item["kev_escalated"] = zero_tolerance and str(item.get("in_kev", "")).lower() in ["true", "1", "yes"]
    return ranked[:limit]