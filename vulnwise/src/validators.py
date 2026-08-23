import json
from io import BytesIO
from typing import Any, Dict, Iterable, Tuple

import pandas as pd

from src.profile_schema import validate_profiles
from src.scorer import normalize_dataset


VULNERABILITY_REQUIRED_COLUMNS = {
    "cve_id",
    "cvss",
    "epss",
    "in_kev",
}


def _read_csv(file_bytes: bytes, filename: str) -> pd.DataFrame:
    try:
        return pd.read_csv(BytesIO(file_bytes))
    except Exception as error:
        raise ValueError(f"Could not parse {filename}: {error}") from error


def validate_vulnerabilities(file_bytes: bytes, filename: str = "vulnerabilities.csv") -> pd.DataFrame:
    dataset = _read_csv(file_bytes, filename)
    normalized = normalize_dataset(dataset)
    missing = sorted(VULNERABILITY_REQUIRED_COLUMNS - set(normalized.columns))
    if "product" not in normalized.columns:
        missing.append("product_name")
    if missing:
        raise ValueError(
            f"{filename} is missing required column(s): {', '.join(missing)}"
        )
    return normalized


def validate_gold_set(file_bytes: bytes, filename: str = "gold_set.csv") -> pd.DataFrame:
    return _read_csv(file_bytes, filename)


def _profile_list(payload: Any) -> Iterable[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ("organizations", "organisations", "profiles"):
            if isinstance(payload.get(key), list):
                return payload[key]
            if isinstance(payload.get(key), dict):
                return [
                    {**value, "id": value.get("id", record_id)}
                    for record_id, value in payload[key].items()
                    if isinstance(value, dict)
                ]
        if all(isinstance(value, dict) for value in payload.values()):
            return [
                {**value, "id": value.get("id", record_id)}
                for record_id, value in payload.items()
            ]
    raise ValueError("profiles.json must contain a list or an 'organizations' list")


def _normalize_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    normalized = dict(profile)
    nested_keys = (
        "profile", "details", "configuration", "organization", "organisation",
        "organization_profile", "organisation_profile", "asset_profile", "context",
    )
    for key in nested_keys:
        nested = profile.get(key)
        if isinstance(nested, dict):
            normalized = {**normalized, **nested}
    for nested in profile.values():
        if isinstance(nested, dict):
            normalized = {**normalized, **nested}
    normalized = {
        str(key).strip().lower().replace("-", "_").replace(" ", "_"): value
        for key, value in normalized.items()
    }
    aliases = {
        "organization": "organisation",
        "organization_name": "organisation",
        "organisation_name": "organisation",
        "org_name": "organisation",
        "org": "organisation",
        "name": "organisation",
        "service_context": "service",
        "service_name": "service",
        "service_type": "service",
        "exposure_level": "exposure",
        "exposure_type": "exposure",
        "service_importance": "importance",
        "importance_level": "importance",
        "installed_technologies": "technologies",
        "technology_stack": "technologies",
        "technologies_monitored": "technologies",
        "monitored_technologies": "technologies",
        "monitored_tech": "technologies",
        "monitored_products": "technologies",
        "products": "technologies",
        "technology": "technologies",
        "assets": "technologies",
        "asset_products": "technologies",
        "affected_products": "technologies",
    }
    for source, target in aliases.items():
        if target not in normalized and source in normalized:
            normalized[target] = normalized[source]
    if isinstance(normalized.get("technologies"), dict):
        normalized["technologies"] = [
            {"product": product, "version": version}
            for product, version in normalized["technologies"].items()
        ]
    elif isinstance(normalized.get("technologies"), list):
        normalized["technologies"] = [
            {"product": technology, "version": ""}
            if isinstance(technology, str) else technology
            for technology in normalized["technologies"]
        ]
    if not normalized.get("technologies") and normalized.get("critical_products"):
        normalized["technologies"] = [
            {"product": product, "version": ""}
            if isinstance(product, str)
            else {"product": product.get("product", product.get("name", "")), "version": product.get("version", "")}
            for product in normalized["critical_products"]
        ]
    if "organisation" in normalized:
        defaulted_fields = []
        for field, default in (
            ("service", "Not specified"),
            ("exposure", "Internal"),
            ("importance", "Normal"),
            ("technologies", []),
        ):
            if field not in normalized:
                defaulted_fields.append(field)
                normalized[field] = default
        normalized["_defaulted_profile_fields"] = defaulted_fields
    return normalized


def validate_profiles_json(file_bytes: bytes, filename: str = "profiles.json") -> list[Dict[str, Any]]:
    try:
        payload = json.loads(file_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Could not parse {filename}: {error}") from error
    try:
        profiles = list(validate_profiles(_normalize_profile(profile) for profile in _profile_list(payload)))
    except (TypeError, ValueError, KeyError) as error:
        raise ValueError(f"Invalid {filename} schema: {error}") from error
    if not profiles:
        raise ValueError(f"Invalid {filename} schema: no organisation profiles found")
    return profiles


def validate_required_uploads(
    vulnerability_file: Tuple[bytes, str] | None,
    gold_file: Tuple[bytes, str] | None,
    profiles_file: Tuple[bytes, str] | None,
) -> tuple[pd.DataFrame, pd.DataFrame, list[Dict[str, Any]]]:
    if not vulnerability_file or not gold_file or not profiles_file:
        raise ValueError(
            "Please upload all three required files: vulnerabilities.csv, gold_set.csv, and profiles.json."
        )
    vulnerabilities = validate_vulnerabilities(*vulnerability_file)
    gold_set = validate_gold_set(*gold_file)
    profiles = validate_profiles_json(*profiles_file)
    return vulnerabilities, gold_set, profiles