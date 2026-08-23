from typing import Any, Dict, Iterable


SCHEMA_DESCRIPTION = (
    "Profile fields: organisation, service, exposure, importance, technologies; "
    "optional risk_appetite, critical_products, and weight_modifiers.criticality_multiplier."
)


def validate_profiles(profiles: Iterable[Dict[str, Any]]) -> list[Dict[str, Any]]:
    required = {"organisation", "service", "exposure", "importance", "technologies"}

    if hasattr(profiles, "to_dict"):
        profiles = profiles.to_dict("records")

    validated = []
    for index, profile in enumerate(profiles):
        if isinstance(profile, str):
            raise ValueError(f"Profile {index} is not a valid object")
        if not hasattr(profile, "keys"):
            raise ValueError(f"Profile {index} is not a valid dictionary-like object")
        missing = required - profile.keys()
        if missing:
            raise ValueError(f"Profile {index} is missing required fields: {sorted(missing)}")
        profile.setdefault("risk_appetite", "Standard")
        profile.setdefault("critical_products", [])
        modifiers = profile.setdefault("weight_modifiers", {})
        modifiers.setdefault("criticality_multiplier", 1.0)
        if float(modifiers["criticality_multiplier"]) < 1:
            raise ValueError(f"Profile {index} has an invalid criticality_multiplier")
        validated.append(profile)
    return validated