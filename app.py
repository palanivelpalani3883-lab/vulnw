from pathlib import Path
from src.matcher import match_vulnerabilities
import hashlib
import pandas as pd
import streamlit as st

from src.expliner import generate_explanation
from src.links import vulnerability_reference
from src.reporting import build_pdf_report
from src.scorer import rank_top_vulnerabilities
from src.validators import validate_gold_set, validate_profiles_json, validate_vulnerabilities


st.set_page_config(page_title="VulnWise - Personalised Vulnerability Triage", layout="wide")

st.markdown(
    """
    <style>
    .stApp {
        background: #0a0a0c;
        color: #e8e3d8;
        isolation: isolate;
        position: relative;
    }
    .stApp > div {
        position: relative;
        z-index: 1;
    }
    .stApp::before,
    .stApp::after {
        content: '';
        inset: 0;
        pointer-events: none;
        position: fixed;
    }
    .stApp::before {
        background-image: radial-gradient(rgba(140, 115, 51, 0.02) 0.7px, transparent 0.7px);
        background-size: 15px 15px;
        z-index: 0;
    }
    .stApp::after {
        background: linear-gradient(115deg, transparent 0%, rgba(140, 115, 51, 0.05) 48%, transparent 100%);
        height: 180vh;
        left: -10vw;
        top: -40vh;
        transform: translateX(-130vw) rotate(8deg);
        width: 120px;
        will-change: transform;
        z-index: 0;
    }
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1400px;
    }
    h1, h2, h3, h4 {
        color: #e8e3d8 !important;
        letter-spacing: -0.03em;
    }
    .stCaption {
        color: #8a8680 !important;
    }
    div[data-testid="stFileUploaderDropzone"],
    div[data-testid="stRadio"],
    div[data-testid="stSelectbox"],
    div[data-testid="stDataFrame"] {
        border: 1px solid rgba(140, 115, 51, 0.42);
        background: #1c1b18;
        border-radius: 14px;
        box-shadow: 0 10px 30px rgba(4, 9, 17, 0.18);
    }
    div[data-testid="stFileUploaderDropzone"] {
        padding: 0.65rem 0.8rem;
        border-style: solid;
    }
    .stButton > button {
        background: #1c1b18;
        color: #e8e3d8;
        border: 1px solid rgba(140, 115, 51, 0.62);
        border-radius: 10px;
        font-weight: 700;
        padding: 0.6rem 1.1rem;
        box-shadow: none;
    }
    .stButton > button:hover {
        border-color: #d4a526;
        color: #e8e3d8;
    }
    .stButton > button[kind="primary"] {
        background: #d4a526;
        border-color: #d4a526;
        color: #0a0a0c;
        box-shadow: 0 12px 24px rgba(212, 165, 38, 0.18);
    }
    .stButton > button:disabled {
        background: rgba(148, 159, 177, 0.2) !important;
        color: rgba(255,255,255,0.7) !important;
        box-shadow: none !important;
    }
    [data-testid="stMetric"] {
        background: rgba(17, 27, 40, 0.9);
        border: 1px solid rgba(129, 148, 184, 0.3);
        border-radius: 14px;
        padding: 0.9rem 1rem;
    }
    [data-testid="stMetricLabel"] {
        color: #9fb0d4 !important;
    }
    [data-testid="stMetricValue"] {
        color: #f6f9ff !important;
        font-weight: 700;
    }
    .stDataFrame {
        border-radius: 14px;
        overflow: hidden;
    }
    .stDataFrame table {
        background: #0a0a0c;
    }
    .stDataFrame thead th {
        background: #1c1b18 !important;
        color: #e8e3d8 !important;
        border-bottom: 1px solid rgba(140, 115, 51, 0.42) !important;
    }
    .stDataFrame tbody td {
        color: #e8e3d8 !important;
        border-bottom: 1px solid rgba(140, 115, 51, 0.2) !important;
        background: #0a0a0c !important;
    }
    .stDataFrame tbody tr:hover td {
        background: #1c1b18 !important;
    }
    .stAlert {
        border-radius: 12px;
        border: 1px solid rgba(212, 165, 38, 0.55);
        background: #1c1b18;
    }
    .cut-line {
        height: 2px;
        background: linear-gradient(90deg, #d4a526, rgba(140, 115, 51, 0.35), transparent);
        margin: 1rem 0 1.25rem;
        border-radius: 999px;
    }
    .stExpander {
        border: 1px solid rgba(140, 115, 51, 0.42);
        border-radius: 12px;
        background: #1c1b18;
    }
    .stExpander summary {
        color: #e8e3d8 !important;
        font-weight: 600;
    }
    [data-testid="stFileUploaderDropzone"] small,
    [data-testid="stFileUploaderDropzone"] span {
        color: #8a8680 !important;
    }
    .stMarkdown code {
        background: rgba(140, 115, 51, 0.16);
        color: #e8e3d8;
        border-radius: 6px;
        padding: 0.12rem 0.35rem;
    }
    @media (prefers-reduced-motion: no-preference) {
        .stApp::after {
            animation: scan-sweep 16s linear infinite;
        }
    }
    @keyframes scan-sweep {
        from { transform: translateX(-130vw) rotate(8deg); }
        to { transform: translateX(230vw) rotate(8deg); }
    }
    @media (prefers-reduced-motion: reduce) {
        .stApp::after {
            animation: none;
            display: none;
        }
    }
    </style>
    """,
    unsafe_allow_html=True,
)


def resolve_bundled_path(candidate_paths):
    for candidate in candidate_paths:
        path = Path(candidate)
        if path.exists():
            return path
    return Path(candidate_paths[0])


@st.cache_data
def read_bundled_file(path: str) -> bytes:
    return Path(path).read_bytes()


def file_input(uploaded_file, bundled_path: str, use_bundled: bool):
    if uploaded_file is not None:
        return uploaded_file.getvalue(), uploaded_file.name
    if use_bundled:
        resolved = resolve_bundled_path([bundled_path, bundled_path.replace("data/", "src/")])
        if resolved.exists():
            return read_bundled_file(str(resolved)), resolved.name
    return None


def status_text(value) -> str:
    return "Uploaded" if value is not None else "Not yet provided"


def why_selected(item: dict, rank: int, profile: dict) -> str:
    factors = []
    cvss = item.get("cvss")
    if cvss is not None and not pd.isna(cvss):
        factors.append(f"CVSS {cvss}")
    if str(item.get("in_kev", "")).lower() in ["true", "1", "yes"]:
        factors.append("listed in CISA KEV")
    epss = item.get("epss")
    if epss is not None and not pd.isna(epss):
        factors.append(f"EPSS {epss}")
    if item.get("is_critical_asset"):
        factors.append(f"affects a critical asset ({item.get('matched_tech', 'unknown')})")
    if not factors:
        factors.append("the available profile and vulnerability signals")
    appetite = profile.get("risk_appetite", "Standard")
    return f"Ranked #{rank}: {', '.join(factors)} under a {appetite} profile."


def display_value(value, fallback: str = "Not available"):
    return fallback if value is None or pd.isna(value) else value


def dataset_description(item: dict, fallback: str | None = None) -> str:
    for key in ("description", "summary", "vulnerability_description", "details"):
        value = item.get(key)
        if value is not None and not pd.isna(value) and str(value).strip():
            return str(value)
    if fallback is not None:
        return fallback
    cve_id = item.get("cve_id", "This vulnerability")
    product = item.get("product") or item.get("matched_tech") or "the selected product"
    return f"No narrative description is supplied in the selected dataset for {cve_id} affecting {product}."


def source_link(item: dict) -> str:
    reference = vulnerability_reference(item)
    if reference:
        return f"[Open source reference]({reference})"
    return "Source link not available in uploaded dataset"


st.title("VulnWise")
st.caption("Personalised vulnerability triage for resource-constrained organisations")

st.subheader("Upload / select datasets")
default_bundled = all(
    Path(path).exists() or Path(path.replace("data/", "src/")).exists()
    for path in ["data/vulnerabilities.csv", "data/gold_set.csv", "data/profile.json"]
)
use_bundled = st.checkbox(
    "Use bundled sample datasets",
    key="use_bundled",
    value=default_bundled,
    help="Explicitly load files from the data folder for a local demonstration.",
)
upload_columns = st.columns(3)
with upload_columns[0]:
    vulnerability_upload = st.file_uploader(
        "Vulnerabilities (vulnerabilities.csv)", type="csv", key="vulnerabilities_upload"
    )
    st.caption(f"{'✅' if vulnerability_upload or use_bundled else '⬜'} {status_text(vulnerability_upload) if not use_bundled else 'Bundled sample selected'}")
with upload_columns[1]:
    gold_upload = st.file_uploader("Gold Set (gold_set.csv)", type="csv", key="gold_upload")
    st.caption(f"{'✅' if gold_upload or use_bundled else '⬜'} {status_text(gold_upload) if not use_bundled else 'Bundled sample selected'}")
with upload_columns[2]:
    profiles_upload = st.file_uploader(
        "Organisation Profiles (profiles.json)", type="json", key="profiles_upload"
    )
    st.caption(f"{'✅' if profiles_upload or use_bundled else '⬜'} {status_text(profiles_upload) if not use_bundled else 'Bundled sample selected'}")

vulnerability_input = file_input(vulnerability_upload, "data/vulnerabilities.csv", use_bundled)
gold_input = file_input(gold_upload, "data/gold_set.csv", use_bundled)
profiles_input = file_input(profiles_upload, "data/profile.json", use_bundled)

validated = {}
validation_errors = []
if vulnerability_input:
    try:
        validated["vulnerabilities"] = validate_vulnerabilities(*vulnerability_input)
    except ValueError as error:
        validation_errors.append(str(error))
if gold_input:
    try:
        validated["gold_set"] = validate_gold_set(*gold_input)
    except ValueError as error:
        validation_errors.append(str(error))
if profiles_input:
    try:
        validated["profiles"] = validate_profiles_json(*profiles_input)
    except ValueError as error:
        validation_errors.append(str(error))

all_files_present = vulnerability_input is not None and gold_input is not None and profiles_input is not None
for error in validation_errors:
    st.error(error)
if not all_files_present:
    st.info("Please provide all three files, or explicitly select the bundled sample datasets.")

profiles = validated.get("profiles", [])
profile_map = {profile["organisation"]: profile for profile in profiles}
if profiles:
    defaulted = sorted({field for item in profiles for field in item.get("_defaulted_profile_fields", [])})
    if defaulted:
        st.warning(
            "Some profile fields were not provided and use neutral defaults: "
            + ", ".join(defaulted)
            + "."
        )
selector_col, info_col = st.columns([2, 1])
with selector_col:
    selected_org = st.selectbox(
        "Select Organisation Profile",
        list(profile_map) or ["Upload a valid profiles.json"],
        disabled=not profile_map,
        key="organisation_profile_selector",
    )
profile = profile_map.get(selected_org)
with info_col:
    if validated.get("vulnerabilities") is not None:
        st.metric("Vulnerabilities loaded", f"{len(validated['vulnerabilities']):,}")

ranking_scope = st.radio(
    "Vulnerability scope",
    ["All uploaded vulnerabilities", "Profile-matched vulnerabilities"],
    horizontal=True,
    help="All uploaded vulnerabilities ranks the complete file. Profile-matched vulnerabilities ranks only products found in the selected organisation profile.",
)

ready = all_files_present and not validation_errors and bool(profile)
analyze = st.button("Analyze Vulnerabilities", type="primary", disabled=not ready)

if analyze and ready:
    try:
        with st.spinner("Validating and ranking vulnerabilities..."):
            vulnerabilities = validated["vulnerabilities"]
            matched = match_vulnerabilities(vulnerabilities, profile)
            if ranking_scope == "All uploaded vulnerabilities":
                ranking_items = vulnerabilities.to_dict("records")
                for item in ranking_items:
                    item.setdefault("matched_tech", item.get("product", "Unknown product"))
            else:
                ranking_items = matched
            ranked = rank_top_vulnerabilities(ranking_items, profile, limit=5)
            signature = hashlib.sha256(
                vulnerability_input[0]
                + profiles_input[0]
                + selected_org.encode("utf-8")
                + ranking_scope.encode("utf-8")
            ).hexdigest()
            st.session_state.analysis = {
                "signature": signature,
                "profile": profile,
                "vulnerabilities": vulnerabilities,
                "ranked": ranked,
                "ranking_scope": ranking_scope,
            }
    except Exception as error:
        st.error(f"Analysis failed: {error}")

analysis = st.session_state.get("analysis")
if (
    analysis
    and analysis["profile"]["organisation"] == selected_org
    and analysis.get("ranking_scope") == ranking_scope
):
    profile = analysis["profile"]
    ranked = analysis["ranked"]
    st.divider()
    st.subheader("Top 5 Prioritized Vulnerabilities")
    st.markdown('<div class="cut-line"></div>', unsafe_allow_html=True)
    if not ranked:
        st.info("Zero matching vulnerabilities were found for the selected organisation profile.")
    else:
        if len(ranked) < 5:
            st.info(f"Only {len(ranked)} vulnerabilities are available - showing all available results.")
        if ranking_scope == "All uploaded vulnerabilities":
            st.caption("Ranking all vulnerabilities in the uploaded feed using the selected profile's scoring rules.")
        rows = []
        for index, item in enumerate(ranked, 1):
            rows.append(
                {
                    "Rank": index,
                    "CVE ID": item.get("cve_id", "Not available"),
                    "Description": dataset_description(item),
                    "CVSS Score": display_value(item.get("cvss")),
                    "EPSS Score": display_value(item.get("epss")),
                    "CISA KEV": display_value(item.get("in_kev")),
                    "Priority Score": item["risk_score"],
                    "Why Selected": why_selected(item, index, profile),
                }
            )
        st.dataframe(pd.DataFrame(rows), hide_index=True, width="stretch")

        for index, item in enumerate(ranked, 1):
            expl = generate_explanation(item, profile)
            badge = item.get("priority", "Low").upper()
            escalation = " | Escalated: Known Exploited + Zero-Tolerance policy" if item.get("kev_escalated") else ""
            with st.expander(f"#{index} [{badge}] {item.get('cve_id', 'Unknown')} - {item.get('matched_tech', 'Unknown technology')} (Score: {item['risk_score']}/100){escalation}"):
                c1, c2 = st.columns([2, 1])
                with c1:
                    st.markdown(f"**Description:** {dataset_description(item)}")
                    st.markdown(f"**Why it matters:** {expl['why']}")
                    st.markdown(f"**Safe Next Action:** `{expl['next_action']}`")
                with c2:
                    st.markdown("**Contributing Factors:**")
                    for key, value in item.get("score_breakdown", {}).items():
                        st.write(f"- `{key}`: {value}")
                    st.markdown(f"**Confidence:** {expl['confidence']}")
                    st.markdown(f"**Installed version:** {display_value(item.get('installed_version'))}")
                    st.markdown(f"**Affected version:** {display_value(item.get('affected_version_range'))}")
                    st.markdown(f"**Source Link:** {source_link(item)}")

        st.download_button(
            "Download PDF report",
            data=build_pdf_report(profile, ranked),
            file_name=f"vulnwise-report-{selected_org.lower().replace(' ', '-')}.pdf",
            mime="application/pdf",
        )
