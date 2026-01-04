#!/usr/bin/env python3
"""
cookie_privacy_audit.py

Analyse cookie capture JSON for GDPR/ePrivacy and CCPA/CPRA risks.

Features:
- Input via:
    - Pasted JSON (interactive) with empty-line + delay auto-execution.
    - Or --file PATH for automated / batch mode (ideal for Scrapy integration).
- Per-record analysis with:
    - Cookie inventory (with 3rd-party & PII flags)
    - Context (jurisdiction, consent, etc.)
    - Violations (HIGH/MEDIUM/LOW) with color
    - Warnings / potential issues
    - Remediation recommendations
    - 3rd-party locator (vendors)
    - PII detection
    - Transfer analysis (esp. EU → US/cloud vendors)
- Optional Markdown export via --markdown report.md
- Can be imported from other tools (e.g. Scrapy) via analyse_data(data).
"""

import sys
import json
import re
import time
import argparse
from typing import Any, Dict, List, Tuple, Optional

# ----------------------------- SETTINGS ---------------------------------

EU_COUNTRY_CODES = {
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE",
    "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT",
    "RO", "SK", "SI", "ES", "SE"
}

# Vendors we treat as 3rd-party trackers + likely extra-EU transfers (for GDPR transfer analysis)
THIRD_PARTY_VENDOR_HINTS = {
    "google_analytics": ["_ga", "_gid", "_gat", "_gcl_", "ga_", "analytics"],
    "google_ads": ["_gcl_au", "gads", "FPGCLDC"],
    "google_tag_manager": ["gtm", "_gtm"],
    "meta_facebook": ["_fbp", "fbc", "fbp", "fb_"],
    "microsoft_clarity": ["_clck", "_clsk", "clarity"],
    "hotjar": ["_hj", "hotjar"],
    "matomo": ["_pk_", "matomo"],
    "linkedin": ["li_", "lidc", "bcookie", "bscookie"],
    "twitter": ["_tw", "gt", "muc_"],
    "hubspot": ["__hstc", "hubspot"],
    "segment": ["ajs_", "segment"],
}


# --------------------------- COLOR SUPPORT ------------------------------

class Colors:
    RESET = "\033[0m"
    INFO = "\033[36m"      # cyan
    LOW = "\033[32m"       # green
    MEDIUM = "\033[33m"    # yellow
    HIGH = "\033[31m"      # red
    TITLE = "\033[95m"     # magenta
    MUTED = "\033[90m"     # grey


def color_by_severity(text: str) -> str:
    """Color lines based on tags like [HIGH], [MEDIUM], [LOW], [CONTEXT]."""
    if "[HIGH]" in text:
        return f"{Colors.HIGH}{text}{Colors.RESET}"
    if "[MEDIUM]" in text:
        return f"{Colors.MEDIUM}{text}{Colors.RESET}"
    if "[LOW]" in text:
        return f"{Colors.LOW}{text}{Colors.RESET}"
    if "[CONTEXT]" in text:
        return f"{Colors.INFO}{text}{Colors.RESET}"
    return text


# -------------------------- HELPER FUNCTIONS ----------------------------

def is_eu_location(location: Optional[str]) -> bool:
    if not location:
        return False
    loc = location.upper()
    if loc == "EU":
        return True
    parts = loc.split("-")
    return parts[0] in EU_COUNTRY_CODES


def is_california_location(location: Optional[str]) -> bool:
    if not location:
        return False
    loc = location.upper()
    return loc == "US-CA" or loc.endswith("-CA") or loc == "CA" or "CALIF" in loc


def detect_vendor_by_name(name_lower: str) -> Optional[str]:
    for vendor, patterns in THIRD_PARTY_VENDOR_HINTS.items():
        for p in patterns:
            if p.lower() in name_lower:
                return vendor
    return None


def detect_pii(name_lower: str, value: str) -> Tuple[bool, List[str]]:
    pii_types: List[str] = []
    value_lower = value.lower()

    # Email address
    if re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", value):
        pii_types.append("email")

    # Phone-like sequences (very rough heuristic)
    if re.search(r"\b\+?\d{7,15}\b", value):
        pii_types.append("phone")

    # Hashed email / hashed ID
    if (
        "hash" in name_lower
        or "hash" in value_lower
        or "sha" in value_lower
        or re.search(r"[0-9a-f]{32,}", value_lower) is not None
    ):
        pii_types.append("hashed_identifier")

    # Explicit IDs
    if any(k in name_lower for k in ["uid", "user_id", "customer_id", "client_id", "account_id"]):
        pii_types.append("identifier")

    # Query-string like value with email= or name=
    if "email=" in value_lower:
        pii_types.append("email")
    if "name=" in value_lower:
        pii_types.append("name")

    return (len(pii_types) > 0, list(sorted(set(pii_types))))


def categorise_cookie(cookie: Dict[str, Any], site_domain: Optional[str]) -> Dict[str, Any]:
    name = str(cookie.get("name", "")).strip()
    value = str(cookie.get("value", ""))
    name_lower = name.lower()
    category = cookie.get("category")
    category_lower = str(category).lower() if category else None
    expiry = cookie.get("expiry")
    cookie_domain = cookie.get("domain")
    cookie_domain_norm = cookie_domain.lstrip(".").lower() if isinstance(cookie_domain, str) else None
    site_domain_norm = site_domain.lower() if isinstance(site_domain, str) else None

    cookie_type: Optional[str] = None

    # 1) Explicit category
    if category_lower in {"essential", "strictly_necessary", "strict", "necessary"}:
        cookie_type = "essential"
    elif category_lower in {"analytics", "statistics"}:
        cookie_type = "analytics"
    elif category_lower in {"marketing", "advertising", "ads"}:
        cookie_type = "marketing"
    elif category_lower in {"functional", "preferences"}:
        cookie_type = "functional"

    # 2) Heuristics
    if cookie_type is None:
        if any(k in name_lower for k in ["_ga", "_gid", "_gat", "analytics", "gtm"]):
            cookie_type = "analytics"
        elif any(k in name_lower for k in ["_fbp", "gclid", "doubleclick", "ad_", "ads"]):
            cookie_type = "marketing"
        elif any(k in name_lower for k in ["session", "csrf", "auth", "login", "cart"]):
            cookie_type = "essential"
        elif any(k in name_lower for k in ["pref", "prefs", "theme", "lang"]):
            cookie_type = "functional"
        else:
            cookie_type = "unknown"

    # 3rd-party by vendor name
    vendor = detect_vendor_by_name(name_lower)

    # 3rd-party by domain difference
    is_third_party_domain = False
    if cookie_domain_norm and site_domain_norm:
        if not cookie_domain_norm.endswith(site_domain_norm):
            is_third_party_domain = True

    is_third_party_vendor = vendor is not None
    is_third_party = is_third_party_domain or is_third_party_vendor

    # PII detection
    contains_pii, pii_types = detect_pii(name_lower, value)

    return {
        "name": name,
        "type": cookie_type,
        "raw_category": category,
        "is_essential": cookie_type == "essential",
        "secure": bool(cookie.get("secure")),
        "same_site": str(cookie.get("sameSite") or "").lower(),
        "http_only": bool(cookie.get("httpOnly")),
        "expiry": expiry,
        "cookie_domain": cookie_domain,
        "is_third_party": is_third_party,
        "third_party_vendor": vendor,
        "contains_pii": contains_pii,
        "pii_types": pii_types,
        "raw": cookie,
    }


def print_cookie_inventory(cookies: List[Dict[str, Any]]) -> None:
    if not cookies:
        print("  [No cookies found]")
        return

    header = "    {:<18} {:<11} {:<9} {:<5} {:<14} {:<5} {:<11} {:<10} {:<9} {}".format(
        "Name", "Type", "Essential", "3rd", "Vendor", "PII", "SameSite", "Secure", "HttpOnly", "Expiry"
    )
    print("  Cookie inventory:")
    print(Colors.MUTED + header + Colors.RESET)
    print("  " + Colors.MUTED + "-" * (len(header) + 2) + Colors.RESET)

    for c in cookies:
        vendor = c["third_party_vendor"] or "-"
        pii_flag = "Yes" if c["contains_pii"] else "No"
        line = "    {:<18} {:<11} {:<9} {:<5} {:<14} {:<5} {:<11} {:<10} {:<9} {}".format(
            c["name"],
            c["type"],
            str(c["is_essential"]),
            "Yes" if c["is_third_party"] else "No",
            vendor,
            pii_flag,
            c["same_site"] or "-",
            str(c["secure"]),
            str(c["http_only"]),
            c["expiry"] if c["expiry"] is not None else "-"
        )
        print(line)


# ------------------------ CORE ANALYSIS LOGIC ---------------------------

def analyse_record(
    record: Dict[str, Any],
    index: int
) -> Tuple[List[str], List[str], List[str], List[str], List[Dict[str, Any]]]:
    """
    Returns (violations, warnings, info, recommendations, cookies)
    """
    violations: List[str] = []
    warnings: List[str] = []
    info: List[str] = []
    recommendations: List[str] = []

    domain = record.get("domain", "?")
    location = record.get("user_location")
    timestamp = record.get("timestamp", "?")
    banner_shown = record.get("consent_banner_shown")
    user_consent = record.get("user_consent") or {}
    cookies_raw = record.get("cookies", []) or []

    cookies = [categorise_cookie(c, domain) for c in cookies_raw]

    is_eu = is_eu_location(location)
    is_ca = is_california_location(location)

    non_essential = [c for c in cookies if not c["is_essential"]]
    analytics = [c for c in cookies if c["type"] == "analytics"]
    marketing = [c for c in cookies if c["type"] == "marketing"]
    uid_like = [c for c in cookies if "identifier" in c["pii_types"] or "hashed_identifier" in c["pii_types"]]
    pii_cookies = [c for c in cookies if c["contains_pii"]]
    third_party_cookies = [c for c in cookies if c["is_third_party"]]
    third_party_vendors = sorted(
        {c["third_party_vendor"] for c in third_party_cookies if c["third_party_vendor"]}
    )

    info.append(
        "[CONTEXT] Record #{idx}: domain={dom}, location={loc}, timestamp={ts}, "
        "cookies={cnt}, banner_shown={banner}, consent_keys={keys}".format(
            idx=index + 1,
            dom=domain,
            loc=location or "-",
            ts=timestamp,
            cnt=len(cookies_raw),
            banner=banner_shown,
            keys=list(user_consent.keys()) if isinstance(user_consent, dict) else "N/A"
        )
    )

    if third_party_vendors:
        info.append(
            "[CONTEXT] Third-party vendors detected: " + ", ".join(third_party_vendors)
        )

    if pii_cookies:
        info.append(
            "[CONTEXT] Cookies containing potential PII: "
            + ", ".join(
                f"{c['name']} ({','.join(c['pii_types'])})" for c in pii_cookies
            )
        )

    # ----- GDPR / ePrivacy -----
    if is_eu:
        info.append("[CONTEXT] Jurisdiction: EU (GDPR + ePrivacy assumed).")

        # Non-essential before consent
        if non_essential and (not banner_shown or not user_consent):
            violations.append(
                "[GDPR/ePrivacy][HIGH] Non-essential cookies are set before any consent "
                "or without a recorded consent object. Non-essential cookies: "
                + ", ".join(c["name"] for c in non_essential)
            )
            recommendations.append(
                "- Block all non-essential cookies (analytics, marketing, profiling) until "
                "the user has given explicit, granular consent via a compliant CMP."
            )

        # Category vs consent flags
        if isinstance(user_consent, dict) and banner_shown:
            analytics_consent = user_consent.get("analytics")
            marketing_consent = user_consent.get("marketing")

            if analytics and analytics_consent is False:
                violations.append(
                    "[GDPR/ePrivacy][HIGH] Analytics cookies present even though analytics "
                    "consent is FALSE. Cookies: " + ", ".join(c["name"] for c in analytics)
                )
                recommendations.append(
                    "- Ensure analytics tooling is fully disabled when analytics consent is FALSE."
                )

            if marketing and marketing_consent is False:
                violations.append(
                    "[GDPR/ePrivacy][HIGH] Marketing cookies present even though marketing "
                    "consent is FALSE. Cookies: " + ", ".join(c["name"] for c in marketing)
                )
                recommendations.append(
                    "- Do not fire marketing/advertising pixels or set ad cookies when the "
                    "user has not opted in to marketing."
                )

        # UID / hashed identifiers / PII
        if pii_cookies:
            non_essential_with_pii = [c for c in pii_cookies if not c["is_essential"]]
            third_party_with_pii = [c for c in pii_cookies if c["is_third_party"]]

            if non_essential_with_pii:
                violations.append(
                    "[GDPR][HIGH] PII stored in non-essential cookies, which likely requires "
                    "explicit consent and strict minimisation. Cookies: "
                    + ", ".join(
                        f"{c['name']} ({','.join(c['pii_types'])})" for c in non_essential_with_pii
                    )
                )
                recommendations.append(
                    "- Avoid storing PII (emails, identifiers, phone numbers, hashes) in "
                    "non-essential cookies. Prefer server-side storage or strictly necessary "
                    "session cookies with strong safeguards and explicit consent where needed."
                )

            if third_party_with_pii:
                violations.append(
                    "[GDPR][HIGH] PII appears to be exposed to third-party vendors via cookies. "
                    "Cookies: "
                    + ", ".join(
                        f"{c['name']} -> {c['third_party_vendor'] or 'unknown_vendor'}"
                        for c in third_party_with_pii
                    )
                )
                recommendations.append(
                    "- Ensure no PII is sent to third-party trackers via cookies unless you have "
                    "a strong lawful basis, appropriate contracts (DPAs), and explicit consent."
                )

        if uid_like:
            violations.append(
                "[GDPR][HIGH] Identifier-like cookies (UID / account IDs / hashed IDs) suggest "
                "profiling/pseudonymous tracking. Cookies: "
                + ", ".join(
                    f"{c['name']} ({','.join(c['pii_types'])})" for c in uid_like
                )
            )
            recommendations.append(
                "- Treat UID / account ID / hashed ID cookies as personal data used for profiling. "
                "Document the lawful basis, include them in your records of processing, and ensure "
                "consent and DPIA where appropriate."
            )

        # Security flags
        insecure = [c for c in cookies if c["same_site"] == "none" and not c["secure"]]
        if insecure:
            warnings.append(
                "[GDPR Article 32][MEDIUM] SameSite=None cookies without Secure flag. "
                "These may be sent over insecure HTTP, weakening protection of personal data. "
                "Cookies: " + ", ".join(c["name"] for c in insecure)
            )
            recommendations.append(
                "- Mark all SameSite=None cookies as Secure and serve them only over HTTPS."
            )

        # Transfer analysis: EU → typical US / global vendors
        if third_party_vendors:
            violations_or_warnings_added = False
            eu_transfer_vendors = [v for v in third_party_vendors]
            if eu_transfer_vendors:
                warnings.append(
                    "[GDPR/Transfers][MEDIUM] Third-party vendors receiving cookie data may "
                    "involve international data transfers (e.g. US-based services). Vendors: "
                    + ", ".join(eu_transfer_vendors)
                )
                recommendations.append(
                    "- Map each third-party vendor to its hosting/processing locations and ensure "
                    "appropriate transfer safeguards (e.g. SCCs, DTIA) for EU users."
                )
                violations_or_warnings_added = True

            if not violations_or_warnings_added and third_party_vendors:
                warnings.append(
                    "[GDPR/Transfers][LOW] Third-party cookies detected; verify whether any "
                    "cross-border transfers occur and ensure compliance with Chapter V GDPR."
                )
                recommendations.append(
                    "- Include cross-border data transfers in your RoPA and privacy documentation, "
                    "even when relying on EU-based processors."
                )

    # ----- CCPA / CPRA -----
    if is_ca:
        info.append("[CONTEXT] Jurisdiction: California (CCPA/CPRA assumed).")

        if marketing and isinstance(user_consent, dict) and user_consent.get("marketing") is False:
            violations.append(
                "[CCPA/CPRA][HIGH] Marketing cookies appear to be set even though user "
                "preference marketing=false. This may conflict with opt-out / Do-Not-Sell/Share."
            )
            recommendations.append(
                "- Ensure that marketing pixels and ad cookies honour user opt-out/state "
                "for marketing and any 'Do Not Sell/Share' controls."
            )

        if analytics or marketing:
            warnings.append(
                "[CCPA/CPRA][MEDIUM] Analytics/marketing cookies detected. Depending on "
                "data sharing with third parties, this may qualify as 'sale' or 'sharing' "
                "and require Do-Not-Sell/Share and GPC support."
            )
            recommendations.append(
                "- Classify each vendor under CCPA/CPRA (sale/sharing) and implement a "
                "Do-Not-Sell/Share mechanism plus GPC handling where required."
            )

        if pii_cookies and third_party_cookies:
            warnings.append(
                "[CCPA/CPRA][MEDIUM] PII present in cookies and third-party trackers. "
                "If this PII is used for cross-context behavioural advertising, it may "
                "strengthen the case that 'sale'/'sharing' is occurring."
            )
            recommendations.append(
                "- Review whether PII in cookies is used for cross-context advertising and ensure "
                "clear notice, opt-out mechanisms, and proper contractual protections."
            )

    # ----- Documentation -----
    unclassified = [c for c in cookies if c["raw_category"] in (None, "", "null")]
    if unclassified:
        warnings.append(
            "[Documentation][LOW] Some cookies have no explicit category (category=null). "
            "Cookies: " + ", ".join(c["name"] for c in unclassified)
        )
        recommendations.append(
            "- Classify all cookies (essential, analytics, functional, marketing) and align "
            "this with your cookie banner and privacy policy."
        )

    return violations, warnings, info, recommendations, cookies


def analyse_data(data: Any) -> List[Dict[str, Any]]:
    """
    Library-style entry point: takes parsed JSON (dict or list), returns list of results.

    Each result is:
        {
          "index": int,
          "record": original_record,
          "cookies": [cookie_meta...],
          "violations": [...],
          "warnings": [...],
          "info": [...],
          "recommendations": [...]
        }
    """
    if isinstance(data, dict):
        records = [data]
    elif isinstance(data, list):
        records = data
    else:
        raise ValueError("Top-level JSON must be an object or a list of objects.")

    all_results: List[Dict[str, Any]] = []
    for idx, record in enumerate(records):
        v, w, info, recos, cookies = analyse_record(record, idx)
        all_results.append({
            "index": idx + 1,
            "record": record,
            "cookies": cookies,
            "violations": v,
            "warnings": w,
            "info": info,
            "recommendations": recos,
        })
    return all_results


# -------------------------- INPUT HANDLING ------------------------------

def read_input_json_interactive(timeout: float = 2.0) -> Any:
    """
    Paste-mode: user pastes JSON, then presses Enter on an empty line.
    We then wait `timeout` seconds and parse.
    """
    print(f"{Colors.TITLE}Paste your JSON below (cookies_captured.json contents).{Colors.RESET}")
    print("When finished, press Enter once more to add an EMPTY line.")
    print(f"The script will then wait {timeout:.0f} seconds and auto-execute.")
    print("-" * 70)

    lines: List[str] = []

    try:
        while True:
            line = sys.stdin.readline()
            if not line:   # EOF
                break
            if line.strip() == "":  # empty line -> end
                break
            lines.append(line)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)

    raw = "".join(lines).strip()
    if not raw:
        print("No input received. Exiting.")
        sys.exit(1)

    time.sleep(timeout)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print("\nERROR: Invalid JSON input.")
        preview = raw[:200].replace("\n", "\\n")
        print(f"Input preview (first 200 chars): {preview}")
        print("Details:", e)
        sys.exit(1)


def read_input_json_file(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = f.read()
    except OSError as e:
        print(f"ERROR: Could not read file: {path}")
        print("Details:", e)
        sys.exit(1)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print("\nERROR: File does not contain valid JSON.")
        preview = raw[:200].replace("\n", "\\n")
        print(f"File preview (first 200 chars): {preview}")
        print("Details:", e)
        sys.exit(1)


# ------------------------ MARKDOWN REPORTING ----------------------------

def generate_markdown_report(results: List[Dict[str, Any]]) -> str:
    lines: List[str] = []
    lines.append("# Cookie Privacy Audit Report")
    lines.append("")

    for r in results:
        idx = r["index"]
        record = r["record"]
        cookies = r["cookies"]

        lines.append(
            f"## Record {idx} – {record.get('domain', '?')} ({record.get('user_location', '-')})"
        )
        lines.append("")

        lines.append("### Cookie Inventory")
        lines.append("")
        if not cookies:
            lines.append("_No cookies found._")
        else:
            lines.append("| Name | Type | Essential | ThirdParty | Vendor | PII | PII Types | SameSite | Secure | HttpOnly | Expiry |")
            lines.append("|------|------|-----------|-----------|--------|-----|-----------|----------|--------|----------|--------|")
            for c in cookies:
                lines.append(
                    f"| {c['name']} | {c['type']} | {c['is_essential']} | "
                    f"{c['is_third_party']} | {c['third_party_vendor'] or '-'} | "
                    f"{c['contains_pii']} | {','.join(c['pii_types']) or '-'} | "
                    f"{c['same_site'] or '-'} | {c['secure']} | {c['http_only']} | {c['expiry'] or '-'} |"
                )
        lines.append("")

        lines.append("### Context")
        lines.append("")
        for line in r["info"]:
            lines.append(f"- {line}")
        lines.append("")

        lines.append("### Violations")
        lines.append("")
        if r["violations"]:
            for v in r["violations"]:
                lines.append(f"- {v}")
        else:
            lines.append("- None detected based on current heuristics.")
        lines.append("")

        lines.append("### Warnings / Potential Issues")
        lines.append("")
        if r["warnings"]:
            for w in r["warnings"]:
                lines.append(f"- {w}")
        else:
            lines.append("- None.")
        lines.append("")

        lines.append("### Recommended Remediation Actions")
        lines.append("")
        recos = []
        seen = set()
        for rec in r["recommendations"]:
            if rec not in seen:
                seen.add(rec)
                recos.append(rec)
        if recos:
            for rec in recos:
                lines.append(f"- {rec}")
        else:
            lines.append("- No specific remediation beyond general best practices.")
        lines.append("")

    return "\n".join(lines)


# ----------------------------- MAIN CLI --------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyse cookie capture JSON for GDPR/ePrivacy and CCPA/CPRA risks."
    )
    parser.add_argument(
        "--file", "-f",
        help="Path to a JSON file (if omitted, the tool will prompt for pasted JSON)."
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=2.0,
        help="Seconds to wait after empty line before parsing pasted JSON (default: 2)."
    )
    parser.add_argument(
        "--markdown", "-m",
        help="Optional path to write a Markdown report (e.g. report.md)."
    )
    args = parser.parse_args()

    # Input source
    if args.file:
        data = read_input_json_file(args.file)
    else:
        data = read_input_json_interactive(timeout=args.delay)

    try:
        results = analyse_data(data)
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    # Console report
    print("\n" + Colors.TITLE + "=" * 80 + Colors.RESET)
    print(Colors.TITLE + "COOKIE PRIVACY AUDIT REPORT" + Colors.RESET)
    print(Colors.TITLE + "=" * 80 + Colors.RESET)

    any_violations = False

    for r in results:
        idx = r["index"]
        record = r["record"]
        cookies = r["cookies"]

        print("\n" + "-" * 80)
        print(f"Record #{idx} – {record.get('domain', '?')} ({record.get('user_location', '-')})")
        print("-" * 80)

        print("\n[1] Cookie inventory")
        print_cookie_inventory(cookies)

        print("\n[2] Context")
        for line in r["info"]:
            print("  " + color_by_severity(line))

        print("\n[3] Findings – Violations")
        if r["violations"]:
            any_violations = True
            for v in r["violations"]:
                print("  - " + color_by_severity(v))
        else:
            print("  - " + Colors.LOW + "[NONE detected based on current heuristics]" + Colors.RESET)

        print("\n[4] Findings – Warnings / Potential Issues")
        if r["warnings"]:
            for w in r["warnings"]:
                print("  - " + color_by_severity(w))
        else:
            print("  - " + Colors.LOW + "[NONE]" + Colors.RESET)

        print("\n[5] Recommended Remediation Actions")
        recos = []
        seen = set()
        for rec in r["recommendations"]:
            if rec not in seen:
                seen.add(rec)
                recos.append(rec)
        if recos:
            for rec in recos:
                print("  " + rec)
        else:
            print("  - No specific remediation beyond general best practices.")

    print("\n" + Colors.TITLE + "=" * 80 + Colors.RESET)
    if any_violations:
        print(Colors.HIGH + "Overall summary: One or more records contain HIGH or MEDIUM severity issues." + Colors.RESET)
        print("Next steps: Prioritise remediation of HIGH findings, then MEDIUM, and update ")
        print("             your cookie banner, consent logic, and documentation accordingly.")
    else:
        print(Colors.LOW + "Overall summary: No clear violations detected, based on the current heuristics." + Colors.RESET)
        print("Note: This tool is heuristic-based and should complement, not replace, a full ")
        print("      legal/privacy review.")
    print(Colors.TITLE + "=" * 80 + Colors.RESET)

    # Optional markdown export
    if args.markdown:
        md = generate_markdown_report(results)
        try:
            with open(args.markdown, "w", encoding="utf-8") as f:
                f.write(md)
            print(f"\nMarkdown report written to {args.markdown}")
        except OSError as e:
            print(f"\nERROR: Could not write markdown file {args.markdown}: {e}")


if __name__ == "__main__":
    main()
