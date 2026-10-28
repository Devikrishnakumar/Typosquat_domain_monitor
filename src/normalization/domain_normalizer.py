"""
domain_normalizer.py
Robust domain normalization, Public Suffix List parsing, IDN/punycode decoding,
and official/approved domain exclusion module for Fake Website Detector.
"""

import re
import urllib.parse
import idna
import tldextract

# RFC 1034 / 1123 label regex: alphanumeric + hyphens, cannot start or end with hyphen
LABEL_REGEX = re.compile(r"^(?!-)[a-zA-Z0-9-]{1,63}(?<!-)$")

# Cache PSL extractor to avoid reloading Public Suffix List on every call
_extract = tldextract.TLDExtract()


class DomainNormalizationResult:
    def __init__(
        self,
        original: str,
        clean_hostname: str = "",
        ascii_domain: str = "",
        unicode_domain: str = "",
        registered_domain: str = "",
        subdomain: str = "",
        tld: str = "",
        is_valid: bool = False,
        error: str = None,
    ):
        self.original = original
        self.clean_hostname = clean_hostname
        self.ascii_domain = ascii_domain
        self.unicode_domain = unicode_domain
        self.registered_domain = registered_domain
        self.subdomain = subdomain
        self.tld = tld
        self.is_valid = is_valid
        self.error = error

    def to_dict(self):
        return {
            "original": self.original,
            "clean_hostname": self.clean_hostname,
            "ascii_domain": self.ascii_domain,
            "unicode_domain": self.unicode_domain,
            "registered_domain": self.registered_domain,
            "subdomain": self.subdomain,
            "tld": self.tld,
            "is_valid": self.is_valid,
            "error": self.error,
        }


def extract_hostname(value: str) -> str:
    """
    Extracts raw hostname from a URL, email, or hostname string,
    stripping protocols, userinfo, ports, paths, and trailing dots.
    """
    if not value or not isinstance(value, str):
        return ""
    val = value.strip()

    # Handle wildcards often found in CT logs (e.g. *.example.com)
    val = re.sub(r"^\*\.", "", val)

    # If scheme is present, or if value starts with //, use urlparse
    if "://" in val:
        try:
            parsed = urllib.parse.urlsplit(val)
            val = parsed.hostname or val
        except Exception:
            pass
    elif "/" in val:
        # Split on first slash if not full scheme
        val = val.split("/")[0]

    # Strip port if present
    if ":" in val:
        val = val.split(":")[0]

    # Strip userinfo (user@domain)
    if "@" in val:
        val = val.split("@")[-1]

    # Lowercase and strip trailing dots and whitespace
    return val.strip().rstrip(".").lower()


def validate_hostname(hostname: str) -> tuple[bool, str]:
    """
    Validates RFC syntax for a normalized hostname.
    Returns (is_valid, error_reason).
    """
    if not hostname:
        return False, "Hostname cannot be empty."

    if len(hostname) > 253:
        return False, f"Hostname exceeds maximum 253 characters ({len(hostname)} chars)."

    # Must contain at least one dot unless localhost
    if "." not in hostname:
        if hostname in {"localhost"}:
            return True, ""
        return False, f"Hostname '{hostname}' must contain a domain label and top-level domain."

    labels = hostname.split(".")
    for idx, label in enumerate(labels):
        if not label:
            return False, f"Empty label in hostname '{hostname}'."
        if len(label) > 63:
            return False, f"Label '{label}' exceeds maximum 63 characters."
        # For punycode labels (xn--...), validate ASCII characters
        if not LABEL_REGEX.match(label):
            return False, f"Label '{label}' contains invalid characters or hyphens at borders."

    return True, ""


def normalize_domain(domain_or_url: str) -> DomainNormalizationResult:
    """
    Normalizes domain or URL:
    - Normalizes case and trailing dots
    - Handles IDN / Punycode (UTS46 & IDNA2008)
    - Validates syntax
    - Extracts registered domain via Public Suffix List
    """
    original = str(domain_or_url or "").strip()
    if not original:
        return DomainNormalizationResult(original=original, error="Input is empty.")

    clean_host = extract_hostname(original)
    if not clean_host:
        return DomainNormalizationResult(original=original, error="Could not extract hostname.")

    # IDN normalization
    try:
        # Unicode representation (e.g. 'xn--pypal-4ve.com' -> 'paypаl.com')
        unicode_host = idna.decode(clean_host)
        # ASCII/Punycode representation (e.g. 'paypаl.com' -> 'xn--pypal-4ve.com')
        ascii_host = idna.encode(clean_host, uts46=True, std3_rules=True).decode("ascii")
    except Exception as exc:
        # If strict idna encoding failed, try fallback
        try:
            ascii_host = clean_host.encode("idna").decode("ascii")
            unicode_host = ascii_host.encode("ascii").decode("idna")
        except Exception:
            return DomainNormalizationResult(
                original=original,
                clean_hostname=clean_host,
                error=f"Invalid IDN / Punycode domain encoding: {exc}",
            )

    is_valid, err = validate_hostname(ascii_host)
    if not is_valid:
        return DomainNormalizationResult(
            original=original,
            clean_hostname=clean_host,
            ascii_domain=ascii_host,
            unicode_domain=unicode_host,
            error=err,
        )

    # Public Suffix List extraction
    extracted = _extract(ascii_host)
    if hasattr(extracted, "top_domain_under_public_suffix") and extracted.top_domain_under_public_suffix:
        registered_domain = extracted.top_domain_under_public_suffix
    else:
        registered_domain = getattr(extracted, "domain", "") + "." + getattr(extracted, "suffix", "")
    subdomain = extracted.subdomain
    tld = extracted.suffix

    return DomainNormalizationResult(
        original=original,
        clean_hostname=clean_host,
        ascii_domain=ascii_host,
        unicode_domain=unicode_host,
        registered_domain=registered_domain or ascii_host,
        subdomain=subdomain,
        tld=tld,
        is_valid=True,
    )


def is_excluded_domain(
    candidate_domain: str,
    official_domains: list[str] = None,
    approved_domains: list[str] = None,
) -> tuple[bool, str]:
    """
    Checks if a candidate domain belongs to official domains or approved legitimate domains.
    Returns (is_excluded, reason).
    """
    norm = normalize_domain(candidate_domain)
    if not norm.is_valid:
        return False, "Invalid candidate domain"

    cand_ascii = norm.ascii_domain.lower()
    cand_reg = norm.registered_domain.lower()

    # Check official domains
    if official_domains:
        for off in official_domains:
            off_norm = normalize_domain(off)
            if not off_norm.is_valid:
                continue
            off_ascii = off_norm.ascii_domain.lower()
            off_reg = off_norm.registered_domain.lower()

            # Exact match
            if cand_ascii == off_ascii:
                return True, f"Exact match with official domain '{off_ascii}'"
            # Subdomain of official domain (e.g. login.paypal.com is official)
            if cand_ascii.endswith(f".{off_ascii}"):
                return True, f"Subdomain of official domain '{off_ascii}'"
            # Same registered domain
            if cand_reg and off_reg and cand_reg == off_reg:
                return True, f"Belongs to official registered domain '{off_reg}'"

    # Check approved domains
    if approved_domains:
        for app in approved_domains:
            app_norm = normalize_domain(app)
            if not app_norm.is_valid:
                continue
            app_ascii = app_norm.ascii_domain.lower()
            app_reg = app_norm.registered_domain.lower()

            if cand_ascii == app_ascii:
                return True, f"Exact match with approved domain '{app_ascii}'"
            if cand_ascii.endswith(f".{app_ascii}"):
                return True, f"Subdomain of approved domain '{app_ascii}'"
            if cand_reg and app_reg and cand_reg == app_reg:
                return True, f"Belongs to approved registered domain '{app_reg}'"

    return False, ""
