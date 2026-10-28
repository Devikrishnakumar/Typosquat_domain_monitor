"""
permutation_filter.py
Generates typosquat/homoglyph permutations for a target brand using dnstwist,
and checks whether an incoming domain matches any of them.
"""

import argparse
import yaml
import dnstwist
import idna


def load_brand_config(config_path="config/brand_config.yaml"):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def get_brand_settings(cli_brand=None, config_path="config/brand_config.yaml"):
    if cli_brand:
        return _validate_domain(cli_brand)
    return get_monitored_brands(config_path)[0]["official_domain"]


def _validate_domain(domain):
    domain = str(domain or "").strip().lower().rstrip(".")
    if not domain or "://" in domain or "/" in domain or ":" in domain:
        raise ValueError(f"Invalid brand domain: {domain!r}")
    try:
        ascii_domain = idna.encode(
            domain,
            uts46=True,
            std3_rules=True,
        ).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError(f"Invalid brand domain: {domain!r}") from exc
    if "." not in ascii_domain or len(ascii_domain) > 253:
        raise ValueError(f"Invalid brand domain: {domain!r}")
    return ascii_domain


def get_monitored_brands(config_path="config/brand_config.yaml"):
    """Load a brand list, while retaining support for the original single-brand file."""
    config = load_brand_config(config_path) or {}
    configured = config.get("brands")
    if configured is None:
        configured = [{
            "name": config.get("brand_name"),
            "official_domain": config.get("official_domain"),
        }]
    if not isinstance(configured, list) or not configured:
        raise ValueError("Brand configuration must contain a non-empty brands list.")

    brands = []
    seen_domains = set()
    for entry in configured:
        if not isinstance(entry, dict):
            raise ValueError("Each brand entry must be a mapping.")
        domain = _validate_domain(entry.get("official_domain") or entry.get("domain"))
        if domain in seen_domains:
            raise ValueError(f"Brand domain is configured more than once: {domain}")
        seen_domains.add(domain)
        brands.append({
            "name": str(entry.get("name") or entry.get("brand_name") or domain),
            "official_domain": domain,
        })
    return brands


def build_permutation_set(official_domain):
    fuzzer = dnstwist.Fuzzer(official_domain)
    fuzzer.generate()

    permutations = set()
    for entry in fuzzer.permutations():
        permutations.add(entry["domain"].lower())

    return permutations


def is_suspicious(domain, permutation_set, official_domain=None):
    domain = domain.lower().lstrip("*.")
    if official_domain and domain == official_domain.lower():
        return False  # never flag the brand's own real domain
    return domain in permutation_set


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--brand", help="Override brand domain, e.g. flipkart.com")
    args = parser.parse_args()

    official_domain = get_brand_settings(cli_brand=args.brand)
    perms = build_permutation_set(official_domain)

    print(f"Brand: {official_domain}")
    print(f"Generated {len(perms)} permutations. Sample:")
    for p in list(perms)[:15]:
        print(f"  {p}")
