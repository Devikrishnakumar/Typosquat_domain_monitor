"""
whois_lookup.py
Fetches domain registration info via RDAP (the modern HTTPS-based
replacement for WHOIS). Extracts registrar, creation date, abuse contacts,
and nameservers.
"""

import requests
import re


def _extract_emails_and_registrar(data):
    registrar = None
    abuse_emails = []

    def process_entity(entity):
        nonlocal registrar
        roles = entity.get("roles", [])
        vcard = entity.get("vcardArray", [])
        items = vcard[1] if len(vcard) > 1 and isinstance(vcard[1], list) else []

        if "registrar" in roles or not registrar:
            for item in items:
                if len(item) > 3 and item[0] == "fn":
                    if not registrar:
                        registrar = item[3]

        if "abuse" in roles:
            for item in items:
                if len(item) > 3 and item[0] == "email":
                    email = str(item[3]).strip()
                    if "@" in email and email not in abuse_emails:
                        abuse_emails.append(email)

        for sub_entity in entity.get("entities", []):
            process_entity(sub_entity)

    for entity in data.get("entities", []):
        process_entity(entity)

    return registrar, abuse_emails


def get_whois_info(domain, timeout=15):
    """
    Returns a dict with registrar, creation_date, abuse emails, and nameservers.
    Returns a dict with empty values if lookup fails.
    """
    # Clean domain
    domain = domain.strip().lower().lstrip("*.")
    if "/" in domain:
        domain = domain.split("/")[0]

    url = f"https://rdap.org/domain/{domain}"

    try:
        response = requests.get(
            url,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishingHunter/2.0)"},
        )
        if response.status_code != 200:
            return _empty_result()

        data = response.json()
        registrar, abuse_emails = _extract_emails_and_registrar(data)

        creation_date = None
        for event in data.get("events", []):
            action = event.get("eventAction")
            if action in ("registration", "registered", "created"):
                creation_date = event.get("eventDate")
                break

        name_servers = [
            ns.get("ldhName")
            for ns in data.get("nameservers", [])
            if ns.get("ldhName")
        ]

        # If no abuse email found, try fallback from remarks or registrar domain
        if not abuse_emails and registrar:
            match = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", str(data))
            if match and "example.com" not in match.group(0):
                abuse_emails.append(match.group(0))

        return {
            "registrar": registrar or "Unknown / Privacy Protected",
            "creation_date": creation_date,
            "emails": abuse_emails,
            "name_servers": name_servers,
        }

    except Exception as e:
        print(f"[!] RDAP lookup failed for {domain}: {e}")
        return _empty_result()


def _empty_result():
    return {
        "registrar": None,
        "creation_date": None,
        "emails": [],
        "name_servers": [],
    }


if __name__ == "__main__":
    result = get_whois_info("paypal.com")
    for key, value in result.items():
        print(f"{key}: {value}")
