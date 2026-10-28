"""
content_signals.py
Analyzes a page's HTML content for phishing indicators:
login forms, password fields, credential inputs, and suspicious verification language.
Fast HTTP retrieval via requests with headless browser fallback.
"""

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright
from src.enrichment.screenshot import _launch_browser
from src.enrichment.network_safety import install_public_network_guard, public_http_get, read_bounded_text

SUSPICIOUS_PHRASES = [
    "verify your account",
    "verify your identity",
    "confirm your account",
    "update your payment",
    "unusual activity",
    "suspended account",
    "click here to verify",
    "your account has been locked",
    "security notification",
    "restore access",
    "login to continue",
    "sign in to your account",
]


def fetch_page_html(domain, timeout_seconds=8):
    """Fetches rendered HTML for a domain. Tries fast HTTP first, then headless browser."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    for scheme in ["https", "http"]:
        try:
            resp = public_http_get(f"{scheme}://{domain}", headers=headers, timeout=timeout_seconds)
            if resp.status_code == 200:
                text = read_bounded_text(resp)
                if text:
                    return text
            else:
                resp.close()
        except Exception:
            continue

    # Fallback to Playwright headless browser
    try:
        with sync_playwright() as p:
            browser = _launch_browser(p)
            if not browser:
                return None
            context = browser.new_context()
            install_public_network_guard(context)
            page = context.new_page()

            for scheme in ["https", "http"]:
                try:
                    page.goto(f"{scheme}://{domain}", timeout=10000, wait_until="domcontentloaded")
                    page.wait_for_timeout(1000)
                    html = page.content()
                    browser.close()
                    return html
                except Exception:
                    continue
            browser.close()
    except Exception:
        pass

    return None


def analyze_content(html):
    """
    Returns a dict with:
      - has_login_form: bool
      - has_password_field: bool
      - suspicious_phrases_found: list of matched phrases
    """
    if not html:
        return {
            "has_login_form": False,
            "has_password_field": False,
            "suspicious_phrases_found": [],
        }

    soup = BeautifulSoup(html, "html.parser")

    password_fields = soup.find_all("input", {"type": "password"})
    has_password_field = len(password_fields) > 0

    forms = soup.find_all("form")
    # Also check inputs that look like credential forms
    inputs = soup.find_all("input")
    has_auth_inputs = any(
        inp.get("name", "").lower() in ["username", "email", "login", "user", "pass", "password"]
        for inp in inputs
    )
    has_login_form = has_password_field or (has_auth_inputs and len(forms) > 0)

    page_text = soup.get_text().lower()
    found_phrases = [phrase for phrase in SUSPICIOUS_PHRASES if phrase in page_text]

    return {
        "has_login_form": has_login_form,
        "has_password_field": has_password_field,
        "suspicious_phrases_found": found_phrases,
    }


if __name__ == "__main__":
    test_domains = ["example.com"]
    for domain in test_domains:
        html = fetch_page_html(domain)
        result = analyze_content(html)
        print(f"{domain} -> login_form: {result['has_login_form']}, phrases: {result['suspicious_phrases_found']}")
