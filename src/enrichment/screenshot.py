"""
screenshot.py
Captures a screenshot of a live domain using Playwright headless Chromium
with automated fallback across system Google Chrome, Microsoft Edge, and Playwright Chromium.
Also handles automatically capturing/refreshing the brand's reference screenshot.
"""

import os
import hashlib
import re
import time
from pathlib import Path
from playwright.sync_api import sync_playwright
from src.enrichment.network_safety import install_public_network_guard

SCREENSHOT_DIR = "data/screenshots"


def _launch_browser(p):
    """
    Attempt launching available Chromium browser:
    1. System Google Chrome (installed on Windows)
    2. System Microsoft Edge (installed on Windows)
    3. Playwright bundled Chromium
    """
    for channel in ["chrome", "msedge", None]:
        try:
            if channel:
                return p.chromium.launch(channel=channel, headless=True)
            else:
                return p.chromium.launch(headless=True)
        except Exception:
            continue
    return None


def capture_screenshot(domain, timeout_ms=30000, retries=2):
    os.makedirs(SCREENSHOT_DIR, exist_ok=True)
    safe_filename = re.sub(r"[^A-Za-z0-9_-]+", "_", domain)
    safe_filename = (
        f"{safe_filename}_{hashlib.sha256(domain.encode('utf-8')).hexdigest()[:10]}"
    )
    output_path = os.path.join(SCREENSHOT_DIR, f"{safe_filename}.png")

    urls_to_try = [f"https://{domain}", f"http://{domain}"]

    try:
        with sync_playwright() as p:
            browser = _launch_browser(p)
            if not browser:
                print(f"[!] No suitable Playwright browser found for {domain}")
                return None
            context = browser.new_context(viewport={"width": 1280, "height": 800})
            install_public_network_guard(context)
            page = context.new_page()

            for attempt in range(1, retries + 2):
                for url in urls_to_try:
                    try:
                        page.goto(url, timeout=timeout_ms, wait_until="domcontentloaded")
                        page.wait_for_timeout(2000)
                        page.screenshot(path=output_path)
                        browser.close()
                        return output_path
                    except Exception:
                        continue
                if attempt < retries + 1:
                    time.sleep(2)

            browser.close()
            return None
    except Exception as exc:
        print(f"[!] Screenshot error for {domain}: {exc}")
        return None


def ensure_reference_screenshot(official_domain):
    """Capture or reuse a reference image stored separately for each brand."""
    safe_domain = re.sub(r"[^A-Za-z0-9_-]+", "_", official_domain)
    digest = hashlib.sha256(official_domain.encode("utf-8")).hexdigest()[:10]
    reference_dir = Path("reference_assets") / "brands"
    reference_dir.mkdir(parents=True, exist_ok=True)
    reference_path = reference_dir / f"{safe_domain}_{digest}.png"
    metadata_path = reference_dir / f"{safe_domain}_{digest}.txt"

    existing_brand = None
    if metadata_path.exists():
        with metadata_path.open("r", encoding="utf-8-sig") as f:
            existing_brand = f.read().strip()

    if reference_path.exists() and existing_brand == official_domain:
        print(f"Using existing reference screenshot for {official_domain}")
        return str(reference_path)

    print(f"Capturing new reference screenshot for {official_domain} (brand changed or reference missing)...")
    captured_path = capture_screenshot(official_domain)

    if captured_path:
        import shutil
        shutil.copy(captured_path, reference_path)
        with metadata_path.open("w", encoding="utf-8") as f:
            f.write(official_domain)
        print(f"Reference screenshot saved for {official_domain}: {reference_path}")
        return str(reference_path)
    else:
        print(f"WARNING: Could not capture reference screenshot for {official_domain}.")
        return None


if __name__ == "__main__":
    test_domains = ["example.com", "google.com"]

    for domain in test_domains:
        result = capture_screenshot(domain)
        if result:
            print(f"{domain:40s} -> saved to {result}")
        else:
            print(f"{domain:40s} -> FAILED (no screenshot)")
