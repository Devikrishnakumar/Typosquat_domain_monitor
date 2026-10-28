"""
domain_scanner.py
Core On-Demand Domain Scanner Engine.
Scans for brand lookalike / typosquat domains using dnstwist permutations,
cross-checks against public Certificate Transparency logs (crt.sh),
performs live multi-signal investigation (DNS, HTTP reachability, Playwright screenshot,
Pillow + ImageHash perceptual hash similarity, WHOIS/RDAP), and persists scored findings to SQLite.
"""

import os
import sys
import json
import socket
import logging
import concurrent.futures
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Callable
import requests
import dnstwist
import dns.resolver

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from src.storage import db
from src.storage.models import Candidate, Brand, DiscoveryObservation, utc_now_iso
from src.enrichment.screenshot import capture_screenshot, ensure_reference_screenshot
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.whois_lookup import get_whois_info
from src.enrichment.content_signals import fetch_page_html, analyze_content
from src.scoring.risk_score import compute_risk_score, risk_level
from src.alerts.telegram_bot import send_alert

logger = logging.getLogger("domain_scanner")
logging.basicConfig(level=logging.INFO)


def _resolve_dns(domain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Fast DNS resolution for A, MX, NS records."""
    res = {"is_live": False, "ip": None, "records": {"A": [], "MX": [], "NS": []}}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = timeout

    try:
        answers = resolver.resolve(domain, "A")
        ips = [rdata.to_text() for rdata in answers]
        if ips:
            res["records"]["A"] = ips
            res["ip"] = ips[0]
            res["is_live"] = True
    except Exception:
        # Fallback to standard socket
        try:
            ip = socket.gethostbyname(domain)
            res["records"]["A"] = [ip]
            res["ip"] = ip
            res["is_live"] = True
        except Exception:
            pass

    try:
        answers = resolver.resolve(domain, "MX")
        res["records"]["MX"] = [f"{r.preference} {r.exchange.to_text()}" for r in answers]
    except Exception:
        pass

    try:
        answers = resolver.resolve(domain, "NS")
        res["records"]["NS"] = [r.to_text() for r in answers]
    except Exception:
        pass

    return res


def _fetch_crtsh_domains(query: str, timeout: int = 6, limit: int = 25) -> List[Dict[str, Any]]:
    """Queries crt.sh Certificate Transparency logs with strict timeout & graceful fallback."""
    url = "https://crt.sh/"
    params = {"q": f"%{query}%", "output": "json"}
    headers = {"User-Agent": "PhishingDetector/2.0"}

    try:
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            found = []
            seen = set()
            for item in data:
                name_value = item.get("name_value", "")
                for raw_d in name_value.split("\n"):
                    clean = raw_d.strip().lower().lstrip("*.")
                    if clean and clean not in seen and "." in clean:
                        seen.add(clean)
                        found.append({
                            "domain": clean,
                            "source": "CRTSH_LOGS",
                            "fuzzer": "certificate_transparency",
                            "cert_id": str(item.get("id")),
                            "issuer": str(item.get("issuer_name", "")),
                        })
                        if len(found) >= limit:
                            return found
            return found
    except Exception as exc:
        logger.warning(f"crt.sh query timed out or unavailable: {exc}")
    return []


class DomainScanner:
    def __init__(self):
        db.init_db()

    def scan_brand(
        self,
        brand_domain: str,
        brand_name: Optional[str] = None,
        max_permutations: int = 35,
        include_crtsh: bool = True,
        take_screenshots: bool = True,
        progress_callback: Optional[Callable[[str, float], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs an on-demand scan for a brand domain:
        1. Ensures brand reference screenshot exists.
        2. Generates dnstwist typosquat permutations.
        3. Cross-checks Certificate Transparency logs (crt.sh).
        4. Performs fast DNS resolution in parallel.
        5. Deep-inspects live domains (HTTP, login forms, screenshot, visual similarity, WHOIS).
        6. Scores risk, records in SQLite, and alerts on HIGH risk.
        """
        brand_domain = brand_domain.strip().lower().rstrip(".")
        if "://" in brand_domain:
            brand_domain = brand_domain.split("://")[-1].split("/")[0]

        if not brand_name:
            brand_name = brand_domain.split(".")[0].capitalize()

        if progress_callback:
            progress_callback(f"Initializing scan for {brand_name} ({brand_domain})...", 0.05)

        # Ensure Brand in SQLite
        session = db.SessionLocal()
        brand_obj = session.query(Brand).filter_by(official_domain=brand_domain).first()
        if not brand_obj:
            brand_obj = Brand(
                organization_id=1,
                name=brand_name,
                official_domain=brand_domain,
                official_website_url=f"https://{brand_domain}",
                keywords=json.dumps([brand_name.lower(), brand_domain.split(".")[0]]),
            )
            session.add(brand_obj)
            session.commit()
            session.refresh(brand_obj)
        brand_id = brand_obj.id
        session.close()

        # Reference screenshot for visual comparison
        if progress_callback:
            progress_callback(f"Checking reference screenshot for {brand_domain}...", 0.10)
        reference_img = ensure_reference_screenshot(brand_domain)

        # 1. Generate dnstwist permutations
        if progress_callback:
            progress_callback("Generating dnstwist typosquatting variations...", 0.20)

        candidates_map = {}
        try:
            fuzzer = dnstwist.Fuzzer(brand_domain)
            fuzzer.generate()
            for p in fuzzer.permutations():
                d = p.get("domain", "").lower()
                if d and d != brand_domain and d not in candidates_map:
                    candidates_map[d] = {
                        "domain": d,
                        "source": "DNSTWIST",
                        "fuzzer": p.get("fuzzer", "typosquat"),
                    }
                    if len(candidates_map) >= max_permutations:
                        break
        except Exception as e:
            logger.error(f"Error generating dnstwist permutations: {e}")

        # 2. Query crt.sh CT logs
        if include_crtsh:
            if progress_callback:
                progress_callback("Cross-checking Certificate Transparency (crt.sh)...", 0.35)
            query_slug = brand_domain.split(".")[0]
            crtsh_records = _fetch_crtsh_domains(query_slug, timeout=6, limit=15)
            for rec in crtsh_records:
                d = rec["domain"]
                if d != brand_domain and d not in candidates_map:
                    candidates_map[d] = rec

        target_domains = list(candidates_map.values())
        if progress_callback:
            progress_callback(f"Testing DNS liveness for {len(target_domains)} candidates...", 0.45)

        # 3. Parallel DNS resolution
        dns_results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            future_to_dom = {
                executor.submit(_resolve_dns, item["domain"]): item["domain"]
                for item in target_domains
            }
            for future in concurrent.futures.as_completed(future_to_dom):
                dom = future_to_dom[future]
                try:
                    dns_results[dom] = future.result()
                except Exception:
                    dns_results[dom] = {"is_live": False, "ip": None, "records": {"A": [], "MX": [], "NS": []}}

        # Sort: live resolving domains first
        live_domains = [item for item in target_domains if dns_results.get(item["domain"], {}).get("is_live")]
        inactive_domains = [item for item in target_domains if not dns_results.get(item["domain"], {}).get("is_live")]
        sorted_targets = live_domains + inactive_domains[:10]  # inspect live + sample of inactive

        total_to_inspect = len(sorted_targets)
        inspected_results = []

        # 4. Deep Inspection of candidates
        for idx, item in enumerate(sorted_targets):
            domain = item["domain"]
            src = item.get("source", "DNSTWIST")
            fuzzer_type = item.get("fuzzer", "permutation")
            dns_info = dns_results.get(domain, {"is_live": False, "ip": None, "records": {}})
            is_live = 1 if dns_info["is_live"] else 0

            pct = 0.50 + (0.45 * (idx / max(1, total_to_inspect)))
            if progress_callback:
                progress_callback(f"Investigating {domain} ({idx+1}/{total_to_inspect})...", pct)

            screenshot_path = None
            visual_sim = None
            has_login = False
            phrases_found = []
            whois_info = {"registrar": "Not queried", "creation_date": None, "emails": []}

            # Only run heavy HTTP/Playwright/RDAP on live domains
            if is_live:
                # Content signals (forms, login inputs)
                try:
                    html = fetch_page_html(domain, timeout_seconds=5)
                    if html:
                        content_signals = analyze_content(html)
                        has_login = content_signals.get("has_login_form", False)
                        phrases_found = content_signals.get("suspicious_phrases_found", [])
                except Exception as e:
                    logger.debug(f"Content analysis error on {domain}: {e}")

                # Screenshot & Visual similarity
                if take_screenshots:
                    try:
                        screenshot_path = capture_screenshot(domain, timeout_ms=12000, retries=1)
                        if screenshot_path and reference_img and os.path.exists(reference_img):
                            visual_sim = compute_similarity(screenshot_path, reference_img)
                    except Exception as e:
                        logger.debug(f"Screenshot error on {domain}: {e}")

                # WHOIS / RDAP lookup
                try:
                    whois_info = get_whois_info(domain, timeout=8)
                except Exception as e:
                    logger.debug(f"WHOIS lookup error on {domain}: {e}")

            # Compute risk score
            score, breakdown = compute_risk_score(
                is_live=bool(is_live),
                visual_similarity=visual_sim,
                has_login_form=has_login,
                suspicious_phrase_count=len(phrases_found),
            )

            # Adjustments for mail servers and homoglyphs
            mx_records = dns_info.get("records", {}).get("MX", [])
            if mx_records and is_live:
                score = min(100.0, score + 10.0)
                breakdown["active_mail_server"] = 10.0

            if fuzzer_type in ["homoglyph", "subdomain"] and is_live:
                score = min(100.0, score + 10.0)
                breakdown["homoglyph_deception"] = 10.0

            level = risk_level(score)

            # Build recommended action
            if level == "HIGH":
                rec_action = f"URGENT: Initiate takedown notice with {whois_info.get('registrar', 'Registrar')} abuse team. Block domain on email/DNS firewalls."
            elif level == "MEDIUM":
                rec_action = "MONITOR: Lookalike domain is actively registered. Track web content updates or DNS changes."
            else:
                rec_action = "LOW RISK: Inactive or benign permutation. No immediate remediation needed."

            now = utc_now_iso()

            # Save to SQLite
            session = db.SessionLocal()
            try:
                cand = session.query(Candidate).filter_by(domain=domain, matched_brand=brand_domain).first()
                if not cand:
                    cand = Candidate(
                        domain=domain,
                        matched_brand=brand_domain,
                        brand_id=brand_id,
                        detected_at=now,
                        first_seen_at=now,
                        last_seen_at=now,
                        discovered_at=now,
                        imported_at=now,
                        event_category="on_demand_scan",
                    )
                    session.add(cand)

                cand.is_live = is_live
                cand.visual_similarity = visual_sim
                cand.has_login_form = 1 if has_login else 0
                cand.suspicious_phrase_count = len(phrases_found)
                cand.risk_score = score
                cand.risk_level = level
                cand.screenshot_path = screenshot_path
                cand.status = "new"
                cand.evidence_status = "complete" if is_live else "dns_only"
                cand.confidence_level = level
                cand.recommended_action = rec_action
                cand.risk_breakdown = json.dumps(breakdown)
                cand.registered_domain = whois_info.get("registrar")
                cand.registered_at = whois_info.get("creation_date")

                session.commit()
                session.refresh(cand)

                # Add discovery observation
                obs = DiscoveryObservation(
                    candidate_id=cand.id,
                    source=src,
                    observed_at=now,
                    imported_at=now,
                    raw_data=json.dumps({
                        "domain": domain,
                        "matched_brand": brand_domain,
                        "fuzzer": fuzzer_type,
                        "dns": dns_info,
                        "whois": whois_info,
                        "phrases": phrases_found,
                    }),
                )
                session.add(obs)
                session.commit()

                # Dispatch Telegram alert if HIGH risk
                if level == "HIGH":
                    try:
                        send_alert(
                            domain=domain,
                            risk_score=score,
                            risk_level=level,
                            matched_brand=brand_domain,
                            source="LIVE_SCAN",
                            risk_reason=f"Active lookalike with score {score}/100. Discovered via {src}.",
                        )
                    except Exception as te:
                        logger.warning(f"Telegram alert delivery notice: {te}")

                inspected_results.append({
                    "id": cand.id,
                    "domain": domain,
                    "matched_brand": brand_domain,
                    "source": src,
                    "permutation_type": fuzzer_type,
                    "is_live": is_live,
                    "ip": dns_info.get("ip"),
                    "risk_score": score,
                    "risk_level": level,
                    "visual_similarity": visual_sim,
                    "has_login_form": has_login,
                    "whois": whois_info,
                    "dns": dns_info,
                    "screenshot_path": screenshot_path,
                    "recommended_action": rec_action,
                })
            finally:
                session.close()

        if progress_callback:
            progress_callback(f"Scan complete! Analyzed {len(inspected_results)} domains.", 1.0)

        # Return sorted by risk score descending
        inspected_results.sort(key=lambda x: x["risk_score"], reverse=True)
        return inspected_results


if __name__ == "__main__":
    scanner = DomainScanner()
    print("Testing scanner on paypal.com with max 10 permutations...")
    results = scanner.scan_brand("paypal.com", max_permutations=10, include_crtsh=False, take_screenshots=False)
    for r in results:
        print(f"[{r['risk_level']}] {r['domain']:30s} Score: {r['risk_score']} Live: {r['is_live']}")
