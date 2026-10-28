"""
domain_investigator.py
Multi-Signal Domain Investigation Engine for Fake Website Detector (Typosquad).
Performs bounded, isolated DNS, HTTP/HTTPS, TLS Certificate, WHOIS/RDAP,
and Browser Content investigations with strict SSRF defenses.
"""

from datetime import datetime, timezone
import json
import logging
import socket
import ssl
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

import dns.resolver
import dns.exception
import requests

from src.normalization.domain_normalizer import normalize_domain
from src.enrichment.network_safety import validate_public_http_url, UnsafeTargetError, public_http_get, read_bounded_text
from src.enrichment.whois_lookup import get_whois_info
from src.enrichment.screenshot import capture_screenshot
from src.enrichment.visual_similarity import compute_similarity
from src.enrichment.content_signals import analyze_content
from src.storage import db
from src.storage.models import CertificateObservation, utc_now_iso

logger = logging.getLogger(__name__)


class DomainInvestigator:
    def __init__(self, timeout_seconds: int = 8, max_response_bytes: int = 1_048_576, allowed_hosts=()):
        self.timeout = timeout_seconds
        self.max_bytes = max_response_bytes
        self.allowed_hosts = tuple(allowed_hosts)

    def investigate_dns(self, domain: str) -> Dict[str, Any]:
        """Queries A, AAAA, CNAME, MX, and NS records with error tracking."""
        results = {
            "is_live": False,
            "status": "NXDOMAIN",
            "records": {},
            "errors": {},
            "timestamp": utc_now_iso(),
        }
        record_types = ["A", "AAAA", "CNAME", "MX", "NS"]
        resolver = dns.resolver.Resolver()
        resolver.lifetime = float(self.timeout)
        resolver.timeout = float(self.timeout)

        has_any_records = False

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                rec_values = []
                for rdata in answers:
                    if rtype == "MX":
                        rec_values.append(f"{rdata.preference} {rdata.exchange.to_text()}")
                    else:
                        rec_values.append(rdata.to_text())
                if rec_values:
                    results["records"][rtype] = rec_values
                    has_any_records = True
            except dns.resolver.NXDOMAIN:
                results["errors"][rtype] = "NXDOMAIN"
            except dns.resolver.NoAnswer:
                pass  # Record type does not exist for this domain
            except dns.resolver.Timeout:
                results["errors"][rtype] = "TIMEOUT"
            except dns.exception.DNSException as e:
                results["errors"][rtype] = str(e)
            except Exception as e:
                results["errors"][rtype] = str(e)

        if has_any_records:
            results["is_live"] = True
            results["status"] = "OK"
        elif "NXDOMAIN" in results["errors"].values():
            results["status"] = "NXDOMAIN"
        elif "TIMEOUT" in results["errors"].values():
            results["status"] = "TIMEOUT"
        else:
            # Fallback to socket gethostbyname
            try:
                ip = socket.gethostbyname(domain)
                results["records"]["A"] = [ip]
                results["is_live"] = True
                results["status"] = "OK"
            except Exception:
                results["status"] = "UNRESOLVED"

        return results

    def investigate_tls_certificate(self, domain: str, candidate_id: Optional[int] = None) -> Dict[str, Any]:
        """
        Retrieves X.509 TLS certificate directly from host on port 443.
        Does not equate valid TLS certificate with trustworthiness.
        """
        cert_data = {
            "has_tls": False,
            "subject": None,
            "issuer": None,
            "valid_from": None,
            "valid_to": None,
            "san_list": [],
            "serial_number": None,
            "fingerprint_sha256": None,
            "is_new": True,
            "error": None,
            "timestamp": utc_now_iso(),
        }

        try:
            validate_public_http_url(f"https://{domain}", allowed_hosts=self.allowed_hosts)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    from cryptography import x509
                    from cryptography.x509.oid import NameOID
                    import hashlib
                    parsed_cert = x509.load_der_x509_certificate(der_cert)
                    cert_data["has_tls"] = True
                    cert_data["fingerprint_sha256"] = hashlib.sha256(der_cert).hexdigest()
                    def name_value(name, oid):
                        values = name.get_attributes_for_oid(oid)
                        return values[0].value if values else name.rfc4514_string()
                    cert_data["subject"] = name_value(parsed_cert.subject, NameOID.COMMON_NAME)
                    cert_data["issuer"] = name_value(parsed_cert.issuer, NameOID.ORGANIZATION_NAME)
                    cert_data["valid_from"] = parsed_cert.not_valid_before_utc.isoformat()
                    cert_data["valid_to"] = parsed_cert.not_valid_after_utc.isoformat()
                    cert_data["serial_number"] = str(parsed_cert.serial_number)
                    try:
                        san = parsed_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                        cert_data["san_list"] = san.value.get_values_for_type(x509.DNSName)
                    except x509.ExtensionNotFound:
                        cert_data["san_list"] = []

            # Check if this certificate fingerprint was previously observed
            if candidate_id and cert_data.get("fingerprint_sha256"):
                session = db.SessionLocal()
                try:
                    prior = session.query(CertificateObservation).filter_by(
                        candidate_id=candidate_id,
                        fingerprint_sha256=cert_data["fingerprint_sha256"]
                    ).first()
                    if prior:
                        cert_data["is_new"] = False
                finally:
                    session.close()

        except Exception as exc:
            cert_data["error"] = str(exc)

        return cert_data

    def investigate_http(self, domain: str) -> Dict[str, Any]:
        """
        Investigates HTTP/HTTPS reachability, redirects, status code, and HTML content.
        Enforces SSRF prevention via validate_public_http_url.
        """
        http_data = {
            "reachable": False,
            "http_status": None,
            "redirect_chain": [],
            "final_url": None,
            "final_hostname": None,
            "https_available": False,
            "html_content": "",
            "page_title": "",
            "error": None,
        }

        # Try HTTPS first, then fallback to HTTP
        candidate_urls = [f"https://{domain}", f"http://{domain}"]

        for url in candidate_urls:
            try:
                # SSRF guard: ensure public IP or allowlisted simulation target
                validate_public_http_url(url, allowed_hosts=self.allowed_hosts)
            except UnsafeTargetError as e:
                http_data["error"] = f"SSRF Blocked: {e}"
                return http_data

            try:
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                }
                resp = public_http_get(
                    url,
                    allowed_hosts=self.allowed_hosts,
                    headers=headers,
                    timeout=self.timeout,
                    stream=True,
                    verify=False,
                )

                # Collect redirect chain
                redirects = [r.url for r in resp.history]
                redirects.append(resp.url)
                http_data["redirect_chain"] = redirects
                http_data["final_url"] = resp.url
                http_data["final_hostname"] = urlparse(resp.url).hostname
                http_data["http_status"] = resp.status_code
                http_data["reachable"] = True
                http_data["https_available"] = resp.url.startswith("https://")

                html_text = read_bounded_text(resp, self.max_bytes)
                http_data["html_content"] = html_text

                # Extract title
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(html_text[:100000], "html.parser")
                if soup.title and soup.title.string:
                    http_data["page_title"] = soup.title.string.strip()

                break  # Successful fetch
            except UnsafeTargetError as exc:
                http_data["error"] = f"SSRF Blocked: {exc}"
                return http_data
            except Exception as exc:
                http_data["error"] = str(exc)

        return http_data

    def run_full_investigation(
        self,
        candidate_id: int,
        domain: str,
        official_domain: str,
        reference_image_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes full multi-signal investigation and persists all observations
        to PostgreSQL/SQLite storage.
        """
        norm = normalize_domain(domain)
        clean_domain = norm.ascii_domain or domain

        # 1. DNS Investigation
        dns_res = self.investigate_dns(clean_domain)

        # 2. TLS Investigation
        tls_res = self.investigate_tls_certificate(clean_domain, candidate_id=candidate_id)

        # 3. HTTP Investigation
        http_res = self.investigate_http(clean_domain)

        # 4. Content Signals & Credential Collection Forms
        has_login_form = False
        suspicious_phrase_count = 0
        if http_res["reachable"] and http_res["html_content"]:
            try:
                content_sig = analyze_content(http_res["html_content"])
                has_login_form = content_sig.get("has_login_form", False)
                suspicious_phrase_count = content_sig.get("phrase_count", 0)
            except Exception as e:
                logger.warning(f"Error analyzing content signals: {e}")

        # 5. Visual Screenshot & Perceptual Similarity
        screenshot_path = None
        visual_similarity = 0.0
        if http_res["reachable"]:
            try:
                screenshot_path = capture_screenshot(clean_domain)
                if screenshot_path and reference_image_path:
                    visual_similarity = compute_similarity(screenshot_path, reference_image_path)
            except Exception as e:
                logger.warning(f"Error capturing screenshot: {e}")

        # 6. RDAP Registration Info
        whois_data = get_whois_info(clean_domain, timeout=5)

        # 7. Persist to Database
        is_live = dns_res["is_live"] or http_res["reachable"]
        inv_id = db.record_investigation(
            candidate_id=candidate_id,
            is_live=is_live,
            http_status=http_res["http_status"],
            redirect_chain=http_res["redirect_chain"],
            final_hostname=http_res["final_hostname"],
            https_available=http_res["https_available"] or tls_res["has_tls"],
            page_title=http_res["page_title"],
            has_credential_form=has_login_form,
            whois_info=whois_data,
            screenshot_path=screenshot_path,
            visual_similarity=visual_similarity,
            error_message=http_res.get("error") or dns_res.get("status"),
        )

        # Record DNS observations
        for rtype, rvals in dns_res["records"].items():
            db.record_dns_observation(
                candidate_id=candidate_id,
                investigation_id=inv_id,
                record_type=rtype,
                records=rvals,
                status="OK",
            )

        # Record Certificate observation if TLS was present
        if tls_res["has_tls"]:
            db.record_certificate_observation(
                candidate_id=candidate_id,
                investigation_id=inv_id,
                subject=tls_res["subject"],
                issuer=tls_res["issuer"],
                valid_from=tls_res["valid_from"],
                valid_to=tls_res["valid_to"],
                san_list=tls_res["san_list"],
                serial_number=tls_res["serial_number"],
                fingerprint_sha256=tls_res["fingerprint_sha256"],
                is_new=tls_res["is_new"],
            )

        # Update candidate summary attributes
        db.update_liveness(candidate_id, is_live)
        if screenshot_path:
            db.update_screenshot_path(candidate_id, screenshot_path)
        db.update_visual_similarity(candidate_id, visual_similarity)
        db.update_content_signals(candidate_id, has_login_form)
        db.update_evidence_details(
            candidate_id=candidate_id,
            evidence_status="complete" if is_live else "unreachable",
            suspicious_phrase_count=suspicious_phrase_count,
        )

        return {
            "investigation_id": inv_id,
            "candidate_id": candidate_id,
            "domain": clean_domain,
            "is_live": is_live,
            "dns": dns_res,
            "tls": tls_res,
            "http": http_res,
            "has_login_form": has_login_form,
            "suspicious_phrase_count": suspicious_phrase_count,
            "visual_similarity": visual_similarity,
            "screenshot_path": screenshot_path,
            "whois": whois_data,
        }
