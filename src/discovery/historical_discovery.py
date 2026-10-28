"""
historical_discovery.py
Historical Certificate Transparency & Domain Intelligence Discovery Engine
Supports crt.sh and pluggable historical providers with rate limiting,
timeout controls, deduplication, and separate observed_at vs imported_at tracking.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import json
import logging
import time
from typing import List, Dict, Any, Optional
import requests

from src.normalization.domain_normalizer import normalize_domain, is_excluded_domain
from src.ingest.permutation_filter import build_permutation_set, is_suspicious
from src.storage.db import (
    insert_candidate,
    create_monitoring_job,
    update_monitoring_job,
    get_approved_domains,
    SessionLocal,
)
from src.storage.models import Candidate, DiscoveryObservation, utc_now_iso

logger = logging.getLogger(__name__)


class HistoricalRecord:
    def __init__(
        self,
        domain: str,
        source: str,
        observed_at: str,
        issuer: Optional[str] = None,
        cert_id: Optional[str] = None,
        raw_data: Optional[Dict[str, Any]] = None,
    ):
        self.domain = domain
        self.source = source
        self.observed_at = observed_at
        self.issuer = issuer
        self.cert_id = cert_id
        self.raw_data = raw_data or {}


class BaseHistoricalProvider(ABC):
    @abstractmethod
    def search(self, query: str, limit: int = 100) -> List[HistoricalRecord]:
        """Search historical domain records for query string."""
        pass

    @property
    @abstractmethod
    def source_name(self) -> str:
        pass

    @property
    @abstractmethod
    def limitations(self) -> str:
        pass


class CrtShProvider(BaseHistoricalProvider):
    """
    Historical Certificate Transparency provider using crt.sh JSON endpoint.
    Includes timeout handling, retry logic, and result bounds.
    """
    BASE_URL = "https://crt.sh/"

    def __init__(self, timeout_seconds: int = 15, max_retries: int = 2):
        self.timeout = timeout_seconds
        self.max_retries = max_retries

    @property
    def source_name(self) -> str:
        return "crt.sh"

    @property
    def limitations(self) -> str:
        return (
            "crt.sh queries public Certificate Transparency logs. It does not reflect "
            "active domain registration or current web hosting, only historical TLS issuance. "
            "Public crt.sh server can occasionally experience high load or rate limits."
        )

    def search(self, query: str, limit: int = 100) -> List[HistoricalRecord]:
        params = {"q": query, "output": "json"}
        headers = {"User-Agent": "Fake-Website-Detector-ThreatIntel/1.0"}

        records = []
        seen_domains = set()

        for attempt in range(1, self.max_retries + 2):
            try:
                resp = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=self.timeout,
                )
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except json.JSONDecodeError:
                        logger.warning(f"crt.sh response was not valid JSON for query '{query}'")
                        return []

                    if not isinstance(data, list):
                        return []

                    for item in data:
                        name_val = item.get("name_value", "")
                        # name_value can be multi-line for multiple SANs
                        sub_names = name_val.split("\n") if name_val else []
                        for raw_name in sub_names:
                            norm = normalize_domain(raw_name)
                            if not norm.is_valid:
                                continue
                            dom = norm.ascii_domain.lower()
                            if dom in seen_domains:
                                continue
                            seen_domains.add(dom)

                            # Parse observed timestamp from entry_timestamp or not_before
                            entry_time = item.get("entry_timestamp") or item.get("not_before")
                            if entry_time:
                                obs_time = str(entry_time)
                            else:
                                obs_time = utc_now_iso()

                            record = HistoricalRecord(
                                domain=dom,
                                source=self.source_name,
                                observed_at=obs_time,
                                issuer=item.get("issuer_name"),
                                cert_id=str(item.get("id") or ""),
                                raw_data=item,
                            )
                            records.append(record)
                            if len(records) >= limit:
                                break
                        if len(records) >= limit:
                            break
                    return records

                elif resp.status_code == 429:
                    logger.warning(f"crt.sh rate limit (429) hit on query '{query}', attempt {attempt}")
                    time.sleep(2 * attempt)
                else:
                    logger.warning(f"crt.sh returned status {resp.status_code} for query '{query}'")
                    time.sleep(1)

            except (requests.RequestException, Exception) as exc:
                logger.warning(f"crt.sh request attempt {attempt} error: {exc}")
                if attempt <= self.max_retries:
                    time.sleep(1.5 * attempt)

        return records


class MockHistoricalProvider(BaseHistoricalProvider):
    """Predictable mock provider for unit tests, offline development, and verification."""
    def __init__(self, sample_records: Optional[List[Dict[str, Any]]] = None):
        self.sample_records = sample_records or []

    @property
    def source_name(self) -> str:
        return "mock_ct"

    @property
    def limitations(self) -> str:
        return "Offline mock data source for testing and local development."

    def search(self, query: str, limit: int = 100) -> List[HistoricalRecord]:
        results = []
        for r in self.sample_records:
            results.append(
                HistoricalRecord(
                    domain=r.get("domain", ""),
                    source=self.source_name,
                    observed_at=r.get("observed_at", "2025-01-15T10:00:00Z"),
                    issuer=r.get("issuer", "Let's Encrypt"),
                    cert_id=r.get("cert_id", "12345"),
                    raw_data=r,
                )
            )
            if len(results) >= limit:
                break
        return results


class HistoricalDiscoveryEngine:
    def __init__(self, provider: Optional[BaseHistoricalProvider] = None):
        self.provider = provider or CrtShProvider()

    def run_brand_discovery(
        self,
        brand_name: str,
        official_domain: str,
        brand_id: Optional[int] = None,
        organization_id: Optional[int] = None,
        max_results: int = 50,
        approved_domains: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Discovers historical lookalike and certificate domains for a brand:
        1. Queries historical Certificate Transparency source.
        2. Filters out official and approved domains.
        3. Matches against permutations or brand keywords.
        4. Saves candidates and observations with separate observed_at and imported_at timestamps.
        5. Preserves duplicates safely without re-inserting or losing historical data.
        """
        job_id = create_monitoring_job(job_type="historical_discovery", brand_id=brand_id)
        imported_at = utc_now_iso()
        discovered_candidates = []
        skipped_official = []
        duplicates_updated = []
        errors = []

        try:
            # Generate search query: e.g. %paypal%
            query_term = official_domain.split(".")[0]
            search_query = f"%{query_term}%"

            # Fetch records from provider
            raw_records = self.provider.search(search_query, limit=max_results)

            # Get approved domains if not provided
            if approved_domains is None and brand_id:
                appr_list = get_approved_domains(brand_id)
                approved_domains = [a["domain"] for a in appr_list]
            approved_domains = approved_domains or []

            # Generate permutation set for strict homoglyph/typosquat matching
            try:
                permutation_set = build_permutation_set(official_domain)
                perm_bases = {p.split(".")[0] for p in permutation_set if len(p.split(".")[0]) >= 4}
            except Exception as e:
                logger.warning(f"Error generating permutations: {e}")
                permutation_set = set()
                perm_bases = set()

            for record in raw_records:
                dom = record.domain.lower()

                # Normalization
                norm = normalize_domain(dom)
                if not norm.is_valid:
                    continue

                # Exclude official brand domains and approved domains
                is_excl, reason = is_excluded_domain(
                    dom,
                    official_domains=[official_domain],
                    approved_domains=approved_domains,
                )
                if is_excl:
                    skipped_official.append({"domain": dom, "reason": reason})
                    continue

                # Check relevance: is it in permutation set OR does it contain the brand slug OR permutation base
                dom_base = dom.split(".")[0]
                is_match = (
                    dom in permutation_set or
                    query_term in dom or
                    any(pb in dom for pb in perm_bases) or
                    is_suspicious(dom, permutation_set, official_domain)
                )

                if not is_match:
                    continue

                # Insert candidate with event_category="historical"
                cand_id = insert_candidate(
                    domain=dom,
                    matched_brand=official_domain,
                    decoded_domain=norm.unicode_domain,
                    organization_id=organization_id,
                    brand_id=brand_id,
                    event_category="historical",
                    source=self.provider.source_name,
                    observed_at=record.observed_at,
                    imported_at=imported_at,
                )

                discovered_candidates.append({
                    "id": cand_id,
                    "domain": dom,
                    "decoded_domain": norm.unicode_domain,
                    "observed_at": record.observed_at,
                    "imported_at": imported_at,
                    "source": self.provider.source_name,
                })

            update_monitoring_job(
                job_id=job_id,
                status="completed",
                items_found=len(raw_records),
                items_processed=len(discovered_candidates),
            )

            return {
                "job_id": job_id,
                "status": "completed",
                "source": self.provider.source_name,
                "limitations": self.provider.limitations,
                "brand": official_domain,
                "total_queried": len(raw_records),
                "discovered_count": len(discovered_candidates),
                "discovered_candidates": discovered_candidates,
                "skipped_official_count": len(skipped_official),
                "imported_at": imported_at,
            }

        except Exception as exc:
            err_msg = str(exc)
            logger.error(f"Historical discovery job failed: {err_msg}", exc_info=True)
            update_monitoring_job(
                job_id=job_id,
                status="failed",
                error_message=err_msg,
            )
            return {
                "job_id": job_id,
                "status": "failed",
                "error": err_msg,
                "source": self.provider.source_name,
            }
