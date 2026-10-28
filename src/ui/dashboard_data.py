"""Dashboard reads with a constant number of database round trips."""
import json
from sqlalchemy import func
from src.storage import db
from src.storage.models import Candidate, DiscoveryObservation


def get_all_flagged_with_observations():
    """Load findings and their newest evidence in one query, including empty cases."""
    with db.SessionLocal() as session:
        latest = session.query(
            DiscoveryObservation.candidate_id,
            func.max(DiscoveryObservation.id).label('observation_id'),
        ).group_by(DiscoveryObservation.candidate_id).subquery()
        rows = (
            session.query(Candidate, DiscoveryObservation.raw_data)
            .outerjoin(latest, latest.c.candidate_id == Candidate.id)
            .outerjoin(DiscoveryObservation, DiscoveryObservation.id == latest.c.observation_id)
            .order_by(Candidate.id.desc()).all()
        )
        results = []
        for candidate, raw_data in rows:
            try:
                evidence = json.loads(raw_data) if raw_data else {}
            except (ValueError, TypeError):
                evidence = {}
            results.append((candidate, evidence if isinstance(evidence, dict) else {}))
        return results
