import pytest
from sqlalchemy import text

from src.storage import db


@pytest.fixture
def sqlite_database():
    original_url = db.DATABASE_URL
    db.configure_database("sqlite://")
    db.init_db()
    yield
    db.Base.metadata.drop_all(db.engine)
    db.configure_database(original_url)


def test_candidate_insert_deduplicates_and_tracks_observations(sqlite_database):
    first_id = db.insert_candidate("paypa1.example", "paypal.example")
    second_id = db.insert_candidate("paypa1.example", "paypal.example")

    assert first_id == second_id
    candidate = db.get_all_candidates()[0]
    assert candidate["seen_count"] == 2
    assert candidate["last_seen_at"]


def test_review_updates_status_and_notes(sqlite_database):
    candidate_id = db.insert_candidate("paypa1.example", "paypal.example")

    db.update_candidate_review(
        candidate_id,
        "under_investigation",
        "Analyst confirmed this needs follow-up.",
    )

    candidate = db.get_all_candidates()[0]
    assert candidate["status"] == "under_investigation"
    assert candidate["analyst_notes"] == "Analyst confirmed this needs follow-up."


def test_review_rejects_unknown_status(sqlite_database):
    candidate_id = db.insert_candidate("paypa1.example", "paypal.example")

    with pytest.raises(ValueError, match="Unsupported candidate status"):
        db.update_candidate_review(candidate_id, "auto_takedown", "")


def test_evidence_breakdown_is_saved(sqlite_database):
    candidate_id = db.insert_candidate("paypa1.example", "paypal.example")

    db.update_evidence_details(
        candidate_id,
        "complete",
        suspicious_phrase_count=2,
        risk_breakdown={"is_live": 25, "has_login_form": 25},
    )

    candidate = db.get_all_candidates()[0]
    assert candidate["evidence_status"] == "complete"
    assert candidate["suspicious_phrase_count"] == 2
    assert candidate["risk_breakdown"] == '{"has_login_form": 25, "is_live": 25}'


def test_init_db_adds_new_fields_to_existing_mvp_schema():
    original_url = db.DATABASE_URL
    db.configure_database("sqlite://")
    try:
        with db.engine.begin() as connection:
            connection.execute(text(
                "CREATE TABLE candidates ("
                "id INTEGER PRIMARY KEY, domain VARCHAR NOT NULL, "
                "decoded_domain VARCHAR, matched_brand VARCHAR NOT NULL, "
                "detected_at VARCHAR NOT NULL, is_live INTEGER, "
                "visual_similarity FLOAT, has_login_form INTEGER, "
                "risk_score FLOAT, risk_level VARCHAR, screenshot_path TEXT, "
                "status VARCHAR)"
            ))

        db.init_db()
        names = {
            column["name"]
            for column in db.inspect(db.engine).get_columns("candidates")
        }
        assert {"analyst_notes", "evidence_status", "risk_breakdown"} <= names
    finally:
        db.configure_database(original_url)
