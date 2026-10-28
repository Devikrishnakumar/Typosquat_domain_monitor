"""initial_enterprise_schema

Revision ID: 001_initial_enterprise_schema
Revises: 
Create Date: 2026-10-27 15:06:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '001_initial_enterprise_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Organizations
    op.create_table(
        'organizations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=100), nullable=False),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug')
    )
    op.create_index(op.f('ix_organizations_slug'), 'organizations', ['slug'], unique=True)

    # 2. Users
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('hashed_password', sa.String(length=255), nullable=False),
        sa.Column('full_name', sa.String(length=255), nullable=True),
        sa.Column('role', sa.String(length=50), nullable=False, server_default='analyst'),
        sa.Column('is_active', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email')
    )
    op.create_index(op.f('ix_users_email'), 'users', ['email'], unique=True)
    op.create_index(op.f('ix_users_organization_id'), 'users', ['organization_id'], unique=False)

    # 3. Brands
    op.create_table(
        'brands',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('official_domain', sa.String(length=255), nullable=False),
        sa.Column('official_website_url', sa.String(length=512), nullable=True),
        sa.Column('keywords', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('monitoring_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('check_interval_minutes', sa.Integer(), nullable=False, server_default='5'),
        sa.Column('alert_threshold', sa.Integer(), nullable=False, server_default='70'),
        sa.Column('telegram_alerts_enabled', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('email_alerts_enabled', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('email_recipients', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.Column('updated_at', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'official_domain', name='uq_org_brand_domain')
    )
    op.create_index(op.f('ix_brands_official_domain'), 'brands', ['official_domain'], unique=False)
    op.create_index(op.f('ix_brands_organization_id'), 'brands', ['organization_id'], unique=False)

    # 4. Approved Domains
    op.create_table(
        'approved_domains',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('brand_id', sa.Integer(), nullable=False),
        sa.Column('domain', sa.String(length=255), nullable=False),
        sa.Column('notes', sa.String(length=512), nullable=True),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['brand_id'], ['brands.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('brand_id', 'domain', name='uq_brand_approved_domain')
    )
    op.create_index(op.f('ix_approved_domains_brand_id'), 'approved_domains', ['brand_id'], unique=False)

    # 5. Candidates
    op.create_table(
        'candidates',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('domain', sa.String(), nullable=False),
        sa.Column('decoded_domain', sa.String(), nullable=True),
        sa.Column('matched_brand', sa.String(), nullable=False),
        sa.Column('detected_at', sa.String(), nullable=False),
        sa.Column('is_live', sa.Integer(), nullable=True),
        sa.Column('visual_similarity', sa.Float(), nullable=True),
        sa.Column('has_login_form', sa.Integer(), nullable=True),
        sa.Column('risk_score', sa.Float(), nullable=True),
        sa.Column('risk_level', sa.String(), nullable=True),
        sa.Column('screenshot_path', sa.Text(), nullable=True),
        sa.Column('status', sa.String(), nullable=False, server_default='new'),
        sa.Column('analyst_notes', sa.Text(), nullable=False, server_default=''),
        sa.Column('evidence_status', sa.String(), nullable=False, server_default='pending'),
        sa.Column('risk_breakdown', sa.Text(), nullable=True),
        sa.Column('suspicious_phrase_count', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('last_seen_at', sa.String(), nullable=True),
        sa.Column('seen_count', sa.Integer(), nullable=False, server_default='1'),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('brand_id', sa.Integer(), nullable=True),
        sa.Column('registered_domain', sa.String(), nullable=True),
        sa.Column('tld', sa.String(), nullable=True),
        sa.Column('event_category', sa.String(), nullable=False, server_default='newly_observed'),
        sa.Column('confidence_level', sa.String(), nullable=True, server_default='MEDIUM'),
        sa.Column('recommended_action', sa.Text(), nullable=True),
        sa.Column('first_seen_at', sa.String(), nullable=True),
        sa.Column('discovered_at', sa.String(), nullable=True),
        sa.Column('imported_at', sa.String(), nullable=True),
        sa.Column('certificate_issued_at', sa.String(), nullable=True),
        sa.Column('registered_at', sa.String(), nullable=True),
        sa.Column('last_investigated_at', sa.String(), nullable=True),
        sa.Column('last_alerted_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['brand_id'], ['brands.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_candidates_domain'), 'candidates', ['domain'], unique=False)
    op.create_index(op.f('ix_candidates_matched_brand'), 'candidates', ['matched_brand'], unique=False)
    op.create_index(op.f('ix_candidates_risk_score'), 'candidates', ['risk_score'], unique=False)
    op.create_index(op.f('ix_candidates_status'), 'candidates', ['status'], unique=False)

    # 6. Discovery Observations
    op.create_table(
        'discovery_observations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('source', sa.String(length=50), nullable=False),
        sa.Column('observed_at', sa.String(), nullable=False),
        sa.Column('imported_at', sa.String(), nullable=False),
        sa.Column('raw_data', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_discovery_observations_candidate_id'), 'discovery_observations', ['candidate_id'], unique=False)

    # 7. Domain Investigations
    op.create_table(
        'domain_investigations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('investigated_at', sa.String(), nullable=False),
        sa.Column('is_live', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('http_status', sa.Integer(), nullable=True),
        sa.Column('redirect_chain', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('final_hostname', sa.String(length=255), nullable=True),
        sa.Column('https_available', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('page_title', sa.Text(), nullable=True),
        sa.Column('has_credential_form', sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column('suspicious_keywords_found', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('whois_registrar', sa.String(length=255), nullable=True),
        sa.Column('whois_created_date', sa.String(), nullable=True),
        sa.Column('whois_expires_date', sa.String(), nullable=True),
        sa.Column('whois_nameservers', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('screenshot_path', sa.Text(), nullable=True),
        sa.Column('visual_similarity', sa.Float(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 8. DNS Observations
    op.create_table(
        'dns_observations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=True),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('record_type', sa.String(length=10), nullable=False),
        sa.Column('records', sa.Text(), nullable=False, server_default='[]'),
        sa.Column('resolved_at', sa.String(), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='OK'),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['domain_investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 9. Certificate Observations
    op.create_table(
        'certificate_observations',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('investigation_id', sa.Integer(), nullable=True),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('subject', sa.Text(), nullable=True),
        sa.Column('issuer', sa.Text(), nullable=True),
        sa.Column('valid_from', sa.String(), nullable=True),
        sa.Column('valid_to', sa.String(), nullable=True),
        sa.Column('san_list', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('fingerprint_sha256', sa.String(length=64), nullable=True),
        sa.Column('is_new', sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column('observed_at', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['investigation_id'], ['domain_investigations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 10. Risk Assessments
    op.create_table(
        'risk_assessments',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('assessed_at', sa.String(), nullable=False),
        sa.Column('score', sa.Float(), nullable=False),
        sa.Column('level', sa.String(length=20), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False, server_default='MEDIUM'),
        sa.Column('breakdown', sa.Text(), nullable=True),
        sa.Column('reasons', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('missing_evidence', sa.Text(), nullable=True, server_default='[]'),
        sa.Column('recommended_action', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 11. Alerts
    op.create_table(
        'alert_records',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('candidate_id', sa.Integer(), nullable=False),
        sa.Column('channel', sa.String(length=20), nullable=False),
        sa.Column('recipient', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='pending'),
        sa.Column('payload', sa.Text(), nullable=True),
        sa.Column('attempts', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.Column('delivered_at', sa.String(), nullable=True),
        sa.ForeignKeyConstraint(['candidate_id'], ['candidates.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )

    # 12. Monitoring Jobs
    op.create_table(
        'monitoring_jobs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('brand_id', sa.Integer(), nullable=True),
        sa.Column('job_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=20), nullable=False, server_default='queued'),
        sa.Column('items_found', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('items_processed', sa.Integer(), nullable=False, server_default='0'),
        sa.Column('started_at', sa.String(), nullable=False),
        sa.Column('completed_at', sa.String(), nullable=True),
        sa.Column('error_message', sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(['brand_id'], ['brands.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )

    # 13. Audit Logs
    op.create_table(
        'audit_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('organization_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=True),
        sa.Column('user_email', sa.String(length=255), nullable=True),
        sa.Column('action', sa.String(length=100), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=True),
        sa.Column('target_id', sa.String(length=100), nullable=True),
        sa.Column('details', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(length=50), nullable=True),
        sa.Column('created_at', sa.String(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('audit_logs')
    op.drop_table('monitoring_jobs')
    op.drop_table('alert_records')
    op.drop_table('risk_assessments')
    op.drop_table('certificate_observations')
    op.drop_table('dns_observations')
    op.drop_table('domain_investigations')
    op.drop_table('discovery_observations')
    op.drop_table('candidates')
    op.drop_table('approved_domains')
    op.drop_table('brands')
    op.drop_table('users')
    op.drop_table('organizations')
