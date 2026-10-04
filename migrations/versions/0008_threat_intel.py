"""threat intel records

Revision ID: 0008_threat_intel
Revises: 0007_user_roles
Create Date: 2026-10-04 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '0008_threat_intel'
down_revision = '0007_user_roles'
branch_labels = None
depends_on = None


def _has_table(name):
    from sqlalchemy import inspect
    return name in inspect(op.get_bind()).get_table_names()


def upgrade():
    if _has_table('threat_intel_records'):
        return
    op.create_table(
        'threat_intel_records',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('indicator', sa.String(length=64), nullable=False),
        sa.Column('kind', sa.String(length=8), nullable=False, server_default='ip'),
        sa.Column('source', sa.String(length=32), nullable=False, server_default='unknown'),
        sa.Column('malicious', sa.Boolean(), nullable=False, server_default=sa.text('1')),
        sa.Column('category', sa.String(length=128), nullable=True),
        sa.Column('confidence', sa.Integer(), nullable=True),
        sa.Column('detail', sa.String(length=255), nullable=True),
        sa.Column('checked_at', sa.DateTime(), nullable=False,
                  server_default=sa.text('CURRENT_TIMESTAMP')),
        sa.UniqueConstraint('indicator', 'kind', 'source',
                            name='uq_threat_indicator_kind_source'),
    )
    op.create_index('ix_threat_intel_records_indicator',
                    'threat_intel_records', ['indicator'])


def downgrade():
    if _has_table('threat_intel_records'):
        op.drop_table('threat_intel_records')
