"""audit logs

Revision ID: 0006_audit_logs
Revises: 0005_alert_rules
Create Date: 2026-10-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '0006_audit_logs'
down_revision = '0005_alert_rules'
branch_labels = None
depends_on = None


def upgrade():
    from sqlalchemy import inspect
    if not inspect(op.get_bind()).has_table('audit_logs'):
        op.create_table(
            'audit_logs',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('user_id', sa.Integer(), nullable=True),
            sa.Column('username', sa.String(length=80), nullable=True),
            sa.Column('action', sa.String(length=64), nullable=False),
            sa.Column('detail', sa.Text(), nullable=True),
            sa.Column('ip_address', sa.String(length=45), nullable=True),
            sa.Column('user_agent', sa.String(length=255), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['users.id']),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_audit_logs_created_at', 'audit_logs',
                        ['created_at'], unique=False)


def downgrade():
    from sqlalchemy import inspect
    if inspect(op.get_bind()).has_table('audit_logs'):
        op.drop_index('ix_audit_logs_created_at', table_name='audit_logs')
        op.drop_table('audit_logs')
