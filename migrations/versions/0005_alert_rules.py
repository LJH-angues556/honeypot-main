"""alert rules and alert history

Revision ID: 0005_alert_rules
Revises: 0004_honeypot_nodes
Create Date: 2026-10-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '0005_alert_rules'
down_revision = '0004_honeypot_nodes'
branch_labels = None
depends_on = None


def upgrade():
    from sqlalchemy import inspect
    inspector = inspect(op.get_bind())

    if not inspector.has_table('alert_rules'):
        op.create_table(
            'alert_rules',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(length=128), nullable=False),
            sa.Column('rule_type', sa.String(length=32), nullable=False),
            sa.Column('severity', sa.String(length=16), nullable=True),
            sa.Column('signature', sa.String(length=128), nullable=True),
            sa.Column('threshold', sa.Integer(), nullable=True),
            sa.Column('window_minutes', sa.Integer(), nullable=True),
            sa.Column('cooldown_minutes', sa.Integer(), nullable=False,
                      server_default='60'),
            sa.Column('enabled', sa.Boolean(), nullable=False,
                      server_default=sa.text('1')),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('updated_at', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
        )

    if not inspector.has_table('alert_histories'):
        op.create_table(
            'alert_histories',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('rule_id', sa.Integer(), nullable=False),
            sa.Column('profile_id', sa.Integer(), nullable=True),
            sa.Column('event_id', sa.Integer(), nullable=True),
            sa.Column('ip_address', sa.String(length=45), nullable=False),
            sa.Column('detail', sa.Text(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.ForeignKeyConstraint(['event_id'], ['attack_events.id']),
            sa.ForeignKeyConstraint(['profile_id'], ['attacker_profiles.id']),
            sa.ForeignKeyConstraint(['rule_id'], ['alert_rules.id']),
            sa.PrimaryKeyConstraint('id'),
        )
        op.create_index('ix_alert_histories_ip_address', 'alert_histories',
                        ['ip_address'], unique=False)


def downgrade():
    from sqlalchemy import inspect
    inspector = inspect(op.get_bind())
    if inspector.has_table('alert_histories'):
        op.drop_index('ix_alert_histories_ip_address', table_name='alert_histories')
        op.drop_table('alert_histories')
    if inspector.has_table('alert_rules'):
        op.drop_table('alert_rules')
