"""honeypot nodes table and attack_events.node_id

Revision ID: 0004_honeypot_nodes
Revises: 0003_system_settings
Create Date: 2026-10-04 00:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0004_honeypot_nodes'
down_revision = '0003_system_settings'
branch_labels = None
depends_on = None


def upgrade():
    from sqlalchemy import inspect
    inspector = inspect(op.get_bind())

    if not inspector.has_table('honeypot_nodes'):
        op.create_table(
            'honeypot_nodes',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('name', sa.String(length=64), nullable=False),
            sa.Column('node_key', sa.String(length=64), nullable=False),
            sa.Column('ip_address', sa.String(length=45), nullable=True),
            sa.Column('service_type', sa.String(length=32), nullable=False,
                      server_default='http'),
            sa.Column('status', sa.String(length=16), nullable=False,
                      server_default='offline'),
            sa.Column('last_heartbeat', sa.DateTime(), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('name'),
        )
        op.create_index('ix_honeypot_nodes_node_key', 'honeypot_nodes',
                        ['node_key'], unique=True)

    event_cols = {c['name'] for c in inspector.get_columns('attack_events')}
    if 'node_id' not in event_cols:
        with op.batch_alter_table('attack_events') as batch_op:
            batch_op.add_column(sa.Column('node_id', sa.Integer(), nullable=True))
            batch_op.create_foreign_key(
                'fk_attack_events_node_id', 'honeypot_nodes',
                ['node_id'], ['id'],
            )


def downgrade():
    from sqlalchemy import inspect
    inspector = inspect(op.get_bind())
    event_cols = {c['name'] for c in inspector.get_columns('attack_events')}
    if 'node_id' in event_cols:
        with op.batch_alter_table('attack_events') as batch_op:
            batch_op.drop_constraint('fk_attack_events_node_id', type_='foreignkey')
            batch_op.drop_column('node_id')
    if inspector.has_table('honeypot_nodes'):
        op.drop_index('ix_honeypot_nodes_node_key', table_name='honeypot_nodes')
        op.drop_table('honeypot_nodes')
