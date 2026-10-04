"""initial

Revision ID: 0001_initial
Revises:
Create Date: 2026-09-28 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0001_initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # users 表
    op.create_table(
        'users',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('username', sa.String(length=80), nullable=False),
        sa.Column('email', sa.String(length=120), nullable=True),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('is_admin', sa.Boolean(), nullable=False),
        sa.Column('email_notifications', sa.Boolean(), nullable=False),
        sa.Column('theme_preference', sa.String(length=10), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('username'),
        sa.UniqueConstraint('email'),
    )
    op.create_index('ix_users_username', 'users', ['username'])
    op.create_index('ix_users_email', 'users', ['email'])

    # attacker_profiles 表
    op.create_table(
        'attacker_profiles',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('asn', sa.String(length=32), nullable=True),
        sa.Column('isp', sa.String(length=128), nullable=True),
        sa.Column('country', sa.String(length=64), nullable=True),
        sa.Column('city', sa.String(length=64), nullable=True),
        sa.Column('tags', sa.JSON(), nullable=True),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_attacker_profiles_ip_address', 'attacker_profiles', ['ip_address'])

    # attack_events 表
    op.create_table(
        'attack_events',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('method', sa.String(length=16), nullable=True),
        sa.Column('path', sa.String(length=255), nullable=True),
        sa.Column('headers', sa.JSON(), nullable=True),
        sa.Column('payload', sa.JSON(), nullable=True),
        sa.Column('honeypot_service', sa.String(length=64), nullable=True),
        sa.Column('signature', sa.String(length=128), nullable=True),
        sa.Column('severity', sa.String(length=16), nullable=True),
        sa.Column('attacker_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['attacker_id'], ['attacker_profiles.id'], ),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index('ix_attack_events_ip_address', 'attack_events', ['ip_address'])


def downgrade():
    op.drop_index('ix_attack_events_ip_address', table_name='attack_events')
    op.drop_table('attack_events')
    op.drop_index('ix_attacker_profiles_ip_address', table_name='attacker_profiles')
    op.drop_table('attacker_profiles')
    op.drop_index('ix_users_email', table_name='users')
    op.drop_index('ix_users_username', table_name='users')
    op.drop_table('users')
