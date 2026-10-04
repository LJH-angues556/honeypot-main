"""system settings table

Revision ID: 0003_system_settings
Revises: 0002_ip_blacklist
Create Date: 2026-10-03 00:10:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0003_system_settings'
down_revision = '0002_ip_blacklist'
branch_labels = None
depends_on = None


def upgrade():
    from sqlalchemy import inspect
    bind = op.get_bind()
    if inspect(bind).has_table('system_settings'):
        return
    op.create_table(
        'system_settings',
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('value', sa.Text(), nullable=True),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('key'),
    )


def downgrade():
    from sqlalchemy import inspect
    bind = op.get_bind()
    if inspect(bind).has_table('system_settings'):
        op.drop_table('system_settings')
