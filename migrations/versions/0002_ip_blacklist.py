"""ip blacklist fields

Revision ID: 0002_ip_blacklist
Revises: 0001_initial
Create Date: 2026-10-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0002_ip_blacklist'
down_revision = '0001_initial'
branch_labels = None
depends_on = None


def upgrade():
    # 幂等守卫:历史上有容器并行执行过本迁移,可能出现"列已存在但版本号滞后"
    from sqlalchemy import inspect
    cols = {c['name'] for c in inspect(op.get_bind()).get_columns('attacker_profiles')}

    # 存量行需要 server_default 回填,添加列后再去掉 server_default(由应用层 default 负责)
    if 'is_blocked' not in cols:
        op.add_column(
            'attacker_profiles',
            sa.Column('is_blocked', sa.Boolean(), nullable=False,
                      server_default=sa.text('0')),
        )
        op.alter_column('attacker_profiles', 'is_blocked', server_default=None)
    if 'block_reason' not in cols:
        op.add_column(
            'attacker_profiles',
            sa.Column('block_reason', sa.String(length=255), nullable=True),
        )
    if 'blocked_at' not in cols:
        op.add_column(
            'attacker_profiles',
            sa.Column('blocked_at', sa.DateTime(), nullable=True),
        )


def downgrade():
    from sqlalchemy import inspect
    cols = {c['name'] for c in inspect(op.get_bind()).get_columns('attacker_profiles')}
    for name in ('blocked_at', 'block_reason', 'is_blocked'):
        if name in cols:
            op.drop_column('attacker_profiles', name)
