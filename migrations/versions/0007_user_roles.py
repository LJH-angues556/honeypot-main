"""user roles and active flag

Revision ID: 0007_user_roles
Revises: 0006_audit_logs
Create Date: 2026-10-03 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


revision = '0007_user_roles'
down_revision = '0006_audit_logs'
branch_labels = None
depends_on = None


def _columns():
    from sqlalchemy import inspect
    return {c['name'] for c in inspect(op.get_bind()).get_columns('users')}


def upgrade():
    bind = op.get_bind()
    cols = _columns()

    if 'role' not in cols:
        op.add_column('users', sa.Column(
            'role', sa.String(length=20), nullable=False, server_default='viewer'))
        # 原 is_admin=True 的用户提升为超级管理员,其余为只读观察员
        if 'is_admin' in cols:
            bind.execute(sa.text(
                "UPDATE users SET role='super_admin' WHERE is_admin=1"))
            bind.execute(sa.text(
                "UPDATE users SET role='viewer' WHERE is_admin=0 OR is_admin IS NULL"))

    if 'active' not in cols:
        op.add_column('users', sa.Column(
            'active', sa.Boolean(), nullable=False, server_default=sa.text('1')))

    # 角色体系就位后删除旧布尔列
    if 'is_admin' in cols:
        op.drop_column('users', 'is_admin')


def downgrade():
    cols = _columns()
    if 'is_admin' not in cols:
        op.add_column('users', sa.Column(
            'is_admin', sa.Boolean(), nullable=False, server_default=sa.text('0')))
        bind = op.get_bind()
        bind.execute(sa.text(
            "UPDATE users SET is_admin=1 WHERE role IN ('admin','super_admin')"))

    if 'role' in cols:
        op.drop_column('users', 'role')
    if 'active' in cols:
        op.drop_column('users', 'active')
