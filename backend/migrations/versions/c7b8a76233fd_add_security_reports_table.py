"""add security_reports table

Revision ID: c7b8a76233fd
Revises: 82ad9a14eb81
Create Date: 2026-09-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7b8a76233fd'
down_revision: Union[str, Sequence[str], None] = '82ad9a14eb81'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('security_reports',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('generated_by_user_id', sa.Integer(), nullable=True),
    sa.Column('generation_status', sa.String(length=16), nullable=False),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('file_path', sa.String(length=255), nullable=True),
    sa.Column('file_size_bytes', sa.Integer(), nullable=True),
    sa.Column('report_period_start', sa.DateTime(), nullable=True),
    sa.Column('report_period_end', sa.DateTime(), nullable=True),
    sa.Column('summary_stats', sa.JSON(), nullable=True),
    sa.Column('model_version_snapshot', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['generated_by_user_id'], ['users.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_security_reports_created_at'), 'security_reports', ['created_at'], unique=False)
    op.create_index(op.f('ix_security_reports_generation_status'), 'security_reports', ['generation_status'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_security_reports_generation_status'), table_name='security_reports')
    op.drop_index(op.f('ix_security_reports_created_at'), table_name='security_reports')
    op.drop_table('security_reports')
