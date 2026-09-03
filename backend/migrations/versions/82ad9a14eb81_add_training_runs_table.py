"""add training_runs table

Revision ID: 82ad9a14eb81
Revises: 0cf1e41c6d30
Create Date: 2026-09-03 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '82ad9a14eb81'
down_revision: Union[str, Sequence[str], None] = '0cf1e41c6d30'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('training_runs',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('component', sa.String(length=32), nullable=False),
    sa.Column('run_id', sa.String(length=64), nullable=False),
    sa.Column('model_version_id', sa.Integer(), nullable=True),
    sa.Column('artifact_dir', sa.String(length=255), nullable=False),
    sa.Column('content_hash', sa.String(length=64), nullable=False),
    sa.Column('trained_at', sa.DateTime(), nullable=True),
    sa.Column('training_duration_seconds', sa.Float(), nullable=True),
    sa.Column('feature_count', sa.Integer(), nullable=True),
    sa.Column('dataset_info', sa.JSON(), nullable=False),
    sa.Column('hyperparameters', sa.JSON(), nullable=False),
    sa.Column('preprocessing_version', sa.String(length=64), nullable=True),
    sa.Column('threshold', sa.Float(), nullable=True),
    sa.Column('metrics', sa.JSON(), nullable=False),
    sa.Column('confusion_matrix', sa.JSON(), nullable=False),
    sa.Column('class_distribution', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(), server_default=sa.text('now()'), nullable=False),
    sa.ForeignKeyConstraint(['model_version_id'], ['model_versions.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('component', 'content_hash', name='uq_training_run_component_hash'),
    sa.UniqueConstraint('run_id')
    )
    op.create_index(op.f('ix_training_runs_component'), 'training_runs', ['component'], unique=False)
    op.create_index(op.f('ix_training_runs_content_hash'), 'training_runs', ['content_hash'], unique=False)
    op.create_index(op.f('ix_training_runs_created_at'), 'training_runs', ['created_at'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_training_runs_created_at'), table_name='training_runs')
    op.drop_index(op.f('ix_training_runs_content_hash'), table_name='training_runs')
    op.drop_index(op.f('ix_training_runs_component'), table_name='training_runs')
    op.drop_table('training_runs')
