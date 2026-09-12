"""Add permissions, providers, and certificate_details to Analysis

Revision ID: c1f9d2e3b4a5
Revises: b85df42b1287
Create Date: 2026-09-12 11:42:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c1f9d2e3b4a5'
down_revision = 'b85df42b1287'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('analyses', sa.Column('providers', sa.JSON(), nullable=True))
    op.add_column('analyses', sa.Column('permissions', sa.JSON(), nullable=True))
    op.add_column('analyses', sa.Column('certificate_details', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('analyses', 'certificate_details')
    op.drop_column('analyses', 'permissions')
    op.drop_column('analyses', 'providers')
