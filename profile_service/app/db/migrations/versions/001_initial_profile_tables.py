"""Initial profile tables

Revision ID: 001
Revises: 
Create Date: 2025-01-21

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create profiles table
    op.create_table(
        'profiles',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('username', sa.String(50), nullable=False),
        sa.Column('bio', sa.Text(), nullable=True),
        sa.Column('avatar_key', sa.String(255), nullable=True),
        sa.Column('reputation_score', sa.Numeric(5, 2), nullable=False, server_default='0.00'),
        sa.Column('reputation_breakdown', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('deleted_at', sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint('user_id'),
        sa.UniqueConstraint('username'),
    )
    
    # Create partial index for active profiles by username
    op.create_index(
        'idx_profiles_username_active',
        'profiles',
        ['username'],
        postgresql_where=sa.text('deleted_at IS NULL'),
    )
    
    # Create partial index for reputation ranking
    op.create_index(
        'idx_profiles_reputation',
        'profiles',
        [sa.text('reputation_score DESC')],
        postgresql_where=sa.text('deleted_at IS NULL'),
    )
    
    # Create user_preferences table
    op.create_table(
        'user_preferences',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('preferences', postgresql.JSONB(), nullable=False, server_default='{}'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['profiles.user_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('user_id'),
    )
    
    # Create reputation_history table
    op.create_table(
        'reputation_history',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('score_delta', sa.Numeric(5, 2), nullable=False),
        sa.Column('new_score', sa.Numeric(5, 2), nullable=False),
        sa.Column('reason', sa.String(50), nullable=False),
        sa.Column('source_event_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_metadata', postgresql.JSONB(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(['user_id'], ['profiles.user_id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('source_event_id'),
    )
    
    # Create index for fetching user's history
    op.create_index(
        'idx_reputation_user_time',
        'reputation_history',
        ['user_id', sa.text('created_at DESC')],
    )


def downgrade() -> None:
    op.drop_table('reputation_history')
    op.drop_table('user_preferences')
    op.drop_index('idx_profiles_reputation', 'profiles')
    op.drop_index('idx_profiles_username_active', 'profiles')
    op.drop_table('profiles')
