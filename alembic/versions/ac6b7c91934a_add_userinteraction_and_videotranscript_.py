"""Add UserInteraction and VideoTranscript models 2

Revision ID: ac6b7c91934a
Revises: f15fc3a05777
Create Date: 2024-08-08 18:47:57.144682

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ac6b7c91934a'
down_revision: Union[str, None] = 'f15fc3a05777'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
