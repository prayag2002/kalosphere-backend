"""Seed initial categories.

This script is run after migrations to populate the categories table
with the initial set of content categories.
"""

import asyncio
import sys
from pathlib import Path
from uuid import uuid4

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from sqlalchemy import select
from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.category import Category


INITIAL_CATEGORIES = [
    {
        "name": "Photography",
        "slug": "photography",
        "description": "Capture moments through the lens — landscape, portrait, street, macro, and more.",
        "display_order": 1,
    },
    {
        "name": "Digital Art",
        "slug": "digital-art",
        "description": "Digital illustrations, paintings, and graphic art created with digital tools.",
        "display_order": 2,
    },
    {
        "name": "Traditional Art",
        "slug": "traditional-art",
        "description": "Paintings, drawings, sculptures, and other physical media artwork.",
        "display_order": 3,
    },
    {
        "name": "Music",
        "slug": "music",
        "description": "Original compositions, covers, remixes, and sound design.",
        "display_order": 4,
    },
    {
        "name": "Writing",
        "slug": "writing",
        "description": "Poetry, short stories, essays, and creative writing.",
        "display_order": 5,
    },
    {
        "name": "Film",
        "slug": "film",
        "description": "Short films, cinematography, documentaries, and video art.",
        "display_order": 6,
    },
    {
        "name": "Design",
        "slug": "design",
        "description": "UI/UX design, graphic design, typography, and visual communication.",
        "display_order": 7,
    },
    {
        "name": "3D Art",
        "slug": "3d-art",
        "description": "3D modeling, rendering, sculpting, and digital environments.",
        "display_order": 8,
    },
    {
        "name": "Animation",
        "slug": "animation",
        "description": "2D and 3D animation, motion graphics, and animated shorts.",
        "display_order": 9,
    },
]


async def seed_categories() -> None:
    """Insert initial categories if they don't already exist."""
    async with AsyncSessionLocal() as db:
        # Check if categories already exist
        result = await db.execute(select(Category).limit(1))
        if result.scalar_one_or_none():
            print("Categories already seeded, skipping.")
            return

        for cat_data in INITIAL_CATEGORIES:
            category = Category(
                id=uuid4(),
                **cat_data,
            )
            db.add(category)

        await db.commit()
        print(f"Seeded {len(INITIAL_CATEGORIES)} categories.")


if __name__ == "__main__":
    asyncio.run(seed_categories())
