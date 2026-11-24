"""Compatibility path for source-aware multiline parsing."""
from app.core.multiline import *  # noqa: F401,F403
import app.core.multiline as _multiline


def __getattr__(name: str):
    return _multiline.__getattr__(name)
