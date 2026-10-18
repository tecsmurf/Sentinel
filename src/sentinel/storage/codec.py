"""Column encoding helpers shared by the storage modules."""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from sentinel.models import from_micros, to_micros

logger = logging.getLogger(__name__)


def dumps(value: Any) -> str:
    """Compact, safe JSON (never pickle) for TEXT columns."""
    return json.dumps(value, default=str, ensure_ascii=False, separators=(",", ":"))


def loads(text: str | None, fallback: Any) -> Any:
    if not text:
        return fallback
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        logger.warning("ignored unreadable JSON column value")
        return fallback


def micros(moment: datetime | None) -> int | None:
    return None if moment is None else to_micros(moment)


def moment(value: int | None) -> datetime | None:
    return None if value is None else from_micros(value)
