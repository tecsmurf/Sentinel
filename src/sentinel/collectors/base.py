"""Types shared by all collectors."""

from __future__ import annotations

from dataclasses import dataclass

from sentinel.models import Severity


@dataclass(slots=True)
class HealthNote:
    """A problem or notable condition in a collector, recorded as monitoring health.

    Examples: a channel that cannot be read, a rotated log, undecodable bytes, or events
    that were overwritten before they could be collected.
    """

    kind: str
    severity: Severity
    message: str
    path: str = ""
    count: int = 1
