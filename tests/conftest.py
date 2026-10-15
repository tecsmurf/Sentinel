"""Shared fixtures. All data is synthetic; nothing reads the real machine's logs (D-015)."""

from __future__ import annotations

import itertools
from datetime import datetime, timedelta

import pytest

from sentinel.analysis.normalize import fingerprint
from sentinel.models import Observation, Severity, SourceType
from sentinel.storage import Database, Repository
from tests.support import BASE_TIME


@pytest.fixture
def database(tmp_path):
    db = Database(tmp_path / "sentinel.db")
    db.initialize()
    return db


@pytest.fixture
def repo(database):
    repository = Repository(database.connect())
    yield repository
    repository.close()


@pytest.fixture
def make_observation():
    """Factory for synthetic observations with unique dedup keys and increasing timestamps."""
    counter = itertools.count(1)

    def factory(
        message: str = "Something failed",
        *,
        severity: Severity = Severity.ERROR,
        source_id: str = "test:source",
        source_type: SourceType = SourceType.TEXT_LOG,
        at: datetime | None = None,
        provider: str = "TestProvider",
        event_code: str = "",
        **extra,
    ) -> Observation:
        n = next(counter)
        dedup_key = extra.pop("dedup_key", f"{source_id}:{n}")
        return Observation(
            source_id=source_id,
            source_type=source_type,
            event_timestamp=at or BASE_TIME + timedelta(seconds=n),
            severity=severity,
            message=message,
            dedup_key=dedup_key,
            fingerprint=fingerprint(provider, event_code, message=message),
            provider=provider,
            event_code=event_code,
            **extra,
        )

    return factory
