from datetime import timedelta

import pytest

from sentinel.scanner.classification import (
    CandidatePolicy,
    assess_candidate,
    classify,
    file_extension,
)
from tests.support import BASE_TIME

NOW = BASE_TIME
POLICY = CandidatePolicy(min_age_days=7)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("report.TXT", ".txt"),
        ("archive.tar.gz", ".gz"),
        ("noext", ""),
        (".hidden", ""),
        ("trailingdot.", ""),
        ("x." + "a" * 40, "(long)"),
    ],
)
def test_file_extension(name, expected):
    assert file_extension(name) == expected


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("~DF1234.tmp", "temporary"),
        ("setup.log", "log"),
        ("app.exe.12345.dmp", "crash_dump"),
        ("installer.MSI", "installer"),
        ("bundle.zip", "archive"),
        ("helper.dll", "executable"),
        ("run.ps1", "script"),
        ("movie.mp4.crdownload", "download"),
        ("~$Budget.xlsx", "office_lock"),
        ("mystery.qqq", "other"),
        ("README", "other"),
    ],
)
def test_classify(name, expected):
    assert classify(name) == expected


def _assess(kind, ext, age_days, created_age_days=None):
    modified = NOW - timedelta(days=age_days)
    created = None if created_age_days is None else NOW - timedelta(days=created_age_days)
    return assess_candidate(kind, ext, modified, created, NOW, POLICY)


class TestAssessCandidate:
    def test_old_temporary_file_is_candidate_with_reasons(self):
        reasons = _assess("temporary", ".tmp", 30)
        assert reasons == [
            "not modified for 30 days",
            "type: Temporary file (.tmp)",
            "located in a temporary directory",
        ]

    def test_recent_file_is_not_candidate(self):
        assert _assess("temporary", ".tmp", 2) is None

    def test_recent_creation_overrides_old_modification_time(self):
        # e.g. extracted from an archive yesterday with an old timestamp
        assert _assess("temporary", ".tmp", 300, created_age_days=1) is None

    @pytest.mark.parametrize("kind", ["executable", "script", "database"])
    def test_risky_types_are_never_candidates(self, kind):
        assert _assess(kind, ".exe", 1000) is None

    def test_caution_classes_carry_caveat(self):
        reasons = _assess("crash_dump", ".dmp", 30)
        assert reasons is not None
        assert reasons[-1].startswith("caution: may be needed to diagnose a crash")

    def test_unknown_types_need_a_longer_age(self):
        assert _assess("other", ".qqq", 10) is None
        assert _assess("other", ".qqq", 40) is not None

    def test_unlisted_known_classes_are_not_candidates(self):
        assert _assess("document", ".pdf", 400) is None
        assert _assess("image", ".png", 400) is None
