import pytest

from sentinel.services.redaction import Redactor


@pytest.fixture
def redactor():
    return Redactor(usernames=["alice"], computers=["ALICE-PC"])


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (r"C:\Users\Alice\AppData\Local\Temp\x.tmp", r"C:\Users\<user>\AppData\Local\Temp\x.tmp"),
        ("c:/users/bob.smith/notes.txt", "c:/users/<user>/notes.txt"),
        (r"C:\Users\Public\Documents", r"C:\Users\Public\Documents"),
        ("mail me at ops.team+alerts@example.co.uk now", "mail me at <email> now"),
        ("connect to 192.168.1.20:443 failed", "connect to <ip>:443 failed"),
        ("build 10.0.26200 is not an address", "build 10.0.26200 is not an address"),
        ("from 2001:0db8:85a3:0000:0000:8a2e:0370:7334", "from <ip>"),
        ("account S-1-5-21-1111111111-2222222222-3333333333-1001", "account <sid>"),
        ("LocalSystem S-1-5-18 stays", "LocalSystem S-1-5-18 stays"),
        ("ALICE-PC rebooted; alice logged on", "<computer> rebooted; <user> logged on"),
        ("malice and alicea are other words", "malice and alicea are other words"),
    ],
)
def test_text_redaction(redactor, raw, expected):
    assert redactor.text(raw) == expected


def test_nested_structures_are_redacted_but_control_keys_are_kept(redactor):
    data = {
        "severity": "alice",
        "items": [{"path": r"C:\Users\alice\x"}, ("ALICE-PC",)],
        "count": 3,
    }
    assert redactor.apply(data) == {
        "severity": "alice",
        "items": [{"path": r"C:\Users\<user>\x"}, ["<computer>"]],
        "count": 3,
    }


def test_too_short_identifiers_are_ignored():
    assert Redactor(usernames=["a"], computers=[""]).text("a b c") == "a b c"


def test_default_identity_comes_from_the_environment(monkeypatch):
    monkeypatch.setenv("USERNAME", "zed-test-user")
    monkeypatch.setenv("COMPUTERNAME", "ZED-TEST-HOST")
    assert Redactor().text("zed-test-user on ZED-TEST-HOST") == "<user> on <computer>"
