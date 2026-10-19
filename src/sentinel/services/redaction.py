"""Redaction of personal and machine identifiers in exported reports.

Applied to every string in a report when the user asks for a redacted export (the
default; see ``privacy.redact_exports_by_default``). Redaction is best effort and the
report says so: it covers the identifiers listed below, not arbitrary secrets that an
application may have written into its own log messages.
"""

from __future__ import annotations

import ipaddress
import os
import re
import socket
from collections.abc import Iterable, Mapping
from typing import Any

USER = "<user>"
COMPUTER = "<computer>"

# Any "\Users\<name>" segment: drive paths, UNC paths (\\server\c$\Users\...), drive-less
# paths, and URLs alike (over-redacting a URL segment is the safe failure). A name may
# contain spaces only when another path separator follows it ("John Smith\AppData").
_PROFILE_PATH = re.compile(
    r"(?i)([\\/]users[\\/]+)(?:([^\\/:*?\"<>|\r\n]+?)(?=[\\/])|([^\\/:*?\"<>|\s]+))"
)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_IPV4 = re.compile(
    r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?![\d.])"
)
# IPv6 candidates (compressed "::", embedded IPv4, zone IDs) are confirmed with ipaddress,
# so times such as 12:00:01 and other colon-separated values are left alone.
_IPV6_CANDIDATE = re.compile(
    r"(?<![\w:.%])[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*(?:%[\w.-]+)?(?![\w:%])"
)
_DOMAIN_SID = re.compile(r"\bS-1-5-21(?:-\d+){3,4}\b")
_KEEP_KEYS = frozenset({"rule_id", "severity", "status", "confidence", "format_version", "kind"})
# Profile folders that are not personal and need no redaction.
_SHARED_PROFILES = frozenset({"public", "default", "all users", "default user", USER})


def _ipv6(match: re.Match[str]) -> str:
    token = match.group(0)
    try:
        ipaddress.IPv6Address(token.split("%", 1)[0])
    except ValueError:
        return token
    return "<ip>"


def _local_identity() -> tuple[list[str], list[str]]:
    users = [os.environ.get("USERNAME", ""), os.environ.get("USER", "")]
    computers = [os.environ.get("COMPUTERNAME", ""), socket.gethostname()]
    return [u for u in users if u], [c for c in computers if c]


class Redactor:
    """Replaces identifiers with placeholders. Construct once per report."""

    def __init__(
        self, usernames: Iterable[str] | None = None, computers: Iterable[str] | None = None
    ) -> None:
        default_users, default_computers = _local_identity()
        users = {u for u in (usernames if usernames is not None else default_users) if len(u) >= 2}
        hosts = {
            c for c in (computers if computers is not None else default_computers) if len(c) >= 2
        }
        self._literals = [
            (re.compile(rf"(?i)(?<![\w-]){re.escape(value)}(?![\w-])"), placeholder)
            for values, placeholder in ((sorted(hosts, key=len, reverse=True), COMPUTER),
                                        (sorted(users, key=len, reverse=True), USER))
            for value in values
        ]  # fmt: skip

    def text(self, value: str) -> str:
        def profile(match: re.Match[str]) -> str:
            name = match.group(2) or match.group(3)
            return match.group(0) if name.casefold() in _SHARED_PROFILES else match.group(1) + USER

        value = _EMAIL.sub("<email>", value)
        value = _PROFILE_PATH.sub(profile, value)
        value = _DOMAIN_SID.sub("<sid>", value)
        value = _IPV6_CANDIDATE.sub(_ipv6, value)  # before IPv4: may embed an IPv4 address
        value = _IPV4.sub("<ip>", value)
        for pattern, placeholder in self._literals:
            value = pattern.sub(placeholder, value)
        return value

    def apply(self, data: Any, key: str | None = None) -> Any:
        """Redact every string inside a JSON-like structure (keys are left as they are)."""
        if key in _KEEP_KEYS:
            return data
        if isinstance(data, str):
            return self.text(data)
        if isinstance(data, Mapping):
            return {k: self.apply(v, k) for k, v in data.items()}
        if isinstance(data, list | tuple):
            return [self.apply(item) for item in data]
        return data
