from sentinel.analysis.normalize import (
    FINGERPRINT_TEXT_LIMIT,
    fingerprint,
    normalize_message,
    prepare_message,
)


class TestNormalizeMessage:
    def test_masks_variable_tokens(self):
        text = (
            "Request 4521 failed at 2026-10-15T12:00:01.123Z for "
            "{3F2504E0-4F89-11D3-9A0C-0305E82C3301} at address 0x7ffd1234 hash deadbeefcafe"
        )
        assert normalize_message(text) == (
            "request <n> failed at <ts> for <guid> at address <hex> hash <hex>"
        )

    def test_collapses_whitespace_and_case(self):
        assert normalize_message("  Disk   FULL\n\ton C:  ") == "disk full on c:"

    def test_output_is_bounded(self):
        assert len(normalize_message("word " * 10_000)) <= FINGERPRINT_TEXT_LIMIT


class TestFingerprint:
    def test_same_error_with_different_values_matches(self):
        a = fingerprint("app", message="Timeout after 3000 ms connecting to 10.0.0.5")
        b = fingerprint("app", message="Timeout after 5000 ms connecting to 10.0.0.9")
        assert a == b

    def test_different_messages_differ(self):
        assert fingerprint("app", message="disk full") != fingerprint("app", message="disk ok")

    def test_context_parts_are_significant(self):
        assert fingerprint("app-a", message="x") != fingerprint("app-b", message="x")

    def test_parts_are_delimited(self):
        assert fingerprint("ab", "c", message="x") != fingerprint("a", "bc", message="x")

    def test_is_short_hex(self):
        value = fingerprint(message="anything")
        assert len(value) == 24
        int(value, 16)


class TestPrepareMessage:
    def test_short_messages_are_unchanged(self):
        assert prepare_message("hello", 100) == ("hello", False)

    def test_long_messages_are_truncated_with_marker(self):
        text, truncated = prepare_message("x" * 1000, 256)
        assert truncated
        assert text.startswith("x" * 256)
        assert text.endswith("[truncated 744 characters]")

    def test_control_characters_are_replaced_but_whitespace_kept(self):
        text, _ = prepare_message("a\x00b\x1bc\td\ne\r", 100)
        assert text == "a�b�c\td\ne\r"
