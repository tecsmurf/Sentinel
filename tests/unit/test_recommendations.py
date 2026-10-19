from sentinel.analysis.recommendations import RULE_NEXT_STEPS, explain_event, next_step
from sentinel.analysis.rules import RULES


def test_known_events_are_explained_case_insensitively():
    advice = explain_event("Service Control Manager", "7031")
    assert advice is not None
    assert "terminated unexpectedly" in advice.meaning
    assert "services.msc" in advice.next_step
    assert explain_event("microsoft-windows-kernel-power", " 41 ").meaning.startswith(
        "The system restarted"
    )


def test_unknown_events_have_no_advice():
    assert explain_event("Contoso", "1") is None


def test_benign_events_are_marked():
    assert explain_event("Microsoft-Windows-DistributedCOM", "10016").commonly_benign


def test_every_rule_has_a_next_step():
    assert {spec.rule_id for spec in RULES} <= set(RULE_NEXT_STEPS)


def test_event_specific_advice_wins_over_rule_default():
    assert "chkdsk" in next_step("repeated_error", "Disk", "7")
    assert next_step("repeated_error") == RULE_NEXT_STEPS["repeated_error"]
    assert next_step("not-a-rule") == "Review the supporting evidence before taking any action."


def test_advice_never_suggests_destructive_actions():
    texts = [*RULE_NEXT_STEPS.values()]
    for provider, code in [("disk", "7"), ("ntfs", "55"), ("application error", "1000")]:
        texts.append(explain_event(provider, code).next_step)
    for text in texts:
        lowered = text.lower()
        assert "delete " not in lowered or "does not delete" in lowered
        assert "format " not in lowered
        assert "chkdsk /f" not in lowered  # repairs are the user's decision, not ours
