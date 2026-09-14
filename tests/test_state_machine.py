"""AssessmentStateMachine unit testleri."""
from core.state_machine import AssessmentStateMachine, Phase


def test_initial_phase():
    sm = AssessmentStateMachine()
    assert sm.current_phase() == Phase.RECON


def test_valid_transition():
    sm = AssessmentStateMachine()
    assert sm.transition(Phase.VULN_MAPPING)
    assert sm.current_phase() == Phase.VULN_MAPPING


def test_invalid_transition():
    sm = AssessmentStateMachine()
    assert not sm.transition(Phase.PRIVESC)


def test_foothold_transition():
    sm = AssessmentStateMachine()
    sm.transition(Phase.VULN_MAPPING)
    sm.transition(Phase.EXPLOITATION)
    sm.on_foothold()
    assert sm.current_phase() == Phase.FOOTHOLD
    assert sm.foothold_obtained


def test_root_transition():
    sm = AssessmentStateMachine()
    sm.transition(Phase.VULN_MAPPING)
    sm.transition(Phase.EXPLOITATION)
    sm.on_foothold()
    sm.on_root()
    assert sm.current_phase() == Phase.PRIVESC
    assert sm.root_obtained


def test_next_phase_sequence():
    sm = AssessmentStateMachine()
    assert sm.next_phase() == Phase.VULN_MAPPING
    sm.transition(Phase.VULN_MAPPING)
    assert sm.next_phase() == Phase.EXPLOITATION


def test_history_tracking():
    sm = AssessmentStateMachine()
    sm.transition(Phase.VULN_MAPPING)
    sm.transition(Phase.EXPLOITATION)
    assert sm.history == [Phase.RECON, Phase.VULN_MAPPING, Phase.EXPLOITATION]
