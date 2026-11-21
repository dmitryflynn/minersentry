"""bench/live_removal.py must not report success for a run that verified nothing."""

import importlib.util
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
spec = importlib.util.spec_from_file_location(
    "live_removal", os.path.join(ROOT, "bench", "live_removal.py"))
live_removal = importlib.util.module_from_spec(spec)
spec.loader.exec_module(live_removal)

PASSED = [("a run key is really removed", "PASSED", "")]


def test_a_clean_run_exits_zero():
    assert live_removal.exit_status(0, PASSED) == 0


@pytest.mark.parametrize("code", [1, 2, 4, 5])
def test_pytest_failing_is_a_failure_even_with_no_rows(code):
    """The bug: an import or collection error yields no rows and no failures,
    and the pytest exit code was discarded, so this exited 0."""
    assert live_removal.exit_status(code, []) == 1


def test_nothing_verified_is_a_failure():
    assert live_removal.exit_status(0, []) == 1


def test_a_failed_row_is_a_failure():
    assert live_removal.exit_status(0, PASSED + [("x", "FAILED", "")]) == 1
    assert live_removal.exit_status(0, [("x", "ERROR", "")]) == 1


def test_skipped_rows_alone_still_count_as_a_run():
    """Unelevated, the service row is skipped and that is expected."""
    assert live_removal.exit_status(0, PASSED + [("svc", "SKIPPED", "admin")]) == 0
