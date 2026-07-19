"""Run-level success gate (audit Batch 1): execute() must classify a run as
FAILED when nothing was processable or every target failed with no crashes."""
from types import SimpleNamespace

from nemesis.models import PipelineStatus
from nemesis.pipeline import _classify_run_status


def _r(status):
    return SimpleNamespace(status=status, crashes=[])


def test_no_targets_processed_is_failed():
    status, reasons = _classify_run_status([], targets_processed=0, total_crashes=0)
    assert status == PipelineStatus.FAILED
    assert reasons


def test_all_failed_no_crashes_is_failed():
    results = [_r(PipelineStatus.FAILED), _r(PipelineStatus.FAILED)]
    status, reasons = _classify_run_status(results, targets_processed=2, total_crashes=0)
    assert status == PipelineStatus.FAILED


def test_all_failed_but_crashes_found_is_success():
    # A crash was found even though target bookkeeping says FAILED → still a win.
    results = [_r(PipelineStatus.FAILED)]
    status, _ = _classify_run_status(results, targets_processed=1, total_crashes=1)
    assert status == PipelineStatus.SUCCESS


def test_one_success_is_success():
    results = [_r(PipelineStatus.FAILED), _r(PipelineStatus.SUCCESS)]
    status, reasons = _classify_run_status(results, targets_processed=2, total_crashes=0)
    assert status == PipelineStatus.SUCCESS
    assert reasons == []


def test_all_skipped_is_success_not_failed():
    # Skipped (e.g. already-covered) targets shouldn't mark the whole run failed.
    results = [_r(PipelineStatus.SKIPPED), _r(PipelineStatus.SKIPPED)]
    status, _ = _classify_run_status(results, targets_processed=2, total_crashes=0)
    assert status == PipelineStatus.SUCCESS
