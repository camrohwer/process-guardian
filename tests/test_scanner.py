import pytest
from unittest.mock import patch, MagicMock

from process_guardian.scanner import scan_processes
from process_guardian.models import ProcessOffender

@pytest.fixture
def mock_process():
    proc = MagicMock()
    proc.info = {
        "pid":1234,
        "name": "testproc",
        "username": "user",
        "cmdline": ["python", "script.py"],
        "memory_percent": 50,
    }
    proc.cpu_percent.side_effect = [0.0, 25.0]
    proc.memory_percent.return_value = 50.0
    return proc

@patch("process_guardian.scanner._iter_processes")
@patch("process_guardian.scanner.utc_time_str", return_value="20260101T000000Z")
def test_scan_processes(mock_utc, mock_iter, mock_process):
    # Mock _iter_processes to return fake process
    mock_iter.return_value = [mock_process]

    # Thresholds lower than our mock CPU/mem to trigger detection
    offenders = scan_processes(cpu_threshold=20, mem_threshold=10, sample_interval=0)

    assert len(offenders) == 1
    offender = offenders[0]
    assert isinstance(offender, ProcessOffender)
    assert offender.pid == 1234
    assert offender.name == "testproc"
    assert offender.user == "user"
    assert offender.cpu_percent == 25.0
    assert offender.cmdline == "python script.py"
    assert offender.first_seen == "20260101T000000Z"

@patch("process_guardian.scanner._iter_processes")
@patch("process_guardian.scanner.utc_time_str", return_value="20260101T000000Z")
def test_scan_processes_excluded_pid(mock_utc, mock_iter, mock_process):
    # Exclude test PID
    mock_iter.return_value = [mock_process]

    offenders = scan_processes(
        cpu_threshold=0, mem_threshold=0, excluded_pids={1234}, sample_interval=0
    )

    assert len(offenders) == 0