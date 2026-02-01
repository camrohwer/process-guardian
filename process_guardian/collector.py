import json
import subprocess
from pathlib import Path
from typing import Any, Dict, Union

import psutil

from process_guardian.tracer import collect_strace
from process_guardian.utils import utc_time_str


def _run_command(cmd: list[str], output_file: Path, timeout: int = 10) -> None:
    """
    Run a system command and write stdout/stderr to a file.
    """
    with output_file.open("w") as f:
        try:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            f.write(f"\n[command timed out after {timeout}s]\n")
        except Exception as e:
            f.write(f"\n[command failed: {e}]\n")


def create_incident_dir(base_dir: Union[str, Path], pid: int) -> Path:
    """
    Create a unique timestamped incident directory for a PID.
    """
    base_dir = Path(base_dir)
    timestamp = utc_time_str()
    incident_dir = base_dir / f"pid-{pid}-{timestamp}"
    incident_dir.mkdir(parents=True, exist_ok=False)
    return incident_dir


def collect_proc_snapshot(pid: int, output_dir: Path) -> None:
    """
    Capture a snapshot of process metadata and resource usage.
    """
    snapshot_file = output_dir / "process_snapshot.json"
    try:
        proc = psutil.Process(pid)
        snapshot: Dict[str, Any] = {
            "pid": pid,
            "name": proc.name(),
            "username": proc.username(),
            "cmdline": proc.cmdline(),
            "exe": proc.exe(),
            "cwd": proc.cwd(),
            "status": proc.status(),
            "create_time": proc.create_time(),
            "cpu_percent": proc.cpu_percent(interval=None),
            "memory_percent": proc.memory_percent(),
            "memory_info": proc.memory_info()._asdict(),
            "num_threads": proc.num_threads(),
            "open_files": [f.path for f in proc.open_files()],
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        snapshot = {
            "pid": pid,
            "error": str(e),
            "collected_at": utc_time_str(),
        }

    snapshot_file.write_text(json.dumps(snapshot, indent=2))


def collect_journal_logs(
    pid: int, output_dir: Path, since: str = "5 minutes ago"
) -> None:
    """
    Collect recent journald logs for a PID.
    """
    timestamp = utc_time_str()
    output_file = output_dir / f"journal_{timestamp}.log"

    cmd = ["journalctl", f"_PID={pid}", "--since", since, "--no-pager"]

    with output_file.open("w") as f:
        f.write(f"# Collected at UTC: {timestamp}\n")
        f.write(f"# PID: {pid}\n")
        f.write(f"# journalctl {' '.join(cmd)}\n\n")

        try:
            subprocess.run(
                cmd,
                stdout=f,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=10,
                check=False,
            )
        except subprocess.TimeoutExpired:
            f.write("\n[journalctl timed out]\n")
        except Exception as e:
            f.write(f"\n[journalctl failed: {e}]\n")


def collect_sys_snapshot(output_dir: Path) -> None:
    """
    Capture general system context.
    """
    commands = {
        "ps.txt": ["ps", "auxf"],
        "top.txt": ["top", "-b", "-n", "1"],
        "uptime.txt": ["uptime"],
        "df.txt": ["df", "-h"],
        "free.txt": ["free", "-m"],
    }

    for filename, cmd in commands.items():
        _run_command(cmd, output_dir / filename)


def collector(
    pid: int,
    base_dir: Union[str, Path] = "/var/log/process-guardian",
    collect_sys: bool = True,
    enable_strace: bool = False,
    strace_duration: int = 5,
) -> Path:
    """
    Entrypoint for main.py.

    Returns the incident directory path.
    """
    base_dir = Path(base_dir)
    base_dir.mkdir(parents=True, exist_ok=True)

    incident_dir = create_incident_dir(base_dir, pid)

    collect_proc_snapshot(pid, incident_dir)
    collect_journal_logs(pid, incident_dir)

    if enable_strace:
        collect_strace(
            pid,
            incident_dir,
            duration=strace_duration,
        )

    if collect_sys:
        collect_sys_snapshot(incident_dir)

    return incident_dir
