import os
import time
from typing import Iterable, List, Optional, Set

import psutil

from process_guardian.models import ProcessOffender
from process_guardian.utils import utc_time_str


def _default_exclusions() -> Set[int]:
    """
    PIDs that never are considered offenders.
    """
    return {
        0,  # kernel
        1,  # systemd / init
        os.getpid(),  # this proc
    }


def _iter_processes() -> Iterable[psutil.Process]:
    """
    Safely yield processes
    """
    for proc in psutil.process_iter(
        attrs=[
            "pid",
            "name",
            "username",
            "cmdline",
            "memory_percent",
        ]
    ):
        try:
            yield proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


def scan_processes(
    cpu_threshold: float,
    mem_threshold: float,
    sample_interval: float = 1.0,
    excluded_pids: Optional[Set[int]] = None,
) -> List[ProcessOffender]:
    """
    Scan running processes and return those exceeding CPU or memory thresholds.
    """
    if excluded_pids is None:
        excluded_pids = _default_exclusions()

    processes: dict[int, psutil.Process] = {}

    # First phase
    for proc in _iter_processes():
        pid = proc.info["pid"]
        if pid in excluded_pids:
            continue

        try:
            proc.cpu_percent(interval=None)  # prime cpu counters
            processes[pid] = proc
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(sample_interval)  # wait for second sample

    offenders: List[ProcessOffender] = []

    # Second phase
    for pid, proc in processes.items():
        try:
            cpu = proc.cpu_percent(interval=None)
            mem = proc.memory_percent()

            if cpu < cpu_threshold and mem < mem_threshold:
                continue

            offenders.append(
                ProcessOffender(
                    pid=pid,
                    name=proc.info.get("name", ""),
                    user=proc.info.get("username", ""),
                    cpu_percent=round(cpu, 2),
                    memory_percent=round(mem, 2),
                    cmdline=" ".join(proc.info.get("cmdline") or []),
                    first_seen=utc_time_str(),
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    offenders.sort(
        key=lambda p: (p.cpu_percent, p.memory_percent), reverse=True
    )

    return offenders
