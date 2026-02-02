import time
from pathlib import Path
from typing import Any

import yaml

from process_guardian.collector import collector
from process_guardian.models import ProcessOffender
from process_guardian.scanner import scan_processes
from process_guardian.terminator import terminate_process
from process_guardian.utils import load_runtime_config, utc_time_str

from importlib.resources import files

CONFIG_PATH = files("process_guardian.config") / "default.yaml"

def load_config_file(path: Path = CONFIG_PATH) -> dict[str, Any]:
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def merge_offenders(
    current: list[ProcessOffender],
    tracked: dict[int, ProcessOffender],
) -> dict[int, ProcessOffender]:
    """
    Merge newly scanned offenders with the currently tracked offenders,
    updating breach counts and first_seen.
    """
    now = utc_time_str()
    new_tracked = tracked.copy()

    for offender in current:
        pid = offender.pid
        if pid in new_tracked:
            prev = new_tracked[pid]
            new_tracked[pid] = ProcessOffender(
                pid=pid,
                name=offender.name,
                user=offender.user,
                cpu_percent=offender.cpu_percent,
                memory_percent=offender.memory_percent,
                cmdline=offender.cmdline,
                first_seen=prev.first_seen or now,
                breach_count=prev.breach_count + 1,
            )
        else:
            new_tracked[pid] = offender

    for pid in list(new_tracked.keys()):
        if pid not in [o.pid for o in current]:
            del new_tracked[pid]

    return new_tracked


def main():
    raw_config: dict[str, Any] = load_config_file(CONFIG_PATH)
    cfg: dict[str, Any] = load_runtime_config(raw_config)

    tracked_offenders: dict[int, ProcessOffender] = {}

    print(f"[{utc_time_str()}] Starting Process Guardian")

    try:
        while True:
            offenders = scan_processes(
                cpu_threshold=cfg["cpu_threshold"],
                mem_threshold=cfg["mem_threshold"],
            )
            tracked_offenders = merge_offenders(offenders, tracked_offenders)

            for pid, offender in tracked_offenders.items():
                if offender.breach_count >= cfg["sustained_breach_count"]:
                    print(
                        f"[{utc_time_str()}] "
                        f"Sustained offender detected: PID {pid}, "
                        f"CPU {offender.cpu_percent}%, "
                        f"MEM {offender.memory_percent}%"
                    )

                    incident_dir: Path = collector(
                        pid,
                        base_dir=cfg["base_incident_dir"],
                        enable_strace=cfg["trace_enabled"],
                        strace_duration=cfg["trace_duration"],
                    )
                    print(
                        f"[{utc_time_str()}] "
                        f"Evidence collected at {incident_dir}"
                    )

                    if cfg["terminator_enabled"]:
                        terminated: bool = terminate_process(
                            pid,
                            force=cfg["terminator_force"],
                            timeout=cfg["terminator_timeout"],
                            dry_run=cfg["terminator_dry_run"],
                            safe_names=cfg["terminator_safe_names"],
                            safe_users=cfg["terminator_safe_users"],
                        )
                        if not terminated:
                            print(
                                f"[{utc_time_str()}] "
                                f"Failed to terminate PID {pid}"
                            )

                    # Reset breach_count to avoid repeated collection
                    tracked_offenders[pid] = ProcessOffender(
                        pid=offender.pid,
                        name=offender.name,
                        user=offender.user,
                        cpu_percent=offender.cpu_percent,
                        memory_percent=offender.memory_percent,
                        cmdline=offender.cmdline,
                        first_seen=offender.first_seen,
                        breach_count=0,
                    )
            time.sleep(cfg["scan_interval"])

    except KeyboardInterrupt:
        print(f"[{utc_time_str()}] Process Guardian stopped by User")


if __name__ == "__main__":
    main()
