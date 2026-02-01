import time
from pathlib import Path
from typing import Dict

import yaml

from process_guardian.collector import collector
from process_guardian.models import ProcessOffender
from process_guardian.scanner import scan_processes
from process_guardian.utils import utc_time_str

CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"


def load_config(path: Path = CONFIG_PATH) -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)


def merge_offenders(
    current: list[ProcessOffender],
    tracked: Dict[int, ProcessOffender],
) -> Dict[int, ProcessOffender]:
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
    config = load_config(CONFIG_PATH)

    CPU_THRESHOLD = config.get("thresholds", {}).get("cpu_percent", 80)
    MEM_THRESHOLD = config.get("thresholds", {}).get("memory_percent", 70)
    SCAN_INTERVAL = config.get("scan", {}).get("interval_seconds", 5)
    SUSTAINED_BREACH_COUNT = config.get("scan", {}).get(
        "sustained_breach_count", 2
    )

    tracked_offenders: Dict[int, ProcessOffender] = {}

    print(f"[{utc_time_str()}] Starting Process Guardian")

    try:
        while True:
            offenders = scan_processes(
                cpu_threshold=CPU_THRESHOLD,
                mem_threshold=MEM_THRESHOLD,
            )
            tracked_offenders = merge_offenders(offenders, tracked_offenders)

            for pid, offender in tracked_offenders.items():
                if offender.breach_count >= SUSTAINED_BREACH_COUNT:
                    print(
                        f"[{utc_time_str}] "
                        f"Sustained offender detected: PID {pid}, "
                        f"CPU {offender.cpu_percent}%, "
                        f"MEM {offender.memory_percent}%"
                    )
                    BASE_DIR = config.get("paths", {}).get(
                        "base_incident_dir", "./incident_logs"
                    )
                    incident_dir = collector(pid, base_dir=BASE_DIR)
                    print(
                        f"[{utc_time_str}] "
                        f"Evidence collected at {incident_dir}"
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
            time.sleep(SCAN_INTERVAL)

    except KeyboardInterrupt:
        print(f"[{utc_time_str()}] Process Guardian stopped by User")


if __name__ == "__main__":
    main()
