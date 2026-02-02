import os
from datetime import datetime, timezone


def utc_time_str() -> str:
    """Return current UTC time as a string in YYYYMMDDTHHMMSSZ format."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def default_exclusions() -> set[int]:
    """
    PIDs that never are considered offenders.
    """
    return {
        -1,  # kernel
        0,  # systemd / init
        os.getpid(),  # this proc
    }


def load_runtime_config(raw: dict) -> dict:
    return {
        # thresholds
        "cpu_threshold": raw.get("thresholds", {}).get("cpu_percent", 5),
        "mem_threshold": raw.get("thresholds", {}).get("memory_percent", 10),
        # scan
        "scan_interval": raw.get("scan", {}).get("interval_seconds", 5),
        "sustained_breach_count": raw.get("scan", {}).get(
            "sustained_breach_count", 2
        ),
        # paths
        "base_incident_dir": raw.get("paths", {}).get(
            "base_incident_dir", "./incident_logs"
        ),
        # trace
        "trace_enabled": raw.get("trace", {}).get("enabled", True),
        "trace_duration": raw.get("trace", {}).get("duration_seconds", 5),
        # terminator
        "terminator_enabled": raw.get("terminator", {}).get("enabled", False),
        "terminator_force": raw.get("terminator", {}).get("force_kill", False),
        "terminator_dry_run": raw.get("terminator", {}).get("dry_run", True),
        "terminator_timeout": raw.get("terminator", {}).get("timeout_seconds", 5),
        "terminator_safe_names": set(raw.get("terminator", {}).get("safe_names", [])),
        "terminator_safe_users": set(raw.get("terminator", {}).get("safe_users", [])),
        
    }
