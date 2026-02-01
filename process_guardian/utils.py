from datetime import datetime, timezone


def utc_time_str() -> str:
    """Return current UTC time as a string in YYYYMMDDTHHMMSSZ format."""
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
