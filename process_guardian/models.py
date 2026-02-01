from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ProcessOffender:
    pid: int
    name: str
    user: str
    cpu_percent: float
    memory_percent: float
    cmdline: str
    first_seen: Optional[str] = None
    breach_count: int = 1
