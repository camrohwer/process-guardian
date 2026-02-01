import shutil
import subprocess
import time
from pathlib import Path

import psutil

from process_guardian.utils import utc_time_str


def strace_installed() -> bool:
    return shutil.which("strace") is not None


def collect_strace(
    pid: int,
    output_dir: Path,
    duration: int = 5,
) -> None:
    """
    Attache strace to a running process
    """
    timestamp = utc_time_str()
    output_file = output_dir / f"strace_{pid}_{timestamp}.log"

    if not strace_installed():
        output_file.write_text("strace not installed\n")
        return

    cmd = [
        "strace",
        "-ttt",
        "-f",
        "-yy",
        "-p",
        str(pid),
    ]

    with output_file.open("w") as f:
        f.write(f"# strace collected at UTC: {timestamp}\n")
        f.write(f"# PID: {pid}\n")
        f.write(f"# Duration: {duration}s\n\n")

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=f,
                stderr=f,
                text=True,
            )
            time.sleep(duration)
            proc.terminate()
        except psutil.NoSuchProcess:
            f.write("\n[process exited before strace attach]\n")
        except Exception as e:
            f.write(f"\n[strace failed: {e}]\n")
