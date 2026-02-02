import psutil

from process_guardian.utils import default_exclusions

def terminate_process(
    pid: int,
    *,
    force: bool = False,
    timeout: int = 5,
    dry_run: bool = True,
    safe_names: set[str],
    safe_users: set[str],
) -> bool:
    """
    Attempt to terminate a process gracefully.
    Force kill if it does not exit within timeout period.
    """
    if pid in default_exclusions():
        if dry_run:
            print(f"[DRY RUN] Skipping protected PID {pid}" if dry_run else "")
        return False
    try:
        proc = psutil.Process(pid)

        # Skip safe processes
        if proc.name() in safe_names or proc.username() in safe_users:
            if dry_run:
                print(
                    f"[DRY RUN] Skipping safe process PID {pid}: {proc.name()}"
                )
            return False

        if dry_run:
            print(f"[DRY RUN] Would terminate PID {pid} ({proc.name()})")
            return False

        # Attempt graceful termination
        proc.terminate()  # send SIGTERM
        try:
            proc.wait(timeout=timeout)
            return True
        except psutil.TimeoutExpired:
            if force:
                proc.kill()  # send SIGKILL
                proc.wait(timeout=timeout)
                return True
            return False
    except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
        print(f"[WARNING] Could not terminate PID {pid}: {e}")
        return False
