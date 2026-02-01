import os
import threading
import time


def cpu_stress(duration_sec: int = 60):
    """Consume CPU for duration_sec seconds"""
    end_time = time.time() + duration_sec
    while time.time() < end_time:
        pass  # busy loop


def memory_stress(size_mb: int = 100, duration_sec: int = 60):
    """Allocate memory for duration_sec seconds"""
    data = ["x" * 1024 * 1024] * size_mb  # ~size_mb MB
    time.sleep(duration_sec)
    del data


if __name__ == "__main__":
    print("Starting stress process. PID:", os.getpid())
    threading.Thread(target=cpu_stress, args=(120,), daemon=True).start()
    threading.Thread(
        target=memory_stress, args=(200, 120), daemon=True
    ).start()
    try:
        while True:
            time.sleep(1)  # keep the process alive
    except KeyboardInterrupt:
        print("\nStress process terminated by user")
