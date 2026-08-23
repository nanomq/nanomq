import os
import signal
import subprocess


def stop_process(process, pid=None):
    if hasattr(process, "join"):
        if process.is_alive():
            process.terminate()
        process.join(timeout=1)
        if process.is_alive():
            process.kill()
            process.join()
    else:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    if pid is not None and pid.value > 0:
        try:
            os.kill(pid.value, signal.SIGKILL)
        except ProcessLookupError:
            pass
        finally:
            pid.value = 0
