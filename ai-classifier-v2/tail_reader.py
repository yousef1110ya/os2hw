import time
import os


def follow(filepath, retry_interval=2.0):
    """
    Tail a file indefinitely, yielding new lines as they are written.

    Handles:
    - File not yet existing at startup (waits until it appears)
    - Log rotation (detects inode change or truncation, reopens)
    - Transient read errors (logs and retries)
    """

    print(f"[tail_reader] Waiting for {filepath} ...")

    while not os.path.exists(filepath):
        time.sleep(retry_interval)

    print(f"[tail_reader] Following {filepath}")

    file = None
    inode = None

    try:

        file = open(filepath, "r")
        file.seek(0, 2)
        inode = os.fstat(file.fileno()).st_ino

        while True:

            line = file.readline()

            if line:
                yield line
                continue

            # No new data — check for rotation before sleeping
            time.sleep(0.1)

            try:
                current_inode = os.stat(filepath).st_ino
            except FileNotFoundError:
                # File was deleted; wait for it to reappear
                print(f"[tail_reader] {filepath} removed, waiting for reappear ...")
                file.close()
                file = None

                while not os.path.exists(filepath):
                    time.sleep(retry_interval)

                file = open(filepath, "r")
                inode = os.fstat(file.fileno()).st_ino
                print(f"[tail_reader] Reopened {filepath}")
                continue

            if current_inode != inode:
                # Log was rotated — reopen from the start of the new file
                print(f"[tail_reader] Rotation detected on {filepath}, reopening ...")
                file.close()
                file = open(filepath, "r")
                inode = os.fstat(file.fileno()).st_ino

    except Exception as exc:
        print(f"[tail_reader] Unexpected error on {filepath}: {exc}")
        raise

    finally:
        if file:
            file.close()
