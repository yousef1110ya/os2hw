import threading

from collections import defaultdict
from collections import deque
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from detectors.base import BaseDetector

from core.types import DetectionType


class BruteForceDetector(BaseDetector):

    NAME = "brute_force"

    # Rolling window in seconds
    WINDOW_SECONDS = 60

    # Number of 401/403 responses from one IP within the window to trigger
    FAILURE_THRESHOLD = 10

    # Evict IPs not seen within this many seconds
    EVICTION_SECONDS = 300

    AUTH_FAILURE_CODES = {401, 403}

    def __init__(self):

        self._lock = threading.Lock()

        self.failure_history = defaultdict(deque)

        self._last_seen = {}

    def _evict_stale_ips(self, now):

        cutoff = now - timedelta(seconds=self.EVICTION_SECONDS)

        stale = [
            ip for ip, last in self._last_seen.items()
            if last < cutoff
        ]

        for ip in stale:
            del self.failure_history[ip]
            del self._last_seen[ip]

    def detect(self, event):

        if not event.ip:
            return []

        if event.status_code not in self.AUTH_FAILURE_CODES:
            return []

        now = datetime.now(timezone.utc)
        ip = event.ip
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        with self._lock:

            self._last_seen[ip] = now

            self.failure_history[ip].append(now)

            while (
                self.failure_history[ip]
                and self.failure_history[ip][0] < cutoff
            ):
                self.failure_history[ip].popleft()

            failure_count = len(self.failure_history[ip])

            if len(self._last_seen) % 100 == 0:
                self._evict_stale_ips(now)

        if failure_count >= self.FAILURE_THRESHOLD:
            return [DetectionType.BRUTE_FORCE, DetectionType.SECURITY]

        return []
