import threading

from collections import defaultdict
from collections import deque
from datetime import datetime
from datetime import timedelta
from datetime import timezone

from detectors.base import BaseDetector

from core.types import DetectionType


class DDOSDetector(BaseDetector):

    NAME = "ddos"

    WINDOW_SECONDS = 60

    REQUEST_THRESHOLD = 100

    RESPONSE_429_THRESHOLD = 20

    # IPs not seen within this many seconds are evicted from memory
    EVICTION_SECONDS = 300

    def __init__(self):

        self._lock = threading.Lock()

        self.request_history = defaultdict(deque)
        self.response_429_history = defaultdict(deque)

        # Tracks last-seen time per IP for eviction
        self._last_seen = {}

    def _evict_stale_ips(self, now):
        """Remove IPs that haven't been seen recently to prevent unbounded growth."""

        cutoff = now - timedelta(seconds=self.EVICTION_SECONDS)

        stale = [
            ip for ip, last in self._last_seen.items()
            if last < cutoff
        ]

        for ip in stale:
            del self.request_history[ip]
            del self.response_429_history[ip]
            del self._last_seen[ip]

    def _trim_window(self, history, cutoff):
        while history and history[0] < cutoff:
            history.popleft()

    def detect(self, event):

        if not event.ip:
            return []

        now = datetime.now(timezone.utc)
        ip = event.ip
        cutoff = now - timedelta(seconds=self.WINDOW_SECONDS)

        with self._lock:

            self._last_seen[ip] = now

            self.request_history[ip].append(now)
            self._trim_window(self.request_history[ip], cutoff)

            if event.status_code == 429:
                self.response_429_history[ip].append(now)
                self._trim_window(self.response_429_history[ip], cutoff)

            request_count = len(self.request_history[ip])
            response_429_count = len(self.response_429_history[ip])

            # Evict stale IPs periodically (every 100 events)
            if len(self._last_seen) % 100 == 0:
                self._evict_stale_ips(now)

        if (
            request_count >= self.REQUEST_THRESHOLD
            or response_429_count >= self.RESPONSE_429_THRESHOLD
        ):
            return [DetectionType.DDOS, DetectionType.TRAFFIC]

        return []
