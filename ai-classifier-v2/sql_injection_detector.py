import re

from detectors.base import BaseDetector

from core.types import DetectionType


class SQLInjectionDetector(BaseDetector):

    NAME = "sql_injection"

    # Patterns checked against the decoded URL path and query string.
    # Each pattern targets a distinct SQLi technique.
    PATTERNS = [
        # Classic tautology: ' OR '1'='1, " OR "a"="a
        re.compile(r"['\"]?\s*or\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+", re.IGNORECASE),

        # UNION-based extraction: UNION SELECT, UNION ALL SELECT
        re.compile(r"\bunion\s+(all\s+)?select\b", re.IGNORECASE),

        # Stacked / batched queries
        re.compile(r";\s*(drop|delete|insert|update|create|alter|truncate)\b", re.IGNORECASE),

        # Comment-based termination: --, #, /*
        re.compile(r"(--|#|/\*).*", re.IGNORECASE),

        # Blind boolean: AND 1=1, AND 1=2
        re.compile(r"\band\s+\d+=\d+", re.IGNORECASE),

        # Time-based blind: SLEEP(), WAITFOR DELAY, BENCHMARK()
        re.compile(r"\b(sleep|waitfor\s+delay|benchmark)\s*\(", re.IGNORECASE),

        # Information schema probing
        re.compile(r"\binformation_schema\b", re.IGNORECASE),

        # Common SQLi tools leave this fingerprint in the user-agent / path
        re.compile(r"sqlmap", re.IGNORECASE),
    ]

    def detect(self, event):

        target = self._build_target(event)

        if not target:
            return []

        for pattern in self.PATTERNS:
            if pattern.search(target):
                return [DetectionType.SQL_INJECTION, DetectionType.SECURITY]

        return []

    def _build_target(self, event):
        """
        Combine path and raw line for matching.
        URL-decode the path so encoded payloads like %27%20OR are caught.
        """

        parts = []

        if event.path:
            parts.append(self._url_decode(event.path))

        if event.raw_line:
            parts.append(event.raw_line)

        return " ".join(parts)

    @staticmethod
    def _url_decode(value):
        """Simple percent-decode; avoids importing urllib in hot path."""
        try:
            from urllib.parse import unquote
            return unquote(value)
        except Exception:
            return value
