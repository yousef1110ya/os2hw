import re

from detectors.base import BaseDetector

from core.types import DetectionType


class XSSDetector(BaseDetector):

    NAME = "xss"

    # Patterns checked against the decoded URL path and raw line.
    PATTERNS = [
        # Classic script tag injection
        re.compile(r"<\s*script[\s>]", re.IGNORECASE),

        # Script closing tag
        re.compile(r"<\s*/\s*script\s*>", re.IGNORECASE),

        # Inline event handlers: onerror=, onload=, onclick=, etc.
        re.compile(r"\bon\w+\s*=", re.IGNORECASE),

        # javascript: URI scheme (href, src, action payloads)
        re.compile(r"javascript\s*:", re.IGNORECASE),

        # vbscript: URI scheme
        re.compile(r"vbscript\s*:", re.IGNORECASE),

        # Common XSS payload entry points: <img, <iframe, <object, <embed, <svg
        re.compile(r"<\s*(img|iframe|object|embed|svg|body|link|meta)[\s>]", re.IGNORECASE),

        # expression() — CSS-based XSS (IE legacy but still probed)
        re.compile(r"expression\s*\(", re.IGNORECASE),

        # document.cookie access attempts
        re.compile(r"document\s*\.\s*cookie", re.IGNORECASE),

        # alert() / prompt() / confirm() — common PoC payloads
        re.compile(r"\b(alert|prompt|confirm)\s*\(", re.IGNORECASE),

        # HTML entity encoded < (%3C) combined with script
        re.compile(r"%3c\s*script", re.IGNORECASE),
    ]

    def detect(self, event):

        target = self._build_target(event)

        if not target:
            return []

        for pattern in self.PATTERNS:
            if pattern.search(target):
                return [DetectionType.XSS, DetectionType.SECURITY]

        return []

    def _build_target(self, event):
        """
        Combine path and raw line; URL-decode to catch encoded payloads.
        """

        parts = []

        if event.path:
            parts.append(self._url_decode(event.path))

        if event.raw_line:
            parts.append(event.raw_line)

        return " ".join(parts)

    @staticmethod
    def _url_decode(value):
        try:
            from urllib.parse import unquote
            return unquote(value)
        except Exception:
            return value
