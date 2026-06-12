from detectors.base import BaseDetector

from core.types import DetectionType


class ErrorDetector(BaseDetector):

    NAME = "error"

    ERROR_KEYWORDS = [
        "exception",
        "traceback",
        "fatal",
        "segmentation fault",
        "stack trace",
        "uncaught"
    ]

    def detect(self, event):

        detections = []

        if (
            event.status_code is not None
            and event.status_code >= 500
        ):
            detections.append(DetectionType.ERROR)

        line = event.raw_line.lower()

        if any(keyword in line for keyword in self.ERROR_KEYWORDS):
            detections.append(DetectionType.ERROR)

        return detections
