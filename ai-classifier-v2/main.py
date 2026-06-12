import threading

from prometheus_client import start_http_server

from config.settings import (
    ACCESS_LOG_PATH,
    ERROR_LOG_PATH,
    PROMETHEUS_PORT
)

from core.engine import DetectionEngine

from core.parser import (
    parse_access,
    parse_error
)

from reader.tail_reader import follow

from metrics.exporter import increment


engine = DetectionEngine()


def process_access_logs():

    for line in follow(ACCESS_LOG_PATH):

        event = parse_access(line)

        if not event:
            continue

        for detection in engine.process(event):
            increment(detection)


def process_error_logs():

    for line in follow(ERROR_LOG_PATH):

        event = parse_error(line)

        # parse_error returns None for blank lines
        if not event:
            continue

        for detection in engine.process(event):
            increment(detection)


if __name__ == "__main__":

    start_http_server(PROMETHEUS_PORT)

    threading.Thread(
        target=process_access_logs,
        daemon=True
    ).start()

    threading.Thread(
        target=process_error_logs,
        daemon=True
    ).start()

    # Block the main thread without busy-spinning
    threading.Event().wait()
