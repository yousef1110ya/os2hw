import re

from core.event import LogEvent


ACCESS_PATTERN = re.compile(
    r'(\d+\.\d+\.\d+\.\d+).*?"(\w+) (.*?) HTTP.*?" (\d+)'
)


def parse_access(line):

    match = ACCESS_PATTERN.search(line)

    if not match:
        return None

    return LogEvent(
        source="access",
        raw_line=line,
        ip=match.group(1),
        method=match.group(2),
        path=match.group(3),
        status_code=int(match.group(4))
    )


def parse_error(line):

    if not line or not line.strip():
        return None

    return LogEvent(
        source="error",
        raw_line=line
    )
