from enum import Enum


class DetectionType(Enum):

    # Operational
    ERROR = "error"

    # Traffic / volumetric
    DDOS = "ddos"
    TRAFFIC = "traffic"
    BRUTE_FORCE = "brute_force"

    # Injection attacks
    SQL_INJECTION = "sql_injection"

    # Client-side attacks
    XSS = "xss"

    # Generic security bucket
    SECURITY = "security"
