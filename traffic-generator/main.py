import os
import time
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import as_completed
from urllib.parse import quote

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning


TARGET_URL = os.getenv(
    "TARGET_URL",
    "https://apache"
).rstrip("/")

CONCURRENCY = int(
    os.getenv(
        "CONCURRENCY",
        "80"
    )
)

DURATION_SECONDS = int(
    os.getenv(
        "DURATION_SECONDS",
        "120"
    )
)

VERIFY_TLS = os.getenv(
    "VERIFY_TLS",
    "false"
).lower() == "true"


if not VERIFY_TLS:
    requests.packages.urllib3.disable_warnings(
        category=InsecureRequestWarning
    )


def request(method, path, **kwargs):

    return requests.request(
        method,
        f"{TARGET_URL}{path}",
        timeout=10,
        verify=VERIFY_TLS,
        headers={
            "User-Agent": "os2-traffic-generator/1.0",
            **kwargs.pop("headers", {})
        },
        **kwargs
    )


def wait_for_target():

    deadline = time.time() + 120

    while time.time() < deadline:
        try:
            response = request(
                "GET",
                "/actuator/health"
            )

            if response.status_code < 500:
                print(
                    "Target is reachable:",
                    response.status_code
                )
                return
        except requests.RequestException as exc:
            print(
                "Waiting for target:",
                exc
            )

        time.sleep(
            3
        )

    raise RuntimeError(
        "Target did not become reachable in time"
    )


def get_user_token():

    email = f"os2-demo-{int(time.time())}@example.com"
    password = "password123"

    register_payload = {
        "name": "OS2 Demo User",
        "email": email,
        "password": password
    }

    response = request(
        "POST",
        "/api/auth/register",
        json=register_payload
    )

    if response.status_code >= 400:
        print(
            "Register failed, trying login:",
            response.status_code,
            response.text[:200]
        )
        response = request(
            "POST",
            "/api/auth/login",
            json={
                "email": email,
                "password": password
            }
        )

    response.raise_for_status()

    token = response.json()[
        "token"
    ]

    print(
        "Demo user token acquired"
    )

    return token


def auth_headers(token):

    return {
        "Authorization": f"Bearer {token}"
    }


def run_seed_traffic(token):

    print(
        "Generating normal, security, and suspicious traffic"
    )

    encoded_sqli = quote(
        "' OR 1=1--"
    )
    encoded_xss = quote(
        "<script>alert(1)</script>"
    )

    requests_to_send = [
        ("GET", "/api/products", auth_headers(token), None),
        ("GET", "/api/categories", auth_headers(token), None),
        ("GET", "/api/users/me", {}, None),
        ("GET", "/api/users", auth_headers(token), None),
        ("GET", f"/api/products?q={encoded_sqli}", {}, None),
        ("GET", f"/api/products?q={encoded_xss}", {}, None),
    ]

    for method, path, headers, payload in requests_to_send:
        try:
            response = request(
                method,
                path,
                headers=headers,
                json=payload
            )
            print(
                method,
                path,
                response.status_code
            )
        except requests.RequestException as exc:
            print(
                method,
                path,
                "failed:",
                exc
            )


def burst_request(token):

    try:
        response = request(
            "GET",
            "/api/products",
            headers=auth_headers(token)
        )
        return response.status_code
    except requests.RequestException:
        return "error"


def run_burst(token):

    print(
        "Generating burst traffic",
        f"concurrency={CONCURRENCY}",
        f"duration_seconds={DURATION_SECONDS}"
    )

    deadline = time.time() + DURATION_SECONDS
    counts = {}

    with ThreadPoolExecutor(
        max_workers=CONCURRENCY
    ) as executor:
        while time.time() < deadline:
            futures = [
                executor.submit(
                    burst_request,
                    token
                )
                for _ in range(CONCURRENCY)
            ]

            for future in as_completed(
                futures
            ):
                status = future.result()
                counts[status] = counts.get(
                    status,
                    0
                ) + 1

    print(
        "Burst result counts:",
        counts
    )


def main():

    wait_for_target()
    token = get_user_token()
    run_seed_traffic(
        token
    )
    run_burst(
        token
    )


if __name__ == "__main__":
    main()
