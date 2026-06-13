# OS2 Project

This repository runs the full university project stack with Docker Compose:

- two e-commerce Spring Boot containers from the DockerHub image `birobyte1110/java-app:docker`
- PostgreSQL, Redis, and RabbitMQ for the e-commerce backend
- Apache HTTPS reverse proxy and load balancer
- AI log classifier that reads Apache access/error logs and app request-body audit logs
- Prometheus, Apache exporter, cAdvisor, and Grafana dashboards
- optional traffic generator for demo/testing

The e-commerce source is kept in the `e-commerce` submodule for review, but the running stack uses the DockerHub image.

## Run

```powershell
docker compose up -d
```

The Spring Boot containers can take around 2 to 3 minutes to finish startup. Apache may return `503` until `app1` and `app2` are ready.

## URLs

- E-commerce API through Apache: `https://localhost`
- E-commerce API with project hostname: `https://os2.com`
- Prometheus direct: `http://localhost:9090`
- Prometheus through Apache: `https://prom.os2.com`
- Grafana direct: `http://localhost:3000`
- Grafana through Apache: `https://grafana.os2.com`
- AI classifier metrics: `http://localhost:8000/metrics`
- Apache exporter metrics: `http://localhost:9117/metrics`
- cAdvisor metrics: `http://localhost:8082/metrics`

Grafana default login:

```text
admin / admin123
```

To use the hostnames, add these entries to your hosts file:

```text
127.0.0.1 os2.com
127.0.0.1 prom.os2.com
127.0.0.1 grafana.os2.com
```

## Demo Traffic

Run a full demo load:

```powershell
docker compose --profile demo run --rm traffic-generator
```

Run a shorter smoke demo:

```powershell
docker compose --profile demo run --rm -e DURATION_SECONDS=20 -e CONCURRENCY=30 traffic-generator
```

The generator creates normal API traffic, unauthenticated/auth-forbidden requests, SQLi/XSS-looking requests, and burst traffic. Apache applies a demo rate-limit hook to the generator traffic and returns `429 Too Many Requests` once the short-window threshold is exceeded. These requests are written to the shared Apache logs, classified by the AI classifier, and exposed to Prometheus/Grafana.

The generator also sends JSON-body SQLi/XSS attempts through `PUT /api/users/me`. The e-commerce app writes sanitized request-body audit events to:

```text
/shared-logs/request-audit.log
```

Sensitive fields such as `password`, `token`, `secret`, `apiKey`, and `Authorization` are masked before they are written.

## Verification

```powershell
docker compose ps
curl.exe -k https://localhost/actuator/health
curl.exe http://localhost:9090/-/ready
curl.exe http://localhost:3000/api/health
curl.exe http://localhost:8000/metrics
```

Prometheus should show these active targets as `up`:

- `spring-cluster`: `app1:8080`, `app2:8080`
- `ai_classifier`: `ai-classifier:8000`
- `apache`: `apache-exporter:9117`
- `cadvisor`: `cadvisor:8080`
- `prometheus`: `prometheus:9090`

Grafana provisions four dashboards under the `OS2` folder:

- AI Log Classifier
- Apache Observability
- Container Observability
- Ecommerce Observability

## Notes

- Mail credentials are optional. If `SPRING_MAIL_USERNAME` and `SPRING_MAIL_PASSWORD` are not set, Compose will warn and pass blank values.
- The stack uses a self-signed certificate from `apache/server.crt` and `apache/server.key`, so browser/curl TLS warnings are expected.
- The optional traffic generator is not started by normal `docker compose up -d` because it is behind the `demo` profile.
- The Apache rate-limit demo uses `apache/rate_limit.lua` through `mod_lua`; it only applies to the traffic generator user agent so normal manual API testing is not throttled.
- Request-body audit logging is implemented in the e-commerce app image. After changing the e-commerce source, rebuild and push the DockerHub `docker` branch image before expecting another machine to pick up the new behavior through this root Compose stack.

## Manual Body Injection Tests

After registering/logging in and getting a bearer token, send these through Apache:

```text
PUT https://localhost/api/users/me
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "' OR 1=1--"
}
```

```text
PUT https://localhost/api/users/me
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "<script>alert(1)</script>"
}
```

Then check:

```text
http://localhost:8000/metrics
```

Expected counters:

```text
log_detections_total{type="sqli"}
log_detections_total{type="xss"}
log_detections_total{type="suspicious"}
```
