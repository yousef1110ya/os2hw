require "apache2"

rate_limit_clients = rate_limit_clients or {}

local WINDOW_SECONDS = 10
local MAX_REQUESTS_PER_WINDOW = 120
local DEMO_USER_AGENT = "os2-traffic-generator"

function rate_limit(r)
    local user_agent = r.headers_in["User-Agent"] or ""

    if not string.find(user_agent, DEMO_USER_AGENT, 1, true) then
        return apache2.DECLINED
    end

    local now = os.time()
    local ip = r.useragent_ip or "unknown"
    local client = rate_limit_clients[ip]

    if client == nil or now - client.started_at >= WINDOW_SECONDS then
        client = {
            started_at = now,
            count = 0
        }
        rate_limit_clients[ip] = client
    end

    client.count = client.count + 1

    if client.count > MAX_REQUESTS_PER_WINDOW then
        r.status = 429
        r.headers_out["Retry-After"] = tostring(WINDOW_SECONDS)
        return 429
    end

    return apache2.DECLINED
end
