-- ce-mcp embedded Lua backend transport primitives
-- Minimal self-driven shell: queue-backed transport so the backend can run
-- without Rust synchronously calling dispatch() for every request.

local function queue_push(queue, value)
    queue[#queue + 1] = value
    return #queue
end

local function queue_shift(queue)
    if #queue == 0 then
        return nil
    end

    local value = queue[1]
    table.remove(queue, 1)
    return value
end

local function createLoopbackTransport(options)
    options = type(options) == "table" and options or {}

    local request_queue = {}
    local response_queue = {}
    local next_request_id = 0
    local closed = false

    local transport = {
        kind = "loopback",
        name = options.name or "embedded-loopback",
    }

    function transport:is_closed()
        return closed
    end

    function transport:close()
        closed = true
    end

    function transport:reset()
        request_queue = {}
        response_queue = {}
        next_request_id = 0
        closed = false
    end

    function transport:stats()
        return {
            kind = self.kind,
            name = self.name,
            closed = closed,
            pending_requests = #request_queue,
            pending_responses = #response_queue,
            next_request_id = next_request_id,
        }
    end

    function transport:push_request(request)
        if closed then
            return nil, "transport closed"
        end
        if type(request) ~= "table" then
            return nil, "request must be a table"
        end
        if request.method == nil or request.method == "" then
            return nil, "request missing method"
        end

        next_request_id = next_request_id + 1
        local envelope = {
            id = request.id or ("req-" .. tostring(next_request_id)),
            method = request.method,
            params_json = request.params_json or "{}",
            submitted_at = request.submitted_at or os.time(),
            meta = request.meta,
        }

        queue_push(request_queue, envelope)
        return envelope
    end

    function transport:pop_request()
        return queue_shift(request_queue)
    end

    function transport:push_response(response)
        if closed then
            return nil, "transport closed"
        end
        if type(response) ~= "table" then
            return nil, "response must be a table"
        end

        local envelope = {
            id = response.id,
            method = response.method,
            body_json = response.body_json or "{}",
            produced_at = response.produced_at or os.time(),
            meta = response.meta,
        }

        queue_push(response_queue, envelope)
        return envelope
    end

    function transport:pop_response()
        return queue_shift(response_queue)
    end

    return transport
end
