-- ce-mcp embedded Lua backend lifecycle shell
-- Wraps the raw command bridge with a tiny runtime + queue transport so the
-- backend can later be driven as a long-lived Lua worker without changing the
-- existing command handler core.

local RAW_COMMAND_BRIDGE = createEmbeddedCommandBridge()

local function normalize_runtime_limit(limit)
    local numeric = tonumber(limit)
    if not numeric then
        return 1
    end
    numeric = math.floor(numeric)
    if numeric < 1 then
        return 1
    end
    if numeric > 128 then
        return 128
    end
    return numeric
end

local function createEmbeddedBackendRuntime(options)
    options = type(options) == "table" and options or {}

    local runtime = {
        transport = options.transport or createLoopbackTransport(options.transport_options),
        bridge = options.bridge or RAW_COMMAND_BRIDGE,
        state = {
            running = false,
            start_count = 0,
            handled_requests = 0,
            last_method = nil,
            last_error = nil,
            last_dispatch_at = nil,
            last_response_id = nil,
            stop_reason = nil,
            mode = options.mode or "embedded",
            created_at = os.time(),
            started_at = nil,
        }
    }

    function runtime:status()
        local transport_stats = self.transport and self.transport:stats() or {}
        return {
            success = true,
            version = VERSION,
            mode = self.state.mode,
            running = self.state.running,
            created_at = self.state.created_at,
            started_at = self.state.started_at,
            start_count = self.state.start_count,
            handled_requests = self.state.handled_requests,
            last_method = self.state.last_method,
            last_error = self.state.last_error,
            last_dispatch_at = self.state.last_dispatch_at,
            last_response_id = self.state.last_response_id,
            stop_reason = self.state.stop_reason,
            transport = transport_stats,
        }
    end

    function runtime:start(config)
        if self.transport and self.transport.is_closed and self.transport:is_closed() and self.transport.reset then
            self.transport:reset()
        end

        self.state.running = true
        self.state.start_count = self.state.start_count + 1
        self.state.stop_reason = nil
        self.state.started_at = os.time()
        self.state.config = type(config) == "table" and config or {}
        return self:status()
    end

    function runtime:stop(reason)
        self.state.running = false
        self.state.stop_reason = reason or self.state.stop_reason or "stopped"
        return self:status()
    end

    function runtime:dispatch(method, params_json)
        if not self.state.running then
            self:start({ reason = "implicit-dispatch-start" })
        end

        self.state.last_method = method
        self.state.last_dispatch_at = os.time()
        self.state.handled_requests = self.state.handled_requests + 1

        local ok, body_json = pcall(self.bridge.dispatch, method, params_json)
        if not ok then
            self.state.last_error = tostring(body_json)
            return encode_backend_error(body_json)
        end

        self.state.last_error = nil
        return body_json
    end

    function runtime:submit(method, params_json, request_id, meta)
        if not self.transport or not self.transport.push_request then
            return { success = false, error = "transport unavailable" }
        end

        local envelope, err = self.transport:push_request({
            id = request_id,
            method = method,
            params_json = params_json or "{}",
            meta = meta,
        })
        if not envelope then
            return { success = false, error = err }
        end

        local stats = self.transport:stats()
        return {
            success = true,
            queued = true,
            id = envelope.id,
            pending_requests = stats.pending_requests or 0,
            pending_responses = stats.pending_responses or 0,
        }
    end

    function runtime:step()
        if not self.state.running then
            return { success = false, error = "runtime not running" }
        end

        if not self.transport or not self.transport.pop_request then
            return { success = false, error = "transport unavailable" }
        end

        local request = self.transport:pop_request()
        if not request then
            return { success = true, processed = 0, idle = true }
        end

        local body_json = self:dispatch(request.method, request.params_json)
        local response, err = self.transport:push_response({
            id = request.id,
            method = request.method,
            body_json = body_json,
            meta = request.meta,
        })
        if not response then
            self.state.last_error = err
            return {
                success = false,
                error = err,
                request_id = request.id,
                method = request.method,
            }
        end

        self.state.last_response_id = response.id
        local stats = self.transport:stats()
        return {
            success = true,
            processed = 1,
            request_id = response.id,
            method = response.method,
            pending_requests = stats.pending_requests or 0,
            pending_responses = stats.pending_responses or 0,
        }
    end

    function runtime:drain(limit)
        local max_steps = normalize_runtime_limit(limit)
        local steps = {}
        local last_idle = false

        for _ = 1, max_steps do
            local result = self:step()
            if not result.success then
                return result
            end
            if (result.processed or 0) == 0 then
                last_idle = true
                break
            end
            steps[#steps + 1] = result
        end

        local stats = self.transport and self.transport:stats() or {}
        return {
            success = true,
            processed = #steps,
            idle = last_idle,
            steps = steps,
            pending_requests = stats.pending_requests or 0,
            pending_responses = stats.pending_responses or 0,
        }
    end

    function runtime:recv_response()
        if not self.transport or not self.transport.pop_response then
            return { success = false, error = "transport unavailable" }
        end

        local response = self.transport:pop_response()
        local stats = self.transport:stats()
        return {
            success = true,
            response = response,
            pending_requests = stats.pending_requests or 0,
            pending_responses = stats.pending_responses or 0,
            idle = response == nil,
        }
    end

    function runtime:cleanup(reason)
        self:stop(reason or "cleanup")
        if self.transport and self.transport.reset then
            self.transport:reset()
        end
        return self.bridge.cleanup()
    end

    return runtime
end

local function ensureEmbeddedBackendRuntime()
    local existing = rawget(_G, "__ce_mcp_embedded_runtime")
    if type(existing) == "table" then
        return existing
    end

    local runtime = createEmbeddedBackendRuntime()
    runtime:start({ reason = "bootstrap" })
    _G["__ce_mcp_embedded_runtime"] = runtime
    return runtime
end

local function decode_runtime_json_argument(argument)
    local ok, decoded = decode_backend_params(argument)
    if not ok then
        return nil, decoded
    end
    return decoded, nil
end

_G["__ce_mcp_embedded_runtime_status_json"] = function()
    return encode_backend_result(ensureEmbeddedBackendRuntime():status())
end

_G["__ce_mcp_embedded_runtime_start_json"] = function(config_json)
    local config, err = decode_runtime_json_argument(config_json)
    if err then
        return encode_backend_error(err)
    end
    return encode_backend_result(ensureEmbeddedBackendRuntime():start(config))
end

_G["__ce_mcp_embedded_runtime_stop_json"] = function(reason)
    return encode_backend_result(ensureEmbeddedBackendRuntime():stop(reason))
end

_G["__ce_mcp_embedded_transport_submit_json"] = function(request_json)
    local request, err = decode_runtime_json_argument(request_json)
    if err then
        return encode_backend_error(err)
    end
    if type(request) ~= "table" then
        return encode_backend_error("request payload must decode to an object")
    end

    local method = request.method
    if method == nil or method == "" then
        return encode_backend_error("request missing method")
    end

    local params_json = request.params_json
    if params_json == nil and request.params ~= nil then
        params_json = json.encode(request.params)
    end

    local result = ensureEmbeddedBackendRuntime():submit(method, params_json or "{}", request.id, request.meta)
    if not result.success then
        return encode_backend_error(result.error)
    end
    return encode_backend_result(result)
end

_G["__ce_mcp_embedded_transport_step_json"] = function(limit)
    return encode_backend_result(ensureEmbeddedBackendRuntime():drain(limit))
end

_G["__ce_mcp_embedded_transport_recv_json"] = function()
    return encode_backend_result(ensureEmbeddedBackendRuntime():recv_response())
end

local function cleanupZombieState()
    return ensureEmbeddedBackendRuntime():cleanup("cleanupZombieState")
end

local function dispatch(method, params_json)
    return ensureEmbeddedBackendRuntime():dispatch(method, params_json)
end
