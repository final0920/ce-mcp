-- ce-mcp embedded Lua script-facing handlers
-- Extracted from bridge.lua for the v0.2.0 modular backend layout.

-- ============================================================================
-- COMMAND HANDLERS - LUA EVALUATION
-- ============================================================================

local function cmd_evaluate_lua(params)
    local code = params.code
    if not code then return { success = false, error = "No code provided" } end
    
    local fn, err = loadstring(code)
    if not fn then return { success = false, error = "Compile error: " .. tostring(err) } end
    
    local ok, result = pcall(fn)
    if not ok then return { success = false, error = "Runtime error: " .. tostring(result) } end
    
    return { success = true, result = tostring(result) }
end

local function cmd_auto_assemble(params)
    local script = params.script or params.code
    local disable = params.disable or false
    
    if not script then return { success = false, error = "No script provided" } end
    
    local success, disableInfo = autoAssemble(script)
    
    if success then
        local result = {
            success = true,
            executed = true
        }
        -- If disable info is returned, include symbol addresses
        if disableInfo and disableInfo.symbols then
            result.symbols = {}
            for name, addr in pairs(disableInfo.symbols) do
                result.symbols[name] = toHex(addr)
            end
        end
        return result
    else
        return {
            success = false,
            error = "AutoAssemble failed: " .. tostring(disableInfo)
        }
    end
end

