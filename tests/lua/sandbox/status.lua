-- Test: sbx.status() shape (pure, no VM booted)
-- Requires: the `sandbox` feature. Runs on any machine — asserts the shape and
-- types of the availability table, not whether Windows Sandbox is actually
-- available (so it passes on hosts without the feature).

assert(type(sbx) == "table", "sbx global should be a table")
assert(type(sbx.provision) == "function", "sbx.provision should be a function")
assert(type(sbx.connect) == "function", "sbx.connect should be a function")
assert(type(sbx.events) == "function", "sbx.events should be a function")
assert(type(sbx.status) == "function", "sbx.status should be a function")
-- Recovery + introspection surface (RETRO B5/F10).
assert(type(sbx.list) == "function", "sbx.list should be a function")
assert(type(sbx.stop) == "function", "sbx.stop should be a function")
assert(type(sbx.stop_all) == "function", "sbx.stop_all should be a function")
assert(type(sbx.attach) == "function", "sbx.attach should be a function")
assert(type(sbx.ops) == "function", "sbx.ops should be a function")

-- sbx.list() works without a VM (returns an empty table on a clean machine).
local running = sbx.list()
assert(type(running) == "table", "sbx.list() should return a table")

-- The op vocabulary matches etw.ops().
local ops = sbx.ops()
assert(type(ops.all) == "table" and #ops.all > 20, "sbx.ops().all should list every token")

local s = sbx.status()
assert(type(s) == "table", "status() should return a table")
assert(type(s.supported) == "boolean", "status.supported should be boolean")
assert(type(s.build) == "number", "status.build should be a number")
assert(type(s.wsb_present) == "boolean", "status.wsb_present should be boolean")
-- reason is a string when unavailable, nil when available.
assert(s.reason == nil or type(s.reason) == "string", "status.reason should be string|nil")

-- When usable, there is no reason; when not, there is one. (Consistency check.)
local usable = s.supported and s.wsb_present
if usable then
    assert(s.reason == nil, "usable sandbox should have no reason")
else
    assert(type(s.reason) == "string" and #s.reason > 0, "unusable sandbox should explain why")
end

return { passed = true }
