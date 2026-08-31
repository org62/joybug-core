-- Test: `etw` global shape + the stateless reader/time helpers (pure, no tracer).
-- Requires: the `etw` feature. Runs on any machine — never launches a tracer
-- (that needs elevation); exercises only the pure surface.

assert(type(etw) == "table", "etw global should be a table")
assert(type(etw.start) == "function", "etw.start should be a function")
assert(type(etw.spawn) == "function", "etw.spawn should be a function")
assert(type(etw.events) == "function", "etw.events should be a function")
assert(type(etw.done) == "function", "etw.done should be a function")
assert(type(etw.time) == "function", "etw.time should be a function")

-- FILETIME epoch (1601-01-01) offset -> Unix epoch -> 00:00:00.000.
assert(etw.time(116444736000000000) == "00:00:00.000", "etw.time epoch should be 00:00:00.000")
-- Before the Unix epoch -> empty.
assert(etw.time(0) == "", "etw.time before unix epoch should be empty")

-- Nonexistent file: empty events, not done.
local missing = os.tmpname() .. "-does-not-exist.jsonl"
assert(#etw.events(missing) == 0, "events of a missing file should be empty")
assert(etw.done(missing) == false, "done of a missing file should be false")

-- Write a 2-line JSONL, read all, then read incrementally from seq 2.
local path = os.tmpname() .. "-etw-shape.jsonl"
local f = assert(io.open(path, "w"))
f:write('{"kind":"file","op":"create","pid":10,"ts":116444736000000000}\n')
f:write('{"kind":"process","op":"start","pid":11,"ts":116444736000000000}\n')
f:close()

local evs = etw.events(path)
assert(#evs == 2, "should read 2 events, got " .. #evs)
assert(evs[1].seq == 1 and evs[1].kind == "file" and evs[1].op == "create", "row 1 shape")
assert(evs[1].time == "00:00:00.000", "row 1 formatted time")
assert(evs[2].seq == 2 and evs[2].kind == "process", "row 2 shape")

-- Append a third line; the incremental read from seq 2 yields exactly one.
local f2 = assert(io.open(path, "a"))
f2:write('{"kind":"network","op":"connect","pid":12,"ts":116444736000000000}\n')
f2:close()

local more = etw.events(path, 2)
assert(#more == 1, "incremental read should yield exactly 1, got " .. #more)
assert(more[1].seq == 3 and more[1].kind == "network", "incremental row shape")

os.remove(path)
return { passed = true }
