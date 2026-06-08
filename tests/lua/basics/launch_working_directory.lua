-- Test: the optional working_directory argument to dbg:launch is passed
-- through to CreateProcessW (lpCurrentDirectory).
--
-- Launching with a non-existent working directory must fail. If the argument
-- were ignored (CreateProcessW called with a NULL current directory), the
-- launch would instead succeed, so this is a functional check that the
-- parameter actually reaches the OS.

local bogus_dir = "C:\\joybug_nonexistent_working_dir_zzz"

local ok = pcall(function()
    dbg:launch('cmd.exe /c "echo test"', false, bogus_dir)
    dbg:run()
end)

assert(not ok, "launch with a non-existent working directory should fail")

return { passed = true }
