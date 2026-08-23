-- Test: the optional 4th argument to dbg:launch (a table of extra environment
-- variables) reaches the child through CreateProcessW's lpEnvironment.
--
-- cmd.exe exits with the value of %JOYBUG_TEST_EXIT%; that variable only
-- exists if our block was applied. The debugger's own environment must still
-- be inherited (the merge is additive): cmd.exe is found via the inherited
-- PATH/SystemRoot, so a replaced-not-merged block would fail to launch at all.

local exit_code = nil

dbg:on_process_exited(function(pid, code)
    exit_code = code
end)

dbg:launch('cmd.exe /c "exit %JOYBUG_TEST_EXIT%"', false, nil, { JOYBUG_TEST_EXIT = "42" })
dbg:run()

assert(exit_code == 42,
    "Expected exit code 42 from the injected environment variable, got " .. tostring(exit_code))

return { passed = true }
