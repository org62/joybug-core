# Detailed Implementation of Stepping (Step In/Over/Out) in TitanEngine, KoiDbg, and GleeBug

This document provides a comprehensive, detailed description of how stepping (Step In, Step Over, Step Out) is implemented in the following debugging engines:

- **[x64dbg/TitanEngine](https://github.com/x64dbg/TitanEngine)**
- **[keowu/koidbg](https://github.com/keowu/koidbg)**
- **[x64dbg/GleeBug](https://github.com/x64dbg/GleeBug)**

---

## 1. x64dbg/TitanEngine

### Step Into

- **Core Mechanism**:
  - Utilizes the hardware debug feature of the CPU by setting the Trap Flag (TF) in the EFlags register (on x86/x64) to trigger a `STATUS_SINGLE_STEP` exception after the next instruction.
  - The function `StepInto` acquires a critical section and checks if a step is already active. If not, it reads the current instruction, and if it's not a special case (like `PUSHF` or segment manipulation), it sets the TF in the thread context and marks stepping as active.
  - The debug loop (`DebugLoop`) handles the exception and calls the registered callback.

- **Special Cases**:
  - If the current instruction is `PUSHF`, it delegates to `StepOver` because stepping into `PUSHF` can cause confusion with TF on the stack.
  - If the instruction is `POP SS` or `MOV SS`, it sets a one-shot breakpoint at the instruction after.

### Step Over

- **Core Mechanism**:
  - Reads and disassembles the current instruction.
  - If it's a `CALL`, `REP`, or `PUSHF`, it sets a one-shot (single-use) breakpoint at the instruction immediately following.
  - Otherwise, it performs a `StepInto`.

### Step Out

- **Core Mechanism**:
  - Initiates a step over with a callback (`StepOutStepCallBack`) that repeatedly steps until a `RET` instruction is encountered.
  - When a `RET` is hit, it can call the final callback or continue stepping if requested.

### Handling `PUSHF`/TF on Stack

- The engine recognizes when the instruction being stepped is `PUSHF` (which pushes EFlags including TF onto the stack). After execution, it erases the TF from the value on the stack to prevent unwanted single-step exceptions.

### Debug Loop

- The main debug loop (`DebugLoop`) processes exceptions and manages step state, resuming threads, restoring breakpoints, and calling user callbacks on each step or breakpoint hit.

---

## 2. keowu/koidbg

### Step Over

- **Core Mechanism**:
  - For x86/x64: Sets the TF in EFlags using `SetThreadContext()`, which will cause a `SingleStep` exception after the next instruction.
  - For ARM64: Sets the single-step bit in the [MDSCR_EL1 register](https://developer.arm.com/documentation/ddi0487/latest), specifically the SS bit (bit 21, "T-Bit"), to enable single-step mode.
  - Implemented in the `stepOver` method of the debugger engine. It opens the thread, sets the appropriate flag, resumes the thread, and updates debugger state.

### Step Into

- **Core Mechanism**:
  - Reads the instruction pointer (RIP/Pc), disassembles the current instruction using Capstone, and determines the next address to step into (for branches/calls).
  - Sets the thread context to the new address if required.
  - For both x86 and ARM64, it uses architecture-specific mechanisms to trigger single-stepping.

### Step Out

- **Core Mechanism**:
  - Disassembles instructions from the current instruction pointer forward until it finds a return instruction (`ret`/`retn` on x86 or equivalent on ARM64).
  - Sets a software breakpoint at the address of the return instruction and resumes execution.
  - When the breakpoint is hit, stepping is complete.

### Disassembler Integration

- The disassembler engine provides functions:
  - `RunCapstoneForSingleStepARM64` / `RunCapstoneForSingleStepx86`: Finds the next address to step to for "step into".
  - `RunCapstoneForStepOutARM64` / `RunCapstoneForStepOutx86`: Finds the next return instruction for "step out".

- These are tightly integrated with the stepping logic to provide accurate and reliable step operations.

---

## 3. x64dbg/GleeBug

### Step Into

- **Core Mechanism**:
  - `Thread::StepInto` sets the Trap Flag in EFlags using the `Registers` abstraction and marks the thread as single-stepping.
  - When a `STATUS_SINGLE_STEP` exception is received, the debug loop clears the single-stepping flag and calls the registered callback.

### Step Over

- **Core Mechanism**:
  - Disassembles the current instruction using Zydis.
  - If the instruction is a `CALL`, `PUSHF`, or a repeated instruction (`REP`/`REPE`/`MOVS` etc.), it sets a one-shot breakpoint at the next instruction.
  - Otherwise, it falls back to `StepInto`.

### Step Out

- **Indirectly Referenced**:
  - While not directly detailed in the provided code, the pattern generally involves scanning ahead for the next `RET` instruction and setting a breakpoint there, as in the other engines.

### Handling Special Instructions

- For `PUSHF`, after stepping, the code ensures that the Trap Flag is cleared from the stack to prevent unwanted single-step exceptions.
- The debug loop (`Debugger::exceptionSingleStep`) distinguishes between internal and external stepping and manages the callback logic accordingly.

### Thread and Step Management

- The engine supports callback stacking and safe thread suspension/resumption for multi-threaded debug targets.
- Safe stepping is managed by suspending all other threads when needed.

---

## Comparison and Common Design Elements

- **Trap Flag/Single-Step Bit**: All engines rely on hardware CPU support for single-stepping—setting a flag in the thread context (TF in EFlags for x86/x64, SS bit in ARM64's MDSCR_EL1).
- **Instruction Analysis**: "Step over" and "step out" require disassembly to determine if the current instruction is a call, return, or repeat, and where to set breakpoints.
- **One-Shot Breakpoints**: Used when stepping over calls or stepping out of functions to resume execution at the appropriate spot.
- **Callbacks**: All engines support passing a callback to be notified when the step finishes.
- **Special Case Handling**: Instructions like `PUSHF` and segment manipulation require special handling to ensure stepping works correctly.

---

## Illustrative Example (x64dbg/TitanEngine "Step Over")

```cpp
void StepOver(LPVOID StepCallBack) {
    ULONG_PTR ueCurrentPosition = GetContextData(UE_CIP);
    unsigned char instr[16];
    MemoryReadSafe(dbgProcessInformation.hProcess, (void*)ueCurrentPosition, instr, sizeof(instr), 0);
    char* DisassembledString = (char*)StaticDisassembleEx(ueCurrentPosition, (LPVOID)instr);
    if(strstr(DisassembledString, "CALL") || strstr(DisassembledString, "REP") || strstr(DisassembledString, "PUSHF")) {
        ueCurrentPosition += StaticLengthDisassemble((void*)instr);
        SetBPX(ueCurrentPosition, UE_BREAKPOINT_TYPE_INT3 + UE_SINGLESHOOT, StepCallBack);
    } else
        StepInto(StepCallBack);
}
```

---

## Summary Table

| Engine        | Step Into                | Step Over                                                                          | Step Out                                     |
|---------------|--------------------------|-------------------------------------------------------------------------------------|----------------------------------------------|
| TitanEngine   | TF in EFlags, callback   | Disassemble, BP after CALL/REP/PUSHF, else StepInto                                | Repeated StepOver until RET, callback        |
| koidbg        | TF (x86) or SS bit (ARM) | Set TF/SS for next instr; on step out, scan for RET and BP there                   | Disassemble, BP at nearest RET               |
| GleeBug       | TF in EFlags, callback   | Disassemble, BP after CALL/REP/PUSHF, else StepInto                                | Not explicit, likely same as TitanEngine     |
