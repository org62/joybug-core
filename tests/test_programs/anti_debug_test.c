// anti_debug_test.c
//
// A minimal "protected" program that looks for a debugger using only the
// indicators that live inside the PEB -- exactly the ones the joybug2
// anti-anti-debug (hide_peb) feature neutralizes. It prints every value it
// observes and returns a detection bitmask as its process exit code:
//
//   bit0 (0x1) = IsDebuggerPresent() / PEB.BeingDebugged
//   bit1 (0x2) = PEB.NtGlobalFlag debug bits
//   bit2 (0x4) = process-heap Flags/ForceFlags debug markers
//
// Exit code 0 means no debugger is observable via the PEB (i.e. hide_peb
// successfully cleaned everything). A non-zero code names which indicator
// leaked.
//
// Deliberately does NOT use CheckRemoteDebuggerPresent /
// NtQueryInformationProcess: those read kernel state that hide_peb does not
// touch, so they would always report "detected" and make the test meaningless.

#include <windows.h>
#include <stdio.h>

// PEB / heap field offsets, native 64-bit layout (Win10/11). Identical on
// x64 and ARM64. Kept as raw offsets to match the implementation's own
// hardcoded layout rather than depending on SDK struct definitions.
#define PEB_BEING_DEBUGGED   0x02
#define PEB_PROCESS_HEAP     0x30
#define PEB_NT_GLOBAL_FLAG   0xBC
#define HEAP_FLAGS           0x70
#define HEAP_FORCE_FLAGS     0x74

// NtGlobalFlag bits set by the loader for a debugged process:
//   FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20)
//   | FLG_HEAP_VALIDATE_PARAMETERS (0x40)
#define NT_GLOBAL_FLAG_DEBUG_BITS 0x70

// Normal, non-debug heap Flags value.
#define HEAP_GROWABLE 0x2

// Read the PEB base from the TEB. The PEB pointer sits at TEB+0x60 on every
// 64-bit Windows ABI; NtCurrentTeb() gives us the TEB without any arch intrinsic.
static unsigned char *get_peb(void) {
    unsigned char *teb = (unsigned char *)NtCurrentTeb();
    return *(unsigned char **)(teb + 0x60);
}

int main(void) {
    unsigned char *peb = get_peb();

    int is_debugger_present = (int)IsDebuggerPresent();
    unsigned char being_debugged = *(unsigned char *)(peb + PEB_BEING_DEBUGGED);
    unsigned long nt_global_flag = *(unsigned long *)(peb + PEB_NT_GLOBAL_FLAG);

    unsigned char *heap = *(unsigned char **)(peb + PEB_PROCESS_HEAP);
    unsigned long heap_flags = *(unsigned long *)(heap + HEAP_FLAGS);
    unsigned long heap_force_flags = *(unsigned long *)(heap + HEAP_FORCE_FLAGS);

    int mask = 0;
    if (is_debugger_present || being_debugged != 0) {
        mask |= 0x1;
    }
    if ((nt_global_flag & NT_GLOBAL_FLAG_DEBUG_BITS) != 0) {
        mask |= 0x2;
    }
    if (heap_force_flags != 0 || (heap_flags & ~(unsigned long)HEAP_GROWABLE) != 0) {
        mask |= 0x4;
    }

    printf("anti_debug_test: PEB=%p\n", (void *)peb);
    printf("  IsDebuggerPresent   = %d\n", is_debugger_present);
    printf("  PEB.BeingDebugged   = %u\n", (unsigned)being_debugged);
    printf("  PEB.NtGlobalFlag    = 0x%lx\n", nt_global_flag);
    printf("  Heap.Flags          = 0x%lx\n", heap_flags);
    printf("  Heap.ForceFlags     = 0x%lx\n", heap_force_flags);
    printf("  detection mask      = 0x%x %s\n", mask, mask == 0 ? "(clean)" : "(debugger detected)");
    fflush(stdout);

    return mask;
}
