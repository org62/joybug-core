#include <stdio.h>
#include <string.h>
#include <windows.h>

// Global to prevent optimization
volatile int g_value = 0;

// Global pointer to dynamically allocated code (for test to read)
volatile void* g_dynamic_code_ptr = NULL;
volatile size_t g_dynamic_code_size = 0;

// Helper function to call
__declspec(noinline) int helper_add(int a, int b) {
    return a + b;
}

// Helper function 2
__declspec(noinline) int helper_multiply(int a, int b) {
    return a * b;
}

// Function with various control flow
// Contains: calls, jumps (conditional and unconditional), ret
__declspec(noinline) int test_control_flow(int x) {
    int result = 0;

    // Call instruction
    result = helper_add(x, 10);

    // Conditional jump
    if (result > 20) {
        result = helper_multiply(result, 2);
    } else {
        result = result + 5;
    }

    // Loop (contains backward jump)
    for (int i = 0; i < 3; i++) {
        result += i;
    }

    // Another conditional
    if (result < 0) {
        return -1;  // Early return
    }

    return result;  // Return instruction
}

// Function for setting breakpoint
__declspec(noinline) void breakpoint_here(void) {
    __nop();
}

#if defined(_M_X64) || defined(__x86_64__)
// Known x64 shellcode: simple add function
// mov eax, ecx      ; 89 c8 (first arg)
// add eax, edx      ; 01 d0 (second arg)
// ret               ; c3
// Total: 5 bytes, but we pad to 16 for safety
static const unsigned char g_add_shellcode[] = {
    0x89, 0xc8,       // mov eax, ecx
    0x01, 0xd0,       // add eax, edx
    0xc3,             // ret
    0x90, 0x90, 0x90, // nop padding
    0x90, 0x90, 0x90,
    0x90, 0x90, 0x90,
    0x90, 0x90        // 16 bytes total
};
#elif defined(_M_ARM64) || defined(__aarch64__)
// Known ARM64 shellcode: simple add function
// add w0, w0, w1    ; 0b 01 00 00 (little-endian: 00 00 01 0b)
// ret               ; d6 5f 03 c0 (little-endian: c0 03 5f d6)
// nop               ; d5 03 20 1f (little-endian: 1f 20 03 d5)
// Total: 16 bytes (4 instructions)
static const unsigned char g_add_shellcode[] = {
    0x00, 0x00, 0x01, 0x0b,  // add w0, w0, w1
    0xc0, 0x03, 0x5f, 0xd6,  // ret
    0x1f, 0x20, 0x03, 0xd5,  // nop
    0x1f, 0x20, 0x03, 0xd5   // nop (16 bytes total)
};
#else
#error "Unsupported architecture"
#endif


typedef int (*AddFunc)(int, int);

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    printf("disassembly_test starting\n");

    // Call test function
    int result = test_control_flow(5);
    g_value = result;

    printf("test_control_flow(5) = %d\n", result);

    // =============================================
    // Allocate RWX memory and copy known shellcode
    // =============================================
    void* rwx_mem = VirtualAlloc(
        NULL,
        4096,  // One page
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (rwx_mem) {
        printf("Allocated RWX memory at %p\n", rwx_mem);

        // Copy known shellcode
        memcpy(rwx_mem, g_add_shellcode, sizeof(g_add_shellcode));

        // Execute it to verify it works
        AddFunc dynamic_add = (AddFunc)rwx_mem;
        int dynamic_result = dynamic_add(30, 12);
        printf("dynamic_add(30, 12) = %d (expected 42)\n", dynamic_result);

        if (dynamic_result != 42) {
            printf("ERROR: dynamic code returned wrong result!\n");
            VirtualFree(rwx_mem, 0, MEM_RELEASE);
            return 1;
        }

        // Store pointer and size in globals for test to read
        g_dynamic_code_ptr = rwx_mem;
        g_dynamic_code_size = sizeof(g_add_shellcode);

        printf("g_dynamic_code_ptr = %p\n", (void*)g_dynamic_code_ptr);
        printf("g_dynamic_code_size = %zu\n", (size_t)g_dynamic_code_size);
    } else {
        printf("Failed to allocate RWX memory: %lu\n", GetLastError());
    }

    // Call breakpoint target
    breakpoint_here();

    // Cleanup
    if (rwx_mem) {
        VirtualFree(rwx_mem, 0, MEM_RELEASE);
    }

    return 0;
}

