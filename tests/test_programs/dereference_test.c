#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Linked list node structure
typedef struct Node {
    int value;
    struct Node* next;
} Node;

// Global pointers for testing different dereference patterns
// These are NOT volatile so they appear in symbols properly
void* g_self_ptr;                    // Will point to itself (loop detection test)
void* g_loop_ptr1;                   // Loop detection with chain: g_loop_ptr1 -> g_loop_ptr2 -> g_loop_ptr1
void* g_loop_ptr2;                   // Second element in loop chain
const wchar_t* g_wide_string_ptr;    // Will point to a wide string (UTF-16)
const char* g_string_ptr;            // Will point to a string
Node* g_list_head;                   // Linked list head
int (*g_main_ptr)(int, char**);      // Will point to main function
void* g_null_ptr;                    // NULL pointer (tests Value output for invalid pointer)
int g_small_int;                     // Small integer value (tests Value output)
void* g_ptr_to_small_int;            // Pointer to small int (tests pointer -> Value chain)
void* g_invalid_ptr;                 // Pointer containing invalid address (tests Unreadable)

// Dummy function - set breakpoint here after globals are initialized
__declspec(noinline) void breakpoint_here(void) {
    // This function exists solely as a breakpoint target
    // The noinline attribute prevents it from being optimized away
    __nop();
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    // Pattern 1: String pointer (ASCII)
    g_string_ptr = "Hello, Dereference!";

    // Pattern 1b: Wide string pointer (UTF-16)
    g_wide_string_ptr = L"Wide String Test!";

    // Pattern 2: Linked list with 3 nodes
    Node* n3 = (Node*)malloc(sizeof(Node));
    if (!n3) return 1;
    n3->value = 3;
    n3->next = NULL;

    Node* n2 = (Node*)malloc(sizeof(Node));
    if (!n2) { free(n3); return 1; }
    n2->value = 2;
    n2->next = n3;

    Node* n1 = (Node*)malloc(sizeof(Node));
    if (!n1) { free(n2); free(n3); return 1; }
    n1->value = 1;
    n1->next = n2;
    g_list_head = n1;

    // Pattern 3: Self-referential pointer (loop detection)
    g_self_ptr = (void*)&g_self_ptr;

    // Pattern 3b: Loop with intermediate pointer (better loop detection test)
    // Chain: g_loop_ptr1 -> g_loop_ptr2 -> g_loop_ptr1 (loop)
    g_loop_ptr1 = (void*)&g_loop_ptr2;
    g_loop_ptr2 = (void*)&g_loop_ptr1;

    // Pattern 4: Function pointer to main
    g_main_ptr = main;

    // Pattern 5: NULL pointer (tests DereferenceValue::Value for invalid pointer target)
    g_null_ptr = NULL;

    // Pattern 6: Small integer value (tests DereferenceValue::Value)
    g_small_int = 0x12345678;
    g_ptr_to_small_int = (void*)&g_small_int;

    // Pattern 7: Invalid pointer (tests DereferenceValue::Unreadable)
    // This pointer contains an address that looks valid but is unmapped
    g_invalid_ptr = (void*)0xDEAD0000BEEF0000ULL;

    // Print for manual verification
    printf("g_string_ptr   @ 0x%p = 0x%p -> \"%s\"\n",
           (void*)&g_string_ptr, (void*)g_string_ptr, g_string_ptr);
    printf("g_wide_string_ptr @ 0x%p = 0x%p -> \"%ls\"\n",
           (void*)&g_wide_string_ptr, (void*)g_wide_string_ptr, g_wide_string_ptr);
    printf("g_list_head    @ 0x%p = 0x%p (value=%d)\n",
           (void*)&g_list_head, (void*)g_list_head, g_list_head->value);
    printf("g_self_ptr     @ 0x%p = 0x%p (self-ref)\n",
           (void*)&g_self_ptr, (void*)g_self_ptr);
    printf("g_loop_ptr1    @ 0x%p = 0x%p (-> g_loop_ptr2)\n",
           (void*)&g_loop_ptr1, (void*)g_loop_ptr1);
    printf("g_loop_ptr2    @ 0x%p = 0x%p (-> g_loop_ptr1, loop)\n",
           (void*)&g_loop_ptr2, (void*)g_loop_ptr2);
    printf("g_main_ptr     @ 0x%p = 0x%p (main func)\n",
           (void*)&g_main_ptr, (void*)g_main_ptr);
    printf("g_null_ptr     @ 0x%p = 0x%p (NULL)\n",
           (void*)&g_null_ptr, (void*)g_null_ptr);
    printf("g_small_int    @ 0x%p = 0x%x (small int)\n",
           (void*)&g_small_int, g_small_int);
    printf("g_ptr_to_small_int @ 0x%p = 0x%p (-> small int)\n",
           (void*)&g_ptr_to_small_int, (void*)g_ptr_to_small_int);
    printf("g_invalid_ptr  @ 0x%p = 0x%p (invalid addr)\n",
           (void*)&g_invalid_ptr, (void*)g_invalid_ptr);

    // Call breakpoint function - debugger should set breakpoint here
    breakpoint_here();


    // Cleanup
    free(n1);
    free(n2);
    free(n3);

    return 0;
}
