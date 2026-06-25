#include <stdio.h>
#include <stdlib.h>
#include <intrin.h>

// Pointer scan test victim.
//
// One static global pointer heads a singly-linked list of NUM_STRUCTS nodes.
// The LAST node holds the sentinel value. A pointer scan that starts from the
// sentinel's address must be able to walk back to the static global:
//
//   g_list_head (static, in PE image)
//     -> node[0].next -> node[1].next -> ... -> node[N-1]
//     -> node[N-1].value  (== SENTINEL, the scan target)
//
// i.e. base = &g_list_head, offsets = [0, 0, ..., 0, 8] (one per hop; the final
// +8 reaches the `value` field).

#define NUM_STRUCTS 4
#define SENTINEL 0x1337C0DE00000000ULL

typedef struct Node {
    struct Node* next;          // offset 0
    unsigned long long value;   // offset 8
} Node;

// Single static global pointer (lives in the module image -> a "static" base).
Node* g_list_head;

// Dedicated breakpoint target; noinline so it survives optimization.
__declspec(noinline) void breakpoint_here(void) {
    __nop();
}

int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;

    // Build the list from tail to head so the last node holds the sentinel.
    Node* prev = NULL;
    for (int i = NUM_STRUCTS - 1; i >= 0; i--) {
        Node* n = (Node*)malloc(sizeof(Node));
        if (!n) return 1;
        n->next = prev;
        n->value = (i == NUM_STRUCTS - 1) ? SENTINEL : (unsigned long long)i;
        prev = n;
    }
    g_list_head = prev;

    // Print the chain for manual verification.
    int idx = 0;
    for (Node* cur = g_list_head; cur != NULL; cur = cur->next) {
        printf("node %d @ 0x%p value=0x%llx next=0x%p\n",
               idx++, (void*)cur, cur->value, (void*)cur->next);
    }
    printf("g_list_head @ 0x%p = 0x%p\n", (void*)&g_list_head, (void*)g_list_head);
    fflush(stdout);

    // Debugger sets a breakpoint here after the list is built.
    breakpoint_here();

    return 0;
}
