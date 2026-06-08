#include <stdio.h>
#include <stdlib.h>
#include <string.h>

char g_search_string[] = "JOYBUG_SEARCH_MARKER";
unsigned char g_hex_pattern[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

__declspec(noinline) void breakpoint_here(void) { volatile int x = 0; (void)x; }

int main(void) {
    char stack_string[] = "JOYBUG_SEARCH_MARKER";
    unsigned char stack_hex[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

    char* heap_string = (char*)malloc(32);
    strcpy(heap_string, "JOYBUG_SEARCH_MARKER");

    unsigned char* heap_hex = (unsigned char*)malloc(6);
    memcpy(heap_hex, (unsigned char[]){0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE}, 6);

    /* Prevent optimization */
    printf("%p %p %p %p %p %p\n",
        (void*)g_search_string, (void*)stack_string, (void*)heap_string,
        (void*)g_hex_pattern, (void*)stack_hex, (void*)heap_hex);

    breakpoint_here();

    free(heap_string);
    free(heap_hex);
    return 0;
}
