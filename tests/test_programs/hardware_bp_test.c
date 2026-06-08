#include <stdio.h>
#include <stdint.h>

volatile uint32_t g_write_dword = 0;   /* Write(Byte4) target */
volatile uint32_t g_rw_dword = 0x42;   /* ReadWrite(Byte4) target */
volatile uint8_t  g_write_byte = 0;    /* Write(Byte1) target */

__declspec(noinline) void breakpoint_here(void) { volatile int x = 0; (void)x; }
__declspec(noinline) void write_dword(void)     { g_write_dword = 0xDEADBEEF; }
__declspec(noinline) void read_rw(void)         { volatile uint32_t v = g_rw_dword; (void)v; }
__declspec(noinline) void write_rw(void)        { g_rw_dword = 0x1234; }
__declspec(noinline) void write_byte(void)      { g_write_byte = 0xAB; }
__declspec(noinline) void execute_target(void)  { volatile int x = 0; (void)x; }

int main(void) {
    breakpoint_here();   /* SW breakpoint - set up all HW watchpoints here */
    write_dword();       /* triggers Write(Byte4) on g_write_dword */
    read_rw();           /* triggers ReadWrite(Byte4) on g_rw_dword (read) */
    write_rw();          /* triggers ReadWrite(Byte4) on g_rw_dword (write) */
    write_byte();        /* triggers Write(Byte1) on g_write_byte */
    execute_target();    /* triggers Execute(Byte1) on execute_target */
    return 0;
}
