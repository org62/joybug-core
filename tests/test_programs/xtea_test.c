/*
 * XTEA encryption test program for instruction tracer validation
 *
 * XTEA (Extended TEA) is a simple block cipher with pure arithmetic operations:
 * - XOR, ADD, shifts
 * - No syscalls during encryption/decryption
 * - Deterministic output for same input
 * - 32 rounds = ~200-300 instructions per encrypt/decrypt
 *
 * Ideal for comparing trap-flag tracer vs emulator traces.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* XTEA block size and rounds */
#define XTEA_ROUNDS 32
#define XTEA_DELTA 0x9E3779B9

/* Global variables to make debugging easier */
volatile uint32_t g_v0 = 0;
volatile uint32_t g_v1 = 0;
volatile uint32_t g_sum = 0;

/*
 * XTEA encrypt function
 * Pure arithmetic: XOR, ADD, shifts - no syscalls
 */
__declspec(noinline)
void xtea_encrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t sum = 0;
    uint32_t delta = XTEA_DELTA;

    for (unsigned int i = 0; i < XTEA_ROUNDS; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }

    v[0] = v0;
    v[1] = v1;

    /* Store to globals for debugging visibility */
    g_v0 = v0;
    g_v1 = v1;
    g_sum = sum;
}

/*
 * XTEA decrypt function
 * Mirror of encrypt, also pure arithmetic
 */
__declspec(noinline)
void xtea_decrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0];
    uint32_t v1 = v[1];
    uint32_t delta = XTEA_DELTA;
    uint32_t sum = delta * XTEA_ROUNDS;

    for (unsigned int i = 0; i < XTEA_ROUNDS; i++) {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    }

    v[0] = v0;
    v[1] = v1;

    /* Store to globals for debugging visibility */
    g_v0 = v0;
    g_v1 = v1;
    g_sum = sum;
}

/*
 * Marker function to set breakpoint before encryption
 * The actual work happens after this returns
 */
__declspec(noinline)
void trace_start_marker(void) {
    /* NOP - just a breakpoint target */
    __nop();
}

/*
 * Marker function to set breakpoint after encryption
 * Indicates end of trace region
 */
__declspec(noinline)
void trace_end_marker(void) {
    /* NOP - just a breakpoint target */
    __nop();
}

/*
 * Main test function
 *
 * Workflow:
 * 1. trace_start_marker() - set breakpoint here
 * 2. xtea_encrypt() - trace this
 * 3. trace_end_marker() - stop tracing here
 * 4. Verify encryption worked
 * 5. Decrypt and verify roundtrip
 */
int main(void) {
    /* Test data: 8 bytes = 2 x 32-bit words */
    uint32_t data[2] = { 0x12345678, 0x9ABCDEF0 };
    uint32_t original[2] = { data[0], data[1] };

    /* 128-bit key (4 x 32-bit words) */
    const uint32_t key[4] = { 0xDEADBEEF, 0xCAFEBABE, 0x8BADF00D, 0xFEEDFACE };

    printf("XTEA Test Program\n");
    printf("=================\n\n");

    printf("Original data: 0x%08X 0x%08X\n", data[0], data[1]);
    printf("Key: 0x%08X 0x%08X 0x%08X 0x%08X\n\n", key[0], key[1], key[2], key[3]);

    /* === TRACE REGION START === */
    trace_start_marker();

    /* Encrypt - this is what we want to trace */
    xtea_encrypt(data, key);

    trace_end_marker();
    /* === TRACE REGION END === */

    printf("Encrypted data: 0x%08X 0x%08X\n", data[0], data[1]);
    printf("Global state: v0=0x%08X v1=0x%08X sum=0x%08X\n\n", g_v0, g_v1, g_sum);

    /* Verify encryption changed the data */
    if (data[0] == original[0] && data[1] == original[1]) {
        printf("ERROR: Encryption did not change data!\n");
        return 1;
    }

    /* Decrypt and verify roundtrip */
    uint32_t encrypted[2] = { data[0], data[1] };
    xtea_decrypt(data, key);

    printf("Decrypted data: 0x%08X 0x%08X\n", data[0], data[1]);

    if (data[0] == original[0] && data[1] == original[1]) {
        printf("\nSUCCESS: Roundtrip verified!\n");
        return 0;
    } else {
        printf("\nERROR: Roundtrip failed!\n");
        printf("Expected: 0x%08X 0x%08X\n", original[0], original[1]);
        printf("Got:      0x%08X 0x%08X\n", data[0], data[1]);
        return 1;
    }
}
