// Pointer-scan benchmark target.
//
// Allocates a large arena (default 6 GB; argv[1] = GB) and fills a configurable
// fraction of 8-byte slots (default 15%; argv[2] = percent) with pointers into
// the arena, to mimic a real pointer-dense process. A sentinel value sits at a
// known slot and the exe global `g_target` holds its address, so a debugger can
// read the scan target and look for paths to it. After setup it calls
// `pause_here()` and waits, keeping the memory committed.

#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <vector>
#include <windows.h>

extern "C" {
    // Address the pointer scan should look for (read by the benchmark harness).
    volatile uint64_t* g_target = nullptr;
    // Total committed arena bytes (for reference).
    volatile uint64_t g_arena_bytes = 0;

    __declspec(noinline) void pause_here(void) { volatile int x = 0; (void)x; }
}

int main(int argc, char** argv) {
    double total_gb = (argc > 1) ? atof(argv[1]) : 6.0;
    int density_pct = (argc > 2) ? atoi(argv[2]) : 15;
    if (density_pct < 0) density_pct = 0;
    if (density_pct > 100) density_pct = 100;

    const size_t BLOCK = (size_t)256 * 1024 * 1024;           // 256 MB blocks
    size_t target_bytes = (size_t)(total_gb * 1024.0 * 1024.0 * 1024.0);
    size_t num_blocks = (target_bytes + BLOCK - 1) / BLOCK;
    const size_t slots_per_block = BLOCK / sizeof(uint64_t);

    std::vector<uint64_t*> blocks;
    blocks.reserve(num_blocks);
    size_t allocated = 0;
    for (size_t i = 0; i < num_blocks; i++) {
        uint64_t* p = (uint64_t*)VirtualAlloc(NULL, BLOCK, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!p) {
            printf("VirtualAlloc failed after %zu blocks (%.2f GB)\n", i, allocated / (1024.0 * 1024 * 1024));
            break;
        }
        blocks.push_back(p);
        allocated += BLOCK;
    }
    g_arena_bytes = allocated;
    if (blocks.empty()) { printf("no memory allocated\n"); return 1; }

    // Fast xorshift PRNG (deterministic, no libc rand contention).
    uint64_t rng = 0x9E3779B97F4A7C15ull;
    auto next = [&]() -> uint64_t {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng;
    };

    // Fill: `density_pct` of slots get a pointer into the arena; the rest get
    // random data (which, being spread over the 64-bit space, essentially never
    // falls inside the committed arena, so it isn't counted as a pointer).
    for (size_t bi = 0; bi < blocks.size(); bi++) {
        uint64_t* b = blocks[bi];
        for (size_t s = 0; s < slots_per_block; s++) {
            uint64_t r = next();
            if ((int)(r % 100) < density_pct) {
                size_t tb = (size_t)(next() % blocks.size());
                size_t ts = (size_t)(next() % slots_per_block);
                b[s] = (uint64_t)(blocks[tb] + ts);
            } else {
                b[s] = r;
            }
        }
    }

    // Sentinel target: a known value at a known slot; expose its address.
    uint64_t* sentinel = blocks.back() + (slots_per_block - 1);
    *sentinel = 0x1337C0DE1337C0DEull;
    g_target = sentinel;

    printf("arena=%.2f GB blocks=%zu density=%d%% target=%p\n",
           allocated / (1024.0 * 1024 * 1024), blocks.size(), density_pct, (void*)sentinel);
    fflush(stdout);

    pause_here();

    // Keep the arena committed until the debugger terminates us.
    for (;;) {
        Sleep(1000);
        volatile uint64_t sum = 0;
        for (auto b : blocks) sum += b[0];
        (void)sum;
    }
}
