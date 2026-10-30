#include "detour.h"
#include "decode.h"
#include <stdint.h>
#include <string.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

#if defined(__x86_64__)
enum { k_need = 14 };
#else
enum { k_need = 6 };
#endif

static int protect_range(void *addr, size_t len, int writable) {
#if defined(_WIN32)
    DWORD old = 0;
    DWORD prot = writable ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
    return VirtualProtect(addr, len, prot, &old) ? 0 : -1;
#else
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~(uintptr_t)(page - 1);
    uintptr_t end = ((uintptr_t)addr + len + (uintptr_t)page - 1) & ~(uintptr_t)(page - 1);
    int prot = writable ? (PROT_READ | PROT_WRITE | PROT_EXEC) : (PROT_READ | PROT_EXEC);
    return mprotect((void *)start, end - start, prot);
#endif
}

static void flush_code(void *addr, size_t len) {
#if defined(_WIN32)
    FlushInstructionCache(GetCurrentProcess(), addr, len);
#else
    __builtin___clear_cache((char *)addr, (char *)addr + len);
#endif
}

static void *alloc_code(size_t len) {
#if defined(_WIN32)
    return VirtualAlloc(0, len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
    void *page = mmap(0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) return 0;
    return page;
#endif
}

static void seal_code(void *addr, size_t len) {
#if !defined(_WIN32)
    mprotect(addr, len, PROT_READ | PROT_EXEC);
#else
    DWORD old = 0;
    VirtualProtect(addr, len, PAGE_EXECUTE_READ, &old);
#endif
    flush_code(addr, len);
}

static void write32(uint8_t *p, int32_t value) {
    memcpy(p, &value, 4);
}

static int32_t read32(const uint8_t *p) {
    int32_t value = 0;
    memcpy(&value, p, 4);
    return value;
}

/* ʕ •ᴥ•ʔ✿ Absolute jump. A rel32 cannot be trusted to reach the loaded library. ✿ ʕ •ᴥ•ʔ */
static int emit_jump(uint8_t *at, void *dest) {
#if defined(__x86_64__)
    uint64_t address = (uint64_t)(uintptr_t)dest;
    at[0] = 0xFF;
    at[1] = 0x25;
    write32(at + 2, 0);
    memcpy(at + 6, &address, 8);
    return 14;
#else
    uint32_t address = (uint32_t)(uintptr_t)dest;
    at[0] = 0x68;
    memcpy(at + 1, &address, 4);
    at[5] = 0xC3;
    return 6;
#endif
}

int detour_install(void *target, void *hook, void **original) {
    uint8_t *src = target;
    uint8_t *gate;
    uint8_t *cursor;
    int filled = 0;
    int patch;

    if (!target || !hook || !original) return -1;
    gate = alloc_code(4096);
    if (!gate) return -1;
    cursor = gate;

    while (filled < k_need) {
        struct Insn insn;
        int64_t next_delta;
        uintptr_t absolute;
        if (filled > 48 || !decode_insn(src + filled, 16, &insn) || insn.len <= 0) return -1;
        if (insn.fix == FIX_REL8) return -1;
        memcpy(cursor, src + filled, (size_t)insn.len);
        if (insn.fix == FIX_REL32 || insn.fix == FIX_RIP32) {
            absolute = (uintptr_t)(src + filled + insn.len) + (intptr_t)read32(src + filled + insn.disp_off);
            next_delta = (int64_t)absolute - (int64_t)(uintptr_t)(cursor + insn.len);
            if (next_delta > 2147483647ll || next_delta < -2147483648ll) return -1;
            write32(cursor + insn.disp_off, (int32_t)next_delta);
        }
        cursor += insn.len;
        filled += insn.len;
    }

    emit_jump(cursor, src + filled);
    seal_code(gate, 4096);
    *original = gate;
    if (protect_range(src, (size_t)filled, 1) != 0) return -1;
    patch = emit_jump(src, hook);
    if (filled > patch) memset(src + patch, 0x90, (size_t)(filled - patch));
    protect_range(src, (size_t)filled, 0);
    flush_code(src, (size_t)filled);
    return 0;
}
