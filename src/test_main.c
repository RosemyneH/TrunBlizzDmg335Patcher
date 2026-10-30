#include "abbrev.h"
#include "decode.h"
#include "detour.h"
#include "elf_sym.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#if !defined(_WIN32)
#include <sys/mman.h>
#include <unistd.h>
#endif

static int g_failed;

static void expect(const char *name, const char *got, const char *want) {
    if (strcmp(got, want) != 0) {
        fprintf(stderr, "%s: got \"%s\" want \"%s\"\n", name, got, want);
        g_failed = 1;
    }
}

static void expect_len(const char *name, const uint8_t *code, int avail, int want_len, int want_fix) {
    struct Insn insn;
    if (!decode_insn(code, avail, &insn) || insn.len != want_len || insn.fix != want_fix) {
        fprintf(stderr, "%s: len %d fix %d\n", name, insn.len, insn.fix);
        g_failed = 1;
    }
}

static int (*g_orig_add)(int);
static int hook_add(int value) {
    return g_orig_add(value) + 10;
}

static uint64_t (*g_orig_load)(void);
static uint64_t hook_load(void) {
    return g_orig_load() + 1;
}

static void test_abbrev(void) {
    char buf[64];
    abbreviate(buf, sizeof buf, "115232");
    expect("damage", buf, "115.2K");
    abbreviate(buf, sizeof buf, "2400000");
    expect("millions", buf, "2.4M");
    abbreviate(buf, sizeof buf, "115250");
    expect("truncate", buf, "115.2K");
    abbreviate(buf, sizeof buf, "999");
    expect("small", buf, "999");
    abbreviate(buf, sizeof buf, "+115232");
    expect("heal", buf, "+115.2K");
    abbreviate(buf, sizeof buf, "-2400000");
    expect("negative", buf, "-2.4M");
    abbreviate(buf, sizeof buf, "XP: 115232");
    expect("xp", buf, "XP: 115.2K");
    abbreviate(buf, sizeof buf, "1000");
    expect("edge", buf, "1.0K");
    abbreviate(buf, sizeof buf, "999999");
    expect("high k", buf, "999.9K");
    abbreviate(buf, sizeof buf, "1000000000");
    expect("billions", buf, "1.0B");
    abbreviate(buf, sizeof buf, "Miss");
    expect("word", buf, "Miss");
    abbreviate(buf, sizeof buf, "115.2K");
    expect("once", buf, "115.2K");
    if (!abbrev_combat_style(0) || !abbrev_combat_style(2) || !abbrev_combat_style(6) || !abbrev_combat_style(9)) g_failed = 1;
    if (abbrev_combat_style(1) || abbrev_combat_style(3) || abbrev_combat_style(5) || abbrev_combat_style(10)) g_failed = 1;
}

static void test_decode(void) {
    static const uint8_t create32[] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08 };
    static const uint8_t update32[] = { 0x53, 0x56, 0xE8, 0x99, 0x49, 0x08, 0x00 };
    static const uint8_t create64[] = {
        0x48, 0x85, 0xFF, 0x0F, 0x84, 0x7F, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x05, 0x20, 0x28, 0x39, 0x02
    };
    static const uint8_t update64[] = { 0x48, 0x83, 0xEC, 0x28, 0x48, 0x89, 0x6C, 0x24, 0x08, 0xE8, 0xD2, 0xE6, 0x48, 0x00 };
    expect_len("push ebp", create32, 7, 1, FIX_NONE);
    expect_len("mov ebp", create32 + 1, 6, 2, FIX_NONE);
    expect_len("push esi", create32 + 3, 4, 1, FIX_NONE);
    expect_len("mov esi", create32 + 4, 3, 3, FIX_NONE);
    expect_len("push ebx", update32, 7, 1, FIX_NONE);
    expect_len("call", update32 + 2, 5, 5, FIX_REL32);
    expect_len("test rdi", create64, 16, 3, FIX_NONE);
    expect_len("je", create64 + 3, 13, 6, FIX_REL32);
#if defined(__x86_64__)
    expect_len("rip mov", create64 + 9, 7, 7, FIX_RIP32);
    expect_len("sub rsp", update64, 14, 4, FIX_NONE);
    expect_len("save rbp", update64 + 4, 10, 5, FIX_NONE);
    expect_len("call time", update64 + 9, 5, 5, FIX_REL32);
    {
        struct Insn insn;
        int total = 0;
        while (total < 14) {
            if (!decode_insn(update64 + total, 14 - total, &insn)) {
                fprintf(stderr, "update64 stalled at %d\n", total);
                g_failed = 1;
                break;
            }
            total += insn.len;
        }
        if (total != 14) {
            fprintf(stderr, "update64 steal %d\n", total);
            g_failed = 1;
        }
        total = 0;
        while (total < 14) {
            if (!decode_insn(create64 + total, 16 - total, &insn)) {
                fprintf(stderr, "create64 stalled at %d\n", total);
                g_failed = 1;
                break;
            }
            total += insn.len;
        }
        if (total != 16) {
            fprintf(stderr, "create64 steal %d\n", total);
            g_failed = 1;
        }
    }
#endif
}

#if defined(__x86_64__)
static void test_detour(void) {
    uint8_t *page;
    uint8_t code[] = {
        0x48, 0x85, 0xFF,
        0x0F, 0x84, 0x07, 0x00, 0x00, 0x00,
        0x48, 0x89, 0xF8,
        0x48, 0xFF, 0xC0,
        0xC3,
        0x31, 0xC0,
        0xC3
    };
    uint8_t load[] = {
        0x48, 0x8B, 0x05, 0x09, 0x00, 0x00, 0x00,
        0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0xC3, 0x90,
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11
    };
    long page_size = sysconf(_SC_PAGESIZE);
    int (*add)(int);
    uint64_t (*readq)(void);

    page = mmap(0, (size_t)page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        fprintf(stderr, "mmap failed\n");
        g_failed = 1;
        return;
    }
    memcpy(page, code, sizeof code);
    mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);
    if (detour_install(page, hook_add, (void **)&g_orig_add) != 0) {
        fprintf(stderr, "detour add failed\n");
        g_failed = 1;
        return;
    }
    add = (int (*)(int))page;
    if (add(0) != 10 || add(5) != 16 || add(1) != 12) {
        fprintf(stderr, "detour add results %d %d %d\n", add(0), add(5), add(1));
        g_failed = 1;
    }

    page = mmap(0, (size_t)page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED) {
        g_failed = 1;
        return;
    }
    memcpy(page, load, sizeof load);
    mprotect(page, (size_t)page_size, PROT_READ | PROT_EXEC);
    if (detour_install(page, hook_load, (void **)&g_orig_load) != 0) {
        fprintf(stderr, "detour load failed\n");
        g_failed = 1;
        return;
    }
    readq = (uint64_t (*)(void))page;
    if (readq() != 0x1122334455667788ull + 1ull) {
        fprintf(stderr, "rip reloc failed\n");
        g_failed = 1;
    }
}
#endif

static void test_symbols(void) {
    static const char *names[] = {
        "_Z20PlayerNameCreateTextP14PLAYERNAMEDESCjPKcPK9CImVectorPKi",
        "s_context"
    };
    const char *path = "/home/emma/Repos/wowdecomp/bin/Linux/WowClient64";
    void *sym[2];
    FILE *file = fopen(path, "rb");
    if (!file) return;
    fclose(file);
    unsigned char prologue[3];
    if (elf_resolve(path, 0, names, sym, 2) != 2 || !sym[0] || !sym[1]) {
        fprintf(stderr, "symbol resolve failed\n");
        g_failed = 1;
        return;
    }
    file = fopen(path, "rb");
    if (!file || fseek(file, (long)(uintptr_t)sym[0], SEEK_SET) != 0 || fread(prologue, 1, 3, file) != 3) {
        if (file) fclose(file);
        fprintf(stderr, "cannot read resolved function\n");
        g_failed = 1;
        return;
    }
    fclose(file);
    if (memcmp(prologue, "\x48\x85\xff", 3) != 0) {
        fprintf(stderr, "PlayerNameCreateText prologue changed\n");
        g_failed = 1;
    }
}

int main(void) {
    test_abbrev();
    test_decode();
#if defined(__x86_64__)
    test_detour();
#endif
    test_symbols();
    if (g_failed) {
        fprintf(stderr, "failed\n");
        return 1;
    }
    printf("ok\n");
    return 0;
}
