#define _GNU_SOURCE
#include "damage.h"
#include "elf_sym.h"
#include <link.h>
#include <stdint.h>
#include <unistd.h>

static uintptr_t g_bias;

static int bias_callback(struct dl_phdr_info *info, size_t size, void *data) {
    (void)size;
    (void)data;
    g_bias = (uintptr_t)info->dlpi_addr;
    return 1;
}

__attribute__((constructor)) static void trunblizz_load(void) {
    static const char *names[] = {
        "_Z20PlayerNameCreateTextP14PLAYERNAMEDESCjPKcPK9CImVectorPKi",
        "_Z25PlayerNameUpdateWorldTextv",
        "_Z19FrameScript_ExecutePKcS0_S0_",
        "s_context"
    };
    char path[4096];
    void *sym[4];
    ssize_t n = readlink("/proc/self/exe", path, sizeof path - 1);
    if (n < 0) return;
    path[n] = 0;
    dl_iterate_phdr(bias_callback, 0);
    if (!elf_resolve(path, g_bias, names, sym, 4) || !sym[0]) return;
    damage_install(sym[0], sym[1], sym[2], sym[3]);
}
