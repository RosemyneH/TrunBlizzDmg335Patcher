#include "elf_sym.h"
#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int elf_resolve(const char *path, uintptr_t bias, const char *const *names, void **out, int count) {
    FILE *file;
    Elf64_Ehdr ehdr;
    Elf64_Shdr *shdrs = 0;
    char *strtab = 0;
    Elf64_Sym *syms = 0;
    int found = 0;
    int n;
    uint16_t i;

    if (!path || !names || !out || count <= 0) return 0;
    for (n = 0; n < count; n++) out[n] = 0;
    file = fopen(path, "rb");
    if (!file) return 0;
    if (fread(&ehdr, sizeof ehdr, 1, file) != 1 || memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0 || ehdr.e_ident[EI_CLASS] != ELFCLASS64) {
        fclose(file);
        return 0;
    }
    if (!ehdr.e_shnum || ehdr.e_shentsize < sizeof(Elf64_Shdr)) {
        fclose(file);
        return 0;
    }
    shdrs = calloc(ehdr.e_shnum, sizeof *shdrs);
    if (!shdrs || fseek(file, (long)ehdr.e_shoff, SEEK_SET) != 0 || fread(shdrs, sizeof *shdrs, ehdr.e_shnum, file) != ehdr.e_shnum) {
        free(shdrs);
        fclose(file);
        return 0;
    }
    for (i = 0; i < ehdr.e_shnum && found < count; i++) {
        Elf64_Shdr *link;
        uint64_t total;
        uint64_t s;
        if (shdrs[i].sh_type != SHT_SYMTAB || shdrs[i].sh_link >= ehdr.e_shnum) continue;
        link = &shdrs[shdrs[i].sh_link];
        if (!shdrs[i].sh_size || !link->sh_size) continue;
        free(strtab);
        free(syms);
        strtab = malloc(link->sh_size);
        syms = malloc(shdrs[i].sh_size);
        if (!strtab || !syms) break;
        if (fseek(file, (long)link->sh_offset, SEEK_SET) != 0 || fread(strtab, 1, link->sh_size, file) != link->sh_size) break;
        if (fseek(file, (long)shdrs[i].sh_offset, SEEK_SET) != 0 || fread(syms, 1, shdrs[i].sh_size, file) != shdrs[i].sh_size) break;
        total = shdrs[i].sh_size / sizeof(Elf64_Sym);
        for (s = 0; s < total; s++) {
            const char *sym;
            if (!syms[s].st_name || syms[s].st_name >= link->sh_size || !syms[s].st_value) continue;
            sym = strtab + syms[s].st_name;
            for (n = 0; n < count; n++) {
                if (!out[n] && strcmp(sym, names[n]) == 0) {
                    out[n] = (void *)(bias + (uintptr_t)syms[s].st_value);
                    found++;
                }
            }
        }
    }
    free(strtab);
    free(syms);
    free(shdrs);
    fclose(file);
    return found;
}
