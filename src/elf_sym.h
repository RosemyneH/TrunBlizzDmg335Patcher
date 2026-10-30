#pragma once
#include <stdint.h>

int elf_resolve(const char *path, uintptr_t bias, const char *const *names, void **out, int count);
