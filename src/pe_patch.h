#pragma once
#include <stddef.h>
#include <stdint.h>

int pe_add_import(const char *path, const char *dll_name, char *err, unsigned err_cap);
uint32_t pe_checksum(const uint8_t *data, size_t size, size_t checksum_off);
