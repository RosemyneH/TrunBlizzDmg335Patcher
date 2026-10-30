#pragma once
#include <stdint.h>

enum {
    FIX_NONE = 0,
    FIX_REL32 = 1,
    FIX_RIP32 = 2,
    FIX_REL8 = 3
};

struct Insn {
    int len;
    int fix;
    int disp_off;
};

int decode_insn(const uint8_t *code, int avail, struct Insn *out);
