#include "decode.h"

static int has_modrm(uint8_t op) {
    switch (op) {
    case 0x00: case 0x01: case 0x02: case 0x03:
    case 0x08: case 0x09: case 0x0A: case 0x0B:
    case 0x10: case 0x11: case 0x12: case 0x13:
    case 0x18: case 0x19: case 0x1A: case 0x1B:
    case 0x20: case 0x21: case 0x22: case 0x23:
    case 0x28: case 0x29: case 0x2A: case 0x2B:
    case 0x30: case 0x31: case 0x32: case 0x33:
    case 0x38: case 0x39: case 0x3A: case 0x3B:
    case 0x63:
    case 0x69: case 0x6B:
    case 0x80: case 0x81: case 0x82: case 0x83:
    case 0x84: case 0x85: case 0x86: case 0x87:
    case 0x88: case 0x89: case 0x8A: case 0x8B:
    case 0x8C: case 0x8D: case 0x8E: case 0x8F:
    case 0xC0: case 0xC1: case 0xC6: case 0xC7:
    case 0xD0: case 0xD1: case 0xD2: case 0xD3:
    case 0xF6: case 0xF7: case 0xFE: case 0xFF:
        return 1;
    default:
        return 0;
    }
}

static int imm_tail(uint8_t op, int opsize16) {
    switch (op) {
    case 0x80: case 0x82: case 0x83: case 0xC0: case 0xC1: case 0xC6: case 0x6B:
        return 1;
    case 0xC7: case 0x69:
        return opsize16 ? 2 : 4;
    case 0x81:
        return opsize16 ? 2 : 4;
    case 0xF6:
        return 1;
    case 0xF7:
        return opsize16 ? 2 : 4;
    default:
        return 0;
    }
}

static int modrm_size(const uint8_t *p, int avail, int *disp_off, int *rip) {
    int mod, rm, n = 1;
    uint8_t sib;
    if (avail < 1) return -1;
    mod = p[0] >> 6;
    rm = p[0] & 7;
    *disp_off = -1;
    *rip = 0;
    if (mod != 3 && rm == 4) {
        if (avail < 2) return -1;
        sib = p[1];
        n = 2;
        if (mod == 0 && (sib & 7) == 5) {
            *disp_off = n;
            n += 4;
        }
    }
    if (mod == 1) {
        *disp_off = n;
        n += 1;
    } else if (mod == 2) {
        *disp_off = n;
        n += 4;
    } else if (mod == 0 && rm == 5) {
        *disp_off = n;
        *rip = 1;
        n += 4;
    }
    if (n > avail) return -1;
    return n;
}

int decode_insn(const uint8_t *code, int avail, struct Insn *out) {
    int i = 0;
    int opsize16 = 0;
    int rip = 0;
    int disp_off = -1;
    int extra;
    int tail;
    uint8_t op;

    if (!code || !out || avail < 1) return 0;
    out->len = 0;
    out->fix = FIX_NONE;
    out->disp_off = -1;

    while (i < avail && i < 14) {
        uint8_t c = code[i];
        if (c == 0x66) {
            opsize16 = 1;
            i++;
            continue;
        }
        if (c == 0x67 || c == 0xF0 || c == 0xF2 || c == 0xF3 || c == 0x2E || c == 0x36 || c == 0x26 || c == 0x3E || c == 0x64 || c == 0x65) {
            i++;
            continue;
        }
#if defined(__x86_64__)
        if (c >= 0x40 && c <= 0x4F) {
            i++;
            continue;
        }
#endif
        break;
    }
    if (i >= avail) return 0;
    op = code[i];

    if (op >= 0x50 && op <= 0x5F) {
        out->len = i + 1;
        return 1;
    }
    if (op >= 0xB8 && op <= 0xBF) {
        out->len = i + 1 + (opsize16 ? 2 : 4);
#if defined(__x86_64__)
        if (i > 0 && code[i - 1] >= 0x48 && code[i - 1] <= 0x4F) out->len = i + 1 + 8;
#endif
        return out->len <= avail;
    }
    if (op == 0x90 || op == 0xC3 || op == 0xCC) {
        out->len = i + 1;
        return 1;
    }
    if (op >= 0x70 && op <= 0x7F) {
        out->len = i + 2;
        out->fix = FIX_REL8;
        out->disp_off = i + 1;
        return out->len <= avail;
    }
    if (op == 0xEB) {
        out->len = i + 2;
        out->fix = FIX_REL8;
        out->disp_off = i + 1;
        return out->len <= avail;
    }
    if (op == 0xE8 || op == 0xE9) {
        out->len = i + 5;
        out->fix = FIX_REL32;
        out->disp_off = i + 1;
        return out->len <= avail;
    }
    if (op == 0x0F) {
        uint8_t op2;
        if (i + 1 >= avail) return 0;
        op2 = code[i + 1];
        if (op2 >= 0x80 && op2 <= 0x8F) {
            out->len = i + 6;
            out->fix = FIX_REL32;
            out->disp_off = i + 2;
            return out->len <= avail;
        }
        if (op2 == 0x1E || op2 == 0x1F) {
            extra = modrm_size(code + i + 2, avail - (i + 2), &disp_off, &rip);
            if (extra < 0) return 0;
            out->len = i + 2 + extra;
            return 1;
        }
        return 0;
    }
    if (!has_modrm(op)) return 0;
    extra = modrm_size(code + i + 1, avail - (i + 1), &disp_off, &rip);
    if (extra < 0) return 0;
    tail = imm_tail(op, opsize16);
    if (op == 0xF6 || op == 0xF7) {
        uint8_t reg = (code[i + 1] >> 3) & 7;
        tail = (reg == 0 || reg == 1) ? imm_tail(op, opsize16) : 0;
    }
    out->len = i + 1 + extra + tail;
    if (out->len > avail) return 0;
    if (rip && disp_off >= 0) {
#if defined(__x86_64__)
        out->fix = FIX_RIP32;
        out->disp_off = i + 1 + disp_off;
#else
        out->fix = FIX_NONE;
#endif
    }
    return 1;
}
