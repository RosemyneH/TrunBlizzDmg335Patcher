#include "abbrev.h"
#include <stdio.h>
#include <string.h>

int abbrev_combat_style(uint32_t type) {
    return type == 0 || type == 2 || type == 4 || type == 6 || type == 7 || type == 8 || type == 9;
}

void abbreviate(char *dst, size_t cap, const char *src) {
    const char *digits = 0;
    const char *end = src;
    unsigned long long value = 0;
    unsigned long long div = 1000ull;
    unsigned frac;
    size_t prefix;
    const char *suffix = "K";

    if (!dst || !cap) return;
    dst[0] = 0;
    if (!src) return;

    for (const char *p = src; *p; p++) {
        if (*p >= '0' && *p <= '9') {
            if (!digits) digits = p;
            end = p + 1;
        } else {
            digits = 0;
        }
    }

    if (!digits || *end) {
        snprintf(dst, cap, "%s", src);
        return;
    }

    for (const char *p = digits; p < end; p++) value = value * 10ull + (unsigned)(*p - '0');
    if (value < 1000ull) {
        snprintf(dst, cap, "%s", src);
        return;
    }

    if (value >= 1000000000ull) {
        div = 1000000000ull;
        suffix = "B";
    } else if (value >= 1000000ull) {
        div = 1000000ull;
        suffix = "M";
    }

    frac = (unsigned)((value % div) * 10ull / div);
    prefix = (size_t)(digits - src);
    if (prefix >= cap) {
        snprintf(dst, cap, "%s", src);
        return;
    }
    memcpy(dst, src, prefix);
    snprintf(dst + prefix, cap - prefix, "%llu.%u%s", value / div, frac, suffix);
}
