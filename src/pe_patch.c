#include "pe_patch.h"
#include <ctype.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

uint32_t pe_checksum(const uint8_t *data, size_t size, size_t checksum_off) {
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < size; i += 2) {
        uint32_t word;
        if (i == checksum_off || i == checksum_off + 2) continue;
        word = (uint32_t)data[i] | ((uint32_t)data[i + 1] << 8);
        sum += word;
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    if (size & 1) {
        sum += data[size - 1];
        sum = (sum & 0xFFFFu) + (sum >> 16);
    }
    sum = (sum & 0xFFFFu) + (sum >> 16);
    return (sum & 0xFFFFu) + (uint32_t)size;
}

static uint32_t align_up(uint32_t value, uint32_t align) {
    return (value + align - 1u) & ~(align - 1u);
}

static int ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == 0 && *b == 0;
}

static const char k_export[] = "TrunBlizzLoad";

static void fail(char *err, unsigned err_cap, const char *text) {
    if (err && err_cap) snprintf(err, err_cap, "%s", text);
}

static void put32(uint8_t *p, uint32_t value) {
    memcpy(p, &value, 4);
}

static int commit_image(const char *path, uint8_t *image, size_t size, uint32_t e_lfanew, char *err, unsigned err_cap) {
    char bak[4096];
    char tmp[4096];
    FILE *file;
    size_t checksum_off = (size_t)e_lfanew + 24u + 64u;
    uint32_t sum;

    memset(image + checksum_off, 0, 4);
    sum = pe_checksum(image, size, checksum_off);
    memcpy(image + checksum_off, &sum, 4);

    snprintf(bak, sizeof bak, "%s.bak", path);
    file = fopen(bak, "rb");
    if (file) {
        fclose(file);
    } else {
        FILE *src = fopen(path, "rb");
        uint8_t buf[8192];
        size_t n;
        file = fopen(bak, "wb");
        if (!file || !src) {
            if (file) fclose(file);
            if (src) fclose(src);
            fail(err, err_cap, "cannot write backup");
            return -1;
        }
        while ((n = fread(buf, 1, sizeof buf, src)) > 0) fwrite(buf, 1, n, file);
        fclose(src);
        fclose(file);
    }

    snprintf(tmp, sizeof tmp, "%s.truntmp", path);
    file = fopen(tmp, "wb");
    if (!file || fwrite(image, 1, size, file) != size) {
        if (file) fclose(file);
        fail(err, err_cap, "cannot write patched exe");
        return -1;
    }
    fclose(file);
    if (rename(tmp, path) != 0) {
        fail(err, err_cap, "cannot replace exe");
        return -1;
    }
    return 0;
}

int pe_add_import(const char *path, const char *dll_name, char *err, unsigned err_cap) {
    FILE *file;
    uint8_t *image = 0;
    long file_size;
    uint32_t e_lfanew, sect_align, file_align, size_headers;
    uint16_t opt_size;
    uint32_t imp_rva, imp_off, new_va, new_off, raw_size, virt_size;
    uint16_t nsec, magic;
    uint8_t *opt;
    uint8_t *sec;
    uint32_t orig_count = 0;
    uint32_t desc_bytes, name_off, int_off, iat_off, ibn_off;
    uint32_t match_index = 0;
    uint32_t match_oft = 0;
    uint32_t match_name = 0;
    uint8_t *blob = 0;
    uint32_t blob_len = 0;
    uint32_t blob_cap = 0;
    int present = 0;
    uint32_t i;

    if (err && err_cap) err[0] = 0;
    file = fopen(path, "rb");
    if (!file) {
        fail(err, err_cap, "cannot open exe");
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        fail(err, err_cap, "cannot read exe");
        return -1;
    }
    file_size = ftell(file);
    if (file_size < 0x200 || file_size > 64 * 1024 * 1024) {
        fclose(file);
        fail(err, err_cap, "unexpected exe size");
        return -1;
    }
    rewind(file);
    image = malloc((size_t)file_size);
    if (!image || fread(image, 1, (size_t)file_size, file) != (size_t)file_size) {
        free(image);
        fclose(file);
        fail(err, err_cap, "cannot read exe");
        return -1;
    }
    fclose(file);

    if (image[0] != 'M' || image[1] != 'Z') {
        free(image);
        fail(err, err_cap, "not a PE");
        return -1;
    }
    memcpy(&e_lfanew, image + 0x3C, 4);
    if (e_lfanew + 0x100 > (uint32_t)file_size || memcmp(image + e_lfanew, "PE\0\0", 4) != 0) {
        free(image);
        fail(err, err_cap, "not a PE");
        return -1;
    }
    memcpy(&nsec, image + e_lfanew + 6, 2);
    memcpy(&opt_size, image + e_lfanew + 20, 2);
    opt = image + e_lfanew + 24;
    memcpy(&magic, opt, 2);
    if (magic != 0x10B) {
        free(image);
        fail(err, err_cap, "only 32-bit Wow.exe is patched on disk");
        return -1;
    }
    memcpy(&sect_align, opt + 0x20, 4);
    memcpy(&file_align, opt + 0x24, 4);
    memcpy(&size_headers, opt + 0x3C, 4);
    memcpy(&imp_rva, opt + 0x68, 4);
    if (!sect_align || !file_align || (sect_align & (sect_align - 1)) || (file_align & (file_align - 1))) {
        free(image);
        fail(err, err_cap, "bad section alignment");
        return -1;
    }
    sec = opt + opt_size;
    if ((uint32_t)(sec - image) + (nsec + 1u) * 40u > size_headers) {
        free(image);
        fail(err, err_cap, "no room for another section header");
        return -1;
    }

    imp_off = 0;
    for (i = 0; i < nsec; i++) {
        uint32_t va, raw_sz, raw;
        memcpy(&va, sec + i * 40 + 12, 4);
        memcpy(&raw_sz, sec + i * 40 + 16, 4);
        memcpy(&raw, sec + i * 40 + 20, 4);
        if (imp_rva >= va && imp_rva < va + raw_sz) imp_off = raw + (imp_rva - va);
    }
    if (!imp_off) {
        free(image);
        fail(err, err_cap, "import directory is not in a section");
        return -1;
    }

    for (;;) {
        uint32_t oft, name, ft, name_rva_off;
        if (imp_off + (orig_count + 1) * 20 > (uint32_t)file_size) {
            free(image);
            fail(err, err_cap, "import directory is truncated");
            return -1;
        }
        memcpy(&oft, image + imp_off + orig_count * 20, 4);
        memcpy(&name, image + imp_off + orig_count * 20 + 12, 4);
        memcpy(&ft, image + imp_off + orig_count * 20 + 16, 4);
        if (!oft && !name && !ft) break;
        name_rva_off = 0;
        for (i = 0; i < nsec; i++) {
            uint32_t va, raw_sz, raw;
            memcpy(&va, sec + i * 40 + 12, 4);
            memcpy(&raw_sz, sec + i * 40 + 16, 4);
            memcpy(&raw, sec + i * 40 + 20, 4);
            if (name >= va && name < va + raw_sz) name_rva_off = raw + (name - va);
        }
        if (name_rva_off && name_rva_off < (uint32_t)file_size && ieq((char *)image + name_rva_off, dll_name)) {
            present = 1;
            match_index = orig_count;
            match_oft = oft;
            match_name = name;
        }
        orig_count++;
    }
    if (present) {
        uint32_t oft_off = 0;
        uint32_t thunk = 0;
        uint32_t sec_va = 0, sec_virt = 0, sec_raw = 0, sec_rawsz = 0, sec_i = 0;
        uint32_t place, ibn_rva, int_rva, iat_rva, need;
        int found_sec = 0;
        for (i = 0; i < nsec; i++) {
            uint32_t va, raw_sz, raw;
            memcpy(&va, sec + i * 40 + 12, 4);
            memcpy(&raw_sz, sec + i * 40 + 16, 4);
            memcpy(&raw, sec + i * 40 + 20, 4);
            if (match_oft >= va && match_oft < va + raw_sz) oft_off = raw + (match_oft - va);
            if (match_name >= va && match_name < va + raw_sz) {
                memcpy(&sec_virt, sec + i * 40 + 8, 4);
                sec_va = va;
                sec_raw = raw;
                sec_rawsz = raw_sz;
                sec_i = i;
                found_sec = 1;
            }
        }
        if (!oft_off || !found_sec) {
            free(image);
            fail(err, err_cap, "existing import is not in a section");
            return -1;
        }
        memcpy(&thunk, image + oft_off, 4);
        if (thunk) {
            free(image);
            fail(err, err_cap, "already patched");
            return 1;
        }
        if (!sec_virt) sec_virt = sec_rawsz;
        place = align_up(sec_virt, 2);
        need = 8 + 8 + 2 + (uint32_t)strlen(k_export) + 1;
        if (place + need > sec_rawsz || sec_va + place + need > sec_va + sect_align) {
            free(image);
            fail(err, err_cap, "no room to name the import");
            return -1;
        }
        int_rva = sec_va + place;
        iat_rva = int_rva + 8;
        ibn_rva = iat_rva + 8;
        memset(image + sec_raw + place, 0, need);
        put32(image + sec_raw + place, ibn_rva);
        put32(image + sec_raw + place + 8, ibn_rva);
        memcpy(image + sec_raw + place + 16 + 2, k_export, strlen(k_export) + 1);
        put32(image + imp_off + match_index * 20, int_rva);
        put32(image + imp_off + match_index * 20 + 16, iat_rva);
        need = place + need;
        memcpy(sec + sec_i * 40 + 8, &need, 4);
        if (commit_image(path, image, (size_t)file_size, e_lfanew, err, err_cap) != 0) {
            free(image);
            return -1;
        }
        free(image);
        fail(err, err_cap, "patched");
        return 0;
    }

    new_va = 0;
    for (i = 0; i < nsec; i++) {
        uint32_t va, virt, raw_sz, end;
        memcpy(&virt, sec + i * 40 + 8, 4);
        memcpy(&va, sec + i * 40 + 12, 4);
        memcpy(&raw_sz, sec + i * 40 + 16, 4);
        if (!virt) virt = raw_sz;
        end = va + align_up(virt, sect_align);
        if (end > new_va) new_va = end;
    }
    new_off = align_up((uint32_t)file_size, file_align);

    desc_bytes = (orig_count + 2) * 20;
    int_off = desc_bytes;
    iat_off = int_off + 8;
    ibn_off = iat_off + 8;
    name_off = align_up(ibn_off + 2 + (uint32_t)strlen(k_export) + 1, 2);
    blob_len = name_off + (uint32_t)strlen(dll_name) + 1;
    blob_cap = blob_len + file_align;
    blob = calloc(1, blob_cap);
    if (!blob) {
        free(image);
        fail(err, err_cap, "out of memory");
        return -1;
    }
    memcpy(blob, image + imp_off, orig_count * 20);
    put32(blob + int_off, new_va + ibn_off);
    put32(blob + iat_off, new_va + ibn_off);
    memcpy(blob + ibn_off + 2, k_export, strlen(k_export) + 1);
    memcpy(blob + name_off, dll_name, strlen(dll_name) + 1);
    virt_size = blob_len;
    raw_size = align_up(blob_len, file_align);

    {
        uint8_t *desc = blob + orig_count * 20;
        uint32_t oft = new_va + int_off;
        uint32_t nm = new_va + name_off;
        uint32_t ft = new_va + iat_off;
        memcpy(desc, &oft, 4);
        memcpy(desc + 12, &nm, 4);
        memcpy(desc + 16, &ft, 4);
    }

    memset(sec + nsec * 40, 0, 40);
    memcpy(sec + nsec * 40, ".trun", 5);
    memcpy(sec + nsec * 40 + 8, &virt_size, 4);
    memcpy(sec + nsec * 40 + 12, &new_va, 4);
    memcpy(sec + nsec * 40 + 16, &raw_size, 4);
    memcpy(sec + nsec * 40 + 20, &new_off, 4);
    {
        uint32_t flags = 0xC0000040u;
        memcpy(sec + nsec * 40 + 36, &flags, 4);
    }
    nsec++;
    memcpy(image + e_lfanew + 6, &nsec, 2);
    {
        uint32_t image_size = align_up(new_va + virt_size, sect_align);
        uint32_t dir_size = (orig_count + 2) * 20;
        memcpy(opt + 0x38, &image_size, 4);
        memcpy(opt + 0x68, &new_va, 4);
        memcpy(opt + 0x6C, &dir_size, 4);
    }

    {
        uint8_t *grown = realloc(image, new_off + raw_size);
        if (!grown) {
            free(blob);
            free(image);
            fail(err, err_cap, "out of memory");
            return -1;
        }
        image = grown;
        if (new_off > (uint32_t)file_size) memset(image + file_size, 0, new_off - (uint32_t)file_size);
        memset(image + new_off, 0, raw_size);
        memcpy(image + new_off, blob, virt_size);
    }
    free(blob);

    if (commit_image(path, image, new_off + raw_size, e_lfanew, err, err_cap) != 0) {
        free(image);
        return -1;
    }
    free(image);
    fail(err, err_cap, "patched");
    return 0;
}
