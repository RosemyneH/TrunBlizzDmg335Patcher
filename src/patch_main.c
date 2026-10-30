#include "pe_patch.h"
#include <stdio.h>
#include <string.h>

static int write_loader(const char *exe_path) {
    char script[4096];
    char dir[4096];
    const char *slash;
    const char *base;
    FILE *file;
    size_t dir_len;

    slash = strrchr(exe_path, '/');
    if (!slash) slash = strrchr(exe_path, '\\');
    base = slash ? slash + 1 : exe_path;
    dir_len = slash ? (size_t)(slash - exe_path) : 1;
    if (dir_len >= sizeof dir) return -1;
    if (slash) {
        memcpy(dir, exe_path, dir_len);
        dir[dir_len] = 0;
    } else {
        memcpy(dir, ".", 2);
    }
    snprintf(script, sizeof script, "%s/TrunBlizzDmg335.sh", dir);
    file = fopen(script, "w");
    if (!file) return -1;
    fprintf(file,
            "#!/bin/sh\n"
            "dir=$(CDPATH= cd -- \"$(dirname \"$0\")\" && pwd)\n"
            "export LD_PRELOAD=\"$dir/libTrunBlizzDmg335Patcher.so${LD_PRELOAD:+:$LD_PRELOAD}\"\n"
            "exec \"$dir/%s\" \"$@\"\n",
            base);
    fclose(file);
    return 0;
}

int main(int argc, char **argv) {
    unsigned char mag[4];
    FILE *file;
    char err[160];
    int rc;

    if (argc != 2) {
        fprintf(stderr, "usage: TrunBlizzDmg335Patcher <Wow.exe or WowClient64>\n");
        return 1;
    }
    file = fopen(argv[1], "rb");
    if (!file || fread(mag, 1, 4, file) != 4) {
        if (file) fclose(file);
        fprintf(stderr, "cannot read %s\n", argv[1]);
        return 1;
    }
    fclose(file);
    if (mag[0] == 'M' && mag[1] == 'Z') {
        rc = pe_add_import(argv[1], "TrunBlizzDmg335Patcher.dll", err, sizeof err);
        printf("%s\n", err[0] ? err : "patched");
        if (rc == 0) printf("copy TrunBlizzDmg335Patcher.dll next to Wow.exe\n");
        return rc < 0 ? 1 : 0;
    }
    if (mag[0] == 0x7F && mag[1] == 'E' && mag[2] == 'L' && mag[3] == 'F') {
        if (write_loader(argv[1]) != 0) {
            fprintf(stderr, "cannot write TrunBlizzDmg335.sh\n");
            return 1;
        }
        printf("wrote TrunBlizzDmg335.sh\n");
        printf("copy libTrunBlizzDmg335Patcher.so next to the client and launch the script\n");
        return 0;
    }
    fprintf(stderr, "not a Wow executable\n");
    return 1;
}
