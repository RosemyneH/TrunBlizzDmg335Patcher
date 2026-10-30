#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "damage.h"

#define RVA_CREATE 0x003E6030u
#define RVA_UPDATE 0x003E6480u
#define RVA_EXEC 0x00419210u
#define RVA_GETLUA 0x00417DB0u

static int same(const uint8_t *p, const uint8_t *sig, size_t n) {
    return memcmp(p, sig, n) == 0;
}

static void install(void) {
    uint8_t *base = (uint8_t *)GetModuleHandleA(0);
    uint8_t *create_fn = base + RVA_CREATE;
    uint8_t *update_fn = base + RVA_UPDATE;
    uint8_t *exec_fn = base + RVA_EXEC;
    uint8_t *get_lua = base + RVA_GETLUA;
    void **lua_state = 0;
    void *update = 0;
    void *exec = 0;
    static const uint8_t k_create[] = { 0x55, 0x8B, 0xEC, 0x56, 0x8B, 0x75, 0x08 };
    static const uint8_t k_update[] = { 0x53, 0x56, 0xE8 };
    static const uint8_t k_exec[] = { 0x55, 0x8B, 0xEC, 0x51 };

    if (!same(create_fn, k_create, sizeof k_create)) return;
    if (same(update_fn, k_update, sizeof k_update)) update = update_fn;
    if (same(exec_fn, k_exec, sizeof k_exec)) exec = exec_fn;
    if (get_lua[0] == 0xA1 && get_lua[5] == 0xC3) {
        uint32_t linked = 0;
        memcpy(&linked, get_lua + 1, 4);
        lua_state = (void **)(uintptr_t)(linked - 0x00400000u + (uintptr_t)base);
    }
    damage_install(create_fn, update, exec, lua_state);
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        install();
    }
    return TRUE;
}
