#include "damage.h"
#include "abbrev.h"
#include "detour.h"
#include <stdio.h>

typedef void (*CreateFn)(void *desc, uint32_t type, const char *text, const void *color, const int32_t *rank);
typedef void (*UpdateFn)(void);
typedef void (*ExecFn)(const char *source, const char *file, const char *taint);

static CreateFn g_create;
static UpdateFn g_update;
static ExecFn g_exec;
static void **g_lua;
static int g_lua_tries;

static const char k_script[] =
    "if not TrunBlizzAbbrev then\n"
    "  function TrunBlizzAbbrev(n)\n"
    "    n = tonumber(n)\n"
    "    if not n then return nil end\n"
    "    local sign = \"\"\n"
    "    if n < 0 then sign = \"-\" n = -n end\n"
    "    if n < 1000 then return sign .. tostring(math.floor(n)) end\n"
    "    local div, suf = 1000, \"K\"\n"
    "    if n >= 1000000000 then div, suf = 1000000000, \"B\"\n"
    "    elseif n >= 1000000 then div, suf = 1000000, \"M\" end\n"
    "    return string.format(\"%s%d.%d%s\", sign, math.floor(n / div), math.floor((n % div) * 10 / div), suf)\n"
    "  end\n"
    "  function TrunBlizzAbbrevText(s)\n"
    "    if type(s) ~= \"string\" then return s end\n"
    "    return (s:gsub(\"([+-]?)(%d+)\", function(sig, digits)\n"
    "      if string.len(digits) < 4 then return sig .. digits end\n"
    "      return sig .. (TrunBlizzAbbrev(digits) or digits)\n"
    "    end))\n"
    "  end\n"
    "end\n"
    "if type(CombatText_AddMessage) == \"function\" and not TrunBlizzCombat then\n"
    "  local orig = CombatText_AddMessage\n"
    "  function CombatText_AddMessage(message, ...)\n"
    "    if type(message) == \"number\" then message = TrunBlizzAbbrev(message) or message\n"
    "    elseif type(message) == \"string\" then message = TrunBlizzAbbrevText(message) end\n"
    "    return orig(message, ...)\n"
    "  end\n"
    "  TrunBlizzCombat = true\n"
    "end\n"
    "if type(CombatFeedback_OnCombatEvent) == \"function\" and not TrunBlizzFeedback then\n"
    "  local orig = CombatFeedback_OnCombatEvent\n"
    "  function CombatFeedback_OnCombatEvent(self, ...)\n"
    "    orig(self, ...)\n"
    "    local font = self and self.feedbackText\n"
    "    if font and font.GetText and font.SetText then\n"
    "      local text = font:GetText()\n"
    "      if type(text) == \"string\" then\n"
    "        local nextText = TrunBlizzAbbrevText(text)\n"
    "        if nextText ~= text then font:SetText(nextText) end\n"
    "      end\n"
    "    end\n"
    "  end\n"
    "  TrunBlizzFeedback = true\n"
    "end\n";

static void log_line(const char *text) {
    FILE *file = fopen("TrunBlizzDmg335Patcher.log", "a");
    if (!file) return;
    fputs(text, file);
    fputc('\n', file);
    fclose(file);
}

static void install_lua(void) {
    static int busy;
    if (busy || !g_exec || g_lua_tries >= 8) return;
    if (g_lua && !*g_lua) return;
    busy = 1;
    g_lua_tries++;
    g_exec(k_script, "TrunBlizzDmg", 0);
    busy = 0;
}

static void hk_create(void *desc, uint32_t type, const char *text, const void *color, const int32_t *rank) {
    char buf[96];
    const char *shown = text;
    if (text && abbrev_combat_style(type)) {
        abbreviate(buf, sizeof buf, text);
        shown = buf;
    }
    install_lua();
    g_create(desc, type, shown, color, rank);
}

static void hk_update(void) {
    install_lua();
    g_update();
}

int damage_install(void *create_fn, void *update_fn, void *exec_fn, void **lua_state) {
    if (!create_fn) return -1;
    g_exec = exec_fn;
    g_lua = lua_state;
    if (update_fn && detour_install(update_fn, hk_update, (void **)&g_update) != 0) {
        log_line("world text update hook failed");
        g_update = 0;
    }
    if (detour_install(create_fn, hk_create, (void **)&g_create) != 0) {
        log_line("damage text hook failed");
        return -1;
    }
    log_line("damage numbers abbreviated");
    return 0;
}
