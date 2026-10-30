CC ?= gcc
CFLAGS := -O2 -std=c11 -Wall -Wextra -fno-strict-aliasing
MINGW := i686-w64-mingw32-gcc
BUILD := build

.PHONY: all test clean

all: test $(BUILD)/TrunBlizzDmg335Patcher $(BUILD)/libTrunBlizzDmg335Patcher.so $(BUILD)/TrunBlizzDmg335Patcher.dll $(BUILD)/TrunBlizzDmg335Patcher.exe

test: $(BUILD)/test_abbrev
	$(BUILD)/test_abbrev

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/test_abbrev: src/test_main.c src/abbrev.c src/decode.c src/detour.c src/elf_sym.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/test_main.c src/abbrev.c src/decode.c src/detour.c src/elf_sym.c

$(BUILD)/TrunBlizzDmg335Patcher: src/patch_main.c src/pe_patch.c | $(BUILD)
	$(CC) $(CFLAGS) -o $@ src/patch_main.c src/pe_patch.c

$(BUILD)/libTrunBlizzDmg335Patcher.so: src/linux_so.c src/elf_sym.c src/damage.c src/detour.c src/decode.c src/abbrev.c | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ src/linux_so.c src/elf_sym.c src/damage.c src/detour.c src/decode.c src/abbrev.c

$(BUILD)/TrunBlizzDmg335Patcher.dll: src/win_dll.c src/damage.c src/detour.c src/decode.c src/abbrev.c | $(BUILD)
	$(MINGW) $(CFLAGS) -shared -o $@ src/win_dll.c src/damage.c src/detour.c src/decode.c src/abbrev.c

$(BUILD)/TrunBlizzDmg335Patcher.exe: src/patch_main.c src/pe_patch.c | $(BUILD)
	$(MINGW) $(CFLAGS) -o $@ src/patch_main.c src/pe_patch.c

clean:
	rm -rf $(BUILD)
