# /mnt/d/moabi/Makefile
# Master build for the Moabi research suite

MOABI_ROOT := /mnt/d/moabi
BIN := $(MOABI_ROOT)/bin
SRC := $(MOABI_ROOT)/src
ZIG := $(BIN)/zig
LUAJIT := $(BIN)/luajit

.PHONY: all clean test tools

all: tools

tools: $(BIN)/moabi-entropy

$(BIN)/moabi-entropy: $(SRC)/analyzer/entropy.zig
	@echo "[BUILD] moabi-entropy"
	@$(ZIG) build-exe $< -O ReleaseSafe --name moabi-entropy -femit-bin=$@
	@echo "[OK] $@"

test: tools
	@echo "[TEST] Entropy analysis of /usr/bin/ls"
	@$(BIN)/moabi-entropy /usr/bin/ls
	@echo ""
	@echo "[TEST] Disassembly of /usr/bin/ls .text"
	@$(LUAJIT) $(SRC)/analyzer/disasm.lua /usr/bin/ls 0 512

clean:
	rm -f $(BIN)/moabi-*

info:
	@echo "MOABI_ROOT: $(MOABI_ROOT)"
	@echo "Zig:        $$($(ZIG) version 2>/dev/null || echo 'not found')"
	@echo "LuaJIT:     $$($(LUAJIT) -v 2>&1 | head -1 || echo 'not found')"
