const std = @import("std");

// ============================================================
// ELF CONSTANTS AND STRUCTURES
// ============================================================

const ELFMAG = [4]u8{ 0x7F, 'E', 'L', 'F' };

const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;

const ELFCLASS64: u8 = 2;

const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_GNU_RELRO: u32 = 0x6474e552;

const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_DYNAMIC: u32 = 6;
const SHT_DYNSYM: u32 = 11;

const Elf64_Ehdr = extern struct {
    e_ident: [16]u8,
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
};

const Elf64_Phdr = extern struct {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
};

const Elf64_Shdr = extern struct {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
};

const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
}

fn ptrCastMut(comptime T: type, data: []u8, offset: usize) ?*T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
}

fn getSecName(data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
    const start = @as(usize, @intCast(strtab_offset)) + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "<empty>";
    return data[start..end];
}

fn writeU16LE(data: []u8, offset: usize, value: u16) void {
    if (offset + 2 > data.len) return;
    data[offset] = @intCast(value & 0xff);
    data[offset + 1] = @intCast((value >> 8) & 0xff);
}

fn isLuaSafeName(name: []const u8) bool {
    if (name.len == 0) return false;
    const first = name[0];
    if (!((first >= 'a' and first <= 'z') or
          (first >= 'A' and first <= 'Z') or
          first == '_'))
        return false;

    for (name) |c| {
        if (!((c >= 'a' and c <= 'z') or
              (c >= 'A' and c <= 'Z') or
              (c >= '0' and c <= '9') or
              c == '_'))
            return false;
    }
    return true;
}

// ============================================================
// ANALYSIS STRUCTURES
// ============================================================

const ElfAnalysis = struct {
    is_pie: bool,
    is_stripped: bool,
    has_dynamic: bool,
    has_dynsym: bool,
    has_symtab: bool,
    base_addr: u64,
    entry_point: u64,
    interp: ?[]const u8,
    load_segments: u32,
    min_vaddr: u64,
    max_vaddr: u64,
};

const SymbolEntry = struct {
    name: []const u8,
    value: u64,
    size: u64,
    sym_type: u8,
    binding: u8,
    section_index: u16,
};

// ============================================================
// ELF ANALYSER
// ============================================================

fn analyseElf(
    data: []const u8,
    ehdr: *const Elf64_Ehdr,
    stdout: anytype,
) !ElfAnalysis {
    var analysis = ElfAnalysis{
        .is_pie = false,
        .is_stripped = true,
        .has_dynamic = false,
        .has_dynsym = false,
        .has_symtab = false,
        .base_addr = 0,
        .entry_point = ehdr.e_entry,
        .interp = null,
        .load_segments = 0,
        .min_vaddr = std.math.maxInt(u64),
        .max_vaddr = 0,
    };

    if (ehdr.e_type == ET_DYN) {
        analysis.is_pie = true;
    }

    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const off = @as(usize, @intCast(ehdr.e_phoff)) +
            @as(usize, pi) * @as(usize, ehdr.e_phentsize);
        const phdr = ptrCast(Elf64_Phdr, data, off) orelse continue;

        if (phdr.p_type == PT_LOAD) {
            analysis.load_segments += 1;
            if (phdr.p_vaddr < analysis.min_vaddr) {
                analysis.min_vaddr = phdr.p_vaddr;
            }
            const end_addr = phdr.p_vaddr + phdr.p_memsz;
            if (end_addr > analysis.max_vaddr) {
                analysis.max_vaddr = end_addr;
            }
        }

        if (phdr.p_type == PT_DYNAMIC) {
            analysis.has_dynamic = true;
        }

        if (phdr.p_type == PT_INTERP) {
            const interp_off = @as(usize, @intCast(phdr.p_offset));
            const interp_sz = @as(usize, @intCast(phdr.p_filesz));
            if (interp_off + interp_sz <= data.len and interp_sz > 0) {
                analysis.interp = data[interp_off .. interp_off + interp_sz - 1];
            }
        }
    }

    if (analysis.min_vaddr == std.math.maxInt(u64)) {
        analysis.min_vaddr = 0;
    }
    analysis.base_addr = analysis.min_vaddr;

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type == SHT_SYMTAB) {
            analysis.is_stripped = false;
            analysis.has_symtab = true;
        }
        if (shdr.sh_type == SHT_DYNSYM) analysis.has_dynsym = true;
        if (shdr.sh_type == SHT_DYNAMIC) analysis.has_dynamic = true;
    }

    try stdout.print("  PIE:            {s}\n", .{if (analysis.is_pie) "YES" else "NO"});
    try stdout.print("  Stripped:       {s}\n", .{if (analysis.is_stripped) "YES" else "NO"});
    try stdout.print("  Has .dynamic:   {s}\n", .{if (analysis.has_dynamic) "YES" else "NO"});
    try stdout.print("  Has .dynsym:    {s}\n", .{if (analysis.has_dynsym) "YES" else "NO"});
    try stdout.print("  Base address:   0x{x:0>16}\n", .{analysis.base_addr});
    try stdout.print("  Entry point:    0x{x:0>16}\n", .{analysis.entry_point});
    try stdout.print("  Load segments:  {d}\n", .{analysis.load_segments});
    try stdout.print("  VAddr range:    0x{x:0>16} - 0x{x:0>16}\n", .{ analysis.min_vaddr, analysis.max_vaddr });
    if (analysis.interp) |interp| {
        try stdout.print("  Interpreter:    {s}\n", .{interp});
    }

    return analysis;
}

// ============================================================
// SYMBOL EXTRACTION
// ============================================================

fn extractSymbols(
    allocator: std.mem.Allocator,
    data: []const u8,
    ehdr: *const Elf64_Ehdr,
    stdout: anytype,
) !std.ArrayList(SymbolEntry) {
    var symbols = std.ArrayList(SymbolEntry).init(allocator);

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type != SHT_SYMTAB and shdr.sh_type != SHT_DYNSYM) continue;

        var sym_strtab_off: usize = 0;
        var sj: u16 = 0;
        while (sj < ehdr.e_shnum) : (sj += 1) {
            const soff = @as(usize, @intCast(ehdr.e_shoff)) +
                @as(usize, sj) * @as(usize, ehdr.e_shentsize);
            const s_shdr = ptrCast(Elf64_Shdr, data, soff) orelse continue;
            if (sj == @as(u16, @intCast(shdr.sh_link)) and s_shdr.sh_type == SHT_STRTAB) {
                sym_strtab_off = @intCast(s_shdr.sh_offset);
                break;
            }
        }

        const entry_size = if (shdr.sh_entsize > 0)
            @as(usize, @intCast(shdr.sh_entsize))
        else
            @sizeOf(Elf64_Sym);
        const count = @as(usize, @intCast(shdr.sh_size)) / entry_size;

        const table_type: []const u8 = if (shdr.sh_type == SHT_SYMTAB) ".symtab" else ".dynsym";
        try stdout.print("  Found {s} with {d} symbols\n", .{ table_type, count });

        var idx: usize = 0;
        while (idx < count) : (idx += 1) {
            const sym_off = @as(usize, @intCast(shdr.sh_offset)) + idx * entry_size;
            const sym = ptrCast(Elf64_Sym, data, sym_off) orelse continue;

            const name_start = sym_strtab_off + @as(usize, sym.st_name);
            if (name_start >= data.len) continue;
            var name_end = name_start;
            while (name_end < data.len and data[name_end] != 0) : (name_end += 1) {}
            const name = data[name_start..name_end];

            if (name.len == 0) continue;
            if (sym.st_value == 0 and sym.st_shndx == 0) continue;

            try symbols.append(.{
                .name = name,
                .value = sym.st_value,
                .size = sym.st_size,
                .sym_type = sym.st_info & 0xf,
                .binding = sym.st_info >> 4,
                .section_index = sym.st_shndx,
            });
        }
    }

    return symbols;
}

// ============================================================
// LIBIFY TRANSFORMATION
// ============================================================

fn libify(
    allocator: std.mem.Allocator,
    data: []const u8,
    analysis: ElfAnalysis,
    output_path: []const u8,
    stdout: anytype,
) !void {
    const output = try allocator.alloc(u8, data.len);
    defer allocator.free(output);
    @memcpy(output, data);

    try stdout.writeAll("\n  Step 1: Patching ELF type ET_EXEC -> ET_DYN...\n");
    writeU16LE(output, 16, ET_DYN);
    try stdout.writeAll("          Done\n");

    if (!analysis.is_pie and analysis.base_addr != 0) {
        try stdout.print("  Step 2: Non-PIE binary, base address 0x{x}\n", .{analysis.base_addr});
        try stdout.writeAll("          Symbol values are absolute addresses\n");
    } else {
        try stdout.writeAll("  Step 2: PIE binary, addresses are relative\n");
    }

    try stdout.writeAll("  Step 3: Writing output...\n");

    const out_file = std.fs.cwd().createFile(output_path, .{ .mode = 0o755 }) catch |err| {
        try stdout.print("          Error: Cannot create output file ({s})\n", .{@errorName(err)});
        return;
    };
    defer out_file.close();

    try out_file.writeAll(output);
    try stdout.print("          Written to: {s}\n", .{output_path});
}

// ============================================================
// LUA CALLER GENERATOR
// ============================================================

fn generateLuaCaller(
    symbols: std.ArrayList(SymbolEntry),
    analysis: ElfAnalysis,
    lib_path: []const u8,
    output_path: []const u8,
    stdout: anytype,
) !void {
    const lua_file = std.fs.cwd().createFile(output_path, .{}) catch |err| {
        try stdout.print("Error: Cannot create Lua file ({s})\n", .{@errorName(err)});
        return;
    };
    defer lua_file.close();
    const w = lua_file.writer();

    try w.writeAll("#!/usr/bin/env luajit\n");
    try w.writeAll("--[[\n");
    try w.writeAll("  MOABI Generated LuaJIT FFI Caller\n");
    try w.writeAll("  Auto-generated by moabi-libify\n");
    try w.writeAll("]]\n\n");

    try w.writeAll("local ffi = require('ffi')\n\n");

    try w.writeAll("-- Function declarations\n");
    try w.writeAll("ffi.cdef[[\n");

    var func_count: u32 = 0;
    for (symbols.items) |sym| {
        const is_func = sym.sym_type == 2;
        const has_value = sym.value != 0;
        const has_section = sym.section_index != 0;
        const safe_name = isLuaSafeName(sym.name);

        if (is_func and has_value and has_section and safe_name) {
            try w.print("    void* {s}();  // addr=0x{x}\n", .{ sym.name, sym.value });
            func_count += 1;
        }
    }

    try w.writeAll("]]\n\n");

    try w.print("local lib_path = '{s}'\n", .{lib_path});
    try w.writeAll("local lib = ffi.load(lib_path)\n\n");

    if (!analysis.is_pie) {
        try w.print("-- Non-PIE binary, original base: 0x{x}\n", .{analysis.base_addr});
    } else {
        try w.writeAll("-- PIE binary: addresses are relative to load base\n");
    }

    try w.writeAll("\n-- Symbol table\n");
    try w.writeAll("local SYMBOLS = {\n");
    for (symbols.items) |sym| {
        const has_value = sym.value != 0;
        const has_section = sym.section_index != 0;
        const safe_name = isLuaSafeName(sym.name);

        if (has_value and has_section and safe_name) {
            try w.print("    ['{s}'] = 0x{x},\n", .{ sym.name, sym.value });
        }
    }
    try w.writeAll("}\n\n");

    try w.writeAll(
        \\local function get_func(name)
        \\    local ok, f = pcall(function() return lib[name] end)
        \\    if ok and f then return f end
        \\    return nil
        \\end
        \\
        \\local function list_functions()
        \\    print('\nAvailable functions:')
        \\    for name, addr in pairs(SYMBOLS) do
        \\        print(string.format('  0x%016x  %s', addr, name))
        \\    end
        \\end
        \\
        \\print('')
        \\print('MOABI Libify - Direct Binary Access')
        \\print('====================================')
        \\print('Library: ' .. lib_path)
        \\
    );

    try w.print("print('Functions discovered: {d}')\n", .{func_count});
    try w.writeAll("list_functions()\n");
    try w.writeAll("print('')\n");

    try stdout.print("  LuaJIT caller written to: {s}\n", .{output_path});
    try stdout.print("  Functions exported: {d}\n", .{func_count});
}

// ============================================================
// MAIN
// ============================================================

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stdout = std.io.getStdOut().writer();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var path: ?[]const u8 = null;
    var output_path: ?[]const u8 = null;
    var generate_lua = true;
    var info_only = false;

    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];

        if (std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) {
            if (ai + 1 < args.len) {
                ai += 1;
                output_path = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--no-lua")) {
            generate_lua = false;
        } else if (std.mem.eql(u8, arg, "--info") or std.mem.eql(u8, arg, "-i")) {
            info_only = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\MOABI-LIBIFY: ELF ET_EXEC -> ET_DYN Transformer
                \\
                \\Usage:
                \\  moabi-libify [options] <binary>
                \\
                \\Options:
                \\  -o, --output <file>  Output path (default: <binary>.so)
                \\  -i, --info           Analyse only, do not transform
                \\  --no-lua             Skip LuaJIT caller generation
                \\  -h, --help           Show this help
                \\
            );
            return;
        } else {
            path = arg;
        }
    }

    if (path == null) {
        try stdout.writeAll("Error: No file specified. Use --help for usage.\n");
        std.process.exit(1);
    }

    const file = std.fs.cwd().openFile(path.?, .{}) catch |err| {
        try stdout.print("Error: Cannot open '{s}' ({s})\n", .{ path.?, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const fsize = @as(usize, @intCast(stat.size));
    const data = try allocator.alloc(u8, fsize);
    defer allocator.free(data);
    _ = try file.readAll(data);

    if (data.len < @sizeOf(Elf64_Ehdr) or !std.mem.eql(u8, data[0..4], &ELFMAG)) {
        try stdout.writeAll("Error: Not a valid ELF file\n");
        std.process.exit(1);
    }

    const ehdr = ptrCast(Elf64_Ehdr, data, 0) orelse {
        try stdout.writeAll("Error: Cannot read ELF header\n");
        std.process.exit(1);
    };

    var strtab_offset: u64 = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
        if (ptrCast(Elf64_Shdr, data, off)) |shdr| {
            strtab_offset = shdr.sh_offset;
        }
    }

    try stdout.writeAll("\n");
    try stdout.writeAll("==================================================\n");
    try stdout.writeAll("  MOABI-LIBIFY v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("  ELF Binary -> Shared Library Transformer\n");
    try stdout.writeAll("==================================================\n\n");

    try stdout.print("Input:  {s}\n", .{path.?});
    try stdout.print("Size:   {d} bytes\n", .{fsize});

    const type_str: []const u8 = switch (ehdr.e_type) {
        ET_EXEC => "ET_EXEC (executable)",
        ET_DYN => "ET_DYN (shared/PIE)",
        else => "Unknown",
    };
    try stdout.print("Type:   {s}\n\n", .{type_str});

    try stdout.writeAll("--- BINARY ANALYSIS ---\n\n");
    const analysis = try analyseElf(data, ehdr, stdout);

    try stdout.writeAll("\n--- SYMBOL EXTRACTION ---\n\n");
    const symbols = try extractSymbols(allocator, data, ehdr, stdout);
    defer symbols.deinit();

    try stdout.print("  Total symbols: {d}\n", .{symbols.items.len});

    if (symbols.items.len > 0) {
        try stdout.writeAll("\n  Functions:\n");
        var shown: u32 = 0;
        for (symbols.items) |sym| {
            const is_func = sym.sym_type == 2;
            const has_value = sym.value != 0;
            const has_section = sym.section_index != 0;
            const safe_name = isLuaSafeName(sym.name);

            if (is_func and has_value and has_section and safe_name) {
                const bind_str: []const u8 = switch (sym.binding) {
                    0 => "LOCAL ",
                    1 => "GLOBAL",
                    2 => "WEAK  ",
                    else => "OTHER ",
                };
                try stdout.print("    {s} 0x{x:0>16} {s}\n", .{ bind_str, sym.value, sym.name });
                shown += 1;
                if (shown >= 20) {
                    try stdout.writeAll("    ... (truncated)\n");
                    break;
                }
            }
        }
    }

    if (info_only) {
        try stdout.writeAll("\n  Info-only mode, no transformation.\n\n");
        return;
    }

    const base_name = std.fs.path.basename(path.?);
    var out_buf: [512]u8 = undefined;
    const out_path = output_path orelse blk: {
        const result = std.fmt.bufPrint(&out_buf, "{s}.so", .{base_name}) catch "output.so";
        break :blk result;
    };

    var lua_buf: [512]u8 = undefined;
    const lua_path = std.fmt.bufPrint(&lua_buf, "{s}.lua", .{out_path}) catch "caller.lua";

    try stdout.writeAll("\n--- TRANSFORMATION ---\n");
    try libify(allocator, data, analysis, out_path, stdout);

    if (generate_lua) {
        try stdout.writeAll("\n--- LuaJIT FFI CALLER ---\n\n");
        try generateLuaCaller(symbols, analysis, out_path, lua_path, stdout);
    }

    try stdout.writeAll("\n--- NEXT STEPS ---\n\n");
    try stdout.print("  1. Verify:      file {s}\n", .{out_path});
    try stdout.print("  2. Run caller:  luajit {s}\n", .{lua_path});
    try stdout.writeAll("\n");
}
