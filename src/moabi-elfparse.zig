const std = @import("std");

// ============================================================
// ELF CONSTANTS
// ============================================================

// ELF Magic
const ELFMAG = [4]u8{ 0x7F, 'E', 'L', 'F' };

// ELF Class
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

// ELF Data encoding
const ELFDATA2LSB: u8 = 1;
const ELFDATA2MSB: u8 = 2;

// ELF Type
const ET_NONE: u16 = 0;
const ET_REL: u16 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const ET_CORE: u16 = 4;

// Program header types
const PT_NULL: u32 = 0;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_SHLIB: u32 = 5;
const PT_PHDR: u32 = 6;
const PT_GNU_EH_FRAME: u32 = 0x6474e550;
const PT_GNU_STACK: u32 = 0x6474e551;
const PT_GNU_RELRO: u32 = 0x6474e552;

// Program header flags
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

// Section header types
const SHT_NULL: u32 = 0;
const SHT_PROGBITS: u32 = 1;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_RELA: u32 = 4;
const SHT_HASH: u32 = 5;
const SHT_DYNAMIC: u32 = 6;
const SHT_NOTE: u32 = 7;
const SHT_NOBITS: u32 = 8;
const SHT_REL: u32 = 9;
const SHT_DYNSYM: u32 = 11;

// Section header flags
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

// ============================================================
// ELF64 STRUCTURES (packed for direct memory mapping)
// ============================================================

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

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn typeStr(t: u16) []const u8 {
    return switch (t) {
        ET_NONE => "NONE",
        ET_REL => "REL (Relocatable)",
        ET_EXEC => "EXEC (Executable)",
        ET_DYN => "DYN (Shared/PIE)",
        ET_CORE => "CORE",
        else => "UNKNOWN",
    };
}

fn machineStr(m: u16) []const u8 {
    return switch (m) {
        0x03 => "x86 (i386)",
        0x3E => "x86_64 (AMD64)",
        0x28 => "ARM",
        0xB7 => "AArch64",
        0xF3 => "RISC-V",
        else => "OTHER",
    };
}

fn phdrTypeStr(t: u32) []const u8 {
    return switch (t) {
        PT_NULL => "NULL",
        PT_LOAD => "LOAD",
        PT_DYNAMIC => "DYNAMIC",
        PT_INTERP => "INTERP",
        PT_NOTE => "NOTE",
        PT_SHLIB => "SHLIB",
        PT_PHDR => "PHDR",
        PT_GNU_EH_FRAME => "GNU_EH_FRAME",
        PT_GNU_STACK => "GNU_STACK",
        PT_GNU_RELRO => "GNU_RELRO",
        else => "OTHER",
    };
}

fn shdrTypeStr(t: u32) []const u8 {
    return switch (t) {
        SHT_NULL => "NULL",
        SHT_PROGBITS => "PROGBITS",
        SHT_SYMTAB => "SYMTAB",
        SHT_STRTAB => "STRTAB",
        SHT_RELA => "RELA",
        SHT_HASH => "HASH",
        SHT_DYNAMIC => "DYNAMIC",
        SHT_NOTE => "NOTE",
        SHT_NOBITS => "NOBITS",
        SHT_REL => "REL",
        SHT_DYNSYM => "DYNSYM",
        else => "OTHER",
    };
}

fn flagsStr(flags: u32, buf: *[4]u8) []const u8 {
    buf[0] = if (flags & PF_R != 0) 'R' else '-';
    buf[1] = if (flags & PF_W != 0) 'W' else '-';
    buf[2] = if (flags & PF_X != 0) 'X' else '-';
    buf[3] = 0;
    return buf[0..3];
}

fn shFlagsStr(flags: u64, buf: *[4]u8) []const u8 {
    buf[0] = if (flags & SHF_WRITE != 0) 'W' else '-';
    buf[1] = if (flags & SHF_ALLOC != 0) 'A' else '-';
    buf[2] = if (flags & SHF_EXECINSTR != 0) 'X' else '-';
    buf[3] = 0;
    return buf[0..3];
}

// Read a section name from the string table
fn getSectionName(data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
    const start = @as(usize, @intCast(strtab_offset)) + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";

    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "<empty>";
    return data[start..end];
}

// Cast raw bytes to a struct pointer
fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
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

    if (args.len < 2) {
        try stdout.print("Usage: {s} <elf-binary>\n", .{args[0]});
        std.process.exit(1);
    }

    const path = args[1];

    // Read entire file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("Error: Cannot open '{s}' ({s})\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const data = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(data);
    _ = try file.readAll(data);

    // ---- ELF HEADER ----
    try stdout.writeAll("\n========================================\n");
    try stdout.writeAll("  MOABI ELF PARSER v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("========================================\n\n");

    if (data.len < @sizeOf(Elf64_Ehdr)) {
        try stdout.writeAll("Error: File too small for ELF header\n");
        std.process.exit(1);
    }

    // Validate magic
    if (!std.mem.eql(u8, data[0..4], &ELFMAG)) {
        try stdout.print("Error: Not an ELF file (magic: {x:0>2} {x:0>2} {x:0>2} {x:0>2})\n", .{
            data[0], data[1], data[2], data[3],
        });
        std.process.exit(1);
    }

    const ehdr = ptrCast(Elf64_Ehdr, data, 0) orelse {
        try stdout.writeAll("Error: Cannot read ELF header\n");
        std.process.exit(1);
    };

    const class_name: []const u8 = switch (ehdr.e_ident[4]) {
        ELFCLASS32 => "ELF32",
        ELFCLASS64 => "ELF64",
        else => "UNKNOWN",
    };

    const endian_name: []const u8 = switch (ehdr.e_ident[5]) {
        ELFDATA2LSB => "Little Endian",
        ELFDATA2MSB => "Big Endian",
        else => "Unknown",
    };

    try stdout.print("File:         {s}\n", .{path});
    try stdout.print("Size:         {d} bytes\n", .{stat.size});
    try stdout.print("Class:        {s}\n", .{class_name});
    try stdout.print("Encoding:     {s}\n", .{endian_name});
    try stdout.print("Type:         {s}\n", .{typeStr(ehdr.e_type)});
    try stdout.print("Machine:      {s}\n", .{machineStr(ehdr.e_machine)});
    try stdout.print("Entry Point:  0x{x:0>16}\n", .{ehdr.e_entry});
    try stdout.print("PH Offset:    0x{x}\n", .{ehdr.e_phoff});
    try stdout.print("SH Offset:    0x{x}\n", .{ehdr.e_shoff});
    try stdout.print("PH Count:     {d}\n", .{ehdr.e_phnum});
    try stdout.print("SH Count:     {d}\n", .{ehdr.e_shnum});
    try stdout.print("SH StrIdx:    {d}\n", .{ehdr.e_shstrndx});

    // ---- PROGRAM HEADERS (Segments) ----
    try stdout.writeAll("\n--- Program Headers (Segments) ---\n");
    try stdout.print("{s:<4} {s:<14} {s:<18} {s:<18} {s:<12} {s:<12} {s:<5}\n", .{
        "Idx", "Type", "Offset", "VirtAddr", "FileSize", "MemSize", "Flags",
    });
    try stdout.writeAll("-" ** 85 ++ "\n");

    var security_warnings: u32 = 0;
    var has_nx_stack = false;

    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const off = @as(usize, @intCast(ehdr.e_phoff)) + @as(usize, pi) * @as(usize, ehdr.e_phentsize);
        const phdr = ptrCast(Elf64_Phdr, data, off) orelse continue;

        var fbuf: [4]u8 = undefined;
        const flags = flagsStr(phdr.p_flags, &fbuf);

        try stdout.print("{d:<4} {s:<14} 0x{x:0>16} 0x{x:0>16} 0x{x:0>8} 0x{x:0>8} {s}\n", .{
            pi,
            phdrTypeStr(phdr.p_type),
            phdr.p_offset,
            phdr.p_vaddr,
            phdr.p_filesz,
            phdr.p_memsz,
            flags,
        });

        // Security checks
        if (phdr.p_type == PT_LOAD and (phdr.p_flags & PF_W != 0) and (phdr.p_flags & PF_X != 0)) {
            try stdout.writeAll("  ⚠  WARNING: W+X segment (writable AND executable)\n");
            security_warnings += 1;
        }

        if (phdr.p_type == PT_GNU_STACK) {
            if (phdr.p_flags & PF_X != 0) {
                try stdout.writeAll("  ⚠  WARNING: Executable stack!\n");
                security_warnings += 1;
            } else {
                has_nx_stack = true;
            }
        }
    }

    // ---- SECTION HEADERS ----
    try stdout.writeAll("\n--- Section Headers ---\n");

    // Get string table for section names
    var strtab_offset: u64 = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const strtab_off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
        if (ptrCast(Elf64_Shdr, data, strtab_off)) |strtab_shdr| {
            strtab_offset = strtab_shdr.sh_offset;
        }
    }

    try stdout.print("{s:<4} {s:<20} {s:<12} {s:<5} {s:<18} {s:<18} {s:<10}\n", .{
        "Idx", "Name", "Type", "Flags", "Offset", "Size", "Align",
    });
    try stdout.writeAll("-" ** 90 ++ "\n");

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) + @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        const name = getSectionName(data, strtab_offset, shdr.sh_name);
        var sfbuf: [4]u8 = undefined;
        const sflags = shFlagsStr(shdr.sh_flags, &sfbuf);

        try stdout.print("{d:<4} {s:<20} {s:<12} {s:<5} 0x{x:0>16} 0x{x:0>8} {d}\n", .{
            si,
            name,
            shdrTypeStr(shdr.sh_type),
            sflags,
            shdr.sh_offset,
            shdr.sh_size,
            shdr.sh_addralign,
        });

        // Flag suspicious sections
        if ((shdr.sh_flags & SHF_WRITE != 0) and (shdr.sh_flags & SHF_EXECINSTR != 0)) {
            try stdout.writeAll("  ⚠  WARNING: Writable + Executable section\n");
            security_warnings += 1;
        }
    }

    // ---- SECURITY SUMMARY ----
    try stdout.writeAll("\n--- Security Summary ---\n");
    try stdout.print("NX Stack:     {s}\n", .{if (has_nx_stack) "YES (good)" else "NO (missing or executable)"});
    try stdout.print("Warnings:     {d}\n", .{security_warnings});

    if (security_warnings == 0) {
        try stdout.writeAll("Status:       CLEAN\n");
    } else {
        try stdout.writeAll("Status:       REVIEW REQUIRED\n");
    }

    try stdout.writeAll("\n");
}
