const std = @import("std");

// ============================================================
// ELF STRUCTURES
// ============================================================

const ELFMAG = [4]u8{ 0x7F, 'E', 'L', 'F' };

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

// Segment flags
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const PT_LOAD: u32 = 1;

// Section flags
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

// Section types
const SHT_NULL: u32 = 0;
const SHT_NOBITS: u32 = 8;

// ============================================================
// CAVE CLASSIFICATION
// ============================================================

const CaveRisk = enum {
    LOW, // zeroed padding, expected
    MEDIUM, // non-zero but low entropy (data remnants)
    HIGH, // high entropy in unexpected place
    CRITICAL, // high entropy inside executable region

    fn label(self: CaveRisk) []const u8 {
        return switch (self) {
            .LOW => "LOW      ",
            .MEDIUM => "MEDIUM   ",
            .HIGH => "HIGH     ",
            .CRITICAL => "CRITICAL ",
        };
    }

    fn marker(self: CaveRisk) []const u8 {
        return switch (self) {
            .LOW => "  ",
            .MEDIUM => "⚠ ",
            .HIGH => "⚠ ",
            .CRITICAL => "🔴",
        };
    }
};

// ============================================================
// CAVE STRUCTURE
// ============================================================

const Cave = struct {
    offset: usize,
    size: usize,
    entropy: f64,
    is_zeroed: bool,
    in_executable: bool,
    in_writable: bool,
    risk: CaveRisk,
    before_section: []const u8,
    after_section: []const u8,
};

// ============================================================
// HELPER FUNCTIONS
// ============================================================

fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
}

fn getSectionName(data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
    const start = @as(usize, @intCast(strtab_offset)) + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "<empty>";
    return data[start..end];
}

fn computeEntropy(block: []const u8) f64 {
    if (block.len == 0) return 0.0;

    var counts = [_]u64{0} ** 256;
    for (block) |b| counts[b] += 1;

    var entropy: f64 = 0.0;
    const len_f = @as(f64, @floatFromInt(block.len));
    const log2 = @log(2.0);

    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / len_f;
        entropy -= p * (@log(p) / log2);
    }
    return entropy;
}

fn isZeroed(block: []const u8) bool {
    for (block) |b| {
        if (b != 0) return false;
    }
    return true;
}

fn isInSegment(
    data: []const u8,
    ehdr: *const Elf64_Ehdr,
    offset: usize,
    size: usize,
    flag: u32,
) bool {
    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const poff = @as(usize, @intCast(ehdr.e_phoff)) +
            @as(usize, pi) * @as(usize, ehdr.e_phentsize);
        const phdr = ptrCast(Elf64_Phdr, data, poff) orelse continue;

        if (phdr.p_type != PT_LOAD) continue;

        const seg_start = @as(usize, @intCast(phdr.p_offset));
        const seg_end = seg_start + @as(usize, @intCast(phdr.p_filesz));

        if (offset >= seg_start and offset + size <= seg_end) {
            if (phdr.p_flags & flag != 0) return true;
        }
    }
    return false;
}

fn classifyRisk(entropy: f64, zeroed: bool, in_exec: bool) CaveRisk {
    if (zeroed) return .LOW;
    if (in_exec and entropy > 6.0) return .CRITICAL;
    if (entropy > 6.0) return .HIGH;
    if (entropy > 3.0) return .MEDIUM;
    return .LOW;
}

// ============================================================
// SECTION ENTRY for sorting
// ============================================================

const SectionEntry = struct {
    name: []const u8,
    offset: usize,
    size: usize,
    sec_type: u32,
    flags: u64,
};

fn sectionCmp(_: void, a: SectionEntry, b: SectionEntry) bool {
    return a.offset < b.offset;
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

    // Read file
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("Error: Cannot open '{s}' ({s})\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const fsize = @as(usize, @intCast(stat.size));
    const data = try allocator.alloc(u8, fsize);
    defer allocator.free(data);
    _ = try file.readAll(data);

    // Validate ELF
    if (data.len < @sizeOf(Elf64_Ehdr) or !std.mem.eql(u8, data[0..4], &ELFMAG)) {
        try stdout.writeAll("Error: Not a valid ELF file\n");
        std.process.exit(1);
    }

    const ehdr = ptrCast(Elf64_Ehdr, data, 0) orelse {
        try stdout.writeAll("Error: Cannot read ELF header\n");
        std.process.exit(1);
    };

    try stdout.writeAll("\n==============================================\n");
    try stdout.writeAll("  MOABI CODE CAVE DETECTOR v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("==============================================\n\n");
    try stdout.print("File: {s}\n", .{path});
    try stdout.print("Size: {d} bytes\n\n", .{fsize});

    // Get string table
    var strtab_offset: u64 = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const stoff = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
        if (ptrCast(Elf64_Shdr, data, stoff)) |strtab_shdr| {
            strtab_offset = strtab_shdr.sh_offset;
        }
    }

    // Collect sections (skip NULL and NOBITS — they don't occupy file space)
    var sections = std.ArrayList(SectionEntry).init(allocator);
    defer sections.deinit();

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type == SHT_NULL) continue;
        if (shdr.sh_type == SHT_NOBITS) continue;
        if (shdr.sh_size == 0) continue;

        const name = getSectionName(data, strtab_offset, shdr.sh_name);
        try sections.append(.{
            .name = name,
            .offset = @intCast(shdr.sh_offset),
            .size = @intCast(shdr.sh_size),
            .sec_type = shdr.sh_type,
            .flags = shdr.sh_flags,
        });
    }

    // Sort by file offset
    std.mem.sort(SectionEntry, sections.items, {}, sectionCmp);

    // ---- SECTION MAP ----
    try stdout.writeAll("--- Section Map (by file offset) ---\n");
    try stdout.print("{s:<4} {s:<20} {s:<18} {s:<18} {s:<10}\n", .{
        "Idx", "Name", "Offset", "End", "Size",
    });
    try stdout.writeAll("-" ** 72 ++ "\n");

    for (sections.items, 0..) |sec, idx| {
        try stdout.print("{d:<4} {s:<20} 0x{x:0>16} 0x{x:0>16} {d}\n", .{
            idx,
            sec.name,
            sec.offset,
            sec.offset + sec.size,
            sec.size,
        });
    }

    // ---- DETECT CAVES ----
    try stdout.writeAll("\n--- Code Caves Detected ---\n");
    try stdout.print("{s:<2} {s:<9} {s:<18} {s:<10} {s:<8} {s:<24} {s}\n", .{
        "", "Risk", "Offset", "Size", "Entropy", "Between", "Notes",
    });
    try stdout.writeAll("-" ** 95 ++ "\n");

    var caves = std.ArrayList(Cave).init(allocator);
    defer caves.deinit();

    const min_cave_size: usize = 16; // ignore tiny alignment padding

    // Check gap before first section (after ELF header)
    if (sections.items.len > 0) {
        const first = sections.items[0];
        const header_end = @sizeOf(Elf64_Ehdr);

        if (first.offset > header_end) {
            const gap_size = first.offset - header_end;
            if (gap_size >= min_cave_size) {
                const block = data[header_end..first.offset];
                const ent = computeEntropy(block);
                const zeroed = isZeroed(block);
                const in_exec = isInSegment(data, ehdr, header_end, gap_size, PF_X);
                const in_write = isInSegment(data, ehdr, header_end, gap_size, PF_W);

                try caves.append(.{
                    .offset = header_end,
                    .size = gap_size,
                    .entropy = ent,
                    .is_zeroed = zeroed,
                    .in_executable = in_exec,
                    .in_writable = in_write,
                    .risk = classifyRisk(ent, zeroed, in_exec),
                    .before_section = "<elf_header>",
                    .after_section = first.name,
                });
            }
        }
    }

    // Check inter-section gaps
    var i: usize = 0;
    while (i + 1 < sections.items.len) : (i += 1) {
        const current = sections.items[i];
        const next = sections.items[i + 1];

        const current_end = current.offset + current.size;

        if (next.offset > current_end) {
            const gap_size = next.offset - current_end;
            if (gap_size >= min_cave_size) {
                const block = data[current_end..next.offset];
                const ent = computeEntropy(block);
                const zeroed = isZeroed(block);
                const in_exec = isInSegment(data, ehdr, current_end, gap_size, PF_X);
                const in_write = isInSegment(data, ehdr, current_end, gap_size, PF_W);

                try caves.append(.{
                    .offset = current_end,
                    .size = gap_size,
                    .entropy = ent,
                    .is_zeroed = zeroed,
                    .in_executable = in_exec,
                    .in_writable = in_write,
                    .risk = classifyRisk(ent, zeroed, in_exec),
                    .before_section = current.name,
                    .after_section = next.name,
                });
            }
        }
    }

    // Check gap after last section to EOF
    if (sections.items.len > 0) {
        const last = sections.items[sections.items.len - 1];
        const last_end = last.offset + last.size;

        if (fsize > last_end) {
            const gap_size = fsize - last_end;
            if (gap_size >= min_cave_size) {
                const block = data[last_end..fsize];
                const ent = computeEntropy(block);
                const zeroed = isZeroed(block);
                const in_exec = isInSegment(data, ehdr, last_end, gap_size, PF_X);
                const in_write = isInSegment(data, ehdr, last_end, gap_size, PF_W);

                try caves.append(.{
                    .offset = last_end,
                    .size = gap_size,
                    .entropy = ent,
                    .is_zeroed = zeroed,
                    .in_executable = in_exec,
                    .in_writable = in_write,
                    .risk = classifyRisk(ent, zeroed, in_exec),
                    .before_section = last.name,
                    .after_section = "<eof>",
                });
            }
        }
    }

    // Print caves
    var total_cave_bytes: usize = 0;
    var critical_count: u32 = 0;
    var high_count: u32 = 0;

    if (caves.items.len == 0) {
        try stdout.writeAll("  No code caves detected (min size: 16 bytes)\n");
    } else {
        for (caves.items) |cave| {
            total_cave_bytes += cave.size;
            if (cave.risk == .CRITICAL) critical_count += 1;
            if (cave.risk == .HIGH) high_count += 1;

            var between_buf: [50]u8 = undefined;
            const between = std.fmt.bufPrint(&between_buf, "{s} -> {s}", .{
                cave.before_section, cave.after_section,
            }) catch "<fmt err>";

            var notes_buf: [80]u8 = undefined;
            var notes_len: usize = 0;

            if (cave.is_zeroed) {
                const z = "zeroed";
                @memcpy(notes_buf[notes_len .. notes_len + z.len], z);
                notes_len += z.len;
            }
            if (cave.in_executable) {
                if (notes_len > 0) {
                    notes_buf[notes_len] = ',';
                    notes_buf[notes_len + 1] = ' ';
                    notes_len += 2;
                }
                const e = "EXEC segment";
                @memcpy(notes_buf[notes_len .. notes_len + e.len], e);
                notes_len += e.len;
            }
            if (cave.in_writable) {
                if (notes_len > 0) {
                    notes_buf[notes_len] = ',';
                    notes_buf[notes_len + 1] = ' ';
                    notes_len += 2;
                }
                const w = "WRITE segment";
                @memcpy(notes_buf[notes_len .. notes_len + w.len], w);
                notes_len += w.len;
            }

            const notes = if (notes_len > 0) notes_buf[0..notes_len] else "-";

            try stdout.print("{s} {s} 0x{x:0>16} {d:<10} {d:.4}   {s:<24} {s}\n", .{
                cave.risk.marker(),
                cave.risk.label(),
                cave.offset,
                cave.size,
                cave.entropy,
                between,
                notes,
            });
        }
    }

    // ---- SUMMARY ----
    try stdout.writeAll("\n--- Cave Analysis Summary ---\n");
    try stdout.print("Total caves found:     {d}\n", .{caves.items.len});
    try stdout.print("Total cave bytes:      {d}\n", .{total_cave_bytes});
    try stdout.print("Cave percentage:       {d:.2}%\n", .{
        if (fsize > 0) @as(f64, @floatFromInt(total_cave_bytes)) / @as(f64, @floatFromInt(fsize)) * 100.0 else 0.0,
    });
    try stdout.print("CRITICAL caves:        {d}\n", .{critical_count});
    try stdout.print("HIGH risk caves:       {d}\n", .{high_count});

    if (critical_count > 0) {
        try stdout.writeAll("\n⚠  CRITICAL: High-entropy content found in executable regions.\n");
        try stdout.writeAll("   This may indicate injected code, packed content, or polymorphic payloads.\n");
        try stdout.writeAll("   Manual review required for CRA compliance.\n");
    } else if (high_count > 0) {
        try stdout.writeAll("\n⚠  HIGH: Suspicious entropy detected in inter-section gaps.\n");
        try stdout.writeAll("   Review recommended.\n");
    } else {
        try stdout.writeAll("\nStatus: CLEAN — all caves contain expected padding/alignment data.\n");
    }

    try stdout.writeAll("\n");
}
