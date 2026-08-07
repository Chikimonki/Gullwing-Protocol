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

const SHT_NULL: u32 = 0;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;

// ============================================================
// PATTERN CATEGORIES
// ============================================================

const Category = enum {
    NORMAL,
    PATH,
    SHELL,
    NETWORK,
    CRYPTO,
    ANTI_DEBUG,
    PACKER,
    SENSITIVE,
    CREDENTIAL,

    fn label(self: Category) []const u8 {
        return switch (self) {
            .NORMAL => "",
            .PATH => "[PATH]     ",
            .SHELL => "[SHELL]    ",
            .NETWORK => "[NETWORK]  ",
            .CRYPTO => "[CRYPTO]   ",
            .ANTI_DEBUG => "[ANTI-DBG] ",
            .PACKER => "[PACKER]   ",
            .SENSITIVE => "[SENSITIVE]",
            .CREDENTIAL => "[CRED]     ",
        };
    }

    fn isFlagged(self: Category) bool {
        return self != .NORMAL;
    }
};

// ============================================================
// PATTERN MATCHING
// ============================================================

const PatternEntry = struct {
    needle: []const u8,
    category: Category,
    case_insensitive: bool,
};

const patterns = [_]PatternEntry{
    // Shell / Command execution
    .{ .needle = "/bin/sh", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "/bin/bash", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "/bin/dash", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "system(", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "execve", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "popen", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "exec(", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "subprocess", .category = .SHELL, .case_insensitive = false },

    // Sensitive paths
    .{ .needle = "/etc/shadow", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/etc/passwd", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/etc/sudoers", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/proc/self", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/dev/mem", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/dev/kmem", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/tmp/", .category = .PATH, .case_insensitive = false },
    .{ .needle = "/var/tmp", .category = .PATH, .case_insensitive = false },

    // Network
    .{ .needle = "socket", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "connect", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "http://", .category = .NETWORK, .case_insensitive = true },
    .{ .needle = "https://", .category = .NETWORK, .case_insensitive = true },
    .{ .needle = "ftp://", .category = .NETWORK, .case_insensitive = true },
    .{ .needle = "recv", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "send", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "SOCK_STREAM", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "AF_INET", .category = .NETWORK, .case_insensitive = false },

    // Crypto
    .{ .needle = "AES", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "RSA", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "SHA256", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "SHA512", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "PRIVATE KEY", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "PUBLIC KEY", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "BEGIN CERT", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "password", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "passwd", .category = .CREDENTIAL, .case_insensitive = false },
    .{ .needle = "secret", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "token", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "api_key", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "apikey", .category = .CREDENTIAL, .case_insensitive = true },

    // Anti-debug / anti-analysis
    .{ .needle = "ptrace", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "debugger", .category = .ANTI_DEBUG, .case_insensitive = true },
    .{ .needle = "gdb", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "strace", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "ltrace", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "SIGTRAP", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "TracerPid", .category = .ANTI_DEBUG, .case_insensitive = false },

    // Packer signatures
    .{ .needle = "UPX!", .category = .PACKER, .case_insensitive = false },
    .{ .needle = "UPX0", .category = .PACKER, .case_insensitive = false },
    .{ .needle = "packed", .category = .PACKER, .case_insensitive = true },
    .{ .needle = "MPRESS", .category = .PACKER, .case_insensitive = false },
};

// ============================================================
// HELPERS
// ============================================================

fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
    if (offset + @sizeOf(T) > data.len) return null;
    return @ptrCast(@alignCast(data[offset..].ptr));
}

fn getElfSectionName(data: []const u8, strtab_offset: u64, name_offset: u32) []const u8 {
    const start = @as(usize, @intCast(strtab_offset)) + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "<empty>";
    return data[start..end];
}

fn isPrintable(c: u8) bool {
    return (c >= 32 and c <= 126) or c == '\t';
}

fn toLowerByte(c: u8) u8 {
    if (c >= 'A' and c <= 'Z') return c + 32;
    return c;
}

fn containsCI(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            if (toLowerByte(haystack[i + j]) != toLowerByte(nc)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn containsCS(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        if (std.mem.eql(u8, haystack[i .. i + needle.len], needle)) return true;
    }
    return false;
}

fn categoriseString(s: []const u8) Category {
    var highest = Category.NORMAL;

    for (patterns) |pat| {
        const found = if (pat.case_insensitive)
            containsCI(s, pat.needle)
        else
            containsCS(s, pat.needle);

        if (found) {
            // Return highest priority category
            const priority = switch (pat.category) {
                .NORMAL => @as(u8, 0),
                .PATH => 1,
                .NETWORK => 2,
                .SHELL => 3,
                .CRYPTO => 4,
                .CREDENTIAL => 5,
                .SENSITIVE => 6,
                .ANTI_DEBUG => 7,
                .PACKER => 8,
            };
            const current = switch (highest) {
                .NORMAL => @as(u8, 0),
                .PATH => 1,
                .NETWORK => 2,
                .SHELL => 3,
                .CRYPTO => 4,
                .CREDENTIAL => 5,
                .SENSITIVE => 6,
                .ANTI_DEBUG => 7,
                .PACKER => 8,
            };
            if (priority > current) highest = pat.category;
        }
    }

    return highest;
}

// Section info for a given offset
const SectionInfo = struct {
    name: []const u8,
    flags: u64,
};

fn findSection(
    data: []const u8,
    ehdr: *const Elf64_Ehdr,
    strtab_offset: u64,
    offset: usize,
) SectionInfo {
    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type == SHT_NULL) continue;

        const sec_start = @as(usize, @intCast(shdr.sh_offset));
        const sec_end = sec_start + @as(usize, @intCast(shdr.sh_size));

        if (offset >= sec_start and offset < sec_end) {
            return .{
                .name = getElfSectionName(data, strtab_offset, shdr.sh_name),
                .flags = shdr.sh_flags,
            };
        }
    }
    return .{ .name = "<unmapped>", .flags = 0 };
}

fn shFlagsStr(flags: u64, buf: *[4]u8) []const u8 {
    buf[0] = if (flags & SHF_WRITE != 0) 'W' else '-';
    buf[1] = if (flags & SHF_ALLOC != 0) 'A' else '-';
    buf[2] = if (flags & SHF_EXECINSTR != 0) 'X' else '-';
    buf[3] = 0;
    return buf[0..3];
}

// Detect possible IP addresses (simple heuristic: x.x.x.x pattern)
fn looksLikeIP(s: []const u8) bool {
    var dots: u32 = 0;
    var digits: u32 = 0;
    for (s) |c| {
        if (c == '.') {
            if (digits == 0) return false;
            dots += 1;
            digits = 0;
        } else if (c >= '0' and c <= '9') {
            digits += 1;
            if (digits > 3) return false;
        } else return false;
    }
    return dots == 3 and digits > 0;
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

    // Parse arguments
    var min_len: usize = 6;
    var show_all = false;
    var path: ?[]const u8 = null;

    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--all") or std.mem.eql(u8, arg, "-a")) {
            show_all = true;
        } else if (std.mem.eql(u8, arg, "--min4")) {
            min_len = 4;
        } else if (std.mem.eql(u8, arg, "--min8")) {
            min_len = 8;
        } else if (std.mem.eql(u8, arg, "--min12")) {
            min_len = 12;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage: moabi-strings [options] <elf-binary>
                \\
                \\Options:
                \\  --all, -a    Show all strings (not just flagged)
                \\  --min4       Minimum string length 4 (default: 6)
                \\  --min8       Minimum string length 8
                \\  --min12      Minimum string length 12
                \\  --help, -h   Show this help
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

    // Read file
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

    // Validate ELF
    const is_elf = data.len >= @sizeOf(Elf64_Ehdr) and std.mem.eql(u8, data[0..4], &ELFMAG);

    var ehdr_opt: ?*const Elf64_Ehdr = null;
    var strtab_offset: u64 = 0;

    if (is_elf) {
        ehdr_opt = ptrCast(Elf64_Ehdr, data, 0);
        if (ehdr_opt) |ehdr| {
            if (ehdr.e_shstrndx < ehdr.e_shnum) {
                const stoff = @as(usize, @intCast(ehdr.e_shoff)) +
                    @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
                if (ptrCast(Elf64_Shdr, data, stoff)) |strtab_shdr| {
                    strtab_offset = strtab_shdr.sh_offset;
                }
            }
        }
    }

    // Header
    try stdout.writeAll("\n====================================================\n");
    try stdout.writeAll("  MOABI STRING EXTRACTOR v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("====================================================\n\n");
    try stdout.print("File:        {s}\n", .{path.?});
    try stdout.print("Size:        {d} bytes\n", .{fsize});
    try stdout.print("ELF:         {s}\n", .{if (is_elf) "yes" else "no (raw string scan)"});
    try stdout.print("Min length:  {d}\n", .{min_len});
    try stdout.print("Mode:        {s}\n\n", .{if (show_all) "ALL strings" else "FLAGGED only (use --all for everything)"});

    // Extract strings
    var total_strings: u32 = 0;
    var flagged_strings: u32 = 0;
    var category_counts = [_]u32{0} ** 9;

    // Section stats
    var strings_in_exec: u32 = 0;
    var strings_in_unmapped: u32 = 0;

    // Print header
    if (is_elf) {
        try stdout.print("{s:<18} {s:<20} {s:<5} {s:<12} {s}\n", .{
            "Offset", "Section", "Perm", "Category", "String",
        });
    } else {
        try stdout.print("{s:<18} {s:<12} {s}\n", .{
            "Offset", "Category", "String",
        });
    }
    try stdout.writeAll("-" ** 100 ++ "\n");

    var pos: usize = 0;
    while (pos < data.len) {
        // Find start of printable sequence
        if (!isPrintable(data[pos])) {
            pos += 1;
            continue;
        }

        const start = pos;
        while (pos < data.len and isPrintable(data[pos])) : (pos += 1) {}
        const slen = pos - start;

        if (slen < min_len) continue;

        const s = data[start..pos];
        total_strings += 1;

        const cat = categoriseString(s);
        if (cat.isFlagged()) flagged_strings += 1;

        // Count categories
        const cat_idx: usize = switch (cat) {
            .NORMAL => 0,
            .PATH => 1,
            .SHELL => 2,
            .NETWORK => 3,
            .CRYPTO => 4,
            .CREDENTIAL => 5,
            .SENSITIVE => 6,
            .ANTI_DEBUG => 7,
            .PACKER => 8,
        };
        category_counts[cat_idx] += 1;

        // Section lookup
        var sec_name: []const u8 = "-";
        var sec_flags: u64 = 0;
        if (is_elf) {
            if (ehdr_opt) |ehdr| {
                const sec = findSection(data, ehdr, strtab_offset, start);
                sec_name = sec.name;
                sec_flags = sec.flags;
            }

            if (std.mem.eql(u8, sec_name, "<unmapped>")) {
                strings_in_unmapped += 1;
            }
            if (sec_flags & SHF_EXECINSTR != 0) {
                strings_in_exec += 1;
            }
        }

        // Decide whether to print
        if (!show_all and !cat.isFlagged()) continue;

        // Truncate display for very long strings
        const max_display: usize = 80;
        const display = if (s.len > max_display) s[0..max_display] else s;
        const truncated = s.len > max_display;

        if (is_elf) {
            var fbuf: [4]u8 = undefined;
            const perm = shFlagsStr(sec_flags, &fbuf);

            try stdout.print("0x{x:0>16} {s:<20} {s:<5} {s:<12}", .{
                start,
                sec_name,
                perm,
                cat.label(),
            });
        } else {
            try stdout.print("0x{x:0>16} {s:<12}", .{
                start,
                cat.label(),
            });
        }

        // Print the string, escaping tabs
        for (display) |c| {
            if (c == '\t') {
                try stdout.writeAll("\\t");
            } else {
                try stdout.writeByte(c);
            }
        }
        if (truncated) try stdout.writeAll("...");
        try stdout.writeAll("\n");
    }

    // ---- IP ADDRESS SCAN ----
    // Quick second pass to find potential IPs embedded in strings
    try stdout.writeAll("\n--- Embedded IP Address Scan ---\n");
    var ip_count: u32 = 0;
    pos = 0;
    while (pos < data.len) {
        if (!isPrintable(data[pos])) {
            pos += 1;
            continue;
        }
        const start = pos;
        while (pos < data.len and isPrintable(data[pos])) : (pos += 1) {}
        const s = data[start..pos];

        // Look for IP-like patterns within the string
        var dot_start: usize = 0;
        while (dot_start < s.len) {
            // Find a digit
            if (s[dot_start] < '0' or s[dot_start] > '9') {
                dot_start += 1;
                continue;
            }
            // Grab the potential IP substring
            var dot_end = dot_start;
            while (dot_end < s.len and
                ((s[dot_end] >= '0' and s[dot_end] <= '9') or s[dot_end] == '.')) : (dot_end += 1)
            {}
            const candidate = s[dot_start..dot_end];
            if (candidate.len >= 7 and looksLikeIP(candidate)) {
                // Skip common version numbers like 2.0, 1.0.0
                if (candidate.len >= 7) {
                    try stdout.print("  0x{x:0>16}: {s}\n", .{ start + dot_start, candidate });
                    ip_count += 1;
                }
            }
            dot_start = dot_end;
        }
    }
    if (ip_count == 0) {
        try stdout.writeAll("  No IP addresses detected.\n");
    }

    // ---- SUMMARY ----
    try stdout.writeAll("\n--- String Analysis Summary ---\n");
    try stdout.print("Total strings (>={d} chars):  {d}\n", .{ min_len, total_strings });
    try stdout.print("Flagged strings:             {d}\n", .{flagged_strings});
    try stdout.writeAll("\nCategory Breakdown:\n");

    const cat_names = [_][]const u8{
        "Normal", "Path", "Shell", "Network",
        "Crypto", "Credential", "Sensitive", "Anti-Debug", "Packer",
    };
    for (cat_names, 0..) |name, idx| {
        if (category_counts[idx] > 0) {
            try stdout.print("  {s:<14} {d}\n", .{ name, category_counts[idx] });
        }
    }

    if (is_elf) {
        try stdout.print("\nStrings in EXEC sections:    {d}\n", .{strings_in_exec});
        try stdout.print("Strings in unmapped regions:  {d}\n", .{strings_in_unmapped});
    }

    // Risk assessment
    try stdout.writeAll("\n--- Risk Assessment ---\n");
    var risk_level: u8 = 0;

    if (category_counts[8] > 0) { // PACKER
        try stdout.writeAll("⚠  PACKER signatures detected — binary may be packed/obfuscated\n");
        risk_level += 3;
    }
    if (category_counts[7] > 0) { // ANTI_DEBUG
        try stdout.writeAll("⚠  Anti-debug references found — binary may resist analysis\n");
        risk_level += 2;
    }
    if (category_counts[6] > 0) { // SENSITIVE
        try stdout.writeAll("⚠  Sensitive file path references detected\n");
        risk_level += 2;
    }
    if (category_counts[5] > 0) { // CREDENTIAL
        try stdout.writeAll("⚠  Credential-related strings found\n");
        risk_level += 1;
    }
    if (category_counts[2] > 0) { // SHELL
        try stdout.writeAll("⚠  Shell/command execution references found\n");
        risk_level += 1;
    }
    if (strings_in_exec > 5) {
        try stdout.writeAll("⚠  Multiple strings found in executable sections (unusual)\n");
        risk_level += 1;
    }
    if (strings_in_unmapped > 0) {
        try stdout.writeAll("⚠  Strings found in unmapped regions (outside declared sections)\n");
        risk_level += 2;
    }

    if (risk_level == 0) {
        try stdout.writeAll("Status: CLEAN\n");
    } else if (risk_level <= 2) {
        try stdout.writeAll("Status: LOW RISK — common patterns, likely benign\n");
    } else if (risk_level <= 5) {
        try stdout.writeAll("Status: MEDIUM RISK — review recommended\n");
    } else {
        try stdout.writeAll("Status: HIGH RISK — manual audit required for CRA compliance\n");
    }

    try stdout.writeAll("\n");
}
