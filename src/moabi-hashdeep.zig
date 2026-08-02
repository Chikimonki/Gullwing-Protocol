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
const SHT_NOBITS: u32 = 8;
const SHF_EXECINSTR: u64 = 4;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;

// ============================================================
// SHA-256 IMPLEMENTATION
// ============================================================

const Sha256 = struct {
    state: [8]u32,
    buf: [64]u8,
    buf_len: usize,
    total_len: u64,

    const K = [64]u32{
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };

    const H0 = [8]u32{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    fn init() Sha256 {
        return .{
            .state = H0,
            .buf = undefined,
            .buf_len = 0,
            .total_len = 0,
        };
    }

    fn rotr(x: u32, comptime n: u5) u32 {
        return (x >> n) | (x << (@as(u5, 32 - @as(u6, n))));
    }

    fn processBlock(self: *Sha256, block: *const [64]u8) void {
        var w: [64]u32 = undefined;
        var i: usize = 0;
        while (i < 16) : (i += 1) {
            w[i] = @as(u32, block[i * 4]) << 24 |
                @as(u32, block[i * 4 + 1]) << 16 |
                @as(u32, block[i * 4 + 2]) << 8 |
                @as(u32, block[i * 4 + 3]);
        }
        while (i < 64) : (i += 1) {
            const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] +% s0 +% w[i - 7] +% s1;
        }

        var a = self.state[0];
        var b = self.state[1];
        var c = self.state[2];
        var d = self.state[3];
        var e = self.state[4];
        var f = self.state[5];
        var g = self.state[6];
        var h = self.state[7];

        i = 0;
        while (i < 64) : (i += 1) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = h +% S1 +% ch +% K[i] +% w[i];
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = S0 +% maj;

            h = g;
            g = f;
            f = e;
            e = d +% temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 +% temp2;
        }

        self.state[0] +%= a;
        self.state[1] +%= b;
        self.state[2] +%= c;
        self.state[3] +%= d;
        self.state[4] +%= e;
        self.state[5] +%= f;
        self.state[6] +%= g;
        self.state[7] +%= h;
    }

    fn update(self: *Sha256, input: []const u8) void {
        var pos: usize = 0;
        self.total_len += input.len;

        // Fill buffer
        if (self.buf_len > 0) {
            const space = 64 - self.buf_len;
            const to_copy = @min(space, input.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + to_copy], input[0..to_copy]);
            self.buf_len += to_copy;
            pos = to_copy;

            if (self.buf_len == 64) {
                self.processBlock(&self.buf);
                self.buf_len = 0;
            }
        }

        // Process full blocks
        while (pos + 64 <= input.len) : (pos += 64) {
            self.processBlock(@ptrCast(input[pos..][0..64]));
        }

        // Buffer remainder
        if (pos < input.len) {
            const remaining = input.len - pos;
            @memcpy(self.buf[0..remaining], input[pos..]);
            self.buf_len = remaining;
        }
    }

    fn final(self: *Sha256) [32]u8 {
        const total_bits = self.total_len * 8;

        // Padding
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..64], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);

        // Length in bits (big endian)
        self.buf[56] = @intCast((total_bits >> 56) & 0xff);
        self.buf[57] = @intCast((total_bits >> 48) & 0xff);
        self.buf[58] = @intCast((total_bits >> 40) & 0xff);
        self.buf[59] = @intCast((total_bits >> 32) & 0xff);
        self.buf[60] = @intCast((total_bits >> 24) & 0xff);
        self.buf[61] = @intCast((total_bits >> 16) & 0xff);
        self.buf[62] = @intCast((total_bits >> 8) & 0xff);
        self.buf[63] = @intCast(total_bits & 0xff);

        self.processBlock(&self.buf);

        // Output
        var digest: [32]u8 = undefined;
        for (self.state, 0..) |s, i| {
            digest[i * 4] = @intCast((s >> 24) & 0xff);
            digest[i * 4 + 1] = @intCast((s >> 16) & 0xff);
            digest[i * 4 + 2] = @intCast((s >> 8) & 0xff);
            digest[i * 4 + 3] = @intCast(s & 0xff);
        }
        return digest;
    }
};

fn sha256(input: []const u8) [32]u8 {
    var h = Sha256.init();
    h.update(input);
    return h.final();
}

fn hexDigest(digest: [32]u8) [64]u8 {
    const hex = "0123456789abcdef";
    var out: [64]u8 = undefined;
    for (digest, 0..) |b, i| {
        out[i * 2] = hex[b >> 4];
        out[i * 2 + 1] = hex[b & 0xf];
    }
    return out;
}

// ============================================================
// ELF HELPERS
// ============================================================

fn ptrCast(comptime T: type, data: []const u8, offset: usize) ?*const T {
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

// Critical sections that should never change between builds/deployments
fn isCriticalSection(name: []const u8) bool {
    const critical = [_][]const u8{
        ".text", ".plt", ".plt.got", ".plt.sec",
        ".got", ".got.plt", ".init", ".fini",
        ".init_array", ".fini_array",
    };
    for (critical) |c| {
        if (std.mem.eql(u8, name, c)) return true;
    }
    return false;
}

fn sectionRisk(name: []const u8, flags: u64) []const u8 {
    if (isCriticalSection(name)) return "CRITICAL";
    if (flags & SHF_EXECINSTR != 0) return "HIGH    ";
    if (flags & SHF_WRITE != 0 and flags & SHF_ALLOC != 0) return "MEDIUM  ";
    return "LOW     ";
}

// ============================================================
// MANIFEST ENTRY
// ============================================================

const ManifestEntry = struct {
    name: []const u8,
    offset: usize,
    size: usize,
    flags: u64,
    hash: [64]u8,
    risk: []const u8,
};

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
    var baseline_path: ?[]const u8 = null;
    var verify_path: ?[]const u8 = null;
    var save_baseline = false;

    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if (std.mem.eql(u8, arg, "--save") or std.mem.eql(u8, arg, "-s")) {
            save_baseline = true;
            if (ai + 1 < args.len) {
                ai += 1;
                baseline_path = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--verify") or std.mem.eql(u8, arg, "-v")) {
            if (ai + 1 < args.len) {
                ai += 1;
                verify_path = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage: moabi-hashdeep [options] <elf-binary>
                \\
                \\Options:
                \\  --save, -s <file>    Save baseline manifest to file
                \\  --verify, -v <file>  Verify against saved baseline
                \\  --help, -h           Show this help
                \\
                \\Examples:
                \\  moabi-hashdeep /usr/bin/ls
                \\  moabi-hashdeep --save ls.manifest /usr/bin/ls
                \\  moabi-hashdeep --verify ls.manifest /usr/bin/ls
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

    // Validate
    if (data.len < @sizeOf(Elf64_Ehdr) or !std.mem.eql(u8, data[0..4], &ELFMAG)) {
        try stdout.writeAll("Error: Not a valid ELF file\n");
        std.process.exit(1);
    }

    const ehdr = ptrCast(Elf64_Ehdr, data, 0) orelse {
        try stdout.writeAll("Error: Cannot read ELF header\n");
        std.process.exit(1);
    };

    // Get string table
    var strtab_offset: u64 = 0;
    if (ehdr.e_shstrndx < ehdr.e_shnum) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, ehdr.e_shstrndx) * @as(usize, ehdr.e_shentsize);
        if (ptrCast(Elf64_Shdr, data, off)) |shdr| {
            strtab_offset = shdr.sh_offset;
        }
    }

    // Header
    try stdout.writeAll("\n====================================================\n");
    try stdout.writeAll("  MOABI HASHDEEP v0.1 (Zig 0.13.0)\n");
    try stdout.writeAll("  Section-Level Cryptographic Integrity Verifier\n");
    try stdout.writeAll("====================================================\n\n");
    try stdout.print("File: {s}\n", .{path.?});
    try stdout.print("Size: {d} bytes\n\n", .{fsize});

    // Whole-file hash
    const file_hash = sha256(data);
    const file_hex = hexDigest(file_hash);
    try stdout.print("SHA-256 (whole file): {s}\n\n", .{file_hex});

    // Hash ELF header separately
    const ehdr_bytes = data[0..@sizeOf(Elf64_Ehdr)];
    const ehdr_hash = sha256(ehdr_bytes);
    const ehdr_hex = hexDigest(ehdr_hash);
    try stdout.print("SHA-256 (ELF header): {s}\n\n", .{ehdr_hex});

    // Process sections
    try stdout.writeAll("--- Section Integrity Map ---\n");
    try stdout.print("{s:<4} {s:<20} {s:<9} {s:<18} {s:<10} {s}\n", .{
        "Idx", "Section", "Risk", "Offset", "Size", "SHA-256",
    });
    try stdout.writeAll("-" ** 120 ++ "\n");

    var manifest = std.ArrayList(ManifestEntry).init(allocator);
    defer manifest.deinit();

    // For composite hash: hash all section hashes together
    var composite = Sha256.init();

    var critical_count: u32 = 0;
    var high_count: u32 = 0;
    var total_sections: u32 = 0;

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type == SHT_NULL) continue;

        const name = getSecName(data, strtab_offset, shdr.sh_name);
        const risk = sectionRisk(name, shdr.sh_flags);
        total_sections += 1;

        if (std.mem.eql(u8, risk[0..8], "CRITICAL")) critical_count += 1;
        if (std.mem.eql(u8, risk[0..4], "HIGH")) high_count += 1;

        // Hash section content
        var sec_hex: [64]u8 = undefined;

        if (shdr.sh_type == SHT_NOBITS) {
            // NOBITS (like .bss) has no file content
            @memset(&sec_hex, '0');
        } else {
            const sec_start = @as(usize, @intCast(shdr.sh_offset));
            const sec_size = @as(usize, @intCast(shdr.sh_size));

            if (sec_start + sec_size <= data.len) {
                const sec_data = data[sec_start .. sec_start + sec_size];
                const sec_hash = sha256(sec_data);
                sec_hex = hexDigest(sec_hash);

                // Feed into composite
                composite.update(&sec_hash);
            } else {
                @memset(&sec_hex, 'X');
            }
        }

        try stdout.print("{d:<4} {s:<20} {s} 0x{x:0>16} {d:<10} {s}\n", .{
            si, name, risk, shdr.sh_offset, shdr.sh_size, sec_hex,
        });

        try manifest.append(.{
            .name = name,
            .offset = @intCast(shdr.sh_offset),
            .size = @intCast(shdr.sh_size),
            .flags = shdr.sh_flags,
            .hash = sec_hex,
            .risk = risk,
        });
    }

    // Composite manifest hash
    const composite_hash = composite.final();
    const composite_hex = hexDigest(composite_hash);

    try stdout.writeAll("\n--- Integrity Summary ---\n");
    try stdout.print("Total sections hashed:    {d}\n", .{total_sections});
    try stdout.print("Critical sections:        {d}\n", .{critical_count});
    try stdout.print("High-risk sections:       {d}\n", .{high_count});
    try stdout.print("Composite manifest hash:  {s}\n", .{composite_hex});

    // ---- SAVE BASELINE ----
    if (save_baseline) {
        const bl_path = baseline_path orelse "moabi.manifest";
        const bl_file = std.fs.cwd().createFile(bl_path, .{}) catch |err| {
            try stdout.print("\nError: Cannot create baseline file '{s}' ({s})\n", .{ bl_path, @errorName(err) });
            std.process.exit(1);
        };
        defer bl_file.close();
        const bw = bl_file.writer();

        // Write header
        try bw.writeAll("# MOABI HASHDEEP MANIFEST v0.1\n");
        try bw.print("# File: {s}\n", .{path.?});
        try bw.print("# Size: {d}\n", .{fsize});
        try bw.print("# File SHA-256: {s}\n", .{file_hex});
        try bw.print("# Composite: {s}\n", .{composite_hex});
        try bw.writeAll("#\n");
        try bw.writeAll("# Format: section_name|offset|size|sha256\n");

        for (manifest.items) |entry| {
            try bw.print("{s}|{d}|{d}|{s}\n", .{
                entry.name, entry.offset, entry.size, entry.hash,
            });
        }

        try stdout.print("\n✓ Baseline saved to: {s}\n", .{bl_path});
    }

    // ---- VERIFY AGAINST BASELINE ----
    if (verify_path) |vpath| {
        try stdout.writeAll("\n--- Verification Against Baseline ---\n");

        const vfile = std.fs.cwd().openFile(vpath, .{}) catch |err| {
            try stdout.print("Error: Cannot open baseline '{s}' ({s})\n", .{ vpath, @errorName(err) });
            std.process.exit(1);
        };
        defer vfile.close();

        const vstat = try vfile.stat();
        const vdata = try allocator.alloc(u8, @intCast(vstat.size));
        defer allocator.free(vdata);
        _ = try vfile.readAll(vdata);

        // Parse baseline
        var modified: u32 = 0;
        var verified: u32 = 0;
        var missing: u32 = 0;

        var line_iter = std.mem.splitScalar(u8, vdata, '\n');
        while (line_iter.next()) |line| {
            if (line.len == 0 or line[0] == '#') continue;

            // Parse: name|offset|size|hash
            var field_iter = std.mem.splitScalar(u8, line, '|');
            const bl_name = field_iter.next() orelse continue;
            _ = field_iter.next(); // offset
            _ = field_iter.next(); // size
            const bl_hash = field_iter.next() orelse continue;

            if (bl_hash.len < 64) continue;

            // Find matching section in current manifest
            var found = false;
            for (manifest.items) |entry| {
                if (std.mem.eql(u8, entry.name, bl_name)) {
                    found = true;
                    if (std.mem.eql(u8, &entry.hash, bl_hash[0..64])) {
                        verified += 1;
                        try stdout.print("  ✓ {s:<20} MATCH\n", .{bl_name});
                    } else {
                        modified += 1;
                        const risk = sectionRisk(bl_name, entry.flags);
                        try stdout.print("  ✗ {s:<20} MODIFIED  [{s}]\n", .{ bl_name, risk });
                        try stdout.print("    baseline: {s}\n", .{bl_hash[0..64]});
                        try stdout.print("    current:  {s}\n", .{entry.hash});
                    }
                    break;
                }
            }

            if (!found) {
                missing += 1;
                try stdout.print("  ? {s:<20} MISSING (section removed)\n", .{bl_name});
            }
        }

        try stdout.writeAll("\n--- Verification Result ---\n");
        try stdout.print("Verified (match):   {d}\n", .{verified});
        try stdout.print("Modified:           {d}\n", .{modified});
        try stdout.print("Missing:            {d}\n", .{missing});

        if (modified == 0 and missing == 0) {
            try stdout.writeAll("\n✓ INTEGRITY VERIFIED — binary matches baseline\n");
        } else {
            try stdout.writeAll("\n✗ INTEGRITY FAILURE — binary has been modified\n");
            try stdout.writeAll("  CRA compliance requires investigation of all modifications.\n");
        }
    }

    // ---- FINAL STATUS ----
    if (!save_baseline and verify_path == null) {
        try stdout.writeAll("\nTip: Use --save <file> to create a baseline for future verification.\n");
        try stdout.writeAll("     Use --verify <file> to check against a saved baseline.\n");
    }

    try stdout.writeAll("\n");
}
