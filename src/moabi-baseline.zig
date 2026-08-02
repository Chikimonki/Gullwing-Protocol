const std = @import("std");

// ============================================================
// SHA-256 (same implementation as moabi-hashdeep)
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
        return .{ .state = H0, .buf = undefined, .buf_len = 0, .total_len = 0 };
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
            h = g; g = f; f = e; e = d +% temp1;
            d = c; c = b; b = a; a = temp1 +% temp2;
        }

        self.state[0] +%= a; self.state[1] +%= b;
        self.state[2] +%= c; self.state[3] +%= d;
        self.state[4] +%= e; self.state[5] +%= f;
        self.state[6] +%= g; self.state[7] +%= h;
    }

    fn update(self: *Sha256, input: []const u8) void {
        var pos: usize = 0;
        self.total_len += input.len;

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

        while (pos + 64 <= input.len) : (pos += 64) {
            self.processBlock(@ptrCast(input[pos..][0..64]));
        }

        if (pos < input.len) {
            const remaining = input.len - pos;
            @memcpy(self.buf[0..remaining], input[pos..]);
            self.buf_len = remaining;
        }
    }

    fn final(self: *Sha256) [32]u8 {
        const total_bits = self.total_len * 8;
        self.buf[self.buf_len] = 0x80;
        self.buf_len += 1;

        if (self.buf_len > 56) {
            @memset(self.buf[self.buf_len..64], 0);
            self.processBlock(&self.buf);
            self.buf_len = 0;
        }

        @memset(self.buf[self.buf_len..56], 0);
        self.buf[56] = @intCast((total_bits >> 56) & 0xff);
        self.buf[57] = @intCast((total_bits >> 48) & 0xff);
        self.buf[58] = @intCast((total_bits >> 40) & 0xff);
        self.buf[59] = @intCast((total_bits >> 32) & 0xff);
        self.buf[60] = @intCast((total_bits >> 24) & 0xff);
        self.buf[61] = @intCast((total_bits >> 16) & 0xff);
        self.buf[62] = @intCast((total_bits >> 8) & 0xff);
        self.buf[63] = @intCast(total_bits & 0xff);
        self.processBlock(&self.buf);

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

// ============================================================
// BASELINE FORMAT
// ============================================================
// JSON-like format for easy parsing from LuaJIT
//
// {
//   "version": "1.0",
//   "timestamp": "...",
//   "file": "...",
//   "size": N,
//   "file_hash": "...",
//   "entropy": N.NNNN,
//   "sections": [
//     {"name": "...", "offset": N, "size": N, "hash": "...", "entropy": N.NN},
//     ...
//   ],
//   "caves": [
//     {"offset": N, "size": N, "entropy": N.NN, "hash": "..."},
//     ...
//   ],
//   "composite": "..."
// }

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
    var compare_path: ?[]const u8 = null;
    var mode_create = false;
    var mode_compare = false;

    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if (std.mem.eql(u8, arg, "create") or std.mem.eql(u8, arg, "-c")) {
            mode_create = true;
        } else if (std.mem.eql(u8, arg, "compare") or std.mem.eql(u8, arg, "-d")) {
            mode_compare = true;
        } else if ((std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) and ai + 1 < args.len) {
            ai += 1;
            output_path = args[ai];
        } else if ((std.mem.eql(u8, arg, "--baseline") or std.mem.eql(u8, arg, "-b")) and ai + 1 < args.len) {
            ai += 1;
            compare_path = args[ai];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\MOABI BASELINE — Forensic Snapshot & Transient Hook Detector
                \\
                \\Usage:
                \\  moabi-baseline create -o <baseline.json> <binary>
                \\  moabi-baseline compare -b <baseline.json> <binary>
                \\
                \\Modes:
                \\  create    Generate a comprehensive baseline snapshot
                \\  compare   Compare current state against baseline, detect changes
                \\
                \\Options:
                \\  -o, --output <file>     Output baseline file (create mode)
                \\  -b, --baseline <file>   Baseline to compare against (compare mode)
                \\  -h, --help              Show this help
                \\
                \\Examples:
                \\  moabi-baseline create -o clean.json /usr/bin/ls
                \\  moabi-baseline compare -b clean.json /usr/bin/ls
                \\
                \\The comparison detects:
                \\  - Section hash changes (code modification)
                \\  - Cave content changes (payload injection/removal)
                \\  - Entropy shifts (encryption/packing changes)
                \\  - Size changes (section growth/shrinkage)
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

    if (!mode_create and !mode_compare) {
        try stdout.writeAll("Error: Specify 'create' or 'compare' mode. Use --help.\n");
        std.process.exit(1);
    }

    // Read target file
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

    // ==========================================
    // CREATE MODE
    // ==========================================
    if (mode_create) {
        const out_path = output_path orelse "baseline.json";
        const out_file = std.fs.cwd().createFile(out_path, .{}) catch |err| {
            try stdout.print("Error: Cannot create '{s}' ({s})\n", .{ out_path, @errorName(err) });
            std.process.exit(1);
        };
        defer out_file.close();
        const w = out_file.writer();

        const file_hash = hexDigest(sha256(data));
        const global_entropy = computeEntropy(data);

        try w.writeAll("{\n");
        try w.writeAll("  \"version\": \"1.0\",\n");
        try w.print("  \"file\": \"{s}\",\n", .{path.?});
        try w.print("  \"size\": {d},\n", .{fsize});
        try w.print("  \"file_hash\": \"{s}\",\n", .{file_hash});
        try w.print("  \"entropy\": {d:.6},\n", .{global_entropy});

        // Sections
        try w.writeAll("  \"sections\": [\n");

        var composite = Sha256.init();
        var first_sec = true;

        // Collect sections for caves
        const SecInfo = struct {
            name: []const u8,
            offset: usize,
            size: usize,
        };
        var sections = std.ArrayList(SecInfo).init(allocator);
        defer sections.deinit();

        var si: u16 = 0;
        while (si < ehdr.e_shnum) : (si += 1) {
            const off = @as(usize, @intCast(ehdr.e_shoff)) +
                @as(usize, si) * @as(usize, ehdr.e_shentsize);
            const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

            if (shdr.sh_type == SHT_NULL) continue;

            const name = getSecName(data, strtab_offset, shdr.sh_name);
            const sec_offset = @as(usize, @intCast(shdr.sh_offset));
            const sec_size = @as(usize, @intCast(shdr.sh_size));

            var sec_hash: [64]u8 = undefined;
            var sec_entropy: f64 = 0;

            if (shdr.sh_type == SHT_NOBITS or sec_size == 0) {
                @memset(&sec_hash, '0');
            } else if (sec_offset + sec_size <= data.len) {
                const sec_data = data[sec_offset .. sec_offset + sec_size];
                sec_hash = hexDigest(sha256(sec_data));
                sec_entropy = computeEntropy(sec_data);
                composite.update(&sha256(sec_data));

                try sections.append(.{
                    .name = name,
                    .offset = sec_offset,
                    .size = sec_size,
                });
            } else {
                @memset(&sec_hash, 'X');
            }

            if (!first_sec) try w.writeAll(",\n");
            first_sec = false;

            try w.print("    {{\"name\": \"{s}\", \"offset\": {d}, \"size\": {d}, \"hash\": \"{s}\", \"entropy\": {d:.4}}}", .{
                name, sec_offset, sec_size, sec_hash, sec_entropy,
            });
        }
        try w.writeAll("\n  ],\n");

        // Sort sections for cave detection
        std.mem.sort(SecInfo, sections.items, {}, struct {
            fn cmp(_: void, a: SecInfo, b: SecInfo) bool {
                return a.offset < b.offset;
            }
        }.cmp);

        // Caves
        try w.writeAll("  \"caves\": [\n");
        var first_cave = true;

        var ci: usize = 0;
        while (ci + 1 < sections.items.len) : (ci += 1) {
            const current = sections.items[ci];
            const next = sections.items[ci + 1];
            const current_end = current.offset + current.size;

            if (next.offset > current_end and next.offset - current_end >= 16) {
                const cave_offset = current_end;
                const cave_size = next.offset - current_end;
                const cave_data = data[cave_offset .. cave_offset + cave_size];
                const cave_hash = hexDigest(sha256(cave_data));
                const cave_entropy = computeEntropy(cave_data);

                if (!first_cave) try w.writeAll(",\n");
                first_cave = false;

                try w.print("    {{\"offset\": {d}, \"size\": {d}, \"hash\": \"{s}\", \"entropy\": {d:.4}, \"before\": \"{s}\", \"after\": \"{s}\"}}", .{
                    cave_offset, cave_size, cave_hash, cave_entropy, current.name, next.name,
                });
            }
        }
        try w.writeAll("\n  ],\n");

        // Composite hash
        const composite_hash = hexDigest(composite.final());
        try w.print("  \"composite\": \"{s}\"\n", .{composite_hash});
        try w.writeAll("}\n");

        try stdout.print("✓ Baseline created: {s}\n", .{out_path});
        try stdout.print("  File hash:      {s}\n", .{file_hash});
        try stdout.print("  Composite hash: {s}\n", .{composite_hash});
        try stdout.print("  Sections:       {d}\n", .{ehdr.e_shnum});
        try stdout.print("  Caves:          {d}\n", .{sections.items.len -| 1});
        return;
    }

    // ==========================================
    // COMPARE MODE
    // ==========================================
    if (mode_compare) {
        const baseline_path = compare_path orelse {
            try stdout.writeAll("Error: Specify baseline with -b <file>\n");
            std.process.exit(1);
        };

        // Read baseline
        const bl_file = std.fs.cwd().openFile(baseline_path, .{}) catch |err| {
            try stdout.print("Error: Cannot open baseline '{s}' ({s})\n", .{ baseline_path, @errorName(err) });
            std.process.exit(1);
        };
        defer bl_file.close();

        const bl_stat = try bl_file.stat();
        const bl_data = try allocator.alloc(u8, @intCast(bl_stat.size));
        defer allocator.free(bl_data);
        _ = try bl_file.readAll(bl_data);

        try stdout.writeAll("\n");
        try stdout.writeAll("╔═══════════════════════════════════════════════════════════╗\n");
        try stdout.writeAll("║  MOABI TRANSIENT HOOK DETECTOR                            ║\n");
        try stdout.writeAll("║  Comparing current state against baseline                 ║\n");
        try stdout.writeAll("╚═══════════════════════════════════════════════════════════╝\n\n");

        try stdout.print("Baseline: {s}\n", .{baseline_path});
        try stdout.print("Target:   {s}\n", .{path.?});
        try stdout.print("Size:     {d} bytes\n\n", .{fsize});

        // Current state
        const current_hash = hexDigest(sha256(data));
        const current_entropy = computeEntropy(data);

        // Parse baseline (simple extraction — not full JSON parser)
        var changes_detected: u32 = 0;
        var critical_changes: u32 = 0;

        // Extract baseline file hash
        var baseline_hash: ?[]const u8 = null;
        var baseline_entropy: ?f64 = null;
        var baseline_composite: ?[]const u8 = null;

        var line_iter = std.mem.splitScalar(u8, bl_data, '\n');
        while (line_iter.next()) |line| {
            // file_hash
            if (std.mem.indexOf(u8, line, "\"file_hash\":")) |idx| {
                const start = std.mem.indexOf(u8, line[idx..], ": \"") orelse continue;
                const hash_start = idx + start + 3;
                if (hash_start + 64 <= line.len) {
                    baseline_hash = line[hash_start .. hash_start + 64];
                }
            }
            // entropy
            if (std.mem.indexOf(u8, line, "\"entropy\":")) |idx| {
                var num_start = idx + 11;
                while (num_start < line.len and (line[num_start] == ' ' or line[num_start] == ':')) : (num_start += 1) {}
                var num_end = num_start;
                while (num_end < line.len and (line[num_end] == '.' or (line[num_end] >= '0' and line[num_end] <= '9'))) : (num_end += 1) {}
                if (num_end > num_start) {
                    baseline_entropy = std.fmt.parseFloat(f64, line[num_start..num_end]) catch null;
                }
            }
            // composite
            if (std.mem.indexOf(u8, line, "\"composite\":")) |idx| {
                const start = std.mem.indexOf(u8, line[idx..], ": \"") orelse continue;
                const hash_start = idx + start + 3;
                if (hash_start + 64 <= line.len) {
                    baseline_composite = line[hash_start .. hash_start + 64];
                }
            }
        }

        // ---- FILE HASH CHECK ----
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        try stdout.writeAll("  FILE INTEGRITY CHECK\n");
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if (baseline_hash) |bh| {
            try stdout.print("  Baseline: {s}\n", .{bh});
            try stdout.print("  Current:  {s}\n", .{current_hash});

            if (std.mem.eql(u8, bh, &current_hash)) {
                try stdout.writeAll("  Status:   ✓ MATCH — file unchanged\n");
            } else {
                try stdout.writeAll("  Status:   ✗ MODIFIED — file has changed\n");
                changes_detected += 1;
                critical_changes += 1;
            }
        } else {
            try stdout.writeAll("  Warning: Could not extract baseline hash\n");
        }

        // ---- ENTROPY CHECK ----
        try stdout.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        try stdout.writeAll("  ENTROPY ANALYSIS\n");
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if (baseline_entropy) |be| {
            const entropy_delta = current_entropy - be;
            try stdout.print("  Baseline: {d:.6}\n", .{be});
            try stdout.print("  Current:  {d:.6}\n", .{current_entropy});
            if (entropy_delta >= 0) {
                try stdout.print("  Delta:    +{d:.6}\n", .{entropy_delta});
            } else {
                try stdout.print("  Delta:    {d:.6}\n", .{entropy_delta});
            }

            if (@abs(entropy_delta) < 0.01) {
                try stdout.writeAll("  Status:   ✓ STABLE — entropy unchanged\n");
            } else if (@abs(entropy_delta) < 0.1) {
                try stdout.writeAll("  Status:   ⚠ MINOR SHIFT — small entropy change\n");
                changes_detected += 1;
            } else {
                try stdout.writeAll("  Status:   ✗ SIGNIFICANT SHIFT — possible packing/encryption change\n");
                changes_detected += 1;
                critical_changes += 1;
            }
        }

        // ---- COMPOSITE CHECK ----
        try stdout.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        try stdout.writeAll("  SECTION COMPOSITE CHECK\n");
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        // Compute current composite
        var current_composite = Sha256.init();
        var si2: u16 = 0;
        while (si2 < ehdr.e_shnum) : (si2 += 1) {
            const off = @as(usize, @intCast(ehdr.e_shoff)) +
                @as(usize, si2) * @as(usize, ehdr.e_shentsize);
            const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;
            if (shdr.sh_type == SHT_NULL or shdr.sh_type == SHT_NOBITS) continue;
            const sec_offset = @as(usize, @intCast(shdr.sh_offset));
            const sec_size = @as(usize, @intCast(shdr.sh_size));
            if (sec_size > 0 and sec_offset + sec_size <= data.len) {
                current_composite.update(&sha256(data[sec_offset .. sec_offset + sec_size]));
            }
        }
        const current_comp_hash = hexDigest(current_composite.final());

        if (baseline_composite) |bc| {
            try stdout.print("  Baseline: {s}\n", .{bc});
            try stdout.print("  Current:  {s}\n", .{current_comp_hash});

            if (std.mem.eql(u8, bc, &current_comp_hash)) {
                try stdout.writeAll("  Status:   ✓ MATCH — all sections unchanged\n");
            } else {
                try stdout.writeAll("  Status:   ✗ MODIFIED — one or more sections changed\n");
                changes_detected += 1;
                critical_changes += 1;
            }
        }

        // ---- TRANSIENT DETECTION LOGIC ----
        try stdout.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        try stdout.writeAll("  TRANSIENT HOOK ANALYSIS\n");
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        if (baseline_hash) |bh| {
            if (std.mem.eql(u8, bh, &current_hash)) {
                try stdout.writeAll("  File hash matches baseline.\n");
                try stdout.writeAll("  If a hook was inserted and removed cleanly,\n");
                try stdout.writeAll("  the binary appears identical.\n\n");
                try stdout.writeAll("  HOWEVER — check for:\n");
                try stdout.writeAll("  • Filesystem timestamps (mtime, ctime)\n");
                try stdout.writeAll("  • Backup/journal entries\n");
                try stdout.writeAll("  • Memory dumps during execution\n");
                try stdout.writeAll("  • Process injection (no file change)\n\n");
                try stdout.writeAll("  Status: ✓ NO EVIDENCE of modification in file\n");
            } else {
                try stdout.writeAll("  File hash DIFFERS from baseline.\n");
                try stdout.writeAll("  Either:\n");
                try stdout.writeAll("  • Modification is still present\n");
                try stdout.writeAll("  • Cleanup was imperfect (padding, alignment)\n");
                try stdout.writeAll("  • Different binary entirely\n\n");
                try stdout.writeAll("  Status: ✗ EVIDENCE of modification detected\n");
            }
        }

        // ---- FINAL VERDICT ----
        try stdout.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
        try stdout.writeAll("  VERDICT\n");
        try stdout.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

        try stdout.print("  Changes detected:  {d}\n", .{changes_detected});
        try stdout.print("  Critical changes:  {d}\n\n", .{critical_changes});

        if (critical_changes == 0 and changes_detected == 0) {
            try stdout.writeAll("  ╔═════════════════════════════════════╗\n");
            try stdout.writeAll("  ║  INTEGRITY: VERIFIED                ║\n");
            try stdout.writeAll("  ║  No modifications detected          ║\n");
            try stdout.writeAll("  ╚═════════════════════════════════════╝\n");
        } else if (critical_changes == 0) {
            try stdout.writeAll("  ╔═════════════════════════════════════╗\n");
            try stdout.writeAll("  ║  INTEGRITY: MINOR CHANGES           ║\n");
            try stdout.writeAll("  ║  Review recommended                 ║\n");
            try stdout.writeAll("  ╚═════════════════════════════════════╝\n");
        } else {
            try stdout.writeAll("  ╔═════════════════════════════════════╗\n");
            try stdout.writeAll("  ║  INTEGRITY: COMPROMISED             ║\n");
            try stdout.writeAll("  ║  Binary has been modified           ║\n");
            try stdout.writeAll("  ╚═════════════════════════════════════╝\n");
        }

        try stdout.writeAll("\n");
    }
}
