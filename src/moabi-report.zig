const std = @import("std");

// ============================================================
// ELF STRUCTURES (consolidated from all tools)
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

const Elf64_Sym = extern struct {
    st_name: u32,
    st_info: u8,
    st_other: u8,
    st_shndx: u16,
    st_value: u64,
    st_size: u64,
};

// Constants
const PT_LOAD: u32 = 1;
const PT_GNU_STACK: u32 = 0x6474e551;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const SHT_NULL: u32 = 0;
const SHT_SYMTAB: u32 = 2;
const SHT_STRTAB: u32 = 3;
const SHT_NOBITS: u32 = 8;
const SHT_DYNSYM: u32 = 11;
const SHF_WRITE: u64 = 1;
const SHF_ALLOC: u64 = 2;
const SHF_EXECINSTR: u64 = 4;
const SHN_UNDEF: u16 = 0;
const STB_GLOBAL: u8 = 1;

// ============================================================
// SHA-256 (from moabi-hashdeep)
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
// GENERIC HELPERS
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

fn getSymName(data: []const u8, strtab_offset: usize, name_offset: u32) []const u8 {
    const start = strtab_offset + @as(usize, name_offset);
    if (start >= data.len) return "<invalid>";
    var end = start;
    while (end < data.len and data[end] != 0) : (end += 1) {}
    if (end == start) return "";
    return data[start..end];
}

fn isPrintable(c: u8) bool {
    return (c >= 32 and c <= 126) or c == '\t';
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

fn startsWith(s: []const u8, prefix: []const u8) bool {
    if (s.len < prefix.len) return false;
    return std.mem.eql(u8, s[0..prefix.len], prefix);
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

// ============================================================
// STRING PATTERNS
// ============================================================

const StringCategory = enum {
    NORMAL, PATH, SHELL, NETWORK, CRYPTO,
    ANTI_DEBUG, PACKER, SENSITIVE, CREDENTIAL,
};

const StringPattern = struct {
    needle: []const u8,
    category: StringCategory,
    case_insensitive: bool,
};

const string_patterns = [_]StringPattern{
    .{ .needle = "/bin/sh", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "/bin/bash", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "system(", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "execve", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "popen", .category = .SHELL, .case_insensitive = false },
    .{ .needle = "/etc/shadow", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/etc/passwd", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/proc/self", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "/dev/mem", .category = .SENSITIVE, .case_insensitive = false },
    .{ .needle = "http://", .category = .NETWORK, .case_insensitive = true },
    .{ .needle = "https://", .category = .NETWORK, .case_insensitive = true },
    .{ .needle = "socket", .category = .NETWORK, .case_insensitive = false },
    .{ .needle = "AES", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "RSA", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "SHA256", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "PRIVATE KEY", .category = .CRYPTO, .case_insensitive = false },
    .{ .needle = "password", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "secret", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "token", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "api_key", .category = .CREDENTIAL, .case_insensitive = true },
    .{ .needle = "ptrace", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "TracerPid", .category = .ANTI_DEBUG, .case_insensitive = false },
    .{ .needle = "UPX!", .category = .PACKER, .case_insensitive = false },
    .{ .needle = "packed", .category = .PACKER, .case_insensitive = true },
};

// Symbol capability patterns
const SymCapability = enum {
    MEMORY, PROCESS, NETWORK, FILE_IO, CRYPTO,
    DYN_LOAD, PRIVILEGE, INFO_LEAK, SIGNAL,
};

const SymPattern = struct {
    prefix: []const u8,
    cap: SymCapability,
};

const sym_patterns = [_]SymPattern{
    .{ .prefix = "mmap", .cap = .MEMORY },
    .{ .prefix = "mprotect", .cap = .MEMORY },
    .{ .prefix = "malloc", .cap = .MEMORY },
    .{ .prefix = "fork", .cap = .PROCESS },
    .{ .prefix = "execve", .cap = .PROCESS },
    .{ .prefix = "execvp", .cap = .PROCESS },
    .{ .prefix = "system", .cap = .PROCESS },
    .{ .prefix = "popen", .cap = .PROCESS },
    .{ .prefix = "ptrace", .cap = .PROCESS },
    .{ .prefix = "clone", .cap = .PROCESS },
    .{ .prefix = "socket", .cap = .NETWORK },
    .{ .prefix = "connect", .cap = .NETWORK },
    .{ .prefix = "bind", .cap = .NETWORK },
    .{ .prefix = "listen", .cap = .NETWORK },
    .{ .prefix = "accept", .cap = .NETWORK },
    .{ .prefix = "sendto", .cap = .NETWORK },
    .{ .prefix = "recvfrom", .cap = .NETWORK },
    .{ .prefix = "getaddrinfo", .cap = .NETWORK },
    .{ .prefix = "open", .cap = .FILE_IO },
    .{ .prefix = "read", .cap = .FILE_IO },
    .{ .prefix = "write", .cap = .FILE_IO },
    .{ .prefix = "unlink", .cap = .FILE_IO },
    .{ .prefix = "chmod", .cap = .FILE_IO },
    .{ .prefix = "fopen", .cap = .FILE_IO },
    .{ .prefix = "EVP_", .cap = .CRYPTO },
    .{ .prefix = "SSL_", .cap = .CRYPTO },
    .{ .prefix = "AES_", .cap = .CRYPTO },
    .{ .prefix = "dlopen", .cap = .DYN_LOAD },
    .{ .prefix = "dlsym", .cap = .DYN_LOAD },
    .{ .prefix = "setuid", .cap = .PRIVILEGE },
    .{ .prefix = "setgid", .cap = .PRIVILEGE },
    .{ .prefix = "chroot", .cap = .PRIVILEGE },
    .{ .prefix = "getenv", .cap = .INFO_LEAK },
    .{ .prefix = "getuid", .cap = .INFO_LEAK },
    .{ .prefix = "uname", .cap = .INFO_LEAK },
    .{ .prefix = "signal", .cap = .SIGNAL },
    .{ .prefix = "sigaction", .cap = .SIGNAL },
};

// ============================================================
// ANALYSIS RESULTS
// ============================================================

const AnalysisResults = struct {
    // Identity
    file_path: []const u8,
    file_size: usize,
    file_hash: [64]u8,
    elf_class: []const u8,
    elf_type: []const u8,
    machine: []const u8,
    entry_point: u64,

    // Entropy
    global_entropy: f64,
    high_entropy_windows: u32,

    // Caves
    total_caves: u32,
    total_cave_bytes: usize,
    caves_in_exec: u32,
    critical_caves: u32,

    // Strings
    total_strings: u32,
    flagged_strings: u32,
    string_cats: [9]u32,

    // Symbols
    has_symtab: bool,
    has_dynsym: bool,
    imported_syms: u32,
    exported_syms: u32,
    sym_caps: [9]u32,
    has_dlopen: bool,
    has_privilege: bool,
    has_network: bool,
    has_process: bool,

    // Security
    has_nx_stack: bool,
    has_wx_segments: bool,
    has_wx_sections: bool,
    critical_sections: u32,
    composite_hash: [64]u8,
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
    var output_path: ?[]const u8 = null;

    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if ((std.mem.eql(u8, arg, "--output") or std.mem.eql(u8, arg, "-o")) and ai + 1 < args.len) {
            ai += 1;
            output_path = args[ai];
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try stdout.writeAll(
                \\Usage: moabi-report [options] <elf-binary>
                \\
                \\Options:
                \\  --output, -o <file>  Save report to file
                \\  --help, -h           Show this help
                \\
                \\Generates a unified CRA compliance report combining:
                \\  - Entropy analysis
                \\  - ELF structure analysis
                \\  - Code cave detection
                \\  - String extraction
                \\  - Symbol analysis
                \\  - Cryptographic integrity verification
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

    // Initialize results
    var results = AnalysisResults{
        .file_path = path.?,
        .file_size = fsize,
        .file_hash = hexDigest(sha256(data)),
        .elf_class = if (ehdr.e_ident[4] == 2) "ELF64" else "ELF32",
        .elf_type = switch (ehdr.e_type) {
            2 => "EXEC", 3 => "DYN (PIE)", else => "OTHER",
        },
        .machine = switch (ehdr.e_machine) {
            0x3E => "x86_64", 0xB7 => "AArch64", 0x03 => "x86", else => "Other",
        },
        .entry_point = ehdr.e_entry,
        .global_entropy = 0,
        .high_entropy_windows = 0,
        .total_caves = 0,
        .total_cave_bytes = 0,
        .caves_in_exec = 0,
        .critical_caves = 0,
        .total_strings = 0,
        .flagged_strings = 0,
        .string_cats = [_]u32{0} ** 9,
        .has_symtab = false,
        .has_dynsym = false,
        .imported_syms = 0,
        .exported_syms = 0,
        .sym_caps = [_]u32{0} ** 9,
        .has_dlopen = false,
        .has_privilege = false,
        .has_network = false,
        .has_process = false,
        .has_nx_stack = false,
        .has_wx_segments = false,
        .has_wx_sections = false,
        .critical_sections = 0,
        .composite_hash = undefined,
    };

    // ==========================================
    // 1. ENTROPY ANALYSIS
    // ==========================================
    results.global_entropy = computeEntropy(data);

    const wsz: usize = 256;
    var woff: usize = 0;
    while (woff + wsz <= data.len) : (woff += wsz) {
        const w_ent = computeEntropy(data[woff .. woff + wsz]);
        if (w_ent > 7.0) results.high_entropy_windows += 1;
    }

    // ==========================================
    // 2. SEGMENT ANALYSIS
    // ==========================================
    var pi: u16 = 0;
    while (pi < ehdr.e_phnum) : (pi += 1) {
        const off = @as(usize, @intCast(ehdr.e_phoff)) +
            @as(usize, pi) * @as(usize, ehdr.e_phentsize);
        const phdr = ptrCast(Elf64_Phdr, data, off) orelse continue;

        if (phdr.p_type == PT_LOAD and (phdr.p_flags & PF_W != 0) and (phdr.p_flags & PF_X != 0)) {
            results.has_wx_segments = true;
        }
        if (phdr.p_type == PT_GNU_STACK) {
            results.has_nx_stack = (phdr.p_flags & PF_X == 0);
        }
    }

    // ==========================================
    // 3. SECTION ANALYSIS + CAVES + HASHING
    // ==========================================

    const SortedSec = struct {
        name: []const u8,
        offset: usize,
        size: usize,
        flags: u64,
        sec_type: u32,
    };

    var sorted_secs = std.ArrayList(SortedSec).init(allocator);
    defer sorted_secs.deinit();

    var composite = Sha256.init();

    var si: u16 = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type == SHT_NULL) continue;

        const name = getSecName(data, strtab_offset, shdr.sh_name);

        // Track symbol tables
        if (shdr.sh_type == SHT_SYMTAB) results.has_symtab = true;
        if (shdr.sh_type == SHT_DYNSYM) results.has_dynsym = true;

        // W+X sections
        if ((shdr.sh_flags & SHF_WRITE != 0) and (shdr.sh_flags & SHF_EXECINSTR != 0)) {
            results.has_wx_sections = true;
        }

        // Critical sections
        const critical = [_][]const u8{
            ".text", ".plt", ".plt.got", ".plt.sec",
            ".got", ".got.plt", ".init", ".fini",
            ".init_array", ".fini_array",
        };
        for (critical) |c| {
            if (std.mem.eql(u8, name, c)) {
                results.critical_sections += 1;
                break;
            }
        }

        // Hash section
        if (shdr.sh_type != SHT_NOBITS and shdr.sh_size > 0) {
            const sec_start = @as(usize, @intCast(shdr.sh_offset));
            const sec_size = @as(usize, @intCast(shdr.sh_size));
            if (sec_start + sec_size <= data.len) {
                const sec_hash = sha256(data[sec_start .. sec_start + sec_size]);
                composite.update(&sec_hash);
            }
        }

        // Collect for cave detection
        if (shdr.sh_type != SHT_NOBITS and shdr.sh_size > 0) {
            try sorted_secs.append(.{
                .name = name,
                .offset = @intCast(shdr.sh_offset),
                .size = @intCast(shdr.sh_size),
                .flags = shdr.sh_flags,
                .sec_type = shdr.sh_type,
            });
        }
    }

    results.composite_hash = hexDigest(composite.final());

    // Sort sections for cave detection
    std.mem.sort(SortedSec, sorted_secs.items, {}, struct {
        fn cmp(_: void, a: SortedSec, b: SortedSec) bool {
            return a.offset < b.offset;
        }
    }.cmp);

    // Cave detection
    var ci: usize = 0;
    while (ci + 1 < sorted_secs.items.len) : (ci += 1) {
        const current = sorted_secs.items[ci];
        const next = sorted_secs.items[ci + 1];
        const current_end = current.offset + current.size;

        if (next.offset > current_end) {
            const gap = next.offset - current_end;
            if (gap >= 16) {
                results.total_caves += 1;
                results.total_cave_bytes += gap;

                const block = data[current_end..next.offset];
                const ent = computeEntropy(block);

                // Check if in exec segment
                var in_exec = false;
                var pj: u16 = 0;
                while (pj < ehdr.e_phnum) : (pj += 1) {
                    const poff = @as(usize, @intCast(ehdr.e_phoff)) +
                        @as(usize, pj) * @as(usize, ehdr.e_phentsize);
                    const phdr = ptrCast(Elf64_Phdr, data, poff) orelse continue;
                    if (phdr.p_type != PT_LOAD) continue;
                    const seg_s = @as(usize, @intCast(phdr.p_offset));
                    const seg_e = seg_s + @as(usize, @intCast(phdr.p_filesz));
                    if (current_end >= seg_s and next.offset <= seg_e and phdr.p_flags & PF_X != 0) {
                        in_exec = true;
                    }
                }

                if (in_exec) results.caves_in_exec += 1;
                if (in_exec and ent > 6.0) results.critical_caves += 1;
            }
        }
    }

    // ==========================================
    // 4. STRING ANALYSIS
    // ==========================================
    var spos: usize = 0;
    while (spos < data.len) {
        if (!isPrintable(data[spos])) {
            spos += 1;
            continue;
        }
        const sstart = spos;
        while (spos < data.len and isPrintable(data[spos])) : (spos += 1) {}
        const slen = spos - sstart;
        if (slen < 6) continue;

        results.total_strings += 1;
        const s = data[sstart..spos];

        for (string_patterns) |pat| {
            const found = if (pat.case_insensitive) containsCI(s, pat.needle) else containsCS(s, pat.needle);
            if (found) {
                results.flagged_strings += 1;
                const idx: usize = switch (pat.category) {
                    .NORMAL => 0, .PATH => 1, .SHELL => 2, .NETWORK => 3,
                    .CRYPTO => 4, .CREDENTIAL => 5, .SENSITIVE => 6,
                    .ANTI_DEBUG => 7, .PACKER => 8,
                };
                results.string_cats[idx] += 1;
                break;
            }
        }
    }

    // ==========================================
    // 5. SYMBOL ANALYSIS
    // ==========================================
    si = 0;
    while (si < ehdr.e_shnum) : (si += 1) {
        const off = @as(usize, @intCast(ehdr.e_shoff)) +
            @as(usize, si) * @as(usize, ehdr.e_shentsize);
        const shdr = ptrCast(Elf64_Shdr, data, off) orelse continue;

        if (shdr.sh_type != SHT_DYNSYM and shdr.sh_type != SHT_SYMTAB) continue;

        // Find linked string table
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

        const entry_size = if (shdr.sh_entsize > 0) @as(usize, @intCast(shdr.sh_entsize)) else @sizeOf(Elf64_Sym);
        const count = @as(usize, @intCast(shdr.sh_size)) / entry_size;

        var idx: usize = 0;
        while (idx < count) : (idx += 1) {
            const sym_off = @as(usize, @intCast(shdr.sh_offset)) + idx * entry_size;
            const sym = ptrCast(Elf64_Sym, data, sym_off) orelse continue;

            const name = getSymName(data, sym_strtab_off, sym.st_name);
            if (name.len == 0) continue;

            const binding = sym.st_info >> 4;
            const is_import = (sym.st_shndx == SHN_UNDEF and binding == STB_GLOBAL);
            const is_export = (sym.st_shndx != SHN_UNDEF and binding == STB_GLOBAL);

            if (is_import) results.imported_syms += 1;
            if (is_export) results.exported_syms += 1;

            for (sym_patterns) |pat| {
                if (startsWith(name, pat.prefix)) {
                    const cap_idx: usize = switch (pat.cap) {
                        .MEMORY => 0, .PROCESS => 1, .NETWORK => 2,
                        .FILE_IO => 3, .CRYPTO => 4, .DYN_LOAD => 5,
                        .PRIVILEGE => 6, .INFO_LEAK => 7, .SIGNAL => 8,
                    };
                    results.sym_caps[cap_idx] += 1;

                    if (pat.cap == .DYN_LOAD) results.has_dlopen = true;
                    if (pat.cap == .PRIVILEGE) results.has_privilege = true;
                    if (pat.cap == .NETWORK) results.has_network = true;
                    if (pat.cap == .PROCESS) results.has_process = true;
                    break;
                }
            }
        }
    }

    // ==========================================
    // GENERATE REPORT
    // ==========================================

    // Use a buffered approach — write to both stdout and optionally file
    var report_file: ?std.fs.File = null;
    defer if (report_file) |rf| rf.close();

    if (output_path) |op| {
        report_file = std.fs.cwd().createFile(op, .{}) catch |err| {
            try stdout.print("Error: Cannot create report file '{s}' ({s})\n", .{ op, @errorName(err) });
            std.process.exit(1);
        };
    }

    // Write to both stdout and file
    const W = struct {
        stdout: @TypeOf(stdout),
        file_writer: ?std.fs.File.Writer,

        fn print(self: @This(), comptime fmt: []const u8, a: anytype) !void {
            try self.stdout.print(fmt, a);
            if (self.file_writer) |fw| try fw.print(fmt, a);
        }

        fn writeAll(self: @This(), s: []const u8) !void {
            try self.stdout.writeAll(s);
            if (self.file_writer) |fw| try fw.writeAll(s);
        }
    };

    const w = W{
        .stdout = stdout,
        .file_writer = if (report_file) |rf| rf.writer() else null,
    };

    // ---- REPORT OUTPUT ----

    try w.writeAll("\n");
    try w.writeAll("╔══════════════════════════════════════════════════════════════╗\n");
    try w.writeAll("║                                                              ║\n");
    try w.writeAll("║         MOABI CRA COMPLIANCE REPORT v0.1                     ║\n");
    try w.writeAll("║         Binary Analysis Suite (Zig 0.13.0)                   ║\n");
    try w.writeAll("║                                                              ║\n");
    try w.writeAll("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Section 1: Identity
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  1. BINARY IDENTITY\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  File:          {s}\n", .{results.file_path});
    try w.print("  Size:          {d} bytes\n", .{results.file_size});
    try w.print("  SHA-256:       {s}\n", .{results.file_hash});
    try w.print("  Class:         {s}\n", .{results.elf_class});
    try w.print("  Type:          {s}\n", .{results.elf_type});
    try w.print("  Architecture:  {s}\n", .{results.machine});
    try w.print("  Entry Point:   0x{x:0>16}\n", .{results.entry_point});
    try w.print("  Composite:     {s}\n", .{results.composite_hash});

    // Section 2: Entropy
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  2. ENTROPY ANALYSIS\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  Global Entropy:        {d:.4} / 8.0\n", .{results.global_entropy});
    try w.print("  High-Entropy Windows:  {d}\n", .{results.high_entropy_windows});

    const entropy_verdict: []const u8 = if (results.global_entropy > 7.5)
        "SUSPICIOUS — possible encryption/packing"
    else if (results.global_entropy > 6.5)
        "ELEVATED — some compressed/encrypted sections"
    else
        "NORMAL — typical compiled binary";
    try w.print("  Verdict:               {s}\n", .{entropy_verdict});

    // Section 3: Structure
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  3. STRUCTURAL ANALYSIS\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  Sections:              {d}\n", .{ehdr.e_shnum});
    try w.print("  Segments:              {d}\n", .{ehdr.e_phnum});
    try w.print("  Critical Sections:     {d}\n", .{results.critical_sections});
    try w.print("  NX Stack:              {s}\n", .{if (results.has_nx_stack) "YES ✓" else "NO ✗"});
    try w.print("  W+X Segments:          {s}\n", .{if (results.has_wx_segments) "YES ✗ (dangerous)" else "NO ✓"});
    try w.print("  W+X Sections:          {s}\n", .{if (results.has_wx_sections) "YES ✗ (dangerous)" else "NO ✓"});

    // Section 4: Code Caves
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  4. CODE CAVE ANALYSIS\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  Caves Found:           {d}\n", .{results.total_caves});
    try w.print("  Total Cave Space:      {d} bytes\n", .{results.total_cave_bytes});
    try w.print("  Cave Percentage:       {d:.2}%\n", .{
        if (fsize > 0) @as(f64, @floatFromInt(results.total_cave_bytes)) / @as(f64, @floatFromInt(fsize)) * 100.0 else 0.0,
    });
    try w.print("  Caves in EXEC:         {d}\n", .{results.caves_in_exec});
    try w.print("  Critical Caves:        {d}\n", .{results.critical_caves});

    // Section 5: Strings
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  5. STRING INTELLIGENCE\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  Total Strings:         {d}\n", .{results.total_strings});
    try w.print("  Flagged Strings:       {d}\n", .{results.flagged_strings});

    const str_cat_names = [_][]const u8{
        "Normal", "Path", "Shell", "Network",
        "Crypto", "Credential", "Sensitive", "Anti-Debug", "Packer",
    };
    for (str_cat_names, 0..) |name, idx| {
        if (results.string_cats[idx] > 0) {
            try w.print("    {s:<14}       {d}\n", .{ name, results.string_cats[idx] });
        }
    }

    // Section 6: Symbols
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  6. CAPABILITY ANALYSIS\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");
    try w.print("  Symbol Table:          {s}\n", .{if (results.has_symtab) "present" else "STRIPPED ✗"});
    try w.print("  Dynamic Symbols:       {s}\n", .{if (results.has_dynsym) "present" else "missing"});
    try w.print("  Imported Functions:    {d}\n", .{results.imported_syms});
    try w.print("  Exported Functions:    {d}\n", .{results.exported_syms});
    try w.writeAll("\n  Capability Map:\n");

    const cap_names = [_][]const u8{
        "Memory", "Process", "Network", "File I/O",
        "Crypto", "Dyn-Load", "Privilege", "Info-Leak", "Signal",
    };
    for (cap_names, 0..) |name, idx| {
        if (results.sym_caps[idx] > 0) {
            const danger = (idx == 1 or idx == 2 or idx == 5 or idx == 6);
            try w.print("    {s:<14}       {d}", .{ name, results.sym_caps[idx] });
            if (danger) try w.writeAll(" ⚠");
            try w.writeAll("\n");
        }
    }

    // ==========================================
    // CRA COMPLIANCE SCORECARD
    // ==========================================

    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  7. CRA COMPLIANCE SCORECARD\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    var total_score: u32 = 0;
    var max_score: u32 = 0;

    // Check 1: NX Stack
    max_score += 10;
    const nx_score: u32 = if (results.has_nx_stack) 10 else 0;
    total_score += nx_score;
    try w.print("  [NX-STACK]       {d:>2}/10  {s}\n", .{
        nx_score, if (results.has_nx_stack) "Non-executable stack enabled" else "FAIL: Stack is executable",
    });

    // Check 2: No W+X Segments
    max_score += 10;
    const wx_seg_score: u32 = if (!results.has_wx_segments) 10 else 0;
    total_score += wx_seg_score;
    try w.print("  [NO-WX-SEG]     {d:>2}/10  {s}\n", .{
        wx_seg_score, if (!results.has_wx_segments) "No writable+executable segments" else "FAIL: W+X segments detected",
    });

    // Check 3: No W+X Sections
    max_score += 10;
    const wx_sec_score: u32 = if (!results.has_wx_sections) 10 else 0;
    total_score += wx_sec_score;
    try w.print("  [NO-WX-SEC]     {d:>2}/10  {s}\n", .{
        wx_sec_score, if (!results.has_wx_sections) "No writable+executable sections" else "FAIL: W+X sections detected",
    });

    // Check 4: Symbol Table Present
    max_score += 10;
    const sym_score: u32 = if (results.has_symtab) 10 else if (results.has_dynsym) 5 else 0;
    total_score += sym_score;
    try w.print("  [SYMBOLS]        {d:>2}/10  {s}\n", .{
        sym_score,
        if (results.has_symtab) "Full symbol table present" else if (results.has_dynsym) "Partial: dynamic symbols only (stripped)" else "FAIL: No symbol information",
    });

    // Check 5: No Critical Caves
    max_score += 10;
    const cave_score: u32 = if (results.critical_caves == 0) 10 else if (results.critical_caves <= 2) 5 else 0;
    total_score += cave_score;
    try w.print("  [CAVES]          {d:>2}/10  {s}\n", .{
        cave_score,
        if (results.critical_caves == 0) "No critical code caves" else "WARNING: Suspicious caves detected",
    });

    // Check 6: Normal Entropy
    max_score += 10;
    const ent_score: u32 = if (results.global_entropy <= 6.5) 10 else if (results.global_entropy <= 7.5) 5 else 0;
    total_score += ent_score;
    try w.print("  [ENTROPY]        {d:>2}/10  {s}\n", .{
        ent_score,
        if (results.global_entropy <= 6.5) "Normal entropy profile" else "WARNING: Elevated entropy",
    });

    // Check 7: No Packer Signatures
    max_score += 10;
    const pack_score: u32 = if (results.string_cats[8] == 0) 10 else 0;
    total_score += pack_score;
    try w.print("  [NO-PACKER]      {d:>2}/10  {s}\n", .{
        pack_score,
        if (results.string_cats[8] == 0) "No packer signatures detected" else "FAIL: Packer signatures found",
    });

    // Check 8: No Anti-Debug
    max_score += 10;
    const adbg_score: u32 = if (results.string_cats[7] == 0) 10 else 5;
    total_score += adbg_score;
    try w.print("  [NO-ANTI-DBG]    {d:>2}/10  {s}\n", .{
        adbg_score,
        if (results.string_cats[7] == 0) "No anti-debug references" else "WARNING: Anti-debug indicators",
    });

    // Check 9: No Dynamic Loading
    max_score += 10;
    const dl_score: u32 = if (!results.has_dlopen) 10 else 3;
    total_score += dl_score;
    try w.print("  [NO-DLOPEN]      {d:>2}/10  {s}\n", .{
        dl_score,
        if (!results.has_dlopen) "No dynamic code loading" else "WARNING: dlopen/dlsym detected",
    });

    // Check 10: No Privilege Escalation
    max_score += 10;
    const priv_score: u32 = if (!results.has_privilege) 10 else 3;
    total_score += priv_score;
    try w.print("  [NO-PRIVESC]     {d:>2}/10  {s}\n", .{
        priv_score,
        if (!results.has_privilege) "No privilege manipulation" else "WARNING: Privilege functions imported",
    });

    // ---- FINAL SCORE ----
    try w.writeAll("\n  ──────────────────────────────────────\n");
    try w.print("  TOTAL SCORE:     {d}/{d}\n", .{ total_score, max_score });

    const percentage = @as(f64, @floatFromInt(total_score)) / @as(f64, @floatFromInt(max_score)) * 100.0;
    try w.print("  PERCENTAGE:      {d:.1}%\n\n", .{percentage});

    if (percentage >= 90.0) {
        try w.writeAll("  ╔═══════════════════════════════════╗\n");
        try w.writeAll("  ║  RESULT: PASS                     ║\n");
        try w.writeAll("  ║  CRA Compliance: SATISFACTORY     ║\n");
        try w.writeAll("  ╚═══════════════════════════════════╝\n");
    } else if (percentage >= 70.0) {
        try w.writeAll("  ╔═══════════════════════════════════╗\n");
        try w.writeAll("  ║  RESULT: CONDITIONAL PASS         ║\n");
        try w.writeAll("  ║  CRA Compliance: REVIEW REQUIRED  ║\n");
        try w.writeAll("  ╚═══════════════════════════════════╝\n");
    } else if (percentage >= 50.0) {
        try w.writeAll("  ╔═══════════════════════════════════╗\n");
        try w.writeAll("  ║  RESULT: MARGINAL                 ║\n");
        try w.writeAll("  ║  CRA Compliance: REMEDIATION REQ  ║\n");
        try w.writeAll("  ╚═══════════════════════════════════╝\n");
    } else {
        try w.writeAll("  ╔═══════════════════════════════════╗\n");
        try w.writeAll("  ║  RESULT: FAIL                     ║\n");
        try w.writeAll("  ║  CRA Compliance: NOT COMPLIANT    ║\n");
        try w.writeAll("  ╚═══════════════════════════════════╝\n");
    }

    // Recommendations
    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  8. RECOMMENDATIONS\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    var rec_count: u32 = 0;

    if (!results.has_nx_stack) {
        rec_count += 1;
        try w.print("  {d}. Enable NX stack: compile with -z noexecstack\n", .{rec_count});
    }
    if (results.has_wx_segments) {
        rec_count += 1;
        try w.print("  {d}. Remove W+X segments: review linker script\n", .{rec_count});
    }
    if (!results.has_symtab) {
        rec_count += 1;
        try w.print("  {d}. Provide unstripped binary or separate debug info for audit\n", .{rec_count});
    }
    if (results.critical_caves > 0) {
        rec_count += 1;
        try w.print("  {d}. Investigate {d} critical code caves for hidden content\n", .{ rec_count, results.critical_caves });
    }
    if (results.has_dlopen) {
        rec_count += 1;
        try w.print("  {d}. Document all dlopen/dlsym usage and loaded libraries\n", .{rec_count});
    }
    if (results.has_privilege) {
        rec_count += 1;
        try w.print("  {d}. Document privilege escalation requirements\n", .{rec_count});
    }
    if (results.string_cats[8] > 0) {
        rec_count += 1;
        try w.print("  {d}. Investigate packer signatures — provide unpacked binary\n", .{rec_count});
    }
    if (results.has_process and results.has_network) {
        rec_count += 1;
        try w.print("  {d}. Document network + process control capability combination\n", .{rec_count});
    }

    if (rec_count == 0) {
        try w.writeAll("  No recommendations — binary meets all checked criteria.\n");
    }

    try w.writeAll("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    try w.writeAll("  Report generated by MOABI Binary Analysis Suite\n");
    try w.writeAll("  https://moabi.com — Inspired by the Witchcraft Compiler Collection\n");
    try w.writeAll("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n");

    if (output_path) |op| {
        try stdout.print("✓ Report saved to: {s}\n\n", .{op});
    }
}
