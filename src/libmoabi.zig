const std = @import("std");

// ============================================================
// MOABI ANALYSIS ENGINE — Shared Library Edition
//
// This exposes our analysis functions as a shared library
// that can be loaded via dlopen / LuaJIT FFI.
//
// Every function is callable directly from LuaJIT.
// ============================================================

// ---- ENTROPY ----

export fn moabi_entropy(data: [*]const u8, len: usize) f64 {
    if (len == 0) return 0.0;

    var counts = [_]u64{0} ** 256;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        counts[data[i]] += 1;
    }

    var entropy: f64 = 0.0;
    const len_f = @as(f64, @floatFromInt(len));
    const log2 = @log(2.0);

    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / len_f;
        entropy -= p * (@log(p) / log2);
    }
    return entropy;
}

// ---- BYTE STATISTICS ----

export fn moabi_byte_mean(data: [*]const u8, len: usize) f64 {
    if (len == 0) return 0.0;
    var sum: u64 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        sum += data[i];
    }
    return @as(f64, @floatFromInt(sum)) / @as(f64, @floatFromInt(len));
}

export fn moabi_byte_stddev(data: [*]const u8, len: usize) f64 {
    if (len == 0) return 0.0;
    const mean = moabi_byte_mean(data, len);
    var variance: f64 = 0.0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const diff = @as(f64, @floatFromInt(data[i])) - mean;
        variance += diff * diff;
    }
    variance /= @as(f64, @floatFromInt(len));
    return @sqrt(variance);
}

export fn moabi_null_ratio(data: [*]const u8, len: usize) f64 {
    if (len == 0) return 0.0;
    var nulls: u64 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (data[i] == 0) nulls += 1;
    }
    return @as(f64, @floatFromInt(nulls)) / @as(f64, @floatFromInt(len));
}

export fn moabi_printable_ratio(data: [*]const u8, len: usize) f64 {
    if (len == 0) return 0.0;
    var printable: u64 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (data[i] >= 32 and data[i] <= 126) printable += 1;
    }
    return @as(f64, @floatFromInt(printable)) / @as(f64, @floatFromInt(len));
}

// ---- WINDOWED ENTROPY ----

export fn moabi_window_entropy(
    data: [*]const u8,
    len: usize,
    window_size: usize,
    results: [*]f64,
    max_results: usize,
) usize {
    if (len == 0 or window_size == 0 or window_size > len) return 0;

    var count: usize = 0;
    var offset: usize = 0;

    while (offset + window_size <= len and count < max_results) : ({
        offset += window_size;
        count += 1;
    }) {
        results[count] = moabi_entropy(data + offset, window_size);
    }

    return count;
}

// ---- HIGH ENTROPY WINDOW COUNTER ----

export fn moabi_count_high_entropy(
    data: [*]const u8,
    len: usize,
    window_size: usize,
    threshold: f64,
) usize {
    if (len == 0 or window_size == 0 or window_size > len) return 0;

    var count: usize = 0;
    var offset: usize = 0;

    while (offset + window_size <= len) : (offset += window_size) {
        const ent = moabi_entropy(data + offset, window_size);
        if (ent > threshold) count += 1;
    }

    return count;
}

// ---- BYTE HISTOGRAM ----

export fn moabi_histogram(
    data: [*]const u8,
    len: usize,
    output: [*]u64,
) void {
    var i: usize = 0;
    while (i < 256) : (i += 1) {
        output[i] = 0;
    }

    i = 0;
    while (i < len) : (i += 1) {
        output[data[i]] += 1;
    }
}

// ---- PATTERN DETECTION ----

export fn moabi_find_pattern(
    data: [*]const u8,
    data_len: usize,
    pattern: [*]const u8,
    pattern_len: usize,
) i64 {
    if (pattern_len == 0 or pattern_len > data_len) return -1;

    var i: usize = 0;
    while (i + pattern_len <= data_len) : (i += 1) {
        var match = true;
        var j: usize = 0;
        while (j < pattern_len) : (j += 1) {
            if (data[i + j] != pattern[j]) {
                match = false;
                break;
            }
        }
        if (match) return @intCast(i);
    }
    return -1;
}

// ---- CAVE DETECTION (simplified) ----

export fn moabi_is_zeroed(data: [*]const u8, len: usize) bool {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (data[i] != 0) return false;
    }
    return true;
}

export fn moabi_is_nop_sled(data: [*]const u8, len: usize) bool {
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (data[i] != 0x90) return false;
    }
    return true;
}

// ---- ELF MAGIC CHECK ----

export fn moabi_is_elf(data: [*]const u8, len: usize) bool {
    if (len < 4) return false;
    return (data[0] == 0x7F and data[1] == 'E' and
            data[2] == 'L' and data[3] == 'F');
}

export fn moabi_elf_class(data: [*]const u8, len: usize) i32 {
    if (len < 5) return -1;
    if (!moabi_is_elf(data, len)) return -1;
    return @as(i32, data[4]);
}

export fn moabi_elf_type(data: [*]const u8, len: usize) i32 {
    if (len < 18) return -1;
    if (!moabi_is_elf(data, len)) return -1;
    return @as(i32, data[16]) | (@as(i32, data[17]) << 8);
}

// ---- SHA-256 ----

const Sha256State = struct {
    state: [8]u32,
    buf: [64]u8,
    buf_len: usize,
    total_len: u64,
};

const SHA256_K = [64]u32{
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

fn sha256_rotr(x: u32, comptime n: u5) u32 {
    return (x >> n) | (x << (@as(u5, 32 - @as(u6, n))));
}

fn sha256_block(state: *[8]u32, block: [*]const u8) void {
    var w: [64]u32 = undefined;
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        w[i] = @as(u32, block[i * 4]) << 24 |
               @as(u32, block[i * 4 + 1]) << 16 |
               @as(u32, block[i * 4 + 2]) << 8 |
               @as(u32, block[i * 4 + 3]);
    }
    while (i < 64) : (i += 1) {
        const s0 = sha256_rotr(w[i-15], 7) ^ sha256_rotr(w[i-15], 18) ^ (w[i-15] >> 3);
        const s1 = sha256_rotr(w[i-2], 17) ^ sha256_rotr(w[i-2], 19) ^ (w[i-2] >> 10);
        w[i] = w[i-16] +% s0 +% w[i-7] +% s1;
    }

    var a = state[0]; var b = state[1]; var c = state[2]; var d = state[3];
    var e = state[4]; var f = state[5]; var g = state[6]; var h = state[7];

    i = 0;
    while (i < 64) : (i += 1) {
        const S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const t1 = h +% S1 +% ch +% SHA256_K[i] +% w[i];
        const S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = S0 +% maj;
        h = g; g = f; f = e; e = d +% t1;
        d = c; c = b; b = a; a = t1 +% t2;
    }

    state[0] +%= a; state[1] +%= b; state[2] +%= c; state[3] +%= d;
    state[4] +%= e; state[5] +%= f; state[6] +%= g; state[7] +%= h;
}

export fn moabi_sha256(data: [*]const u8, len: usize, output: [*]u8) void {
    var state = [8]u32{
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    var pos: usize = 0;
    while (pos + 64 <= len) : (pos += 64) {
        sha256_block(&state, data + pos);
    }

    var last_block: [128]u8 = undefined;
    const remaining = len - pos;
    var bi: usize = 0;
    while (bi < remaining) : (bi += 1) {
        last_block[bi] = data[pos + bi];
    }
    last_block[remaining] = 0x80;
    bi = remaining + 1;
    
    const need_extra = (remaining >= 56);
    const final_len: usize = if (need_extra) 128 else 64;
    
    while (bi < final_len - 8) : (bi += 1) {
        last_block[bi] = 0;
    }

    const total_bits = @as(u64, len) * 8;
    last_block[final_len - 8] = @intCast((total_bits >> 56) & 0xff);
    last_block[final_len - 7] = @intCast((total_bits >> 48) & 0xff);
    last_block[final_len - 6] = @intCast((total_bits >> 40) & 0xff);
    last_block[final_len - 5] = @intCast((total_bits >> 32) & 0xff);
    last_block[final_len - 4] = @intCast((total_bits >> 24) & 0xff);
    last_block[final_len - 3] = @intCast((total_bits >> 16) & 0xff);
    last_block[final_len - 2] = @intCast((total_bits >> 8) & 0xff);
    last_block[final_len - 1] = @intCast(total_bits & 0xff);

    sha256_block(&state, &last_block);
    if (need_extra) {
        sha256_block(&state, last_block[64..].ptr);
    }

    for (state, 0..) |s, si| {
        output[si * 4]     = @intCast((s >> 24) & 0xff);
        output[si * 4 + 1] = @intCast((s >> 16) & 0xff);
        output[si * 4 + 2] = @intCast((s >> 8) & 0xff);
        output[si * 4 + 3] = @intCast(s & 0xff);
    }
}

// ============================================================
// ZERO-COPY FILE MAPPING
// ============================================================

const posix = std.posix;

export fn moabi_mmap_file(
    path: [*:0]const u8,
    len_out: *usize,
) ?[*]u8 {
    const file = std.fs.cwd().openFileZ(
        path, .{}) catch return null;
    defer file.close();

    const stat = file.stat() catch return null;
    const size = @as(usize, @intCast(stat.size));
    if (size == 0) return null;
    len_out.* = size;

    const mapped = posix.mmap(
        null,
        size,
        posix.PROT.READ,
        .{ .TYPE = .PRIVATE },
        file.handle,
        0,
    ) catch return null;

    return @ptrCast(mapped.ptr);
}

export fn moabi_munmap(ptr: [*]align(4096) const u8, len: usize) void {
    posix.munmap(ptr[0..len]);
}

export fn moabi_file_size(path: [*:0]const u8) i64 {
    const file = std.fs.cwd().openFileZ(
        path, .{}) catch return -1;
    defer file.close();
    const stat = file.stat() catch return -1;
    return @intCast(stat.size);
}

// ---- VERSION ----

export fn moabi_version() u32 {
    return 0x00010000; // 1.0.0
}
