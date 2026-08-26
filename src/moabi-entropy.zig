const std = @import("std");

pub fn main() !void {
    // Standard Zig setup for CLI tools
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Get stdout writer for easy printing
    const stdout = std.io.getStdOut().writer();

    // 1. Handle Arguments (Native Zig way)
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try stdout.print("Usage: {s} <file>\n", .{args[0]});
        std.process.exit(1);
    }

    const path = args[1];
    try stdout.writeAll("\n--- MOABI WITCHCRAFT ENTROPY v0.8 (Zig 0.13.0) ---\n");

    // 2. Open File
    // std.fs.cwd() works in 0.13.0 provided you import std correctly
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("Error: Could not open file '{s}' ({s})\n", .{ path, @errorName(err) });
        std.process.exit(1);
    };
    defer file.close();

    // 3. Read File into Memory
    const stat = try file.stat();
    const data = try allocator.alloc(u8, @intCast(stat.size));
    defer allocator.free(data);
    _ = try file.readAll(data);

    // 4. Global Shannon Entropy
    var counts = [_]u64{0} ** 256;
    for (data) |b| counts[b] += 1;

    var entropy: f64 = 0.0;
    const len_f = @as(f64, @floatFromInt(data.len));
    const log2 = @log(2.0);

    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / len_f;
        entropy -= p * (@log(p) / log2);
    }

    try stdout.print("File: {s}\nSize: {d} bytes\nEntropy: {d:.4}\n", .{ path, stat.size, entropy });

    // 5. Scan for Anomalies (Sliding Window)
    try stdout.writeAll("\nScanning for Anomalies (Window 256)...\n");
    const window_size = 256;
    var offset: usize = 0;

    while (offset + window_size <= data.len) : (offset += window_size) {
        var w_counts = [_]u64{0} ** 256;
        const window = data[offset .. offset + window_size];
        
        for (window) |b| w_counts[b] += 1;

        var w_entropy: f64 = 0.0;
        for (w_counts) |c| {
            if (c == 0) continue;
            const p = @as(f64, @floatFromInt(c)) / 256.0;
            w_entropy -= p * (@log(p) / log2);
        }

        if (w_entropy > 7.0) {
            try stdout.print("  0x{x:0>8}: {d:.4} [ANOMALY]\n", .{ offset, w_entropy });
        }
    }
}
