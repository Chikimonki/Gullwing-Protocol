const std = @import("std");

pub fn main() !void {
    // Use GPA instead of page_allocator for better performance
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const alloc = gpa.allocator();

    // Get args properly using Zig's built-in
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);

    if (args.len < 2) {
        try std.io.getStdErr().writer().print("Usage: moabi-entropy <file>\n", .{});
        std.process.exit(1);
    }

    const path = args[1];
    
    const stdout = std.io.getStdOut().writer();
    try stdout.print("\n--- MOABI WITCHCRAFT ENTROPY v0.8 ---\n", .{});

    // This should work now
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        try stdout.print("Error opening file: {}\n", .{err});
        std.process.exit(1);
    };
    defer file.close();

    const st = try file.stat();
    const data = try alloc.alloc(u8, @intCast(st.size));
    defer alloc.free(data);
    _ = try file.readAll(data);

    // Shannon Entropy math
    var counts = [_]u64{0} ** 256;
    for (data) |b| counts[b] += 1;
    var entropy: f64 = 0.0;
    const lf: f64 = @floatFromInt(data.len);
    for (counts) |c| {
        if (c == 0) continue;
        const p = @as(f64, @floatFromInt(c)) / lf;
        entropy -= p * @log(p) / @log(@as(f64, 2.0));
    }

    // Output results using Zig's built-in printing
    try stdout.print("File: {s}\nSize: {d}\nEntropy: {d:.4}\n", .{path, st.size, entropy});

    // Scan for anomalies
    try stdout.print("\nScanning for Anomalies (Window 256)...\n", .{});
    const wsz = 256;
    var off: usize = 0;
    while (off + wsz <= data.len) : (off += wsz) {
        var w_counts = [_]u64{0} ** 256;
        for (data[off .. off + wsz]) |b| w_counts[b] += 1;
        var w_e: f64 = 0.0;
        for (w_counts) |c| {
            if (c == 0) continue;
            const p = @as(f64, @floatFromInt(c)) / 256.0;
            w_e -= p * @log(p) / @log(@as(f64, 2.0));
        }

        if (w_e > 7.0) {
            try stdout.print("  0x{x:0>8}: {d:.4} [ANOMALY]\n", .{off, w_e});
        }
    }
}
