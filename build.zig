const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{});

    // ---- SHARED LIBRARY ----
    const lib = b.addSharedLibrary(.{
        .name = "moabi",
        .root_source_file = .{
            .path = "src/libmoabi.zig"
        },
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    // ---- STANDALONE TOOLS ----
    const tools = [_][]const u8{
        "moabi-entropy",
        "moabi-elfparse",
        "moabi-caves",
        "moabi-strings",
        "moabi-symbols",
        "moabi-hashdeep",
        "moabi-report",
        "moabi-baseline",
        "moabi-libify",
    };

    for (tools) |tool| {
        const exe = b.addExecutable(.{
            .name = tool,
            .root_source_file = .{
                .path = b.fmt("src/{s}.zig", .{tool})
            },
            .target = target,
            .optimize = optimize,
        });
        b.installArtifact(exe);
    }

    // ---- BUILD STEPS ----

    // zig build lib
    const lib_step = b.step("lib", "Build shared library only");
    const lib_only = b.addSharedLibrary(.{
        .name = "moabi",
        .root_source_file = .{
            .path = "src/libmoabi.zig"
        },
        .target = target,
        .optimize = optimize,
    });
    lib_step.dependOn(&b.addInstallArtifact(
        lib_only, .{}).step);

    // zig build tools
    const tools_step = b.step(
        "tools", "Build standalone tools only");
    for (tools) |tool| {
        const exe = b.addExecutable(.{
            .name = tool,
            .root_source_file = .{
                .path = b.fmt("src/{s}.zig", .{tool})
            },
            .target = target,
            .optimize = optimize,
        });
        tools_step.dependOn(
            &b.addInstallArtifact(exe, .{}).step);
    }

    // zig build arm64
    const arm64_step = b.step(
        "arm64", "Cross-compile for AArch64");
    const arm64_target = b.resolveTargetQuery(
        std.Target.Query.parse(.{
            .arch_os_abi = "aarch64-linux-gnu"
        }) catch unreachable);

    const arm64_lib = b.addSharedLibrary(.{
        .name = "moabi-arm64",
        .root_source_file = .{
            .path = "src/libmoabi.zig"
        },
        .target = arm64_target,
        .optimize = optimize,
    });
    arm64_step.dependOn(
        &b.addInstallArtifact(arm64_lib, .{}).step);

    // zig build riscv64
    const riscv_step = b.step(
        "riscv64", "Cross-compile for RISC-V 64");
    const riscv_target = b.resolveTargetQuery(
        std.Target.Query.parse(.{
            .arch_os_abi = "riscv64-linux-gnu"
        }) catch unreachable);

    const riscv_lib = b.addSharedLibrary(.{
        .name = "moabi-riscv64",
        .root_source_file = .{
            .path = "src/libmoabi.zig"
        },
        .target = riscv_target,
        .optimize = optimize,
    });
    riscv_step.dependOn(
        &b.addInstallArtifact(riscv_lib, .{}).step);
}
