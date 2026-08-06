const std = @import("std");

// build.zig for the syscaller test helper.
//
// The Makefile builds the binary directly with `zig build-exe` (to place it at dist/syscaller and
// pick the arch from GO_ARCH). This build script is for local development convenience:
//   zig build          -> builds zig-out/bin/syscaller
//   zig build test     -> runs the pure-logic unit tests (no root, no syscalls issued)
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseSafe by default: this tool deliberately pokes at destructive syscalls, so keep the
    // language safety checks on while staying tiny and libc-free.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    const exe = b.addExecutable(.{
        .name = "syscaller",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.installArtifact(exe);

    const unit_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run pure-logic unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
