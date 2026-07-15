const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const module = b.addModule("linux_tracepoints", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const module_tests = b.addTest(.{
        .root_module = module,
    });
    const run_module_tests = b.addRunArtifact(module_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_module_tests.step);
}
