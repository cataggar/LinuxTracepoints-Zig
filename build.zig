const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const test_filter = b.option(
        []const u8,
        "test-filter",
        "Run unit tests whose names contain this text",
    );
    const integration = b.option(
        bool,
        "integration",
        "Include the kernel user_events integration test in the test step",
    ) orelse false;
    const test_filters: []const []const u8 = if (test_filter) |filter|
        &.{filter}
    else
        &.{};

    const module = b.addModule("linux_tracepoints", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const decode_module = b.addModule("linux_tracepoints_decode", .{
        .root_source_file = b.path("src/decode.zig"),
        .target = target,
        .optimize = optimize,
    });

    const module_tests = b.addTest(.{
        .root_module = module,
        .filters = test_filters,
    });
    const run_module_tests = b.addRunArtifact(module_tests);
    const decode_tests = b.addTest(.{
        .name = "linux-tracepoints-decode-tests",
        .root_module = decode_module,
        .filters = test_filters,
    });
    const run_decode_tests = b.addRunArtifact(decode_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_module_tests.step);
    test_step.dependOn(&run_decode_tests.step);

    const decode_test_step = b.step(
        "test-decode",
        "Run portable decoder tests",
    );
    decode_test_step.dependOn(&run_decode_tests.step);

    const test_compile_step = b.step(
        "test-compile",
        "Compile library tests without running them",
    );
    test_compile_step.dependOn(&module_tests.step);
    test_compile_step.dependOn(&decode_tests.step);

    const portable_target = b.resolveTargetQuery(.{
        .cpu_arch = .x86_64,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const portable_decode_module = b.createModule(.{
        .root_source_file = b.path("src/decode.zig"),
        .target = portable_target,
        .optimize = optimize,
    });
    const portable_probe_module = b.createModule(.{
        .root_source_file = b.path("tests/portable_decode.zig"),
        .target = portable_target,
        .optimize = optimize,
    });
    portable_probe_module.addImport(
        "linux_tracepoints_decode",
        portable_decode_module,
    );
    const portable_probe = b.addObject(.{
        .name = "linux-tracepoints-decode-freestanding",
        .root_module = portable_probe_module,
    });
    const portable_wasm_target = b.resolveTargetQuery(.{
        .cpu_arch = .wasm32,
        .os_tag = .freestanding,
        .abi = .none,
    });
    const portable_wasm_decode_module = b.createModule(.{
        .root_source_file = b.path("src/decode.zig"),
        .target = portable_wasm_target,
        .optimize = optimize,
    });
    const portable_wasm_probe_module = b.createModule(.{
        .root_source_file = b.path("tests/portable_decode.zig"),
        .target = portable_wasm_target,
        .optimize = optimize,
    });
    portable_wasm_probe_module.addImport(
        "linux_tracepoints_decode",
        portable_wasm_decode_module,
    );
    const portable_wasm_probe = b.addObject(.{
        .name = "linux-tracepoints-decode-wasm32-freestanding",
        .root_module = portable_wasm_probe_module,
    });
    const portable_step = b.step(
        "test-decode-portable",
        "Compile the decoder for x86_64- and wasm32-freestanding",
    );
    portable_step.dependOn(&portable_probe.step);
    portable_step.dependOn(&portable_wasm_probe.step);

    const compile_fail_step = b.step(
        "test-compile-fail",
        "Check compile-time contract diagnostics",
    );
    const compile_fail_cases = [_]struct {
        name: []const u8,
        expected: []const u8,
    }{
        .{ .name = "invalid_provider_name", .expected = "provider name must contain only ASCII letters, digits, and '_'" },
        .{ .name = "level_zero", .expected = "provider event level must be nonzero" },
        .{ .name = "duplicate_event_symbol", .expected = "duplicate provider event symbol: duplicate" },
        .{ .name = "duplicate_field", .expected = "duplicate provider field name: duplicate" },
        .{ .name = "invalid_options", .expected = "EventHeader option must start with an uppercase ASCII letter" },
        .{ .name = "duplicate_options", .expected = "EventHeader options must have unique, alphabetically sorted types" },
        .{ .name = "zero_bound", .expected = "bounded string and binary maxima must be nonzero" },
        .{ .name = "unsupported_encoding", .expected = "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported" },
        .{ .name = "excessive_nesting", .expected = "provider field nesting exceeds the supported depth of 16" },
        .{ .name = "invalid_eventheader_format", .expected = "EventHeader field format is incompatible with its encoding" },
        .{ .name = "invalid_eventheader_name", .expected = "EventHeader event name must not contain ';'" },
        .{ .name = "raw_auto_layout", .expected = "raw payload must be an extern struct" },
        .{ .name = "raw_padding", .expected = "raw payload has inter-field padding" },
        .{ .name = "raw_usize", .expected = "raw payload integers must have a byte-complete fixed-width representation" },
    };
    for (compile_fail_cases) |case| {
        const fixture_module = b.createModule(.{
            .root_source_file = b.path(b.fmt(
                "tests/compile_fail/{s}.zig",
                .{case.name},
            )),
            .target = target,
            .optimize = optimize,
        });
        fixture_module.addImport("linux_tracepoints", module);
        const fixture = b.addTest(.{
            .name = b.fmt("compile-fail-{s}", .{case.name}),
            .root_module = fixture_module,
        });
        fixture.expect_errors = .{ .contains = case.expected };
        compile_fail_step.dependOn(&fixture.step);
    }

    const integration_module = b.createModule(.{
        .root_source_file = b.path("tests/integration/user_events.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration_module.addImport("linux_tracepoints", module);
    const integration_tests = b.addTest(.{
        .name = "user-events-integration",
        .root_module = integration_module,
        .filters = test_filters,
    });
    const run_integration_tests = b.addRunArtifact(integration_tests);
    const integration_step = b.step(
        "integration",
        "Run the kernel user_events integration test",
    );
    integration_step.dependOn(&run_integration_tests.step);
    if (integration) test_step.dependOn(&run_integration_tests.step);
}
