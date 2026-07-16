const std = @import("std");
const tracepoints = @import("linux_tracepoints");

const IntegrationProvider = tracepoints.provider.Provider(.{
    .name = "Zig_Integration",
    .events = &.{.{
        .symbol = "probe",
        .level = 4,
        .fields = &.{.{ .name = "value", .kind = .u32 }},
    }},
});

test "generated provider registers and cleans up against user_events" {
    var provider: IntegrationProvider.Instance = .{};
    provider.registerAll() catch |err| switch (err) {
        error.UserEventsUnavailable => return error.SkipZigTest,
        else => return err,
    };
    defer provider.unregisterAll() catch @panic("integration cleanup failed");

    try std.testing.expect(provider.data_file.isOpen());
    try std.testing.expectEqual(
        @as(u32, IntegrationProvider.event_set_count),
        provider.data_file.registeredEventCount(),
    );

    const Lazy = struct {
        fn build(calls: *usize) IntegrationProvider.Payload(.probe) {
            calls.* += 1;
            return .{ .value = 1 };
        }
    };
    var lazy_calls: usize = 0;
    try std.testing.expectEqual(
        tracepoints.user_events.WriteOutcome.disabled,
        try provider.writeLazy(.probe, &lazy_calls, Lazy.build, .{}),
    );
    try std.testing.expectEqual(@as(usize, 0), lazy_calls);

    try provider.unregisterAll();
    try std.testing.expect(!provider.data_file.isOpen());
    try std.testing.expectEqual(@as(u32, 0), provider.data_file.registeredEventCount());
}
