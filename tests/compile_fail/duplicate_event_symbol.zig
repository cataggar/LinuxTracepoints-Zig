const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .events = &.{
            .{ .symbol = "duplicate", .level = 4 },
            .{ .symbol = "duplicate", .level = 5 },
        },
    });
}
