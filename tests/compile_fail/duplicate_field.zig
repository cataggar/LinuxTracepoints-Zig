const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .events = &.{.{
            .symbol = "event",
            .level = 4,
            .fields = &.{
                .{ .name = "duplicate", .kind = .u8 },
                .{ .name = "duplicate", .kind = .u16 },
            },
        }},
    });
}
