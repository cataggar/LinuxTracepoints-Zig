const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .events = &.{.{
            .symbol = "event",
            .level = 4,
            .fields = &.{.{ .name = "text", .kind = .zstring8 }},
        }},
    });
}
