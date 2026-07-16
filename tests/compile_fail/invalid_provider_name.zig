const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "invalid-name",
        .events = &.{.{ .symbol = "event", .level = 4 }},
    });
}
