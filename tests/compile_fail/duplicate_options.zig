const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .options = "A1A2",
        .events = &.{.{ .symbol = "event", .level = 4 }},
    });
}
