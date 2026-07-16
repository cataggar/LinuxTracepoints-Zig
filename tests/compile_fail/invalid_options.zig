const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .options = "invalid",
        .events = &.{.{ .symbol = "event", .level = 4 }},
    });
}
