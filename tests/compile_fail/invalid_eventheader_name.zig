const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.eventheader.EventDefinition(.{
        .name = "invalid;event",
        .level = 4,
    });
}
