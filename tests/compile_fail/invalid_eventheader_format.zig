const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.eventheader.EventDefinition(.{
        .name = "event",
        .level = 4,
        .fields = &.{.{
            .name = "value",
            .encoding = .value8,
            .format = .uuid,
        }},
    });
}
