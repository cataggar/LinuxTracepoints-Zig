const tracepoints = @import("linux_tracepoints");

const Payload = struct {
    value: u32,
};

comptime {
    _ = tracepoints.user_events.RawDescriptor("raw_auto u32 value", Payload);
}
