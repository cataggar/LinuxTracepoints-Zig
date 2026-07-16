const tracepoints = @import("linux_tracepoints");

const Payload = extern struct {
    value: usize,
};

comptime {
    _ = tracepoints.user_events.RawDescriptor("raw_usize usize value", Payload);
}
