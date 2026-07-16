const tracepoints = @import("linux_tracepoints");

const Payload = extern struct {
    first: u8,
    second: u32,
};

comptime {
    _ = tracepoints.user_events.RawDescriptor(
        "raw_padding u8 first; u32 second",
        Payload,
    );
}
