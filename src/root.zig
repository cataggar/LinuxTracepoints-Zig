//! Comptime-first Linux producers plus portable offline trace decoders.

const builtin = @import("builtin");

pub const abi = @import("abi/linux.zig");
pub const decode = @import("decode.zig");
pub const eventheader = @import("eventheader.zig");
pub const perf = @import("perf.zig");
pub const provider = @import("provider.zig");
pub const tracefs = @import("tracefs.zig");
pub const user_events = @import("user_events.zig");

test {
    _ = abi;
    _ = decode;
    _ = eventheader;
    if (@sizeOf(usize) == 8 and
        (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64) and
        builtin.cpu.arch.endian() == .little)
    {
        _ = perf;
    }
    _ = provider;
    _ = tracefs;
    _ = user_events;
}
