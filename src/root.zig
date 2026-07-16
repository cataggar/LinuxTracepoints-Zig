//! Comptime-first Linux user events and EventHeader support.

pub const abi = @import("abi/linux.zig");
pub const eventheader = @import("eventheader.zig");
pub const tracefs = @import("tracefs.zig");
pub const user_events = @import("user_events.zig");

test {
    _ = abi;
    _ = eventheader;
    _ = tracefs;
    _ = user_events;
}
