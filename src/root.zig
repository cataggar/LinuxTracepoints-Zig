//! Comptime-first Linux user events and EventHeader support.

pub const abi = @import("abi/linux.zig");
pub const user_events = @import("user_events.zig");

test {
    _ = abi;
    _ = user_events;
}
