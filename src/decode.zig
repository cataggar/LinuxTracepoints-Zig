//! Portable, allocation-conscious decoders for Linux tracing file formats.
//!
//! This namespace has no dependency on the Linux producer or on libc. Borrowed
//! views retain slices into caller-owned input. Types whose names start with
//! `Owned` take and retain an explicit caller allocator.

pub const bytes = @import("decode/bytes.zig");
pub const tracefs_format = @import("decode/tracefs_format.zig");
pub const eventheader = @import("decode/eventheader.zig");
pub const perf_data = @import("decode/perf_data.zig");

pub const tracefs = tracefs_format;
pub const perf = perf_data;
pub const Error = bytes.Error;
pub const Limits = bytes.Limits;
pub const Cursor = bytes.Cursor;

test {
    _ = bytes;
    _ = tracefs_format;
    _ = eventheader;
    _ = perf_data;
}
