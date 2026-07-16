const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux or
        (builtin.cpu.arch != .x86_64 and builtin.cpu.arch != .aarch64) or
        @sizeOf(usize) != 8 or builtin.cpu.arch.endian() != .little)
    {
        @compileError(
            "perf collection supports only 64-bit little-endian x86_64 and AArch64 Linux targets",
        );
    }
}

pub const PERF_TYPE_TRACEPOINT: u32 = 2;

pub const PERF_SAMPLE_IP: u64 = 1 << 0;
pub const PERF_SAMPLE_TID: u64 = 1 << 1;
pub const PERF_SAMPLE_TIME: u64 = 1 << 2;
pub const PERF_SAMPLE_ADDR: u64 = 1 << 3;
pub const PERF_SAMPLE_ID: u64 = 1 << 6;
pub const PERF_SAMPLE_CPU: u64 = 1 << 7;
pub const PERF_SAMPLE_PERIOD: u64 = 1 << 8;
pub const PERF_SAMPLE_STREAM_ID: u64 = 1 << 9;
pub const PERF_SAMPLE_RAW: u64 = 1 << 10;
pub const PERF_SAMPLE_IDENTIFIER: u64 = 1 << 16;

pub const PERF_SAMPLE_SUPPORTED: u64 = PERF_SAMPLE_IDENTIFIER |
    PERF_SAMPLE_IP |
    PERF_SAMPLE_TID |
    PERF_SAMPLE_TIME |
    PERF_SAMPLE_ADDR |
    PERF_SAMPLE_ID |
    PERF_SAMPLE_STREAM_ID |
    PERF_SAMPLE_CPU |
    PERF_SAMPLE_PERIOD |
    PERF_SAMPLE_RAW;

pub const PERF_RECORD_LOST: u32 = 2;
pub const PERF_RECORD_SAMPLE: u32 = 9;

pub const PERF_FLAG_FD_CLOEXEC: usize = 1 << 3;

pub const PERF_ATTR_SIZE_VER0: u32 = 64;

pub const PerfEventAttrFlags = packed struct(u64) {
    disabled: bool = false,
    inherit: bool = false,
    pinned: bool = false,
    exclusive: bool = false,
    exclude_user: bool = false,
    exclude_kernel: bool = false,
    exclude_hv: bool = false,
    exclude_idle: bool = false,
    mmap: bool = false,
    comm: bool = false,
    freq: bool = false,
    inherit_stat: bool = false,
    enable_on_exec: bool = false,
    task: bool = false,
    watermark: bool = false,
    precise_ip: u2 = 0,
    mmap_data: bool = false,
    sample_id_all: bool = false,
    _reserved: u45 = 0,

    pub fn bits(self: PerfEventAttrFlags) u64 {
        return @bitCast(self);
    }
};

/// The first published 64-byte Linux `struct perf_event_attr` layout.
pub const perf_event_attr = extern struct {
    type: u32 = PERF_TYPE_TRACEPOINT,
    size: u32 = PERF_ATTR_SIZE_VER0,
    config: u64 = 0,
    sample_period: u64 = 0,
    sample_type: u64 = 0,
    read_format: u64 = 0,
    flags: u64 = 0,
    wakeup_events: u32 = 0,
    bp_type: u32 = 0,
    config1: u64 = 0,
};

pub const PerfEventAttrV0 = perf_event_attr;

pub const perf_event_header = extern struct {
    type: u32,
    misc: u16,
    size: u16,
};

pub const PerfEventHeader = perf_event_header;

pub const PERF_EVENT_IOC_ENABLE: u32 = linux.IOCTL.IO('$', 0);
pub const PERF_EVENT_IOC_DISABLE: u32 = linux.IOCTL.IO('$', 1);
pub const PERF_EVENT_IOC_RESET: u32 = linux.IOCTL.IO('$', 3);
pub const PERF_IOC_FLAG_GROUP: usize = 1 << 0;

pub const PERF_MMAP_DATA_HEAD_OFFSET: usize = 1024;
pub const PERF_MMAP_DATA_TAIL_OFFSET: usize = 1032;
pub const PERF_MMAP_DATA_OFFSET_OFFSET: usize = 1040;
pub const PERF_MMAP_DATA_SIZE_OFFSET: usize = 1048;

/// Prefix of Linux `struct perf_event_mmap_page` through the data-ring fields.
pub const perf_event_mmap_page_data = extern struct {
    _metadata: [PERF_MMAP_DATA_HEAD_OFFSET]u8,
    data_head: u64,
    data_tail: u64,
    data_offset: u64,
    data_size: u64,
};

pub const PerfEventMmapPageData = perf_event_mmap_page_data;

comptime {
    assertAbi(@sizeOf(PerfEventAttrFlags) == 8, "invalid perf attr flags size");
    assertAbi(@bitSizeOf(PerfEventAttrFlags) == 64, "invalid perf attr flags bits");

    assertAbi(@sizeOf(perf_event_attr) == 64, "perf_event_attr V0 must be 64 bytes");
    assertAbi(@alignOf(perf_event_attr) == 8, "perf_event_attr V0 must be 8-byte aligned");
    assertAbi(@offsetOf(perf_event_attr, "type") == 0, "invalid perf_event_attr.type offset");
    assertAbi(@offsetOf(perf_event_attr, "size") == 4, "invalid perf_event_attr.size offset");
    assertAbi(@offsetOf(perf_event_attr, "config") == 8, "invalid perf_event_attr.config offset");
    assertAbi(@offsetOf(perf_event_attr, "sample_period") == 16, "invalid perf_event_attr.sample_period offset");
    assertAbi(@offsetOf(perf_event_attr, "sample_type") == 24, "invalid perf_event_attr.sample_type offset");
    assertAbi(@offsetOf(perf_event_attr, "read_format") == 32, "invalid perf_event_attr.read_format offset");
    assertAbi(@offsetOf(perf_event_attr, "flags") == 40, "invalid perf_event_attr.flags offset");
    assertAbi(@offsetOf(perf_event_attr, "wakeup_events") == 48, "invalid perf_event_attr.wakeup_events offset");
    assertAbi(@offsetOf(perf_event_attr, "bp_type") == 52, "invalid perf_event_attr.bp_type offset");
    assertAbi(@offsetOf(perf_event_attr, "config1") == 56, "invalid perf_event_attr.config1 offset");

    assertAbi(@sizeOf(perf_event_header) == 8, "perf_event_header must be 8 bytes");
    assertAbi(@offsetOf(perf_event_header, "type") == 0, "invalid perf_event_header.type offset");
    assertAbi(@offsetOf(perf_event_header, "misc") == 4, "invalid perf_event_header.misc offset");
    assertAbi(@offsetOf(perf_event_header, "size") == 6, "invalid perf_event_header.size offset");

    assertAbi(PERF_EVENT_IOC_ENABLE == 0x2400, "invalid PERF_EVENT_IOC_ENABLE");
    assertAbi(PERF_EVENT_IOC_DISABLE == 0x2401, "invalid PERF_EVENT_IOC_DISABLE");
    assertAbi(PERF_EVENT_IOC_RESET == 0x2403, "invalid PERF_EVENT_IOC_RESET");

    assertAbi(@offsetOf(perf_event_mmap_page_data, "data_head") == 1024, "invalid perf mmap data_head offset");
    assertAbi(@offsetOf(perf_event_mmap_page_data, "data_tail") == 1032, "invalid perf mmap data_tail offset");
    assertAbi(@offsetOf(perf_event_mmap_page_data, "data_offset") == 1040, "invalid perf mmap data_offset offset");
    assertAbi(@offsetOf(perf_event_mmap_page_data, "data_size") == 1048, "invalid perf mmap data_size offset");
    assertAbi(@sizeOf(perf_event_mmap_page_data) == 1056, "invalid perf mmap metadata prefix size");
}

fn assertAbi(comptime condition: bool, comptime message: []const u8) void {
    if (!condition) @compileError(message);
}

fn putNative(output: []u8, offset: usize, value: anytype) void {
    const value_bytes = std.mem.asBytes(&value);
    @memcpy(output[offset .. offset + value_bytes.len], value_bytes);
}

test "perf_event_attr V0 uses exact bytes and flag positions" {
    const flags = PerfEventAttrFlags{
        .disabled = true,
        .exclude_user = true,
        .exclude_kernel = true,
        .exclude_hv = true,
        .watermark = true,
        .precise_ip = 2,
        .sample_id_all = true,
    };
    const expected_flags = (@as(u64, 1) << 0) |
        (@as(u64, 1) << 4) |
        (@as(u64, 1) << 5) |
        (@as(u64, 1) << 6) |
        (@as(u64, 1) << 14) |
        (@as(u64, 2) << 15) |
        (@as(u64, 1) << 18);
    try std.testing.expectEqual(expected_flags, flags.bits());

    const attr = perf_event_attr{
        .config = 0x1122334455667788,
        .sample_period = 0x1020304050607080,
        .sample_type = PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_RAW,
        .read_format = 0xaabbccdd,
        .flags = flags.bits(),
        .wakeup_events = 7,
        .bp_type = 0x1234,
        .config1 = 0x8877665544332211,
    };
    var expected = [_]u8{0} ** PERF_ATTR_SIZE_VER0;
    putNative(&expected, 0, PERF_TYPE_TRACEPOINT);
    putNative(&expected, 4, PERF_ATTR_SIZE_VER0);
    putNative(&expected, 8, attr.config);
    putNative(&expected, 16, attr.sample_period);
    putNative(&expected, 24, attr.sample_type);
    putNative(&expected, 32, attr.read_format);
    putNative(&expected, 40, attr.flags);
    putNative(&expected, 48, attr.wakeup_events);
    putNative(&expected, 52, attr.bp_type);
    putNative(&expected, 56, attr.config1);
    try std.testing.expectEqualSlices(u8, &expected, std.mem.asBytes(&attr));
}
