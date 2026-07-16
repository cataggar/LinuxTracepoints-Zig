const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("linux_tracepoints supports Linux targets only");
    }
}

pub const perf = @import("perf.zig");

pub const enable_word_size: u8 = @sizeOf(u32);

pub const RegistrationFlags = packed struct(u16) {
    persist: bool = false,
    multi_format: bool = false,
    _reserved: u14 = 0,
};

/// Linux UAPI `struct user_reg`.
pub const UserReg = extern struct {
    size: u32 align(1),
    enable_bit: u8 align(1),
    enable_size: u8 align(1),
    flags: u16 align(1),
    enable_addr: u64 align(1),
    name_args: u64 align(1),
    write_index: u32 align(1),

    pub fn init(
        enable_word: *align(@sizeOf(u32)) u32,
        enable_bit: u5,
        flags: RegistrationFlags,
        name_args: [:0]const u8,
    ) UserReg {
        return .{
            .size = @intCast(@sizeOf(UserReg)),
            .enable_bit = @intCast(enable_bit),
            .enable_size = enable_word_size,
            .flags = @bitCast(flags),
            .enable_addr = @intCast(@intFromPtr(enable_word)),
            .name_args = @intCast(@intFromPtr(name_args.ptr)),
            .write_index = 0,
        };
    }
};

/// Linux UAPI `struct user_unreg`.
pub const UserUnreg = extern struct {
    size: u32 align(1),
    disable_bit: u8 align(1),
    reserved: u8 align(1),
    reserved2: u16 align(1),
    disable_addr: u64 align(1),

    pub fn init(
        enable_word: *align(@sizeOf(u32)) u32,
        disable_bit: u5,
    ) UserUnreg {
        return .{
            .size = @intCast(@sizeOf(UserUnreg)),
            .disable_bit = @intCast(disable_bit),
            .reserved = 0,
            .reserved2 = 0,
            .disable_addr = @intCast(@intFromPtr(enable_word)),
        };
    }
};

// The kernel UAPI intentionally encodes pointer size in these ioctl numbers.
pub const DIAG_IOCSREG = linux.IOCTL.IOWR('*', 0, *UserReg);
pub const DIAG_IOCSDEL = linux.IOCTL.IOW('*', 1, [*:0]const u8);
pub const DIAG_IOCSUNREG = linux.IOCTL.IOW('*', 2, *UserUnreg);

pub fn writeIndexBytes(write_index: u32) [@sizeOf(u32)]u8 {
    return @bitCast(write_index);
}

comptime {
    assertAbi(@sizeOf(UserReg) == 28, "user_reg must be 28 bytes");
    assertAbi(@bitSizeOf(UserReg) == 224, "user_reg must be 224 bits");
    assertAbi(@offsetOf(UserReg, "size") == 0, "invalid user_reg.size offset");
    assertAbi(@offsetOf(UserReg, "enable_bit") == 4, "invalid user_reg.enable_bit offset");
    assertAbi(@offsetOf(UserReg, "enable_size") == 5, "invalid user_reg.enable_size offset");
    assertAbi(@offsetOf(UserReg, "flags") == 6, "invalid user_reg.flags offset");
    assertAbi(@offsetOf(UserReg, "enable_addr") == 8, "invalid user_reg.enable_addr offset");
    assertAbi(@offsetOf(UserReg, "name_args") == 16, "invalid user_reg.name_args offset");
    assertAbi(@offsetOf(UserReg, "write_index") == 24, "invalid user_reg.write_index offset");

    assertAbi(@sizeOf(UserUnreg) == 16, "user_unreg must be 16 bytes");
    assertAbi(@bitSizeOf(UserUnreg) == 128, "user_unreg must be 128 bits");
    assertAbi(@offsetOf(UserUnreg, "size") == 0, "invalid user_unreg.size offset");
    assertAbi(@offsetOf(UserUnreg, "disable_bit") == 4, "invalid user_unreg.disable_bit offset");
    assertAbi(@offsetOf(UserUnreg, "reserved") == 5, "invalid user_unreg.reserved offset");
    assertAbi(@offsetOf(UserUnreg, "reserved2") == 6, "invalid user_unreg.reserved2 offset");
    assertAbi(@offsetOf(UserUnreg, "disable_addr") == 8, "invalid user_unreg.disable_addr offset");

    if (builtin.cpu.arch == .x86_64 and @sizeOf(usize) == 8) {
        assertAbi(DIAG_IOCSREG == 0xc0082a00, "invalid x86_64 DIAG_IOCSREG");
        assertAbi(DIAG_IOCSDEL == 0x40082a01, "invalid x86_64 DIAG_IOCSDEL");
        assertAbi(DIAG_IOCSUNREG == 0x40082a02, "invalid x86_64 DIAG_IOCSUNREG");
    } else if (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) {
        assertAbi(DIAG_IOCSREG == 0xc0042a00, "invalid 32-bit x86 DIAG_IOCSREG");
        assertAbi(DIAG_IOCSDEL == 0x40042a01, "invalid 32-bit x86 DIAG_IOCSDEL");
        assertAbi(DIAG_IOCSUNREG == 0x40042a02, "invalid 32-bit x86 DIAG_IOCSUNREG");
    }
}

fn assertAbi(comptime condition: bool, comptime message: []const u8) void {
    if (!condition) @compileError(message);
}

test "registration structures use the kernel ABI" {
    var enable_word: u32 align(@sizeOf(u32)) = 0;
    const name_args: [:0]const u8 = "zig_test u32 value";

    const reg = UserReg.init(
        &enable_word,
        3,
        .{ .persist = true, .multi_format = true },
        name_args,
    );
    try std.testing.expectEqual(@as(u32, 28), reg.size);
    try std.testing.expectEqual(@as(u8, 3), reg.enable_bit);
    try std.testing.expectEqual(@as(u8, 4), reg.enable_size);
    try std.testing.expectEqual(@as(u16, 3), reg.flags);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&enable_word)), reg.enable_addr);
    try std.testing.expectEqual(@as(u64, @intFromPtr(name_args.ptr)), reg.name_args);

    const unreg = UserUnreg.init(&enable_word, 3);
    try std.testing.expectEqual(@as(u32, 16), unreg.size);
    try std.testing.expectEqual(@as(u8, 3), unreg.disable_bit);
    try std.testing.expectEqual(@as(u64, @intFromPtr(&enable_word)), unreg.disable_addr);
}

test "write index bytes use native endian" {
    const index: u32 = 0x12345678;
    try std.testing.expectEqual(index, @as(u32, @bitCast(writeIndexBytes(index))));
}

test {
    if (@sizeOf(usize) == 8 and
        (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .aarch64) and
        builtin.cpu.arch.endian() == .little)
    {
        _ = perf;
    }
}
