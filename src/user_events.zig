const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const abi = @import("abi/linux.zig");

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("linux_tracepoints supports Linux targets only");
    }
}

pub const RegisterError = error{
    AlreadyRegistered,
    DescriptionTooLong,
    InvalidArgument,
    InvalidFileDescriptor,
    PermissionDenied,
    SystemResources,
    Unexpected,
    UserEventsUnavailable,
};

pub const UnregisterError = error{
    InvalidArgument,
    InvalidFileDescriptor,
    NotRegistered,
    PermissionDenied,
    Unexpected,
};

pub const DeleteError = error{
    EventBusy,
    EventNotFound,
    InvalidArgument,
    InvalidFileDescriptor,
    NameTooLong,
    PermissionDenied,
    Unexpected,
};

pub const WriteError = error{
    DisabledOrInvalidFileDescriptor,
    InvalidArgument,
    InvalidMemory,
    NotRegistered,
    PayloadTooLarge,
    ShortWrite,
    SystemResources,
    Unexpected,
    WouldBlock,
};

pub const WriteOutcome = enum {
    disabled,
    written,
};

const max_name_args_len = 511;

pub fn register(
    fd: linux.fd_t,
    enable_word: *align(@sizeOf(u32)) u32,
    enable_bit: u5,
    flags: abi.RegistrationFlags,
    name_args: [:0]const u8,
) RegisterError!u32 {
    if (name_args.len > max_name_args_len) return error.DescriptionTooLong;

    var registration: abi.UserReg align(8) = .init(
        enable_word,
        enable_bit,
        flags,
        name_args,
    );

    while (true) {
        const result = linux.ioctl(fd, abi.DIAG_IOCSREG, @intFromPtr(&registration));
        switch (linux.errno(result)) {
            .SUCCESS => return registration.write_index,
            .INTR => continue,
            .PERM, .ACCES => return error.PermissionDenied,
            .@"2BIG" => return error.DescriptionTooLong,
            .INVAL => return error.InvalidArgument,
            .BADF => return error.InvalidFileDescriptor,
            .ADDRINUSE => return error.AlreadyRegistered,
            .MFILE, .NOMEM, .NOSPC => return error.SystemResources,
            .NOTTY => return error.UserEventsUnavailable,
            else => return error.Unexpected,
        }
    }
}

pub fn unregister(
    fd: linux.fd_t,
    enable_word: *align(@sizeOf(u32)) u32,
    disable_bit: u5,
) UnregisterError!void {
    var registration: abi.UserUnreg align(8) = .init(enable_word, disable_bit);

    while (true) {
        const result = linux.ioctl(fd, abi.DIAG_IOCSUNREG, @intFromPtr(&registration));
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INTR => continue,
            .PERM, .ACCES => return error.PermissionDenied,
            .INVAL => return error.InvalidArgument,
            .BADF => return error.InvalidFileDescriptor,
            .NOENT => return error.NotRegistered,
            else => return error.Unexpected,
        }
    }
}

pub fn delete(fd: linux.fd_t, name: [:0]const u8) DeleteError!void {
    if (name.len > max_name_args_len) return error.NameTooLong;

    while (true) {
        const result = linux.ioctl(fd, abi.DIAG_IOCSDEL, @intFromPtr(name.ptr));
        switch (linux.errno(result)) {
            .SUCCESS => return,
            .INTR => continue,
            .PERM, .ACCES => return error.PermissionDenied,
            .@"2BIG" => return error.NameTooLong,
            .INVAL => return error.InvalidArgument,
            .BADF => return error.InvalidFileDescriptor,
            .BUSY => return error.EventBusy,
            .NOENT => return error.EventNotFound,
            else => return error.Unexpected,
        }
    }
}

pub fn isEnabled(
    enable_word: *align(@sizeOf(u32)) const u32,
    enable_bit: u5,
) bool {
    const mask = @as(u32, 1) << enable_bit;
    return (@atomicLoad(u32, enable_word, .monotonic) & mask) != 0;
}

pub fn write(
    fd: linux.fd_t,
    write_index: u32,
    enable_word: *align(@sizeOf(u32)) const u32,
    enable_bit: u5,
    payload: []const u8,
) WriteError!WriteOutcome {
    if (!isEnabled(enable_word, enable_bit)) return .disabled;
    writeEnabled(fd, write_index, payload) catch |err| switch (err) {
        error.DisabledOrInvalidFileDescriptor => {
            if (!isEnabled(enable_word, enable_bit)) return .disabled;
            return err;
        },
        else => return err,
    };
    return .written;
}

pub fn writeEnabled(
    fd: linux.fd_t,
    write_index: u32,
    payload: []const u8,
) WriteError!void {
    return writeEnabledWith(fd, write_index, payload, linux.writev);
}

fn writeEnabledWith(
    fd: linux.fd_t,
    write_index: u32,
    payload: []const u8,
    comptime writevFn: anytype,
) WriteError!void {
    if (payload.len > std.math.maxInt(usize) - @sizeOf(u32)) {
        return error.PayloadTooLarge;
    }

    var index = write_index;
    const vectors = [_]std.posix.iovec_const{
        .{
            .base = std.mem.asBytes(&index).ptr,
            .len = @sizeOf(u32),
        },
        .{
            .base = payload.ptr,
            .len = payload.len,
        },
    };
    const expected = @sizeOf(u32) + payload.len;

    while (true) {
        const result = writevFn(fd, &vectors, vectors.len);
        switch (linux.errno(result)) {
            .SUCCESS => {
                if (result != expected) return error.ShortWrite;
                return;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .BADF => return error.DisabledOrInvalidFileDescriptor,
            .NOENT => return error.NotRegistered,
            .INVAL => return error.InvalidArgument,
            .FAULT => return error.InvalidMemory,
            .NOMEM, .NOBUFS => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

test "enabled check selects the requested bit" {
    var enable_word: u32 align(@sizeOf(u32)) = 0;
    try std.testing.expect(!isEnabled(&enable_word, 5));

    @atomicStore(u32, &enable_word, @as(u32, 1) << 5, .monotonic);
    try std.testing.expect(isEnabled(&enable_word, 5));
    try std.testing.expect(!isEnabled(&enable_word, 4));
}

test "writev framing starts with the native-endian index" {
    const FakeWritev = struct {
        var calls: usize = 0;
        var observed_index: u32 = 0;
        var observed_payload: [16]u8 = undefined;
        var observed_payload_len: usize = 0;
        var result: usize = 0;

        fn call(
            _: linux.fd_t,
            vectors: [*]const std.posix.iovec_const,
            count: usize,
        ) usize {
            calls += 1;
            std.debug.assert(count == 2);
            std.debug.assert(vectors[0].len == @sizeOf(u32));

            var index_bytes: [@sizeOf(u32)]u8 = undefined;
            @memcpy(&index_bytes, vectors[0].base[0..vectors[0].len]);
            observed_index = @bitCast(index_bytes);

            observed_payload_len = vectors[1].len;
            @memcpy(
                observed_payload[0..observed_payload_len],
                vectors[1].base[0..vectors[1].len],
            );
            return result;
        }
    };

    const payload = "abc";
    FakeWritev.calls = 0;
    FakeWritev.result = @sizeOf(u32) + payload.len;

    try writeEnabledWith(10, 0x12345678, payload, FakeWritev.call);
    try std.testing.expectEqual(@as(usize, 1), FakeWritev.calls);
    try std.testing.expectEqual(@as(u32, 0x12345678), FakeWritev.observed_index);
    try std.testing.expectEqualStrings(
        payload,
        FakeWritev.observed_payload[0..FakeWritev.observed_payload_len],
    );
}

test "writev reports short writes and disabled races" {
    const FakeWritev = struct {
        var result: usize = 0;

        fn call(
            _: linux.fd_t,
            _: [*]const std.posix.iovec_const,
            _: usize,
        ) usize {
            return result;
        }
    };

    FakeWritev.result = 1;
    try std.testing.expectError(
        error.ShortWrite,
        writeEnabledWith(10, 1, "abc", FakeWritev.call),
    );

    FakeWritev.result = errnoResult(.BADF);
    try std.testing.expectError(
        error.DisabledOrInvalidFileDescriptor,
        writeEnabledWith(10, 1, "abc", FakeWritev.call),
    );
}

fn errnoResult(err: linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(err))));
}
