const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const abi = @import("abi/linux.zig");
const tracefs = @import("tracefs.zig");

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

pub const DataFileOpenError = tracefs.OpenError || error{AlreadyOpen};

pub const DataFileCloseError = error{
    EventsStillRegistered,
    InputOutput,
    Interrupted,
    InvalidFileDescriptor,
    NoSpace,
    Unexpected,
};

pub const EventRegisterError = RegisterError || error{
    DataFileClosed,
    EventAlreadyRegistered,
};

pub const EventUnregisterError = UnregisterError || error{DataFileClosed};

pub const EventWriteError = WriteError || error{
    DataFileClosed,
    EventNotRegistered,
};

const max_name_args_len = 511;
const rawRegister = register;
const rawUnregister = unregister;

/// Owns a `user_events_data` descriptor.
///
/// Initialize in its final storage and do not copy after opening. `close`
/// refuses to release the descriptor until every associated event unregisters.
pub const DataFile = struct {
    fd: ?linux.fd_t = null,
    registration_count: u32 = 0,

    pub fn open(self: *DataFile) DataFileOpenError!void {
        if (self.fd != null) return error.AlreadyOpen;
        self.fd = try tracefs.openUserEventsData();
    }

    pub fn openPath(self: *DataFile, path: [:0]const u8) DataFileOpenError!void {
        if (self.fd != null) return error.AlreadyOpen;
        self.fd = try tracefs.openUserEventsDataAt(path);
    }

    pub fn close(self: *DataFile) DataFileCloseError!void {
        return self.closeWith(linux.close);
    }

    pub fn isOpen(self: *const DataFile) bool {
        return self.fd != null;
    }

    pub fn registeredEventCount(self: *const DataFile) u32 {
        return self.registration_count;
    }

    fn closeWith(self: *DataFile, comptime closeFn: anytype) DataFileCloseError!void {
        if (self.registration_count != 0) return error.EventsStillRegistered;
        const fd = self.fd orelse return;

        // Linux releases the descriptor even when close reports an error.
        self.fd = null;
        switch (linux.errno(closeFn(fd))) {
            .SUCCESS => return,
            .INTR => return error.Interrupted,
            .IO => return error.InputOutput,
            .NOSPC, .DQUOT => return error.NoSpace,
            .BADF => return error.InvalidFileDescriptor,
            else => return error.Unexpected,
        }
    }
};

/// A registration tied to one `DataFile` and one stable caller-owned enable word.
///
/// The event and its `DataFile` must not be copied while registered. Teardown
/// must not race writers until a later synchronized lifecycle layer is added.
pub const Event = struct {
    data_file: ?*DataFile = null,
    enable_word: ?*align(@sizeOf(u32)) u32 = null,
    enable_bit: u5 = 0,
    write_index: u32 = 0,

    pub fn register(
        self: *Event,
        data_file: *DataFile,
        enable_word: *align(@sizeOf(u32)) u32,
        enable_bit: u5,
        flags: abi.RegistrationFlags,
        name_args: [:0]const u8,
    ) EventRegisterError!void {
        return self.registerWith(
            data_file,
            enable_word,
            enable_bit,
            flags,
            name_args,
            rawRegister,
        );
    }

    pub fn unregister(self: *Event) EventUnregisterError!void {
        return self.unregisterWith(rawUnregister);
    }

    pub fn write(self: *const Event, payload: []const u8) EventWriteError!WriteOutcome {
        const data_file = self.data_file orelse return error.EventNotRegistered;
        const enable_word = self.enable_word orelse return error.EventNotRegistered;
        const fd = data_file.fd orelse return error.DataFileClosed;
        return userEventWrite(fd, self.write_index, enable_word, self.enable_bit, payload);
    }

    pub fn isRegistered(self: *const Event) bool {
        return self.data_file != null;
    }

    pub fn isEnabled(self: *const Event) bool {
        const enable_word = self.enable_word orelse return false;
        return userEventIsEnabled(enable_word, self.enable_bit);
    }

    fn registerWith(
        self: *Event,
        data_file: *DataFile,
        enable_word: *align(@sizeOf(u32)) u32,
        enable_bit: u5,
        flags: abi.RegistrationFlags,
        name_args: [:0]const u8,
        comptime registerFn: anytype,
    ) EventRegisterError!void {
        if (self.data_file != null) return error.EventAlreadyRegistered;
        const fd = data_file.fd orelse return error.DataFileClosed;
        if (data_file.registration_count == std.math.maxInt(u32)) {
            return error.SystemResources;
        }

        const write_index = try registerFn(
            fd,
            enable_word,
            enable_bit,
            flags,
            name_args,
        );

        self.data_file = data_file;
        self.enable_word = enable_word;
        self.enable_bit = enable_bit;
        self.write_index = write_index;
        data_file.registration_count += 1;
    }

    fn unregisterWith(
        self: *Event,
        comptime unregisterFn: anytype,
    ) EventUnregisterError!void {
        const data_file = self.data_file orelse return;
        const enable_word = self.enable_word.?;
        const fd = data_file.fd orelse return error.DataFileClosed;

        unregisterFn(fd, enable_word, self.enable_bit) catch |err| switch (err) {
            error.NotRegistered => {},
            else => return err,
        };

        const mask = @as(u32, 1) << self.enable_bit;
        _ = @atomicRmw(u32, enable_word, .And, ~mask, .monotonic);
        std.debug.assert(data_file.registration_count != 0);
        data_file.registration_count -= 1;
        self.* = .{};
    }
};

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

const userEventIsEnabled = isEnabled;

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

const userEventWrite = write;

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

test "data file close is idempotent and refuses active registrations" {
    const FakeClose = struct {
        var calls: usize = 0;
        var result: usize = 0;

        fn call(_: linux.fd_t) usize {
            calls += 1;
            return result;
        }
    };

    var data_file: DataFile = .{
        .fd = 10,
        .registration_count = 1,
    };
    FakeClose.calls = 0;
    FakeClose.result = 0;

    try std.testing.expectError(
        error.EventsStillRegistered,
        data_file.closeWith(FakeClose.call),
    );
    try std.testing.expectEqual(@as(usize, 0), FakeClose.calls);
    try std.testing.expect(data_file.isOpen());

    data_file.registration_count = 0;
    try data_file.closeWith(FakeClose.call);
    try data_file.closeWith(FakeClose.call);
    try std.testing.expectEqual(@as(usize, 1), FakeClose.calls);
    try std.testing.expect(!data_file.isOpen());
}

test "event lifecycle commits and releases registration state" {
    const Fake = struct {
        var register_error: ?RegisterError = null;
        var unregister_error: ?UnregisterError = null;
        var unregister_calls: usize = 0;

        fn registerCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
            _: abi.RegistrationFlags,
            _: [:0]const u8,
        ) RegisterError!u32 {
            if (register_error) |err| return err;
            return 37;
        }

        fn unregisterCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
        ) UnregisterError!void {
            unregister_calls += 1;
            if (unregister_error) |err| return err;
        }
    };

    var data_file: DataFile = .{ .fd = 10 };
    var enable_word: u32 align(@sizeOf(u32)) = 0;
    var event: Event = .{};
    Fake.register_error = null;
    Fake.unregister_error = null;
    Fake.unregister_calls = 0;

    try event.registerWith(
        &data_file,
        &enable_word,
        3,
        .{},
        "zig_lifecycle u32 value",
        Fake.registerCall,
    );
    try std.testing.expect(event.isRegistered());
    try std.testing.expectEqual(@as(u32, 1), data_file.registeredEventCount());
    try std.testing.expectEqual(@as(u32, 37), event.write_index);
    try std.testing.expectEqual(
        WriteOutcome.disabled,
        try event.write("payload"),
    );

    @atomicStore(
        u32,
        &enable_word,
        (@as(u32, 1) << 3) | (@as(u32, 1) << 5),
        .monotonic,
    );
    try event.unregisterWith(Fake.unregisterCall);
    try event.unregisterWith(Fake.unregisterCall);
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());
    try std.testing.expectEqual(@as(usize, 1), Fake.unregister_calls);
    try std.testing.expectEqual(
        @as(u32, 1) << 5,
        @atomicLoad(u32, &enable_word, .monotonic),
    );
}

test "event lifecycle preserves state after syscall failures" {
    const Fake = struct {
        var register_error: ?RegisterError = null;
        var unregister_error: ?UnregisterError = null;

        fn registerCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
            _: abi.RegistrationFlags,
            _: [:0]const u8,
        ) RegisterError!u32 {
            if (register_error) |err| return err;
            return 12;
        }

        fn unregisterCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
        ) UnregisterError!void {
            if (unregister_error) |err| return err;
        }
    };

    var data_file: DataFile = .{ .fd = 10 };
    var enable_word: u32 align(@sizeOf(u32)) = 0;
    var event: Event = .{};

    Fake.register_error = error.PermissionDenied;
    try std.testing.expectError(
        error.PermissionDenied,
        event.registerWith(
            &data_file,
            &enable_word,
            0,
            .{},
            "zig_failure",
            Fake.registerCall,
        ),
    );
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());

    Fake.register_error = null;
    try event.registerWith(
        &data_file,
        &enable_word,
        0,
        .{},
        "zig_failure",
        Fake.registerCall,
    );
    Fake.unregister_error = error.PermissionDenied;
    try std.testing.expectError(
        error.PermissionDenied,
        event.unregisterWith(Fake.unregisterCall),
    );
    try std.testing.expect(event.isRegistered());
    try std.testing.expectEqual(@as(u32, 1), data_file.registeredEventCount());

    Fake.unregister_error = error.NotRegistered;
    try event.unregisterWith(Fake.unregisterCall);
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());
}

fn errnoResult(err: linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(err))));
}
