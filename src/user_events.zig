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
const closed_fd: linux.fd_t = -1;
const writer_closing: u32 = @as(u32, 1) << 31;
const writer_count_mask: u32 = writer_closing - 1;
const rawRegister = register;
const rawUnregister = unregister;

const LinuxFutex = struct {
    fn wait(ptr: *align(@alignOf(u32)) const u32, expected: u32) void {
        while (true) {
            switch (linux.errno(linux.futex_4arg(
                ptr,
                .{ .cmd = .WAIT, .private = true },
                expected,
                null,
            ))) {
                .SUCCESS, .AGAIN => return,
                .INTR => continue,
                else => unreachable,
            }
        }
    }

    fn wake(ptr: *align(@alignOf(u32)) const u32, max_waiters: u32) void {
        switch (linux.errno(linux.futex_4arg(
            ptr,
            .{ .cmd = .WAKE, .private = true },
            max_waiters,
            null,
        ))) {
            .SUCCESS => {},
            else => unreachable,
        }
    }
};

// Zig 0.16's current std.Thread exposes its futex only internally. Keep the
// synchronization primitive isolated so it can use std.Thread.Futex when that
// public API is restored without changing lifecycle code.
const Futex = LinuxFutex;

const LifecycleLock = struct {
    state: std.atomic.Value(u32) = .init(0),

    fn lock(self: *LifecycleLock) void {
        if (self.state.cmpxchgStrong(0, 1, .acquire, .monotonic) == null) return;
        self.lockSlow();
    }

    fn lockSlow(self: *LifecycleLock) void {
        while (self.state.swap(2, .acquire) != 0) {
            Futex.wait(&self.state.raw, 2);
        }
    }

    fn unlock(self: *LifecycleLock) void {
        const previous = self.state.swap(0, .release);
        std.debug.assert(previous != 0);
        if (previous == 2) Futex.wake(&self.state.raw, 1);
    }
};

/// Owns a `user_events_data` descriptor.
///
/// An opened value is noncopyable and address-stable. Zig cannot enforce
/// move-only semantics, so initialize it in its final storage and do not copy
/// it after `open` succeeds. `close` refuses to release the descriptor until
/// every associated event unregisters.
pub const DataFile = struct {
    fd: std.atomic.Value(linux.fd_t) = .init(closed_fd),
    registration_count: u32 = 0,
    lifecycle_lock: LifecycleLock = .{},

    pub fn open(self: *DataFile) DataFileOpenError!void {
        self.lifecycle_lock.lock();
        defer self.lifecycle_lock.unlock();

        if (self.fd.load(.acquire) != closed_fd) return error.AlreadyOpen;
        self.fd.store(try tracefs.openUserEventsData(), .release);
    }

    pub fn openPath(self: *DataFile, path: [:0]const u8) DataFileOpenError!void {
        self.lifecycle_lock.lock();
        defer self.lifecycle_lock.unlock();

        if (self.fd.load(.acquire) != closed_fd) return error.AlreadyOpen;
        self.fd.store(try tracefs.openUserEventsDataAt(path), .release);
    }

    pub fn close(self: *DataFile) DataFileCloseError!void {
        return self.closeWith(linux.close);
    }

    pub fn isOpen(self: *const DataFile) bool {
        return self.fd.load(.acquire) != closed_fd;
    }

    pub fn registeredEventCount(self: *const DataFile) u32 {
        const mutable: *DataFile = @constCast(self);
        mutable.lifecycle_lock.lock();
        defer mutable.lifecycle_lock.unlock();
        return self.registration_count;
    }

    fn closeWith(self: *DataFile, comptime closeFn: anytype) DataFileCloseError!void {
        self.lifecycle_lock.lock();
        defer self.lifecycle_lock.unlock();

        if (self.registration_count != 0) return error.EventsStillRegistered;
        const fd = self.fd.load(.acquire);
        if (fd == closed_fd) return;

        // Publish closure before entering the kernel. Linux releases the
        // descriptor even when close reports an error.
        self.fd.store(closed_fd, .release);
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

/// A managed registration tied to one `DataFile`.
///
/// A registered value is noncopyable and address-stable. Zig cannot enforce
/// move-only semantics: initialize it in its final storage and do not copy it
/// while registered. The aligned enable word is owned by the event so the
/// kernel pointer remains valid for the complete registration lifetime.
pub const Event = struct {
    data_file: ?*DataFile = null,
    enable_word: u32 align(@sizeOf(u32)) = 0,
    enable_bit: std.atomic.Value(u32) = .init(0),
    write_index: u32 = 0,
    registered: std.atomic.Value(bool) = .init(false),
    writer_state: std.atomic.Value(u32) = .init(writer_closing),
    lifecycle_lock: LifecycleLock = .{},

    pub fn register(
        self: *Event,
        data_file: *DataFile,
        enable_bit: u5,
        flags: abi.RegistrationFlags,
        name_args: [:0]const u8,
    ) EventRegisterError!void {
        return self.registerWith(
            data_file,
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
        return self.writeWith(payload, linux.writev);
    }

    pub fn writeTyped(
        self: *const Event,
        payload: anytype,
    ) EventWriteError!WriteOutcome {
        const Payload = payloadPointerChild(@TypeOf(payload));
        comptime validatePayload(Payload);
        return self.writeTypedWith(Payload, payload, linux.writev);
    }

    pub fn isRegistered(self: *const Event) bool {
        return self.registered.load(.acquire);
    }

    pub fn isEnabled(self: *const Event) bool {
        return userEventIsEnabled(&self.enable_word, self.currentEnableBit());
    }

    fn registerWith(
        self: *Event,
        data_file: *DataFile,
        enable_bit: u5,
        flags: abi.RegistrationFlags,
        name_args: [:0]const u8,
        comptime registerFn: anytype,
    ) EventRegisterError!void {
        // Lock ordering is always Event, then DataFile.
        self.lifecycle_lock.lock();
        defer self.lifecycle_lock.unlock();
        data_file.lifecycle_lock.lock();
        defer data_file.lifecycle_lock.unlock();

        if (self.registered.load(.acquire)) return error.EventAlreadyRegistered;
        const fd = data_file.fd.load(.acquire);
        if (fd == closed_fd) return error.DataFileClosed;
        if (data_file.registration_count == std.math.maxInt(u32)) {
            return error.SystemResources;
        }

        @atomicStore(u32, &self.enable_word, 0, .monotonic);
        const write_index = try registerFn(
            fd,
            &self.enable_word,
            enable_bit,
            flags,
            name_args,
        );

        self.data_file = data_file;
        self.enable_bit.store(enable_bit, .release);
        self.write_index = write_index;
        data_file.registration_count += 1;
        self.registered.store(true, .release);
        self.writer_state.store(0, .release);
    }

    fn unregisterWith(
        self: *Event,
        comptime unregisterFn: anytype,
    ) EventUnregisterError!void {
        // Lock ordering is always Event, then DataFile.
        self.lifecycle_lock.lock();
        defer self.lifecycle_lock.unlock();
        if (!self.registered.load(.acquire)) return;

        const data_file = self.data_file.?;
        data_file.lifecycle_lock.lock();
        defer data_file.lifecycle_lock.unlock();
        const fd = data_file.fd.load(.acquire);
        if (fd == closed_fd) return error.DataFileClosed;

        self.sealAndDrainWriters();
        unregisterFn(fd, &self.enable_word, self.currentEnableBit()) catch |err| switch (err) {
            error.NotRegistered => {},
            else => {
                self.writer_state.store(0, .release);
                return err;
            },
        };

        @atomicStore(u32, &self.enable_word, 0, .monotonic);
        std.debug.assert(data_file.registration_count != 0);
        data_file.registration_count -= 1;
        self.registered.store(false, .release);
        self.data_file = null;
        self.write_index = 0;
    }

    fn writeWith(
        self: *const Event,
        payload: []const u8,
        comptime writevFn: anytype,
    ) EventWriteError!WriteOutcome {
        const enable_bit = self.currentEnableBit();
        if (!userEventIsEnabled(&self.enable_word, enable_bit)) return .disabled;
        try self.enterWriter();
        defer self.leaveWriter();

        const data_file = self.data_file orelse return error.EventNotRegistered;
        const fd = data_file.fd.load(.acquire);
        if (fd == closed_fd) return error.DataFileClosed;
        writeEnabledWith(fd, self.write_index, payload, writevFn) catch |err| switch (err) {
            error.DisabledOrInvalidFileDescriptor => {
                if (!userEventIsEnabled(&self.enable_word, enable_bit)) return .disabled;
                return err;
            },
            else => return err,
        };
        return .written;
    }

    fn writeTypedWith(
        self: *const Event,
        comptime Payload: type,
        payload: *const Payload,
        comptime writevFn: anytype,
    ) EventWriteError!WriteOutcome {
        const enable_bit = self.currentEnableBit();
        if (!userEventIsEnabled(&self.enable_word, enable_bit)) return .disabled;
        try self.enterWriter();
        defer self.leaveWriter();

        const data_file = self.data_file orelse return error.EventNotRegistered;
        const fd = data_file.fd.load(.acquire);
        if (fd == closed_fd) return error.DataFileClosed;
        writeTypedEnabledWith(fd, self.write_index, Payload, payload, writevFn) catch |err| switch (err) {
            error.DisabledOrInvalidFileDescriptor => {
                if (!userEventIsEnabled(&self.enable_word, enable_bit)) return .disabled;
                return err;
            },
            else => return err,
        };
        return .written;
    }

    fn enterWriter(self: *const Event) EventWriteError!void {
        const mutable: *Event = @constCast(self);
        var state = mutable.writer_state.load(.monotonic);
        while (true) {
            if ((state & writer_closing) != 0) return error.EventNotRegistered;
            if ((state & writer_count_mask) == writer_count_mask) {
                return error.SystemResources;
            }
            state = mutable.writer_state.cmpxchgWeak(
                state,
                state + 1,
                .acquire,
                .monotonic,
            ) orelse return;
        }
    }

    fn leaveWriter(self: *const Event) void {
        const mutable: *Event = @constCast(self);
        const previous = mutable.writer_state.fetchSub(1, .release);
        std.debug.assert((previous & writer_count_mask) != 0);
        if (previous == writer_closing | 1) {
            Futex.wake(&mutable.writer_state.raw, 1);
        }
    }

    fn sealAndDrainWriters(self: *Event) void {
        var state = self.writer_state.fetchOr(writer_closing, .acq_rel) | writer_closing;
        while ((state & writer_count_mask) != 0) {
            Futex.wait(&self.writer_state.raw, state);
            state = self.writer_state.load(.acquire);
        }
    }

    fn currentEnableBit(self: *const Event) u5 {
        return @intCast(self.enable_bit.load(.acquire));
    }
};

/// Builds a validated, allocation-free writer for a fixed raw user-event
/// payload. Raw descriptor methods taking an fd are unmanaged: the caller must
/// synchronize descriptor and registration lifetime. `writeEvent` uses the
/// managed `Event` writer gate.
pub fn RawDescriptor(
    comptime name_args: [:0]const u8,
    comptime Payload: type,
) type {
    comptime {
        if (name_args.len > max_name_args_len) {
            @compileError("raw event name and arguments exceed the kernel limit");
        }
        validatePayload(Payload);
    }

    return struct {
        pub const payload_type = Payload;
        pub const registration_name_args = name_args;

        pub fn registerEvent(
            event: *Event,
            data_file: *DataFile,
            enable_bit: u5,
            flags: abi.RegistrationFlags,
        ) EventRegisterError!void {
            return event.register(data_file, enable_bit, flags, name_args);
        }

        pub fn writeEvent(
            event: *const Event,
            payload: *const Payload,
        ) EventWriteError!WriteOutcome {
            return event.writeTyped(payload);
        }

        /// Unmanaged raw write. The caller owns all fd and registration
        /// synchronization.
        pub fn write(
            fd: linux.fd_t,
            write_index: u32,
            enable_word: *align(@sizeOf(u32)) const u32,
            enable_bit: u5,
            payload: *const Payload,
        ) WriteError!WriteOutcome {
            if (!isEnabled(enable_word, enable_bit)) return .disabled;
            writeTypedEnabled(fd, write_index, payload) catch |err| switch (err) {
                error.DisabledOrInvalidFileDescriptor => {
                    if (!isEnabled(enable_word, enable_bit)) return .disabled;
                    return err;
                },
                else => return err,
            };
            return .written;
        }

        /// Unmanaged raw write which skips the kernel enable-word check.
        pub fn writeEnabled(
            fd: linux.fd_t,
            write_index: u32,
            payload: *const Payload,
        ) WriteError!void {
            return writeTypedEnabled(fd, write_index, payload);
        }
    };
}

fn payloadPointerChild(comptime Pointer: type) type {
    return switch (@typeInfo(Pointer)) {
        .pointer => |pointer| if (pointer.size == .one)
            pointer.child
        else
            @compileError("typed payload must be passed by single-item pointer"),
        else => @compileError("typed payload must be passed by pointer"),
    };
}

fn validatePayload(comptime Payload: type) void {
    const info = switch (@typeInfo(Payload)) {
        .@"struct" => |info| info,
        else => @compileError("raw payload must be an extern struct"),
    };
    if (info.layout != .@"extern") {
        @compileError("raw payload must be an extern struct");
    }

    var expected_offset: usize = 0;
    inline for (info.fields) |field| {
        validatePayloadElement(field.type);
        if (@offsetOf(Payload, field.name) != expected_offset) {
            @compileError("raw payload has inter-field padding");
        }
        expected_offset += @sizeOf(field.type);
    }
    if (@sizeOf(Payload) != expected_offset) {
        @compileError("raw payload has tail padding");
    }
}

fn validatePayloadElement(comptime Element: type) void {
    switch (@typeInfo(Element)) {
        .int => |integer| {
            if (Element == usize or Element == isize or
                integer.bits == 0 or
                integer.bits % 8 != 0 or
                @sizeOf(Element) * 8 != integer.bits)
            {
                @compileError(
                    "raw payload integers must have a byte-complete fixed-width representation",
                );
            }
        },
        .array => |array| validatePayloadElement(array.child),
        .@"struct" => validatePayload(Element),
        else => @compileError(
            "raw payload fields must be fixed-width integers, fixed arrays, or nested extern structs",
        ),
    }
}

/// Unmanaged raw registration. The caller owns enable-word, descriptor, and
/// concurrent lifecycle synchronization.
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

/// Unmanaged raw unregister. The caller owns enable-word, descriptor, and
/// concurrent lifecycle synchronization.
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

/// Unmanaged raw delete operation. The caller owns descriptor synchronization.
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

/// Unmanaged raw enabled check. The caller owns enable-word lifetime.
pub fn isEnabled(
    enable_word: *align(@sizeOf(u32)) const u32,
    enable_bit: u5,
) bool {
    const mask = @as(u32, 1) << enable_bit;
    return (@atomicLoad(u32, enable_word, .monotonic) & mask) != 0;
}

const userEventIsEnabled = isEnabled;

/// Unmanaged raw byte-slice write. The caller owns fd, registration, and
/// enable-word lifetime synchronization.
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

/// Unmanaged raw byte-slice write which skips the enable-word check.
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

fn writeTypedEnabled(
    fd: linux.fd_t,
    write_index: u32,
    payload: anytype,
) WriteError!void {
    const Payload = payloadPointerChild(@TypeOf(payload));
    comptime validatePayload(Payload);
    return writeTypedEnabledWith(fd, write_index, Payload, payload, linux.writev);
}

fn writeTypedEnabledWith(
    fd: linux.fd_t,
    write_index: u32,
    comptime Payload: type,
    payload: *const Payload,
    comptime writevFn: anytype,
) WriteError!void {
    var index = write_index;
    const vectors = [_]std.posix.iovec_const{
        .{
            .base = std.mem.asBytes(&index).ptr,
            .len = @sizeOf(u32),
        },
        .{
            .base = @ptrCast(payload),
            .len = @sizeOf(Payload),
        },
    };
    const expected = @sizeOf(u32) + @sizeOf(Payload);

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

test "typed payload validation and exact two-iovec framing" {
    const Nested = extern struct {
        bytes: [2]u8,
    };
    const Payload = extern struct {
        value: u32,
        nested: [2]Nested,
    };
    const Descriptor = RawDescriptor(
        "zig_typed u32 value; u8 bytes[4]",
        Payload,
    );
    _ = Descriptor;

    const FakeWritev = struct {
        var calls: usize = 0;
        var payload_address: usize = 0;
        var payload_length: usize = 0;
        var index: u32 = 0;

        fn call(
            _: linux.fd_t,
            vectors: [*]const std.posix.iovec_const,
            count: usize,
        ) usize {
            calls += 1;
            std.debug.assert(count == 2);
            std.debug.assert(vectors[0].len == @sizeOf(u32));
            index = @bitCast(vectors[0].base[0..@sizeOf(u32)].*);
            payload_address = @intFromPtr(vectors[1].base);
            payload_length = vectors[1].len;
            return vectors[0].len + vectors[1].len;
        }
    };

    var payload: Payload = .{
        .value = 0x12345678,
        .nested = .{
            .{ .bytes = .{ 1, 2 } },
            .{ .bytes = .{ 3, 4 } },
        },
    };
    FakeWritev.calls = 0;
    try writeTypedEnabledWith(7, 29, Payload, &payload, FakeWritev.call);
    try std.testing.expectEqual(@as(usize, 1), FakeWritev.calls);
    try std.testing.expectEqual(@as(u32, 29), FakeWritev.index);
    try std.testing.expectEqual(@intFromPtr(&payload), FakeWritev.payload_address);
    try std.testing.expectEqual(@sizeOf(Payload), FakeWritev.payload_length);
}

test "disabled managed typed write does not invoke writev" {
    const Payload = extern struct {
        value: u32,
    };
    const FakeWritev = struct {
        var calls: usize = 0;

        fn call(
            _: linux.fd_t,
            _: [*]const std.posix.iovec_const,
            _: usize,
        ) usize {
            calls += 1;
            return 0;
        }
    };

    var event: Event = .{};
    var payload: Payload = .{ .value = 1 };
    FakeWritev.calls = 0;
    try std.testing.expectEqual(
        WriteOutcome.disabled,
        try event.writeTypedWith(Payload, &payload, FakeWritev.call),
    );
    try std.testing.expectEqual(@as(usize, 0), FakeWritev.calls);
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
        .fd = .init(10),
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
        var registered_enable_address: usize = 0;

        fn registerCall(
            _: linux.fd_t,
            enable_word: *align(@sizeOf(u32)) u32,
            _: u5,
            _: abi.RegistrationFlags,
            _: [:0]const u8,
        ) RegisterError!u32 {
            if (register_error) |err| return err;
            registered_enable_address = @intFromPtr(enable_word);
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

    var data_file: DataFile = .{ .fd = .init(10) };
    var event: Event = .{};
    Fake.register_error = null;
    Fake.unregister_error = null;
    Fake.unregister_calls = 0;
    Fake.registered_enable_address = 0;

    try event.registerWith(
        &data_file,
        3,
        .{},
        "zig_lifecycle u32 value",
        Fake.registerCall,
    );
    try std.testing.expect(event.isRegistered());
    try std.testing.expectEqual(
        @intFromPtr(&event.enable_word),
        Fake.registered_enable_address,
    );
    try std.testing.expectEqual(@as(u32, 1), data_file.registeredEventCount());
    try std.testing.expectEqual(@as(u32, 37), event.write_index);
    try std.testing.expectEqual(
        WriteOutcome.disabled,
        try event.write("payload"),
    );

    @atomicStore(
        u32,
        &event.enable_word,
        (@as(u32, 1) << 3) | (@as(u32, 1) << 5),
        .monotonic,
    );
    try event.unregisterWith(Fake.unregisterCall);
    try event.unregisterWith(Fake.unregisterCall);
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());
    try std.testing.expectEqual(@as(usize, 1), Fake.unregister_calls);
    try std.testing.expectEqual(
        @as(u32, 0),
        @atomicLoad(u32, &event.enable_word, .monotonic),
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

    var data_file: DataFile = .{ .fd = .init(10) };
    var event: Event = .{};

    Fake.register_error = error.PermissionDenied;
    try std.testing.expectError(
        error.PermissionDenied,
        event.registerWith(
            &data_file,
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
        0,
        .{},
        "zig_failure",
        Fake.registerCall,
    );
    Fake.unregister_error = error.PermissionDenied;
    @atomicStore(u32, &event.enable_word, 1, .release);
    try std.testing.expectError(
        error.PermissionDenied,
        event.unregisterWith(Fake.unregisterCall),
    );
    try std.testing.expect(event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), event.writer_state.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), data_file.registeredEventCount());

    const FakeWritev = struct {
        var calls: usize = 0;

        fn call(
            _: linux.fd_t,
            vectors: [*]const std.posix.iovec_const,
            _: usize,
        ) usize {
            calls += 1;
            return vectors[0].len + vectors[1].len;
        }
    };
    FakeWritev.calls = 0;
    try std.testing.expectEqual(
        WriteOutcome.written,
        try event.writeWith("still open", FakeWritev.call),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeWritev.calls);

    Fake.unregister_error = error.NotRegistered;
    try event.unregisterWith(Fake.unregisterCall);
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());
}

test "close is blocked by multiple shared registrations" {
    const Fake = struct {
        var next_index: u32 = 1;
        var close_calls: usize = 0;

        fn registerCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
            _: abi.RegistrationFlags,
            _: [:0]const u8,
        ) RegisterError!u32 {
            defer next_index += 1;
            return next_index;
        }

        fn unregisterCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
        ) UnregisterError!void {}

        fn closeCall(_: linux.fd_t) usize {
            close_calls += 1;
            return 0;
        }
    };

    var data_file: DataFile = .{ .fd = .init(10) };
    var first: Event = .{};
    var second: Event = .{};
    Fake.next_index = 1;
    Fake.close_calls = 0;

    try first.registerWith(&data_file, 0, .{}, "zig_first", Fake.registerCall);
    try second.registerWith(&data_file, 0, .{}, "zig_second", Fake.registerCall);
    try std.testing.expectEqual(@as(u32, 2), data_file.registeredEventCount());
    try std.testing.expectError(
        error.EventsStillRegistered,
        data_file.closeWith(Fake.closeCall),
    );

    try first.unregisterWith(Fake.unregisterCall);
    try std.testing.expectError(
        error.EventsStillRegistered,
        data_file.closeWith(Fake.closeCall),
    );
    try second.unregisterWith(Fake.unregisterCall);
    try data_file.closeWith(Fake.closeCall);
    try std.testing.expectEqual(@as(usize, 1), Fake.close_calls);
}

test "unregister seals and drains an active writer" {
    const Concurrent = struct {
        var entered: std.atomic.Value(u32) = .init(0);
        var release_writer: std.atomic.Value(u32) = .init(0);
        var unregister_calls: std.atomic.Value(u32) = .init(0);
        var writer_result: std.atomic.Value(u32) = .init(0);
        var unregister_result: std.atomic.Value(u32) = .init(0);

        fn registerCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
            _: abi.RegistrationFlags,
            _: [:0]const u8,
        ) RegisterError!u32 {
            return 41;
        }

        fn writevCall(
            _: linux.fd_t,
            vectors: [*]const std.posix.iovec_const,
            count: usize,
        ) usize {
            std.debug.assert(count == 2);
            entered.store(1, .release);
            Futex.wake(&entered.raw, 1);
            while (release_writer.load(.acquire) == 0) {
                Futex.wait(&release_writer.raw, 0);
            }
            return vectors[0].len + vectors[1].len;
        }

        fn unregisterCall(
            _: linux.fd_t,
            _: *align(@sizeOf(u32)) u32,
            _: u5,
        ) UnregisterError!void {
            _ = unregister_calls.fetchAdd(1, .release);
        }

        fn writer(event: *Event) void {
            const outcome = event.writeWith("x", writevCall) catch {
                writer_result.store(2, .release);
                return;
            };
            writer_result.store(if (outcome == .written) 1 else 3, .release);
        }

        fn unregisterer(event: *Event) void {
            event.unregisterWith(unregisterCall) catch {
                unregister_result.store(2, .release);
                return;
            };
            unregister_result.store(1, .release);
        }
    };

    var data_file: DataFile = .{ .fd = .init(10) };
    var event: Event = .{};
    Concurrent.entered.store(0, .monotonic);
    Concurrent.release_writer.store(0, .monotonic);
    Concurrent.unregister_calls.store(0, .monotonic);
    Concurrent.writer_result.store(0, .monotonic);
    Concurrent.unregister_result.store(0, .monotonic);

    try event.registerWith(&data_file, 0, .{}, "zig_drain", Concurrent.registerCall);
    @atomicStore(u32, &event.enable_word, 1, .release);

    const writer = try std.Thread.spawn(.{}, Concurrent.writer, .{&event});
    while (Concurrent.entered.load(.acquire) == 0) {
        Futex.wait(&Concurrent.entered.raw, 0);
    }

    const unregisterer = try std.Thread.spawn(.{}, Concurrent.unregisterer, .{&event});
    while ((event.writer_state.load(.acquire) & writer_closing) == 0) {
        std.atomic.spinLoopHint();
        std.Thread.yield() catch {};
    }
    try std.testing.expectEqual(@as(u32, 0), Concurrent.unregister_calls.load(.acquire));

    Concurrent.release_writer.store(1, .release);
    Futex.wake(&Concurrent.release_writer.raw, 1);
    writer.join();
    unregisterer.join();

    try std.testing.expectEqual(@as(u32, 1), Concurrent.writer_result.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), Concurrent.unregister_result.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), Concurrent.unregister_calls.load(.acquire));
    try std.testing.expect(!event.isRegistered());
    try std.testing.expectEqual(@as(u32, 0), data_file.registeredEventCount());
}

fn errnoResult(err: linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(err))));
}
