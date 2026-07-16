//! Optional Linux `perf_event_open` tracepoint collection.
//!
//! Numeric tracepoint and CPU IDs are supplied by the caller. This module does
//! not discover tracefs IDs, CPUs, or event formats. Samples expose RAW bytes
//! for routing through the portable tracefs-format decoder.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const perf_abi = @import("abi/perf.zig");
const perf_data = @import("decode/perf_data.zig");

comptime {
    if (builtin.os.tag != .linux or
        (builtin.cpu.arch != .x86_64 and builtin.cpu.arch != .aarch64) or
        @sizeOf(usize) != 8)
    {
        @compileError(
            "perf collection supports only 64-bit x86_64 and AArch64 Linux targets",
        );
    }
}

const closed_fd: linux.fd_t = -1;
const collector_exclusive: u32 = @as(u32, 1) << 31;
const collector_operation_mask: u32 = collector_exclusive - 1;

pub const SampleFields = struct {
    identifier: bool = false,
    ip: bool = false,
    tid: bool = false,
    time: bool = false,
    addr: bool = false,
    id: bool = false,
    stream_id: bool = false,
    cpu: bool = false,
    period: bool = false,
    raw: bool = false,

    pub fn bits(self: SampleFields) u64 {
        var result: u64 = 0;
        if (self.identifier) result |= perf_abi.PERF_SAMPLE_IDENTIFIER;
        if (self.ip) result |= perf_abi.PERF_SAMPLE_IP;
        if (self.tid) result |= perf_abi.PERF_SAMPLE_TID;
        if (self.time) result |= perf_abi.PERF_SAMPLE_TIME;
        if (self.addr) result |= perf_abi.PERF_SAMPLE_ADDR;
        if (self.id) result |= perf_abi.PERF_SAMPLE_ID;
        if (self.stream_id) result |= perf_abi.PERF_SAMPLE_STREAM_ID;
        if (self.cpu) result |= perf_abi.PERF_SAMPLE_CPU;
        if (self.period) result |= perf_abi.PERF_SAMPLE_PERIOD;
        if (self.raw) result |= perf_abi.PERF_SAMPLE_RAW;
        return result;
    }
};

pub const TracepointConfig = struct {
    tracepoint_id: u64,
    sample_period: u64 = 1,
    sample_fields: SampleFields = .{
        .tid = true,
        .time = true,
        .cpu = true,
        .raw = true,
    },
    exclude_user: bool = false,
    exclude_kernel: bool = false,
    exclude_hv: bool = false,
};

pub const RingOptions = struct {
    /// Number of data pages after the metadata page.
    data_pages: usize = 8,
    /// Number of records required before poll wakeup.
    wakeup_events: u32 = 1,
};

pub const OpenError = error{
    AlreadyOpen,
    Busy,
    InvalidCpu,
    InvalidGroup,
    InvalidArgument,
    InvalidRingOptions,
    InvalidMmapMetadata,
    PermissionDenied,
    DeviceBusy,
    TracepointUnavailable,
    CpuUnavailable,
    KernelUnsupported,
    EventUnsupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    SystemResources,
    MappingDenied,
    MappingFailed,
    Unexpected,
};

pub const CloseError = error{
    ReaderActive,
    Busy,
    UnmapFailed,
    CloseInterrupted,
    CloseInputOutput,
    CloseNoSpace,
    InvalidFileDescriptor,
    Unexpected,
};

pub const ControlError = error{
    Closed,
    Busy,
    InvalidArgument,
    InvalidFileDescriptor,
    PermissionDenied,
    DeviceBusy,
    Unexpected,
};

pub const RingError = error{
    Closed,
    ReaderActive,
    Busy,
    InvalidHeadTail,
    IncompleteRecord,
    InvalidRecordSize,
    StaleRecord,
    InsufficientScratch,
};

pub const DecodeError = RingError || perf_data.Error;

pub const InitError = OpenError || error{
    AlreadyInitialized,
    EmptyCpuSet,
    EmptyTracepointSet,
    TooManyEvents,
    OutOfMemory,
};

pub const PollError = error{
    Closed,
    Busy,
    Interrupted,
    InvalidTimeout,
    TooManyDescriptors,
    SystemResources,
    Unexpected,
};

pub const AccessError = error{
    Closed,
    Busy,
};

const EventState = enum(u8) {
    closed,
    opening,
    open,
    reading,
    closing,
};

const System = struct {
    fn pageSize() usize {
        return std.heap.pageSize();
    }

    fn perfEventOpen(
        attr: *perf_abi.perf_event_attr,
        pid: linux.pid_t,
        cpu: i32,
        group_fd: linux.fd_t,
        flags: usize,
    ) usize {
        return linux.perf_event_open(
            @ptrCast(attr),
            pid,
            cpu,
            group_fd,
            flags,
        );
    }

    fn mmap(
        length: usize,
        fd: linux.fd_t,
    ) usize {
        return linux.mmap(
            null,
            length,
            .{ .READ = true, .WRITE = true },
            .{ .TYPE = .SHARED },
            fd,
            0,
        );
    }

    fn munmap(address: [*]const u8, length: usize) usize {
        return linux.munmap(address, length);
    }

    fn ioctl(fd: linux.fd_t, request: u32, argument: usize) usize {
        return linux.ioctl(fd, request, argument);
    }

    fn close(fd: linux.fd_t) usize {
        return linux.close(fd);
    }

    fn poll(fds: [*]linux.pollfd, count: linux.nfds_t, timeout: i32) usize {
        return linux.poll(fds, count, timeout);
    }
};

/// Owns one perf descriptor and its independent mmap ring.
///
/// An opened value is noncopyable and address-stable. Initialize it in final
/// storage and do not copy it until `close` succeeds. Closing is idempotent
/// and refuses while a `Reader` lease is active.
pub const CpuEvent = struct {
    state: std.atomic.Value(u8) = .init(@intFromEnum(EventState.closed)),
    fd: linux.fd_t = closed_fd,
    mapping: ?[*]u8 = null,
    mapping_len: usize = 0,
    data_offset: usize = 0,
    data_size: usize = 0,
    tail: u64 = 0,
    sample_layout: perf_data.SampleLayout = .{ .sample_type = 0 },
    cpu_id: i32 = -1,
    tracepoint_id: u64 = 0,

    pub fn open(
        self: *CpuEvent,
        config: TracepointConfig,
        cpu: i32,
        group_fd: linux.fd_t,
        options: RingOptions,
    ) OpenError!void {
        return self.openWith(System, config, cpu, group_fd, options);
    }

    pub fn openStandalone(
        self: *CpuEvent,
        config: TracepointConfig,
        cpu: i32,
        options: RingOptions,
    ) OpenError!void {
        return self.open(config, cpu, closed_fd, options);
    }

    pub fn isOpen(self: *const CpuEvent) bool {
        return switch (eventState(self)) {
            .open, .reading => true,
            else => false,
        };
    }

    pub fn cpuId(self: *const CpuEvent) i32 {
        return self.cpu_id;
    }

    pub fn tracepointId(self: *const CpuEvent) u64 {
        return self.tracepoint_id;
    }

    pub fn enable(self: *CpuEvent) ControlError!void {
        return self.controlWith(
            System,
            perf_abi.PERF_EVENT_IOC_ENABLE,
            0,
        );
    }

    pub fn disable(self: *CpuEvent) ControlError!void {
        return self.controlWith(
            System,
            perf_abi.PERF_EVENT_IOC_DISABLE,
            0,
        );
    }

    pub fn reset(self: *CpuEvent) ControlError!void {
        return self.controlWith(
            System,
            perf_abi.PERF_EVENT_IOC_RESET,
            0,
        );
    }

    pub fn reader(self: *CpuEvent) RingError!Reader {
        const open_value = @intFromEnum(EventState.open);
        const reading_value = @intFromEnum(EventState.reading);
        if (self.state.cmpxchgStrong(
            open_value,
            reading_value,
            .acq_rel,
            .acquire,
        )) |actual| {
            return switch (@as(EventState, @enumFromInt(actual))) {
                .closed => error.Closed,
                .reading => error.ReaderActive,
                .opening, .closing => error.Busy,
                .open => unreachable,
            };
        }

        return .{
            .event = self,
            .tail = self.tail,
        };
    }

    pub fn close(self: *CpuEvent) CloseError!void {
        return self.closeWith(System);
    }

    pub fn deinit(self: *CpuEvent) CloseError!void {
        return self.close();
    }

    fn openWith(
        self: *CpuEvent,
        comptime Sys: type,
        config: TracepointConfig,
        cpu: i32,
        group_fd: linux.fd_t,
        options: RingOptions,
    ) OpenError!void {
        if (self.state.cmpxchgStrong(
            @intFromEnum(EventState.closed),
            @intFromEnum(EventState.opening),
            .acq_rel,
            .acquire,
        )) |actual| {
            return switch (@as(EventState, @enumFromInt(actual))) {
                .closed => unreachable,
                .opening, .closing => error.Busy,
                .open, .reading => error.AlreadyOpen,
            };
        }
        errdefer self.state.store(@intFromEnum(EventState.closed), .release);

        if (cpu < 0) return error.InvalidCpu;
        if (group_fd < closed_fd) return error.InvalidGroup;
        if (config.sample_period == 0 or config.sample_fields.bits() == 0) {
            return error.InvalidArgument;
        }

        const page_size = Sys.pageSize();
        if (page_size < @sizeOf(perf_abi.perf_event_mmap_page_data) or
            !std.math.isPowerOfTwo(page_size) or
            options.data_pages == 0 or
            !std.math.isPowerOfTwo(options.data_pages))
        {
            return error.InvalidRingOptions;
        }
        if (options.data_pages > std.math.maxInt(usize) / page_size) {
            return error.InvalidRingOptions;
        }
        const data_bytes = options.data_pages * page_size;
        if (data_bytes > std.math.maxInt(usize) - page_size) {
            return error.InvalidRingOptions;
        }
        const mapping_len = page_size + data_bytes;

        var attr = makeAttr(config, options);
        const fd = try openPerfEventWith(
            Sys,
            &attr,
            cpu,
            group_fd,
        );
        errdefer _ = Sys.close(fd);

        const map_result = Sys.mmap(mapping_len, fd);
        switch (linux.errno(map_result)) {
            .SUCCESS => {},
            .ACCES, .PERM => return error.MappingDenied,
            .AGAIN, .NOMEM, .NFILE, .MFILE => return error.SystemResources,
            .INVAL, .NODEV, .BADF => return error.MappingFailed,
            else => return error.Unexpected,
        }
        const mapping: [*]u8 = @ptrFromInt(map_result);
        errdefer _ = Sys.munmap(mapping, mapping_len);

        const runtime_offset_u64 = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_OFFSET_OFFSET),
            .acquire,
        );
        const runtime_size_u64 = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_SIZE_OFFSET),
            .acquire,
        );
        if (runtime_offset_u64 > std.math.maxInt(usize) or
            runtime_size_u64 > std.math.maxInt(usize))
        {
            return error.InvalidMmapMetadata;
        }
        const runtime_offset: usize = @intCast(runtime_offset_u64);
        const runtime_size: usize = @intCast(runtime_size_u64);
        if (runtime_offset != page_size or
            runtime_size != data_bytes or
            !std.math.isPowerOfTwo(runtime_size) or
            runtime_offset > mapping_len or
            runtime_size > mapping_len - runtime_offset)
        {
            return error.InvalidMmapMetadata;
        }

        const tail = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_TAIL_OFFSET),
            .acquire,
        );
        const head = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_HEAD_OFFSET),
            .acquire,
        );
        if (head -% tail > runtime_size) return error.InvalidMmapMetadata;

        self.fd = fd;
        self.mapping = mapping;
        self.mapping_len = mapping_len;
        self.data_offset = runtime_offset;
        self.data_size = runtime_size;
        self.tail = tail;
        self.sample_layout = .{
            .sample_type = config.sample_fields.bits(),
            .endian = .little,
        };
        self.cpu_id = cpu;
        self.tracepoint_id = config.tracepoint_id;
        self.state.store(@intFromEnum(EventState.open), .release);
    }

    fn closeWith(self: *CpuEvent, comptime Sys: type) CloseError!void {
        while (true) {
            const current = eventState(self);
            switch (current) {
                .closed => return,
                .reading => return error.ReaderActive,
                .opening, .closing => return error.Busy,
                .open => {},
            }
            if (self.state.cmpxchgStrong(
                @intFromEnum(EventState.open),
                @intFromEnum(EventState.closing),
                .acq_rel,
                .acquire,
            ) == null) break;
        }

        var first_error: ?CloseError = null;
        if (self.mapping) |mapping| {
            switch (linux.errno(Sys.munmap(mapping, self.mapping_len))) {
                .SUCCESS => {
                    self.mapping = null;
                    self.mapping_len = 0;
                    self.data_offset = 0;
                    self.data_size = 0;
                },
                else => first_error = error.UnmapFailed,
            }
        }

        if (self.fd != closed_fd) {
            const fd = self.fd;
            self.fd = closed_fd;
            const close_error: ?CloseError = switch (linux.errno(Sys.close(fd))) {
                .SUCCESS => null,
                .INTR => error.CloseInterrupted,
                .IO => error.CloseInputOutput,
                .NOSPC, .DQUOT => error.CloseNoSpace,
                .BADF => error.InvalidFileDescriptor,
                else => error.Unexpected,
            };
            if (first_error == null) first_error = close_error;
        }

        if (self.mapping == null and self.fd == closed_fd) {
            self.tail = 0;
            self.sample_layout = .{ .sample_type = 0 };
            self.cpu_id = -1;
            self.tracepoint_id = 0;
            self.state.store(@intFromEnum(EventState.closed), .release);
        } else {
            self.state.store(@intFromEnum(EventState.open), .release);
        }

        if (first_error) |err| return err;
    }

    fn controlWith(
        self: *CpuEvent,
        comptime Sys: type,
        request: u32,
        argument: usize,
    ) ControlError!void {
        switch (eventState(self)) {
            .closed => return error.Closed,
            .opening, .closing => return error.Busy,
            .open, .reading => {},
        }
        if (self.fd == closed_fd) return error.Closed;

        while (true) {
            switch (linux.errno(Sys.ioctl(self.fd, request, argument))) {
                .SUCCESS => return,
                .INTR => continue,
                .BADF => return error.InvalidFileDescriptor,
                .INVAL, .NOENT => return error.InvalidArgument,
                .PERM, .ACCES => return error.PermissionDenied,
                .BUSY => return error.DeviceBusy,
                else => return error.Unexpected,
            }
        }
    }

    fn enableGroupWith(self: *CpuEvent, comptime Sys: type) ControlError!void {
        return self.controlWith(
            Sys,
            perf_abi.PERF_EVENT_IOC_ENABLE,
            perf_abi.PERF_IOC_FLAG_GROUP,
        );
    }

    fn disableGroupWith(self: *CpuEvent, comptime Sys: type) ControlError!void {
        return self.controlWith(
            Sys,
            perf_abi.PERF_EVENT_IOC_DISABLE,
            perf_abi.PERF_IOC_FLAG_GROUP,
        );
    }

    fn resetGroupWith(self: *CpuEvent, comptime Sys: type) ControlError!void {
        return self.controlWith(
            Sys,
            perf_abi.PERF_EVENT_IOC_RESET,
            perf_abi.PERF_IOC_FLAG_GROUP,
        );
    }

    fn hasResources(self: *const CpuEvent) bool {
        return self.mapping != null or self.fd != closed_fd;
    }
};

pub const RecordRef = struct {
    header: perf_abi.perf_event_header,
    first: []const u8,
    second: []const u8,
    tail: u64,

    pub fn byteLen(self: RecordRef) usize {
        return self.first.len + self.second.len;
    }

    pub fn contiguous(self: RecordRef) ?[]const u8 {
        return if (self.second.len == 0) self.first else null;
    }

    /// Explicitly copies a wrapped record. A contiguous record remains
    /// borrowed from the ring and does not use `scratch`.
    pub fn copyTo(self: RecordRef, scratch: []u8) RingError![]const u8 {
        if (self.contiguous()) |record| return record;
        const length = self.byteLen();
        if (scratch.len < length) return error.InsufficientScratch;
        std.mem.copyForwards(u8, scratch[0..self.first.len], self.first);
        std.mem.copyForwards(
            u8,
            scratch[self.first.len..length],
            self.second,
        );
        return scratch[0..length];
    }
};

pub const LostRecord = struct {
    id: u64,
    count: u64,
};

pub const OtherRecord = struct {
    type: u32,
    misc: u16,
    payload: []const u8,
};

pub const DecodedRecord = union(enum) {
    sample: perf_data.Sample,
    lost: LostRecord,
    other: OtherRecord,
};

pub const DrainStats = struct {
    records: usize = 0,
    samples: usize = 0,
    lost_records: usize = 0,
    lost_events: u64 = 0,
    other_records: usize = 0,
    bytes_committed: u64 = 0,
};

/// Exclusive, noncopyable lease over one `CpuEvent` ring.
///
/// `next` never advances the ring. The caller must finish reading or decoding
/// a `RecordRef`, then call `commit`. Errors leave the local and published
/// tails unchanged. `discardPending` is the explicit corruption recovery.
pub const Reader = struct {
    event: *CpuEvent,
    tail: u64,
    active: bool = true,

    pub fn next(self: *Reader) RingError!?RecordRef {
        if (!self.active) return error.Closed;
        const mapping = self.event.mapping orelse return error.Closed;
        const head = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_HEAD_OFFSET),
            .acquire,
        );
        const available = head -% self.tail;
        if (available > self.event.data_size) return error.InvalidHeadTail;
        if (available == 0) return null;
        if (available < @sizeOf(perf_abi.perf_event_header)) {
            return error.IncompleteRecord;
        }

        var header_bytes: [@sizeOf(perf_abi.perf_event_header)]u8 = undefined;
        self.copyRingBytes(self.tail, &header_bytes);
        const record_size = readU16Little(header_bytes[6..8]);
        if (record_size < @sizeOf(perf_abi.perf_event_header) or
            record_size > self.event.data_size)
        {
            return error.InvalidRecordSize;
        }
        if (record_size > available) return error.IncompleteRecord;

        const ring_offset: usize =
            @intCast(self.tail & @as(u64, @intCast(self.event.data_size - 1)));
        const first_len = @min(
            @as(usize, record_size),
            self.event.data_size - ring_offset,
        );
        const data = mapping + self.event.data_offset;
        const first = (data + ring_offset)[0..first_len];
        const second_len = @as(usize, record_size) - first_len;
        const second = data[0..second_len];

        return .{
            .header = .{
                .type = readU32Little(header_bytes[0..4]),
                .misc = readU16Little(header_bytes[4..6]),
                .size = record_size,
            },
            .first = first,
            .second = second,
            .tail = self.tail,
        };
    }

    pub fn decode(
        self: *Reader,
        record_ref: RecordRef,
        scratch: []u8,
        limits: perf_data.Limits,
    ) DecodeError!DecodedRecord {
        if (!self.active) return error.Closed;
        if (record_ref.tail != self.tail) return error.StaleRecord;

        const record_bytes = try record_ref.copyTo(scratch);
        const record = try perf_data.parseRecord(record_bytes, .little);
        if (record.size != record_bytes.len or
            record.type != record_ref.header.type or
            record.misc != record_ref.header.misc or
            record.size != record_ref.header.size)
        {
            return error.InvalidRecordSize;
        }
        return switch (record.type) {
            perf_abi.PERF_RECORD_SAMPLE => .{
                .sample = try perf_data.decodeSampleWithLayout(
                    record,
                    self.event.sample_layout,
                    limits,
                ),
            },
            perf_abi.PERF_RECORD_LOST => blk: {
                const lost = try perf_data.decodeLost(record, .little);
                break :blk .{ .lost = .{
                    .id = lost.id,
                    .count = lost.count,
                } };
            },
            else => .{ .other = .{
                .type = record.type,
                .misc = record.misc,
                .payload = record.payload,
            } },
        };
    }

    /// Publishes consumption only after the caller's final record data read.
    pub fn commit(self: *Reader, record: RecordRef) RingError!void {
        if (!self.active) return error.Closed;
        if (record.tail != self.tail) return error.StaleRecord;
        if (record.header.size < @sizeOf(perf_abi.perf_event_header) or
            record.header.size > self.event.data_size or
            record.byteLen() != record.header.size)
        {
            return error.InvalidRecordSize;
        }
        const mapping = self.event.mapping orelse return error.Closed;
        const next_tail = self.tail +% record.header.size;

        @atomicStore(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_TAIL_OFFSET),
            next_tail,
            .release,
        );
        self.tail = next_tail;
        self.event.tail = next_tail;
    }

    /// Drops everything currently published by the kernel and returns the
    /// number of bytes skipped. This is the explicit recovery path after a
    /// corrupt header, incomplete record, or head/tail overrun.
    pub fn discardPending(self: *Reader) RingError!u64 {
        if (!self.active) return error.Closed;
        const mapping = self.event.mapping orelse return error.Closed;
        const head = @atomicLoad(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_HEAD_OFFSET),
            .acquire,
        );
        const discarded = head -% self.tail;

        @atomicStore(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_TAIL_OFFSET),
            head,
            .release,
        );
        self.tail = head;
        self.event.tail = head;
        return discarded;
    }

    pub fn drain(
        self: *Reader,
        scratch: []u8,
        limits: perf_data.Limits,
        context: anytype,
        comptime visit: anytype,
    ) !DrainStats {
        var stats = DrainStats{};
        while (try self.next()) |record| {
            const decoded = try self.decode(record, scratch, limits);
            try visit(context, decoded);
            try self.commit(record);

            stats.records += 1;
            stats.bytes_committed +%= record.header.size;
            switch (decoded) {
                .sample => stats.samples += 1,
                .lost => |lost| {
                    stats.lost_records += 1;
                    stats.lost_events = std.math.add(
                        u64,
                        stats.lost_events,
                        lost.count,
                    ) catch std.math.maxInt(u64);
                },
                .other => stats.other_records += 1,
            }
        }
        return stats;
    }

    pub fn close(self: *Reader) void {
        self.deinit();
    }

    pub fn deinit(self: *Reader) void {
        if (!self.active) return;
        self.event.tail = self.tail;
        const previous = self.event.state.cmpxchgStrong(
            @intFromEnum(EventState.reading),
            @intFromEnum(EventState.open),
            .release,
            .monotonic,
        );
        std.debug.assert(previous == null);
        self.active = false;
    }

    fn copyRingBytes(self: *Reader, position: u64, output: []u8) void {
        const mapping = self.event.mapping.?;
        const ring_offset: usize =
            @intCast(position & @as(u64, @intCast(self.event.data_size - 1)));
        const first_len = @min(output.len, self.event.data_size - ring_offset);
        const data = mapping + self.event.data_offset;
        std.mem.copyForwards(
            u8,
            output[0..first_len],
            (data + ring_offset)[0..first_len],
        );
        std.mem.copyForwards(
            u8,
            output[first_len..],
            data[0 .. output.len - first_len],
        );
    }
};

pub const ReadyEvent = struct {
    slot: usize,
    cpu: i32,
    tracepoint_id: u64,
    revents: i16,
    /// Valid only while the originating `ReadyIterator` remains active.
    event: *CpuEvent,
};

/// Keeps collector-owned event storage alive while the event is borrowed.
///
/// This value is noncopyable. Call `deinit` after the final access through
/// `get`; collector teardown returns `Busy` while a lease remains active.
pub const EventLease = struct {
    collector: *Collector,
    value: *CpuEvent,
    active: bool = true,

    pub fn get(self: *EventLease) *CpuEvent {
        std.debug.assert(self.active);
        return self.value;
    }

    pub fn close(self: *EventLease) void {
        self.deinit();
    }

    pub fn deinit(self: *EventLease) void {
        if (!self.active) return;
        self.collector.releaseOperation();
        self.active = false;
    }
};

/// Iterates one stable poll result while holding the collector storage alive.
///
/// This value is noncopyable. Call `deinit` after iteration.
pub const ReadyIterator = struct {
    collector: *Collector,
    ready_count: usize,
    index: usize = 0,
    active: bool = true,

    pub fn count(self: *const ReadyIterator) usize {
        return self.ready_count;
    }

    pub fn next(self: *ReadyIterator) ?ReadyEvent {
        if (!self.active) return null;
        const poll_fds = self.collector.poll_fds orelse return null;
        const events = self.collector.events.?;
        const ready_mask = linux.POLL.IN |
            linux.POLL.ERR |
            linux.POLL.HUP |
            linux.POLL.NVAL;
        while (self.index < poll_fds.len) {
            const index = self.index;
            self.index += 1;
            if (poll_fds[index].revents & ready_mask == 0) continue;
            return .{
                .slot = index,
                .cpu = events[index].cpuId(),
                .tracepoint_id = events[index].tracepointId(),
                .revents = poll_fds[index].revents,
                .event = &events[index],
            };
        }
        return null;
    }

    pub fn close(self: *ReadyIterator) void {
        self.deinit();
    }

    pub fn deinit(self: *ReadyIterator) void {
        if (!self.active) return;
        self.collector.releasePoll();
        self.collector.releaseOperation();
        self.active = false;
    }
};

/// Owns row-major CPU × tracepoint events and poll descriptors.
///
/// Each CPU's first tracepoint is its group leader. Every event has a separate
/// mmap ring; FD_OUTPUT redirection is never used. An initialized collector is
/// noncopyable and address-stable.
pub const Collector = struct {
    operation_state: std.atomic.Value(u32) = .init(0),
    poll_active: std.atomic.Value(bool) = .init(false),
    allocator: ?std.mem.Allocator = null,
    events: ?[]CpuEvent = null,
    poll_fds: ?[]linux.pollfd = null,
    cpu_count: usize = 0,
    tracepoint_count: usize = 0,

    pub fn init(
        self: *Collector,
        allocator: std.mem.Allocator,
        cpus: []const i32,
        tracepoints: []const TracepointConfig,
        options: RingOptions,
    ) InitError!void {
        return self.initWith(
            System,
            allocator,
            cpus,
            tracepoints,
            options,
        );
    }

    pub fn eventAt(
        self: *Collector,
        cpu_index: usize,
        tracepoint_index: usize,
    ) AccessError!?EventLease {
        try self.acquireOperation();
        errdefer self.releaseOperation();

        const events = self.events.?;
        if (cpu_index >= self.cpu_count or
            tracepoint_index >= self.tracepoint_count)
        {
            self.releaseOperation();
            return null;
        }
        return .{
            .collector = self,
            .value = &events[cpu_index * self.tracepoint_count + tracepoint_index],
        };
    }

    pub fn readerAt(
        self: *Collector,
        cpu_index: usize,
        tracepoint_index: usize,
    ) RingError!?Reader {
        try self.acquireOperation();
        defer self.releaseOperation();

        const events = self.events.?;
        if (cpu_index >= self.cpu_count or
            tracepoint_index >= self.tracepoint_count)
        {
            return null;
        }
        return try events[
            cpu_index * self.tracepoint_count + tracepoint_index
        ].reader();
    }

    pub fn enableAll(self: *Collector) ControlError!void {
        return self.enableAllWith(System);
    }

    pub fn disableAll(self: *Collector) ControlError!void {
        return self.disableAllWith(System);
    }

    pub fn resetAll(self: *Collector) ControlError!void {
        return self.resetAllWith(System);
    }

    pub fn poll(
        self: *Collector,
        timeout_milliseconds: i32,
    ) PollError!ReadyIterator {
        return self.pollWith(System, timeout_milliseconds);
    }

    pub fn close(self: *Collector) CloseError!void {
        return self.closeWith(System);
    }

    pub fn deinit(self: *Collector) CloseError!void {
        return self.close();
    }

    fn initWith(
        self: *Collector,
        comptime Sys: type,
        allocator: std.mem.Allocator,
        cpus: []const i32,
        tracepoints: []const TracepointConfig,
        options: RingOptions,
    ) InitError!void {
        if (self.operation_state.cmpxchgStrong(
            0,
            collector_exclusive,
            .acq_rel,
            .acquire,
        ) != null) {
            return error.Busy;
        }
        defer self.operation_state.store(0, .release);

        if (self.events != null or self.poll_fds != null) {
            return error.AlreadyInitialized;
        }
        if (cpus.len == 0) return error.EmptyCpuSet;
        if (tracepoints.len == 0) return error.EmptyTracepointSet;
        if (tracepoints.len > std.math.maxInt(usize) / cpus.len) {
            return error.TooManyEvents;
        }
        const slot_count = cpus.len * tracepoints.len;

        const events = try allocator.alloc(CpuEvent, slot_count);
        errdefer allocator.free(events);
        for (events) |*event| event.* = .{};

        const poll_fds = try allocator.alloc(linux.pollfd, slot_count);
        errdefer allocator.free(poll_fds);

        var opened: usize = 0;
        errdefer {
            var index = opened;
            while (index != 0) {
                index -= 1;
                events[index].closeWith(Sys) catch {};
            }
        }

        for (cpus, 0..) |cpu, cpu_index| {
            var leader_fd: linux.fd_t = closed_fd;
            for (tracepoints, 0..) |config, tracepoint_index| {
                const index = cpu_index * tracepoints.len + tracepoint_index;
                try events[index].openWith(
                    Sys,
                    config,
                    cpu,
                    leader_fd,
                    options,
                );
                opened += 1;
                if (tracepoint_index == 0) leader_fd = events[index].fd;
                poll_fds[index] = .{
                    .fd = events[index].fd,
                    .events = linux.POLL.IN |
                        linux.POLL.ERR |
                        linux.POLL.HUP,
                    .revents = 0,
                };
            }
        }

        self.allocator = allocator;
        self.events = events;
        self.poll_fds = poll_fds;
        self.cpu_count = cpus.len;
        self.tracepoint_count = tracepoints.len;
    }

    fn enableAllWith(self: *Collector, comptime Sys: type) ControlError!void {
        try self.acquireOperation();
        defer self.releaseOperation();

        const events = self.events.?;
        for (0..self.cpu_count) |cpu_index| {
            try events[cpu_index * self.tracepoint_count].enableGroupWith(Sys);
        }
    }

    fn disableAllWith(self: *Collector, comptime Sys: type) ControlError!void {
        try self.acquireOperation();
        defer self.releaseOperation();

        const events = self.events.?;
        for (0..self.cpu_count) |cpu_index| {
            try events[cpu_index * self.tracepoint_count].disableGroupWith(Sys);
        }
    }

    fn resetAllWith(self: *Collector, comptime Sys: type) ControlError!void {
        try self.acquireOperation();
        defer self.releaseOperation();

        const events = self.events.?;
        for (0..self.cpu_count) |cpu_index| {
            try events[cpu_index * self.tracepoint_count].resetGroupWith(Sys);
        }
    }

    fn pollWith(
        self: *Collector,
        comptime Sys: type,
        timeout_milliseconds: i32,
    ) PollError!ReadyIterator {
        if (timeout_milliseconds < -1) return error.InvalidTimeout;
        try self.acquireOperation();
        errdefer self.releaseOperation();
        try self.acquirePoll();
        errdefer self.releasePoll();

        const poll_fds = self.poll_fds.?;
        for (poll_fds) |*poll_fd| poll_fd.revents = 0;

        const result = Sys.poll(
            poll_fds.ptr,
            poll_fds.len,
            timeout_milliseconds,
        );
        switch (linux.errno(result)) {
            .SUCCESS => return .{
                .collector = self,
                .ready_count = result,
            },
            .INTR => return error.Interrupted,
            .AGAIN, .NOMEM => return error.SystemResources,
            .INVAL => return error.TooManyDescriptors,
            else => return error.Unexpected,
        }
    }

    fn closeWith(self: *Collector, comptime Sys: type) CloseError!void {
        if (self.operation_state.cmpxchgStrong(
            0,
            collector_exclusive,
            .acq_rel,
            .acquire,
        ) != null) {
            return error.Busy;
        }
        defer self.operation_state.store(0, .release);

        const events = self.events orelse return;
        for (events) |*event| {
            switch (eventState(event)) {
                .reading => return error.ReaderActive,
                .opening, .closing => return error.Busy,
                .closed, .open => {},
            }
        }

        var first_error: ?CloseError = null;
        var index = events.len;
        while (index != 0) {
            index -= 1;
            events[index].closeWith(Sys) catch |err| {
                if (first_error == null) first_error = err;
            };
            self.poll_fds.?[index].fd = events[index].fd;
        }

        for (events) |*event| {
            if (event.hasResources()) {
                if (first_error) |err| return err;
                return error.Unexpected;
            }
        }

        const allocator = self.allocator.?;
        allocator.free(self.poll_fds.?);
        allocator.free(events);
        self.allocator = null;
        self.events = null;
        self.poll_fds = null;
        self.cpu_count = 0;
        self.tracepoint_count = 0;
        if (first_error) |err| return err;
    }

    fn acquireOperation(self: *Collector) AccessError!void {
        while (true) {
            const current = self.operation_state.load(.acquire);
            if (current & collector_exclusive != 0) return error.Busy;
            if (current == collector_operation_mask) return error.Busy;
            if (self.operation_state.cmpxchgWeak(
                current,
                current + 1,
                .acq_rel,
                .acquire,
            ) == null) {
                break;
            }
        }
        if (self.events == null) {
            self.releaseOperation();
            return error.Closed;
        }
    }

    fn releaseOperation(self: *Collector) void {
        const previous = self.operation_state.fetchSub(1, .release);
        std.debug.assert(previous != 0 and
            previous & collector_exclusive == 0);
    }

    fn acquirePoll(self: *Collector) AccessError!void {
        if (self.poll_active.cmpxchgStrong(
            false,
            true,
            .acquire,
            .monotonic,
        ) != null) {
            return error.Busy;
        }
    }

    fn releasePoll(self: *Collector) void {
        const was_active = self.poll_active.swap(false, .release);
        std.debug.assert(was_active);
    }
};

fn makeAttr(
    config: TracepointConfig,
    options: RingOptions,
) perf_abi.perf_event_attr {
    const flags = perf_abi.PerfEventAttrFlags{
        .disabled = true,
        .exclude_user = config.exclude_user,
        .exclude_kernel = config.exclude_kernel,
        .exclude_hv = config.exclude_hv,
    };
    return .{
        .config = config.tracepoint_id,
        .sample_period = config.sample_period,
        .sample_type = config.sample_fields.bits(),
        .flags = flags.bits(),
        .wakeup_events = options.wakeup_events,
    };
}

fn openPerfEventWith(
    comptime Sys: type,
    attr: *perf_abi.perf_event_attr,
    cpu: i32,
    group_fd: linux.fd_t,
) OpenError!linux.fd_t {
    while (true) {
        const result = Sys.perfEventOpen(
            attr,
            -1,
            cpu,
            group_fd,
            perf_abi.PERF_FLAG_FD_CLOEXEC,
        );
        switch (linux.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .ACCES, .PERM => return error.PermissionDenied,
            .@"2BIG", .INVAL => return error.InvalidArgument,
            .BADF => return error.InvalidGroup,
            .BUSY => return error.DeviceBusy,
            .NOENT => return error.TracepointUnavailable,
            .NODEV => return error.CpuUnavailable,
            .NOSYS => return error.KernelUnsupported,
            .OPNOTSUPP => return error.EventUnsupported,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOMEM, .NOSPC => return error.SystemResources,
            else => return error.Unexpected,
        }
    }
}

fn eventState(event: *const CpuEvent) EventState {
    return @enumFromInt(event.state.load(.acquire));
}

fn metadataU64(mapping: [*]u8, offset: usize) *align(8) u64 {
    return @ptrFromInt(@intFromPtr(mapping) + offset);
}

fn readU16Little(input: *const [2]u8) u16 {
    return @as(u16, input[0]) | (@as(u16, input[1]) << 8);
}

fn readU32Little(input: *const [4]u8) u32 {
    return @as(u32, input[0]) |
        (@as(u32, input[1]) << 8) |
        (@as(u32, input[2]) << 16) |
        (@as(u32, input[3]) << 24);
}

const synthetic_data_offset = 2048;
const synthetic_data_size = 64;
const synthetic_mapping_size = synthetic_data_offset + synthetic_data_size;

const SyntheticRing = struct {
    storage: [synthetic_mapping_size]u8 align(4096) =
        [_]u8{0} ** synthetic_mapping_size,
    event: CpuEvent = .{},

    fn init(self: *SyntheticRing, tail: u64, sample_type: u64) void {
        @memset(&self.storage, 0);
        self.event = .{};
        self.event.mapping = self.storage[0..].ptr;
        self.event.mapping_len = self.storage.len;
        self.event.data_offset = synthetic_data_offset;
        self.event.data_size = synthetic_data_size;
        self.event.tail = tail;
        self.event.sample_layout = .{ .sample_type = sample_type };
        self.event.cpu_id = 3;
        self.event.tracepoint_id = 47;
        @atomicStore(
            u64,
            metadataU64(
                self.event.mapping.?,
                perf_abi.PERF_MMAP_DATA_TAIL_OFFSET,
            ),
            tail,
            .monotonic,
        );
        @atomicStore(
            u64,
            metadataU64(
                self.event.mapping.?,
                perf_abi.PERF_MMAP_DATA_HEAD_OFFSET,
            ),
            tail,
            .monotonic,
        );
        self.event.state.store(@intFromEnum(EventState.open), .release);
    }

    fn write(self: *SyntheticRing, position: u64, input: []const u8) void {
        const offset: usize =
            @intCast(position & (synthetic_data_size - 1));
        const first_len = @min(input.len, synthetic_data_size - offset);
        const data = self.storage[synthetic_data_offset..];
        std.mem.copyForwards(
            u8,
            data[offset .. offset + first_len],
            input[0..first_len],
        );
        std.mem.copyForwards(
            u8,
            data[0 .. input.len - first_len],
            input[first_len..],
        );
    }

    fn setHead(self: *SyntheticRing, head: u64) void {
        @atomicStore(
            u64,
            metadataU64(
                self.event.mapping.?,
                perf_abi.PERF_MMAP_DATA_HEAD_OFFSET,
            ),
            head,
            .release,
        );
    }

    fn publishedTail(self: *SyntheticRing) u64 {
        return @atomicLoad(
            u64,
            metadataU64(
                self.event.mapping.?,
                perf_abi.PERF_MMAP_DATA_TAIL_OFFSET,
            ),
            .acquire,
        );
    }
};

fn putU16Little(output: []u8, offset: usize, value: u16) void {
    output[offset] = @truncate(value);
    output[offset + 1] = @truncate(value >> 8);
}

fn putU32Little(output: []u8, offset: usize, value: u32) void {
    for (0..4) |index| {
        output[offset + index] = @truncate(value >> @intCast(index * 8));
    }
}

fn putU64Little(output: []u8, offset: usize, value: u64) void {
    for (0..8) |index| {
        output[offset + index] = @truncate(value >> @intCast(index * 8));
    }
}

fn putRecordHeader(
    output: []u8,
    record_type: u32,
    misc: u16,
    size: u16,
) void {
    putU32Little(output, 0, record_type);
    putU16Little(output, 4, misc);
    putU16Little(output, 6, size);
}

const FakeSystem = struct {
    const max_calls = 8;
    const page_size = 4096;
    const mapping_size = 2 * page_size;

    var maps: [max_calls][mapping_size]u8 align(page_size) = undefined;
    var attrs: [max_calls]perf_abi.perf_event_attr = undefined;
    var cpus: [max_calls]i32 = undefined;
    var group_fds: [max_calls]linux.fd_t = undefined;
    var open_flags: [max_calls]usize = undefined;
    var ioctl_fds: [max_calls]linux.fd_t = undefined;
    var ioctl_requests: [max_calls]u32 = undefined;
    var ioctl_arguments: [max_calls]usize = undefined;
    var open_calls: usize = 0;
    var mmap_calls: usize = 0;
    var munmap_calls: usize = 0;
    var close_calls: usize = 0;
    var ioctl_calls: usize = 0;
    var poll_calls: usize = 0;
    var fail_open_call: ?usize = null;
    var bad_metadata_call: ?usize = null;
    var ready_slot: ?usize = null;
    var interrupt_poll: bool = false;

    fn reset() void {
        open_calls = 0;
        mmap_calls = 0;
        munmap_calls = 0;
        close_calls = 0;
        ioctl_calls = 0;
        poll_calls = 0;
        fail_open_call = null;
        bad_metadata_call = null;
        ready_slot = null;
        interrupt_poll = false;
        @memset(std.mem.asBytes(&maps), 0);
    }

    fn pageSize() usize {
        return page_size;
    }

    fn perfEventOpen(
        attr: *perf_abi.perf_event_attr,
        pid: linux.pid_t,
        cpu: i32,
        group_fd: linux.fd_t,
        flags: usize,
    ) usize {
        std.debug.assert(pid == -1);
        const call = open_calls;
        open_calls += 1;
        attrs[call] = attr.*;
        cpus[call] = cpu;
        group_fds[call] = group_fd;
        open_flags[call] = flags;
        if (fail_open_call == call) return errnoResult(.ACCES);
        return 100 + call;
    }

    fn mmap(length: usize, fd: linux.fd_t) usize {
        std.debug.assert(length == mapping_size);
        std.debug.assert(fd >= 100);
        const call = mmap_calls;
        mmap_calls += 1;
        const mapping = maps[call][0..].ptr;
        @atomicStore(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_OFFSET_OFFSET),
            page_size,
            .monotonic,
        );
        @atomicStore(
            u64,
            metadataU64(mapping, perf_abi.PERF_MMAP_DATA_SIZE_OFFSET),
            if (bad_metadata_call == call) page_size / 2 else page_size,
            .monotonic,
        );
        return @intFromPtr(mapping);
    }

    fn munmap(_: [*]const u8, length: usize) usize {
        std.debug.assert(length == mapping_size or
            length == synthetic_mapping_size);
        munmap_calls += 1;
        return 0;
    }

    fn ioctl(fd: linux.fd_t, request: u32, argument: usize) usize {
        const call = ioctl_calls;
        ioctl_calls += 1;
        ioctl_fds[call] = fd;
        ioctl_requests[call] = request;
        ioctl_arguments[call] = argument;
        return 0;
    }

    fn close(_: linux.fd_t) usize {
        close_calls += 1;
        return 0;
    }

    fn poll(fds: [*]linux.pollfd, count: linux.nfds_t, timeout: i32) usize {
        std.debug.assert(timeout >= -1);
        poll_calls += 1;
        if (interrupt_poll) return errnoResult(.INTR);
        if (ready_slot) |slot| {
            std.debug.assert(slot < count);
            fds[slot].revents = linux.POLL.IN;
            return 1;
        }
        return 0;
    }
};

fn errnoResult(err: linux.E) usize {
    return @bitCast(-@as(isize, @intFromEnum(err)));
}

test "sample fields map only to the supported portable layout" {
    const fields = SampleFields{
        .identifier = true,
        .ip = true,
        .tid = true,
        .time = true,
        .addr = true,
        .id = true,
        .stream_id = true,
        .cpu = true,
        .period = true,
        .raw = true,
    };
    try std.testing.expectEqual(perf_abi.PERF_SAMPLE_SUPPORTED, fields.bits());
    try std.testing.expectEqual(
        perf_data.SampleType.supported,
        fields.bits(),
    );
}

test "public raw-syscall lifecycle rejects invalid unopened operations" {
    var event = CpuEvent{};
    try std.testing.expectError(
        error.InvalidCpu,
        event.openStandalone(.{ .tracepoint_id = 1 }, -1, .{}),
    );
    try std.testing.expectError(error.Closed, event.enable());
    try std.testing.expectError(error.Closed, event.disable());
    try std.testing.expectError(error.Closed, event.reset());
    try event.close();

    var collector = Collector{};
    try std.testing.expectError(
        error.EmptyCpuSet,
        collector.init(
            std.testing.allocator,
            &.{},
            &.{.{ .tracepoint_id = 1 }},
            .{},
        ),
    );
    try std.testing.expectError(error.Closed, collector.poll(0));
    try collector.close();
}

test "reader borrows contiguous records and publishes tail on commit" {
    var ring = SyntheticRing{};
    ring.init(0, 0);
    var bytes = [_]u8{0} ** 16;
    putRecordHeader(&bytes, 77, 0x1234, bytes.len);
    @memcpy(bytes[8..], "payload!");
    ring.write(0, &bytes);
    ring.setHead(bytes.len);

    var reader = try ring.event.reader();
    defer reader.deinit();
    const record = (try reader.next()).?;
    try std.testing.expectEqual(@as(u32, 77), record.header.type);
    try std.testing.expectEqual(@as(u16, 0x1234), record.header.misc);
    try std.testing.expectEqual(@as(usize, bytes.len), record.byteLen());
    try std.testing.expect(record.contiguous() != null);

    const decoded = try reader.decode(record, &.{}, .{});
    switch (decoded) {
        .other => |other| {
            try std.testing.expectEqual(@as(u32, 77), other.type);
            try std.testing.expectEqualSlices(u8, "payload!", other.payload);
        },
        else => return error.TestUnexpectedResult,
    }
    try std.testing.expectEqual(@as(u64, 0), ring.publishedTail());
    try reader.commit(record);
    try std.testing.expectEqual(@as(u64, bytes.len), ring.publishedTail());
    try std.testing.expectError(error.StaleRecord, reader.commit(record));
    try std.testing.expect((try reader.next()) == null);
}

test "reader parses wrapped headers and LOST payloads with explicit scratch" {
    var ring = SyntheticRing{};
    const tail = 60;
    ring.init(tail, 0);
    var bytes = [_]u8{0} ** 24;
    putRecordHeader(&bytes, perf_abi.PERF_RECORD_LOST, 0, bytes.len);
    putU64Little(&bytes, 8, 0x1122334455667788);
    putU64Little(&bytes, 16, 19);
    ring.write(tail, &bytes);
    ring.setHead(tail + bytes.len);

    var reader = try ring.event.reader();
    defer reader.deinit();
    const record = (try reader.next()).?;
    try std.testing.expectEqual(@as(usize, 4), record.first.len);
    try std.testing.expectEqual(@as(usize, 20), record.second.len);
    var too_small: [23]u8 = undefined;
    try std.testing.expectError(
        error.InsufficientScratch,
        record.copyTo(&too_small),
    );
    try std.testing.expectEqual(@as(u64, tail), ring.publishedTail());

    var scratch: [24]u8 = undefined;
    const decoded = try reader.decode(record, &scratch, .{});
    switch (decoded) {
        .lost => |lost| {
            try std.testing.expectEqual(
                @as(u64, 0x1122334455667788),
                lost.id,
            );
            try std.testing.expectEqual(@as(u64, 19), lost.count);
        },
        else => return error.TestUnexpectedResult,
    }
    try reader.commit(record);
    try std.testing.expectEqual(
        @as(u64, tail + bytes.len),
        ring.publishedTail(),
    );
}

test "reader leaves corrupt and incomplete records pending until discard" {
    {
        var ring = SyntheticRing{};
        ring.init(0, 0);
        ring.setHead(4);
        var reader = try ring.event.reader();
        defer reader.deinit();
        try std.testing.expectError(error.IncompleteRecord, reader.next());
        try std.testing.expectEqual(@as(u64, 0), ring.publishedTail());
        try std.testing.expectEqual(@as(u64, 4), try reader.discardPending());
        try std.testing.expectEqual(@as(u64, 4), ring.publishedTail());
    }
    {
        var ring = SyntheticRing{};
        ring.init(0, 0);
        var bytes = [_]u8{0} ** 8;
        putRecordHeader(&bytes, 1, 0, 7);
        ring.write(0, &bytes);
        ring.setHead(bytes.len);
        var reader = try ring.event.reader();
        defer reader.deinit();
        try std.testing.expectError(error.InvalidRecordSize, reader.next());
        try std.testing.expectEqual(@as(u64, 0), ring.publishedTail());
    }
    {
        var ring = SyntheticRing{};
        ring.init(0, 0);
        var bytes = [_]u8{0} ** 8;
        putRecordHeader(&bytes, 1, 0, 16);
        ring.write(0, &bytes);
        ring.setHead(bytes.len);
        var reader = try ring.event.reader();
        defer reader.deinit();
        try std.testing.expectError(error.IncompleteRecord, reader.next());
        try std.testing.expectEqual(@as(u64, 0), ring.publishedTail());
    }
    {
        var ring = SyntheticRing{};
        ring.init(0, 0);
        var bytes = [_]u8{0} ** 8;
        putRecordHeader(&bytes, 1, 0, synthetic_data_size + 1);
        ring.write(0, &bytes);
        ring.setHead(bytes.len);
        var reader = try ring.event.reader();
        defer reader.deinit();
        try std.testing.expectError(error.InvalidRecordSize, reader.next());
        try std.testing.expectEqual(@as(u64, 0), ring.publishedTail());
    }
    {
        var ring = SyntheticRing{};
        ring.init(0, 0);
        ring.setHead(synthetic_data_size + 1);
        var reader = try ring.event.reader();
        defer reader.deinit();
        try std.testing.expectError(error.InvalidHeadTail, reader.next());
        try std.testing.expectEqual(
            @as(u64, synthetic_data_size + 1),
            try reader.discardPending(),
        );
    }
}

test "reader decodes TID TIME CPU and kernel-padded RAW source" {
    const sample_type = perf_abi.PERF_SAMPLE_TID |
        perf_abi.PERF_SAMPLE_TIME |
        perf_abi.PERF_SAMPLE_CPU |
        perf_abi.PERF_SAMPLE_RAW;
    var ring = SyntheticRing{};
    ring.init(0, sample_type);
    var bytes = [_]u8{0} ** 40;
    putRecordHeader(&bytes, perf_abi.PERF_RECORD_SAMPLE, 0, bytes.len);
    putU32Little(&bytes, 8, 10);
    putU32Little(&bytes, 12, 11);
    putU64Little(&bytes, 16, 0x123456789abcdef0);
    putU32Little(&bytes, 24, 3);
    putU32Little(&bytes, 28, 0);
    putU32Little(&bytes, 32, 4);
    bytes[36] = 0xaa;
    bytes[37] = 0xbb;
    bytes[38] = 0xcc;
    bytes[39] = 0;
    ring.write(0, &bytes);
    ring.setHead(bytes.len);

    var reader = try ring.event.reader();
    defer reader.deinit();
    const record = (try reader.next()).?;
    const decoded = try reader.decode(record, &.{}, .{});
    switch (decoded) {
        .sample => |sample| {
            try std.testing.expectEqual(@as(?u32, 10), sample.pid);
            try std.testing.expectEqual(@as(?u32, 11), sample.tid);
            try std.testing.expectEqual(
                @as(?u64, 0x123456789abcdef0),
                sample.time,
            );
            try std.testing.expectEqual(@as(?u32, 3), sample.cpu);
            try std.testing.expectEqualSlices(
                u8,
                &.{ 0xaa, 0xbb, 0xcc, 0 },
                sample.raw.?,
            );
        },
        else => return error.TestUnexpectedResult,
    }
    try reader.commit(record);
}

test "reader drain reports samples losses opaque records and committed bytes" {
    var ring = SyntheticRing{};
    ring.init(0, 0);
    var records = [_]u8{0} ** 32;
    putRecordHeader(records[0..8], 55, 0, 8);
    putRecordHeader(
        records[8..],
        perf_abi.PERF_RECORD_LOST,
        0,
        24,
    );
    putU64Little(&records, 16, 9);
    putU64Little(&records, 24, 5);
    ring.write(0, &records);
    ring.setHead(records.len);

    const Visitor = struct {
        fn visit(count: *usize, _: DecodedRecord) !void {
            count.* += 1;
        }
    };
    var visits: usize = 0;
    var scratch: [24]u8 = undefined;
    var reader = try ring.event.reader();
    defer reader.deinit();
    const stats = try reader.drain(
        &scratch,
        .{},
        &visits,
        Visitor.visit,
    );
    try std.testing.expectEqual(@as(usize, 2), visits);
    try std.testing.expectEqual(@as(usize, 2), stats.records);
    try std.testing.expectEqual(@as(usize, 0), stats.samples);
    try std.testing.expectEqual(@as(usize, 1), stats.lost_records);
    try std.testing.expectEqual(@as(u64, 5), stats.lost_events);
    try std.testing.expectEqual(@as(usize, 1), stats.other_records);
    try std.testing.expectEqual(@as(u64, 32), stats.bytes_committed);
    try std.testing.expectEqual(@as(u64, 32), ring.publishedTail());
}

test "one reader lease blocks another reader and close" {
    FakeSystem.reset();
    var ring = SyntheticRing{};
    ring.init(0, 0);
    var reader = try ring.event.reader();
    try std.testing.expectError(error.ReaderActive, ring.event.reader());
    try std.testing.expectError(
        error.ReaderActive,
        ring.event.closeWith(FakeSystem),
    );
    reader.deinit();
    try ring.event.closeWith(FakeSystem);
    try ring.event.closeWith(FakeSystem);
    try std.testing.expectEqual(@as(usize, 1), FakeSystem.munmap_calls);
}

test "collector opens per-CPU groups controls leaders polls and cleans up" {
    FakeSystem.reset();
    const cpus = [_]i32{ 2, 5 };
    const configs = [_]TracepointConfig{
        .{ .tracepoint_id = 11 },
        .{
            .tracepoint_id = 12,
            .sample_period = 7,
            .exclude_kernel = true,
        },
    };
    var collector = Collector{};
    try collector.initWith(
        FakeSystem,
        std.testing.allocator,
        &cpus,
        &configs,
        .{ .data_pages = 1, .wakeup_events = 3 },
    );

    try std.testing.expectEqual(@as(usize, 4), FakeSystem.open_calls);
    try std.testing.expectEqualSlices(
        linux.fd_t,
        &.{ -1, 100, -1, 102 },
        FakeSystem.group_fds[0..4],
    );
    try std.testing.expectEqualSlices(i32, &.{ 2, 2, 5, 5 }, FakeSystem.cpus[0..4]);
    for (FakeSystem.open_flags[0..4]) |flags| {
        try std.testing.expectEqual(perf_abi.PERF_FLAG_FD_CLOEXEC, flags);
    }
    try std.testing.expectEqual(@as(u64, 11), FakeSystem.attrs[0].config);
    try std.testing.expectEqual(@as(u64, 12), FakeSystem.attrs[1].config);
    try std.testing.expectEqual(@as(u64, 7), FakeSystem.attrs[1].sample_period);
    try std.testing.expectEqual(@as(u32, 3), FakeSystem.attrs[0].wakeup_events);
    var first_event = (try collector.eventAt(0, 0)).?;
    var second_event = (try collector.eventAt(0, 1)).?;
    try std.testing.expect(
        first_event.get().mapping.? != second_event.get().mapping.?,
    );
    second_event.deinit();
    first_event.deinit();
    try std.testing.expect(
        FakeSystem.attrs[0].flags &
            (perf_abi.PerfEventAttrFlags{ .disabled = true }).bits() != 0,
    );
    try std.testing.expect(
        FakeSystem.attrs[1].flags &
            (perf_abi.PerfEventAttrFlags{ .exclude_kernel = true }).bits() != 0,
    );

    try collector.enableAllWith(FakeSystem);
    try collector.disableAllWith(FakeSystem);
    try collector.resetAllWith(FakeSystem);
    try std.testing.expectEqual(@as(usize, 6), FakeSystem.ioctl_calls);
    try std.testing.expectEqualSlices(
        linux.fd_t,
        &.{ 100, 102, 100, 102, 100, 102 },
        FakeSystem.ioctl_fds[0..6],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{
            perf_abi.PERF_EVENT_IOC_ENABLE,
            perf_abi.PERF_EVENT_IOC_ENABLE,
            perf_abi.PERF_EVENT_IOC_DISABLE,
            perf_abi.PERF_EVENT_IOC_DISABLE,
            perf_abi.PERF_EVENT_IOC_RESET,
            perf_abi.PERF_EVENT_IOC_RESET,
        },
        FakeSystem.ioctl_requests[0..6],
    );
    for (FakeSystem.ioctl_arguments[0..6]) |argument| {
        try std.testing.expectEqual(perf_abi.PERF_IOC_FLAG_GROUP, argument);
    }

    FakeSystem.ready_slot = 1;
    var ready = try collector.pollWith(FakeSystem, 10);
    try std.testing.expectEqual(@as(usize, 1), ready.count());
    const item = ready.next().?;
    try std.testing.expectEqual(@as(usize, 1), item.slot);
    try std.testing.expectEqual(@as(i32, 2), item.cpu);
    try std.testing.expectEqual(@as(u64, 12), item.tracepoint_id);
    try std.testing.expect(ready.next() == null);
    ready.deinit();

    try collector.closeWith(FakeSystem);
    try collector.closeWith(FakeSystem);
    try std.testing.expectEqual(@as(usize, 4), FakeSystem.munmap_calls);
    try std.testing.expectEqual(@as(usize, 4), FakeSystem.close_calls);
}

test "collector leases block teardown and serialize poll result access" {
    FakeSystem.reset();
    var collector = Collector{};
    try collector.initWith(
        FakeSystem,
        std.testing.allocator,
        &.{0},
        &.{.{ .tracepoint_id = 11 }},
        .{ .data_pages = 1 },
    );

    var event_lease = (try collector.eventAt(0, 0)).?;
    try std.testing.expectError(
        error.Busy,
        collector.closeWith(FakeSystem),
    );
    event_lease.deinit();

    var ready = try collector.pollWith(FakeSystem, 0);
    try std.testing.expectError(
        error.Busy,
        collector.pollWith(FakeSystem, 0),
    );
    try std.testing.expectError(
        error.Busy,
        collector.closeWith(FakeSystem),
    );
    ready.deinit();

    var reader = (try collector.readerAt(0, 0)).?;
    try std.testing.expectError(
        error.ReaderActive,
        collector.closeWith(FakeSystem),
    );
    reader.deinit();
    try collector.closeWith(FakeSystem);
}

test "finite poll surfaces interruption instead of restarting timeout" {
    FakeSystem.reset();
    var collector = Collector{};
    try collector.initWith(
        FakeSystem,
        std.testing.allocator,
        &.{0},
        &.{.{ .tracepoint_id = 11 }},
        .{ .data_pages = 1 },
    );
    defer collector.closeWith(FakeSystem) catch unreachable;

    FakeSystem.interrupt_poll = true;
    try std.testing.expectError(
        error.Interrupted,
        collector.pollWith(FakeSystem, 10),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeSystem.poll_calls);
}

test "collector rolls back every opened slot after a later open failure" {
    FakeSystem.reset();
    FakeSystem.fail_open_call = 2;
    const cpus = [_]i32{ 1, 4 };
    const configs = [_]TracepointConfig{
        .{ .tracepoint_id = 20 },
        .{ .tracepoint_id = 21 },
    };
    var collector = Collector{};
    try std.testing.expectError(
        error.PermissionDenied,
        collector.initWith(
            FakeSystem,
            std.testing.allocator,
            &cpus,
            &configs,
            .{ .data_pages = 1 },
        ),
    );
    try std.testing.expect(collector.events == null);
    try std.testing.expectEqual(@as(usize, 2), FakeSystem.munmap_calls);
    try std.testing.expectEqual(@as(usize, 2), FakeSystem.close_calls);
}

test "invalid runtime mmap metadata unmaps and closes the descriptor" {
    FakeSystem.reset();
    FakeSystem.bad_metadata_call = 0;
    var event = CpuEvent{};
    try std.testing.expectError(
        error.InvalidMmapMetadata,
        event.openWith(
            FakeSystem,
            .{ .tracepoint_id = 9 },
            0,
            -1,
            .{ .data_pages = 1 },
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), FakeSystem.munmap_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeSystem.close_calls);
    try std.testing.expect(!event.isOpen());
}

test {
    _ = perf_abi;
    _ = perf_data;
}
