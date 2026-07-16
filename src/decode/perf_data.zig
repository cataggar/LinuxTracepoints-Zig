//! Borrowed, seekable parser for normal-mode `PERFILE2` perf.data files.
//!
//! Feature payloads and unknown records remain opaque. Pipe reconstruction,
//! compression, AUX payload streaming, and symbolization are intentionally out
//! of scope.

const std = @import("std");
const bytes = @import("bytes.zig");

pub const Error = bytes.Error;
pub const Endian = bytes.Endian;
pub const Limits = bytes.Limits;

pub const pipe_header_size = 16;
pub const legacy_file_header_size = 72;
pub const file_header_size = 104;
pub const section_size = 16;
pub const perf_attr_size_ver0 = 64;
pub const record_header_size = 8;

pub const SourceWordSize = enum {
    auto,
    bits32,
    bits64,
};

pub const ParseOptions = struct {
    source_word_size: SourceWordSize = .auto,
};

pub const SampleType = struct {
    pub const ip: u64 = 1 << 0;
    pub const tid: u64 = 1 << 1;
    pub const time: u64 = 1 << 2;
    pub const addr: u64 = 1 << 3;
    pub const read: u64 = 1 << 4;
    pub const callchain: u64 = 1 << 5;
    pub const id: u64 = 1 << 6;
    pub const cpu: u64 = 1 << 7;
    pub const period: u64 = 1 << 8;
    pub const stream_id: u64 = 1 << 9;
    pub const raw: u64 = 1 << 10;
    pub const identifier: u64 = 1 << 16;

    pub const supported: u64 = identifier | ip | tid | time | addr |
        id | stream_id | cpu | period | raw;
    pub const unsupported_before_raw: u64 = read | callchain;
};

pub const RecordType = struct {
    pub const sample: u32 = 9;
    pub const auxtrace: u32 = 71;
};

pub const Section = struct {
    offset: u64,
    size: u64,
    data: []const u8,

    pub fn endOffset(self: Section) Error!u64 {
        if (self.size > std.math.maxInt(u64) - self.offset) {
            return error.IntegerOverflow;
        }
        return self.offset + self.size;
    }
};

pub const Header = struct {
    endian: Endian,
    size: u64,
    attr_size: u64,
    attrs: Section,
    data: Section,
    event_types: Section,
    feature_bitmap: [4]u64,
};

pub const File = struct {
    bytes_data: []const u8,
    header: Header,
    limits: Limits,
    attr_count: usize,
    attr_bytes_size: usize,
    feature_count: usize,
    feature_descriptors_offset: usize,

    pub fn parse(data: []const u8, limits: Limits) Error!File {
        return File.parseWithOptions(data, limits, .{});
    }

    pub fn parseWithOptions(
        data: []const u8,
        limits: Limits,
        options: ParseOptions,
    ) Error!File {
        if (data.len > limits.max_bytes) return error.LimitExceeded;
        if (data.len < pipe_header_size) return error.Truncated;

        const endian: Endian = if (std.mem.eql(u8, data[0..8], "PERFILE2"))
            .little
        else if (std.mem.eql(u8, data[0..8], "2ELIFREP"))
            .big
        else
            return error.InvalidFormat;

        var cursor = bytes.Cursor.init(data, endian);
        try cursor.skip(8);
        const header_size_u64 = try cursor.readU64();
        if (header_size_u64 == pipe_header_size) return error.UnsupportedPipeMode;
        if ((header_size_u64 != legacy_file_header_size and
            header_size_u64 < file_header_size) or header_size_u64 & 7 != 0)
        {
            return error.InvalidFormat;
        }
        const header_size = try bytes.checkedUsize(header_size_u64);
        if (header_size > data.len) return error.Truncated;

        const attr_entry_size_u64 = try cursor.readU64();
        const attrs = try readSection(&cursor, data);
        const data_section = try readSection(&cursor, data);
        const event_types = try readSection(&cursor, data);
        const feature_bitmap = if (header_size == legacy_file_header_size)
            [_]u64{0} ** 4
        else
            try normalizeFeatureBitmap(
                try bytes.checkedRange(
                    data,
                    legacy_file_header_size,
                    file_header_size - legacy_file_header_size,
                ),
                endian,
                options.source_word_size,
            );

        var attr_count: usize = 0;
        var attr_bytes_size: usize = 0;
        if (attrs.size != 0) {
            if (attr_entry_size_u64 < perf_attr_size_ver0 + section_size) {
                return error.InvalidSection;
            }
            if (attr_entry_size_u64 & 7 != 0) return error.InvalidSection;
            const attr_entry_size = try bytes.checkedUsize(attr_entry_size_u64);
            if (attrs.data.len % attr_entry_size != 0) return error.InvalidSection;
            attr_count = attrs.data.len / attr_entry_size;
            if (attr_count > limits.max_attrs) return error.LimitExceeded;
            attr_bytes_size = attr_entry_size - section_size;
        } else if (attr_entry_size_u64 != 0) {
            if (attr_entry_size_u64 < perf_attr_size_ver0 + section_size) {
                return error.InvalidSection;
            }
            if (attr_entry_size_u64 & 7 != 0) return error.InvalidSection;
            const attr_entry_size = try bytes.checkedUsize(attr_entry_size_u64);
            attr_bytes_size = attr_entry_size - section_size;
        }

        var feature_count: usize = 0;
        for (feature_bitmap) |word| {
            feature_count += @popCount(word);
        }
        if (feature_bitmap[0] & 1 != 0) return error.InvalidFormat;
        const counted_sections = try bytes.checkedAdd(
            try bytes.checkedAdd(3, attr_count),
            feature_count,
        );
        if (counted_sections > limits.max_sections) {
            return error.LimitExceeded;
        }
        const descriptor_bytes = try bytes.checkedMul(feature_count, section_size);
        const data_end_u64 = try data_section.endOffset();
        const feature_descriptors_offset = try bytes.checkedUsize(data_end_u64);
        _ = bytes.checkedRange(
            data,
            feature_descriptors_offset,
            descriptor_bytes,
        ) catch return error.InvalidSection;

        var file = File{
            .bytes_data = data,
            .header = .{
                .endian = endian,
                .size = header_size_u64,
                .attr_size = attr_entry_size_u64,
                .attrs = attrs,
                .data = data_section,
                .event_types = event_types,
                .feature_bitmap = feature_bitmap,
            },
            .limits = limits,
            .attr_count = attr_count,
            .attr_bytes_size = attr_bytes_size,
            .feature_count = feature_count,
            .feature_descriptors_offset = feature_descriptors_offset,
        };

        var attrs_iterator = file.attrIterator();
        var id_count: usize = 0;
        while (try attrs_iterator.next()) |attr| {
            id_count = try bytes.checkedAdd(id_count, attr.idCount());
            if (id_count > limits.max_items) return error.LimitExceeded;
        }
        var features = file.featureIterator();
        while (try features.next()) |_| {}

        return file;
    }

    pub fn attrIterator(self: *const File) AttrIterator {
        return .{ .file = self };
    }

    pub fn attrAt(self: *const File, index: usize) Error!AttrView {
        if (index >= self.attr_count) return error.InvalidSection;
        const entry_size = try bytes.checkedUsize(self.header.attr_size);
        const entry_offset = try bytes.checkedMul(index, entry_size);
        const entry = try bytes.checkedRange(
            self.header.attrs.data,
            entry_offset,
            entry_size,
        );
        const attr_bytes = entry[0..self.attr_bytes_size];
        if (attr_bytes.len < perf_attr_size_ver0) return error.InvalidSection;
        const raw_declared_size = try bytes.readIntAt(
            u32,
            attr_bytes,
            4,
            self.header.endian,
        );
        const declared_size = if (raw_declared_size == 0)
            perf_attr_size_ver0
        else
            raw_declared_size;
        if (declared_size < perf_attr_size_ver0 or declared_size > attr_bytes.len) {
            return error.InvalidSection;
        }

        var descriptor = bytes.Cursor.init(
            entry[self.attr_bytes_size..],
            self.header.endian,
        );
        const ids_section = try readSection(&descriptor, self.bytes_data);
        if (ids_section.offset & 7 != 0 or ids_section.size & 7 != 0) {
            return error.InvalidSection;
        }
        return .{
            .index = index,
            .bytes = attr_bytes,
            .declared_bytes = attr_bytes[0..declared_size],
            .declared_size = declared_size,
            .ids = ids_section.data,
            .endian = self.header.endian,
        };
    }

    pub fn featureIterator(self: *const File) FeatureIterator {
        return .{ .file = self };
    }

    pub fn recordIterator(self: *const File) RecordIterator {
        return .{
            .data = self.header.data.data,
            .endian = self.header.endian,
            .max_records = self.limits.max_records,
        };
    }
};

pub fn parse(data: []const u8, limits: Limits) Error!File {
    return File.parse(data, limits);
}

pub fn parseWithOptions(
    data: []const u8,
    limits: Limits,
    options: ParseOptions,
) Error!File {
    return File.parseWithOptions(data, limits, options);
}

pub const AttrView = struct {
    index: usize,
    bytes: []const u8,
    declared_bytes: []const u8,
    declared_size: u32,
    ids: []const u8,
    endian: Endian,

    pub fn eventType(self: AttrView) Error!u32 {
        return bytes.readIntAt(u32, self.declared_bytes, 0, self.endian);
    }

    pub fn declaredSize(self: AttrView) Error!u32 {
        return self.declared_size;
    }

    pub fn rawDeclaredSize(self: AttrView) Error!u32 {
        return bytes.readIntAt(u32, self.bytes, 4, self.endian);
    }

    pub fn config(self: AttrView) Error!u64 {
        return bytes.readIntAt(u64, self.declared_bytes, 8, self.endian);
    }

    pub fn samplePeriodOrFreq(self: AttrView) Error!u64 {
        return bytes.readIntAt(u64, self.declared_bytes, 16, self.endian);
    }

    pub fn sampleType(self: AttrView) Error!u64 {
        return bytes.readIntAt(u64, self.declared_bytes, 24, self.endian);
    }

    pub fn readFormat(self: AttrView) Error!u64 {
        return bytes.readIntAt(u64, self.declared_bytes, 32, self.endian);
    }

    pub fn options(self: AttrView) Error!u64 {
        if (self.endian == .little) {
            return bytes.readIntAt(u64, self.declared_bytes, 40, .little);
        }
        const bitfield = try bytes.checkedRange(self.declared_bytes, 40, 8);
        var result: u64 = 0;
        for (bitfield, 0..) |byte, index| {
            const shift: u6 = @intCast(index * 8);
            result |= @as(u64, @bitReverse(byte)) << shift;
        }
        return result;
    }

    pub fn idCount(self: AttrView) usize {
        return self.ids.len / 8;
    }

    pub fn idIterator(self: AttrView) IdIterator {
        return .{ .cursor = bytes.Cursor.init(self.ids, self.endian) };
    }
};

pub const AttrIterator = struct {
    file: *const File,
    index: usize = 0,

    pub fn next(self: *AttrIterator) Error!?AttrView {
        if (self.index == self.file.attr_count) return null;
        const result = try self.file.attrAt(self.index);
        self.index += 1;
        return result;
    }
};

pub const IdIterator = struct {
    cursor: bytes.Cursor,

    pub fn next(self: *IdIterator) Error!?u64 {
        if (self.cursor.atEnd()) return null;
        return @as(?u64, try self.cursor.readU64());
    }
};

pub const Feature = struct {
    index: u16,
    section: Section,
    data: []const u8,
};

pub const FeatureIterator = struct {
    file: *const File,
    bit_index: usize = 0,
    descriptor_index: usize = 0,

    pub fn next(self: *FeatureIterator) Error!?Feature {
        while (self.bit_index < 256) : (self.bit_index += 1) {
            const index = self.bit_index;
            const word = index / 64;
            const bit: u6 = @intCast(index % 64);
            if (self.file.header.feature_bitmap[word] & (@as(u64, 1) << bit) == 0) {
                continue;
            }
            self.bit_index += 1;
            const descriptor_offset = try bytes.checkedAdd(
                self.file.feature_descriptors_offset,
                try bytes.checkedMul(self.descriptor_index, section_size),
            );
            self.descriptor_index += 1;
            var cursor = bytes.Cursor.init(
                try bytes.checkedRange(
                    self.file.bytes_data,
                    descriptor_offset,
                    section_size,
                ),
                self.file.header.endian,
            );
            const section = try readSection(&cursor, self.file.bytes_data);
            return .{
                .index = @intCast(index),
                .section = section,
                .data = section.data,
            };
        }
        if (self.descriptor_index != self.file.feature_count) {
            return error.InvalidSection;
        }
        return null;
    }
};

pub const Record = struct {
    type: u32,
    misc: u16,
    size: u16,
    bytes: []const u8,
    payload: []const u8,

    pub fn isSample(self: Record) bool {
        return self.type == RecordType.sample;
    }
};

pub const RecordIterator = struct {
    data: []const u8,
    endian: Endian,
    max_records: usize,
    position: usize = 0,
    count: usize = 0,

    pub fn next(self: *RecordIterator) Error!?Record {
        if (self.position == self.data.len) return null;
        if (self.count >= self.max_records) return error.LimitExceeded;
        if (self.position > self.data.len or
            record_header_size > self.data.len - self.position)
        {
            return error.Truncated;
        }
        var cursor = bytes.Cursor.init(self.data[self.position..], self.endian);
        const record_type = try cursor.readU32();
        const misc = try cursor.readU16();
        const size = try cursor.readU16();
        if (size < record_header_size) return error.InvalidFormat;
        if (size > self.data.len - self.position) return error.Truncated;
        if (record_type == RecordType.auxtrace) {
            return error.UnsupportedLayout;
        }
        const record_bytes = self.data[self.position .. self.position + size];
        self.position += size;
        self.count += 1;
        return .{
            .type = record_type,
            .misc = misc,
            .size = size,
            .bytes = record_bytes,
            .payload = record_bytes[record_header_size..],
        };
    }
};

pub const Sample = struct {
    identifier: ?u64 = null,
    ip: ?u64 = null,
    pid: ?u32 = null,
    tid: ?u32 = null,
    time: ?u64 = null,
    addr: ?u64 = null,
    id: ?u64 = null,
    stream_id: ?u64 = null,
    cpu: ?u32 = null,
    cpu_reserved: ?u32 = null,
    period: ?u64 = null,
    raw: ?[]const u8 = null,
};

pub fn decodeSample(
    record: Record,
    attr: AttrView,
    limits: Limits,
) Error!Sample {
    if (!record.isSample()) return error.UnsupportedLayout;
    const sample_type = try attr.sampleType();
    if (sample_type & SampleType.unsupported_before_raw != 0) {
        return error.UnsupportedLayout;
    }
    if (sample_type & ~SampleType.supported != 0) {
        return error.UnsupportedLayout;
    }

    var result = Sample{};
    var cursor = bytes.Cursor.init(record.payload, attr.endian);
    if (sample_type & SampleType.identifier != 0) {
        result.identifier = try cursor.readU64();
    }
    if (sample_type & SampleType.ip != 0) result.ip = try cursor.readU64();
    if (sample_type & SampleType.tid != 0) {
        result.pid = try cursor.readU32();
        result.tid = try cursor.readU32();
    }
    if (sample_type & SampleType.time != 0) result.time = try cursor.readU64();
    if (sample_type & SampleType.addr != 0) result.addr = try cursor.readU64();
    if (sample_type & SampleType.id != 0) result.id = try cursor.readU64();
    if (sample_type & SampleType.stream_id != 0) {
        result.stream_id = try cursor.readU64();
    }
    if (sample_type & SampleType.cpu != 0) {
        result.cpu = try cursor.readU32();
        result.cpu_reserved = try cursor.readU32();
    }
    if (sample_type & SampleType.period != 0) result.period = try cursor.readU64();
    if (sample_type & SampleType.raw != 0) {
        const raw_size = try cursor.readU32();
        const raw_size_usize: usize = raw_size;
        if (raw_size_usize > limits.max_bytes) return error.LimitExceeded;
        result.raw = try cursor.readSlice(raw_size_usize);
        if (cursor.position & 7 != 0) return error.InvalidFormat;
    }
    if (!cursor.atEnd()) return error.InvalidFormat;
    return result;
}

pub const SessionIndex = struct {
    pub const Entry = struct {
        id: u64,
        attr: AttrView,
    };

    allocator: std.mem.Allocator,
    entries: []Entry,

    pub fn init(
        allocator: std.mem.Allocator,
        file: *const File,
        limits: Limits,
    ) Error!SessionIndex {
        var total: usize = 0;
        var attrs = file.attrIterator();
        while (try attrs.next()) |attr| {
            total = try bytes.checkedAdd(total, attr.idCount());
            if (total > limits.max_items) return error.LimitExceeded;
        }

        const entries = try allocator.alloc(Entry, total);
        errdefer allocator.free(entries);
        var entry_index: usize = 0;
        attrs = file.attrIterator();
        while (try attrs.next()) |attr| {
            var ids = attr.idIterator();
            while (try ids.next()) |id| {
                entries[entry_index] = .{ .id = id, .attr = attr };
                entry_index += 1;
            }
        }
        std.mem.sortUnstable(Entry, entries, {}, lessThanEntry);
        if (entries.len > 1) {
            for (entries[1..], entries[0 .. entries.len - 1]) |entry, previous| {
                if (entry.id == previous.id) return error.InvalidFormat;
            }
        }
        return .{ .allocator = allocator, .entries = entries };
    }

    pub fn deinit(self: *SessionIndex) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn find(self: *const SessionIndex, id: u64) ?AttrView {
        var begin: usize = 0;
        var end = self.entries.len;
        while (begin < end) {
            const middle = begin + (end - begin) / 2;
            if (self.entries[middle].id < id) {
                begin = middle + 1;
            } else {
                end = middle;
            }
        }
        return if (begin != self.entries.len and self.entries[begin].id == id)
            self.entries[begin].attr
        else
            null;
    }

    fn lessThanEntry(_: void, first: Entry, second: Entry) bool {
        return first.id < second.id;
    }
};

fn normalizeFeatureBitmap(
    raw: []const u8,
    endian: Endian,
    source_word_size: SourceWordSize,
) Error![4]u64 {
    var words64 = [_]u64{0} ** 4;
    for (&words64, 0..) |*word, index| {
        word.* = try bytes.readIntAt(u64, raw, index * 8, endian);
    }
    if (endian == .little or source_word_size == .bits64) return words64;

    var words32 = [_]u64{0} ** 4;
    for (0..8) |index| {
        const word = try bytes.readIntAt(u32, raw, index * 4, .big);
        const shift: u6 = @intCast((index % 2) * 32);
        words32[index / 2] |= @as(u64, word) << shift;
    }
    if (source_word_size == .bits32) return words32;
    if (std.mem.eql(u64, &words64, &words32)) return words64;

    const hostname_feature = 3;
    const hostname_mask = @as(u64, 1) << hostname_feature;
    const word64_has_hostname = words64[0] & hostname_mask != 0;
    const word32_has_hostname = words32[0] & hostname_mask != 0;
    if (word64_has_hostname != word32_has_hostname) {
        return if (word64_has_hostname) words64 else words32;
    }
    return error.AmbiguousLayout;
}

fn readSection(cursor: *bytes.Cursor, file_data: []const u8) Error!Section {
    const offset = try cursor.readU64();
    const size = try cursor.readU64();
    if (size > std.math.maxInt(u64) - offset) return error.IntegerOverflow;
    const offset_usize = try bytes.checkedUsize(offset);
    const size_usize = try bytes.checkedUsize(size);
    const section_data = bytes.checkedRange(file_data, offset_usize, size_usize) catch {
        return error.InvalidSection;
    };
    return .{ .offset = offset, .size = size, .data = section_data };
}

fn putU16(output: []u8, offset: usize, value: u16, endian: Endian) void {
    switch (endian) {
        .little => {
            output[offset] = @truncate(value);
            output[offset + 1] = @truncate(value >> 8);
        },
        .big => {
            output[offset] = @truncate(value >> 8);
            output[offset + 1] = @truncate(value);
        },
    }
}

fn putU32(output: []u8, offset: usize, value: u32, endian: Endian) void {
    switch (endian) {
        .little => for (0..4) |index| {
            output[offset + index] = @truncate(value >> @intCast(index * 8));
        },
        .big => for (0..4) |index| {
            output[offset + index] = @truncate(value >> @intCast((3 - index) * 8));
        },
    }
}

fn putU64(output: []u8, offset: usize, value: u64, endian: Endian) void {
    switch (endian) {
        .little => for (0..8) |index| {
            output[offset + index] = @truncate(value >> @intCast(index * 8));
        },
        .big => for (0..8) |index| {
            output[offset + index] = @truncate(value >> @intCast((7 - index) * 8));
        },
    }
}

fn putAttrOptions(
    output: []u8,
    offset: usize,
    value: u64,
    endian: Endian,
) void {
    if (endian == .little) {
        putU64(output, offset, value, .little);
        return;
    }
    for (0..8) |index| {
        const byte: u8 = @truncate(value >> @intCast(index * 8));
        output[offset + index] = @bitReverse(byte);
    }
}

const Fixture = struct {
    storage: [512]u8 = [_]u8{0} ** 512,
    length: usize = 0,

    fn init(endian: Endian, with_feature: bool) Fixture {
        var fixture = Fixture{};
        const sample_type = SampleType.identifier | SampleType.ip |
            SampleType.tid | SampleType.time | SampleType.addr | SampleType.id |
            SampleType.stream_id | SampleType.cpu | SampleType.period |
            SampleType.raw;
        const attrs_offset: usize = file_header_size;
        const attrs_size: usize = 80;
        const data_offset = attrs_offset + attrs_size;
        const data_size: usize = 88;
        const descriptor_offset: usize = data_offset + data_size;
        const ids_offset: usize =
            descriptor_offset + if (with_feature)
                @as(usize, section_size)
            else
                @as(usize, 0);
        const feature_offset: usize = ids_offset + 8;
        fixture.length = feature_offset + if (with_feature)
            @as(usize, 4)
        else
            @as(usize, 0);

        @memcpy(
            fixture.storage[0..8],
            if (endian == .little) "PERFILE2" else "2ELIFREP",
        );
        putU64(&fixture.storage, 8, file_header_size, endian);
        putU64(&fixture.storage, 16, attrs_size, endian);
        putU64(&fixture.storage, 24, attrs_offset, endian);
        putU64(&fixture.storage, 32, attrs_size, endian);
        putU64(&fixture.storage, 40, data_offset, endian);
        putU64(&fixture.storage, 48, data_size, endian);
        putU64(&fixture.storage, 56, 0, endian);
        putU64(&fixture.storage, 64, 0, endian);
        if (with_feature) putU64(&fixture.storage, 96, @as(u64, 1) << 8, endian);

        const attr = fixture.storage[attrs_offset .. attrs_offset + 64];
        putU32(attr, 0, 2, endian);
        putU32(attr, 4, 64, endian);
        putU64(attr, 8, 0x1122334455667788, endian);
        putU64(attr, 16, 1000, endian);
        putU64(attr, 24, sample_type, endian);
        putU64(attr, 32, 0, endian);
        putAttrOptions(attr, 40, 0x55aa, endian);
        putU64(&fixture.storage, attrs_offset + 64, ids_offset, endian);
        putU64(&fixture.storage, attrs_offset + 72, 8, endian);

        putU32(&fixture.storage, data_offset, RecordType.sample, endian);
        putU16(&fixture.storage, data_offset + 4, 0x1234, endian);
        putU16(&fixture.storage, data_offset + 6, data_size, endian);
        var position = data_offset + record_header_size;
        putU64(&fixture.storage, position, 0xaabbccdd, endian);
        position += 8;
        putU64(&fixture.storage, position, 0x1000, endian);
        position += 8;
        putU32(&fixture.storage, position, 10, endian);
        putU32(&fixture.storage, position + 4, 11, endian);
        position += 8;
        putU64(&fixture.storage, position, 12, endian);
        position += 8;
        putU64(&fixture.storage, position, 0x2000, endian);
        position += 8;
        putU64(&fixture.storage, position, 0xaabbccdd, endian);
        position += 8;
        putU64(&fixture.storage, position, 13, endian);
        position += 8;
        putU32(&fixture.storage, position, 3, endian);
        putU32(&fixture.storage, position + 4, 0, endian);
        position += 8;
        putU64(&fixture.storage, position, 14, endian);
        position += 8;
        putU32(&fixture.storage, position, 4, endian);
        fixture.storage[position + 4] = 0xaa;
        fixture.storage[position + 5] = 0xbb;
        fixture.storage[position + 6] = 0xcc;
        fixture.storage[position + 7] = 0xee;

        if (with_feature) {
            putU64(&fixture.storage, descriptor_offset, feature_offset, endian);
            putU64(&fixture.storage, descriptor_offset + 8, 4, endian);
            @memcpy(fixture.storage[feature_offset .. feature_offset + 4], "feat");
        }
        putU64(&fixture.storage, ids_offset, 0xaabbccdd, endian);
        return fixture;
    }

    fn bytes(self: *const Fixture) []const u8 {
        return self.storage[0..self.length];
    }
};

test "parses little-endian attrs IDs unknown feature records and sample order" {
    const fixture = Fixture.init(.little, true);
    const file = try parse(fixture.bytes(), .{});
    try std.testing.expectEqual(@as(usize, 1), file.attr_count);
    const attr = try file.attrAt(0);
    try std.testing.expectEqual(@as(u32, 2), try attr.eventType());
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try attr.config());
    try std.testing.expectEqual(@as(u64, 0x55aa), try attr.options());
    var ids = attr.idIterator();
    try std.testing.expectEqual(@as(u64, 0xaabbccdd), (try ids.next()).?);
    try std.testing.expect((try ids.next()) == null);

    var features = file.featureIterator();
    const feature = (try features.next()).?;
    try std.testing.expectEqual(@as(u16, 200), feature.index);
    try std.testing.expectEqualSlices(u8, "feat", feature.data);
    try std.testing.expect((try features.next()) == null);

    var records = file.recordIterator();
    const record = (try records.next()).?;
    try std.testing.expect(record.isSample());
    try std.testing.expect((try records.next()) == null);
    const sample = try decodeSample(record, attr, .{});
    try std.testing.expectEqual(@as(?u64, 0xaabbccdd), sample.identifier);
    try std.testing.expectEqual(@as(?u64, 0x1000), sample.ip);
    try std.testing.expectEqual(@as(?u32, 10), sample.pid);
    try std.testing.expectEqual(@as(?u32, 11), sample.tid);
    try std.testing.expectEqual(@as(?u64, 12), sample.time);
    try std.testing.expectEqual(@as(?u64, 0x2000), sample.addr);
    try std.testing.expectEqual(@as(?u64, 0xaabbccdd), sample.id);
    try std.testing.expectEqual(@as(?u64, 13), sample.stream_id);
    try std.testing.expectEqual(@as(?u32, 3), sample.cpu);
    try std.testing.expectEqual(@as(?u64, 14), sample.period);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xaa, 0xbb, 0xcc, 0xee },
        sample.raw.?,
    );

    var index = try SessionIndex.init(std.testing.allocator, &file, .{});
    defer index.deinit();
    try std.testing.expectEqual(@as(usize, 0), index.find(0xaabbccdd).?.index);

    var tiny_storage: [1]u8 = undefined;
    var tiny = std.heap.FixedBufferAllocator.init(&tiny_storage);
    try std.testing.expectError(
        error.OutOfMemory,
        SessionIndex.init(tiny.allocator(), &file, .{}),
    );
}

test "parses big-endian header attrs IDs and sample payload" {
    const fixture = Fixture.init(.big, true);
    const file = try parseWithOptions(
        fixture.bytes(),
        .{},
        .{ .source_word_size = .bits64 },
    );
    try std.testing.expectEqual(Endian.big, file.header.endian);
    const attr = try file.attrAt(0);
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try attr.config());
    try std.testing.expectEqual(@as(u64, 0x55aa), try attr.options());
    var features = file.featureIterator();
    const feature = (try features.next()).?;
    try std.testing.expectEqual(@as(u16, 200), feature.index);
    try std.testing.expectEqualSlices(u8, "feat", feature.data);
    var records = file.recordIterator();
    const sample = try decodeSample((try records.next()).?, attr, .{});
    try std.testing.expectEqual(@as(?u32, 10), sample.pid);
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xaa, 0xbb, 0xcc, 0xee },
        sample.raw.?,
    );
}

test "normalizes 32-bit and 64-bit big-endian feature bitmap words" {
    inline for (.{ SourceWordSize.bits32, SourceWordSize.bits64 }) |word_size| {
        var storage = [_]u8{0} ** 144;
        @memcpy(storage[0..8], "2ELIFREP");
        putU64(&storage, 8, file_header_size, .big);
        putU64(&storage, 40, file_header_size, .big);
        if (word_size == .bits32) {
            putU32(&storage, 72, @as(u32, 1) << 3, .big);
            putU32(&storage, 76, @as(u32, 1) << 8, .big);
        } else {
            putU64(
                &storage,
                72,
                (@as(u64, 1) << 3) | (@as(u64, 1) << 40),
                .big,
            );
        }
        putU64(&storage, 104, 136, .big);
        putU64(&storage, 112, 4, .big);
        putU64(&storage, 120, 140, .big);
        putU64(&storage, 128, 4, .big);
        @memcpy(storage[136..140], "host");
        @memcpy(storage[140..144], "feat");

        const file = try parse(&storage, .{});
        var features = file.featureIterator();
        const hostname = (try features.next()).?;
        try std.testing.expectEqual(@as(u16, 3), hostname.index);
        try std.testing.expectEqualSlices(u8, "host", hostname.data);
        const other = (try features.next()).?;
        try std.testing.expectEqual(@as(u16, 40), other.index);
        try std.testing.expectEqualSlices(u8, "feat", other.data);
        try std.testing.expect((try features.next()) == null);
    }
}

test "requires a source word size for ambiguous big-endian feature bitmaps" {
    var storage = [_]u8{0} ** 124;
    @memcpy(storage[0..8], "2ELIFREP");
    putU64(&storage, 8, file_header_size, .big);
    putU64(&storage, 40, file_header_size, .big);
    putU32(&storage, 72, @as(u32, 1) << 8, .big);
    putU64(&storage, 104, 120, .big);
    putU64(&storage, 112, 4, .big);
    @memcpy(storage[120..124], "feat");

    try std.testing.expectError(error.AmbiguousLayout, parse(&storage, .{}));
    const file = try parseWithOptions(
        &storage,
        .{},
        .{ .source_word_size = .bits32 },
    );
    var features = file.featureIterator();
    try std.testing.expectEqual(@as(u16, 8), (try features.next()).?.index);
    try std.testing.expect((try features.next()) == null);
}

test "accepts historical headers and normalizes ABI0 attr size" {
    var historical = [_]u8{0} ** legacy_file_header_size;
    @memcpy(historical[0..8], "PERFILE2");
    putU64(&historical, 8, legacy_file_header_size, .little);
    const old_file = try parse(&historical, .{});
    try std.testing.expectEqual(
        [_]u64{0} ** 4,
        old_file.header.feature_bitmap,
    );
    var old_features = old_file.featureIterator();
    try std.testing.expect((try old_features.next()) == null);

    var fixture = Fixture.init(.little, false);
    putU32(&fixture.storage, file_header_size + 4, 0, .little);
    const file = try parse(fixture.bytes(), .{});
    const attr = try file.attrAt(0);
    try std.testing.expectEqual(@as(u32, 0), try attr.rawDeclaredSize());
    try std.testing.expectEqual(
        @as(u32, perf_attr_size_ver0),
        try attr.declaredSize(),
    );
    try std.testing.expectEqual(@as(u64, 0x1122334455667788), try attr.config());
}

test "PERF_SAMPLE_RAW declared bytes include ABI alignment" {
    var fixture = Fixture.init(.little, false);
    const file = try parse(fixture.bytes(), .{});
    const attr = try file.attrAt(0);
    var records = file.recordIterator();
    const sample = try decodeSample((try records.next()).?, attr, .{});
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0xaa, 0xbb, 0xcc, 0xee },
        sample.raw.?,
    );

    const raw_size_offset = file_header_size + 80 + 8 + 72;
    putU32(&fixture.storage, raw_size_offset, 3, .little);
    const malformed_file = try parse(fixture.bytes(), .{});
    const malformed_attr = try malformed_file.attrAt(0);
    var malformed_records = malformed_file.recordIterator();
    try std.testing.expectError(
        error.InvalidFormat,
        decodeSample(
            (try malformed_records.next()).?,
            malformed_attr,
            .{},
        ),
    );
}

test "recognizes pipe mode section overflow and unsupported sample prefixes" {
    var pipe = [_]u8{0} ** 16;
    @memcpy(pipe[0..8], "PERFILE2");
    putU64(&pipe, 8, pipe_header_size, .little);
    try std.testing.expectError(error.UnsupportedPipeMode, parse(&pipe, .{}));

    var overflow = [_]u8{0} ** file_header_size;
    @memcpy(overflow[0..8], "PERFILE2");
    putU64(&overflow, 8, file_header_size, .little);
    putU64(&overflow, 16, 80, .little);
    putU64(&overflow, 40, std.math.maxInt(u64), .little);
    putU64(&overflow, 48, 2, .little);
    try std.testing.expectError(error.IntegerOverflow, parse(&overflow, .{}));

    var invalid_section = [_]u8{0} ** file_header_size;
    @memcpy(invalid_section[0..8], "PERFILE2");
    putU64(&invalid_section, 8, file_header_size, .little);
    putU64(&invalid_section, 16, 80, .little);
    putU64(&invalid_section, 56, file_header_size, .little);
    putU64(&invalid_section, 64, 1, .little);
    try std.testing.expectError(
        error.InvalidSection,
        parse(&invalid_section, .{}),
    );

    var fixture = Fixture.init(.little, false);
    const attrs_offset = file_header_size;
    const sample_type = SampleType.identifier | SampleType.read | SampleType.raw;
    putU64(&fixture.storage, attrs_offset + 24, sample_type, .little);
    const file = try parse(fixture.bytes(), .{});
    const attr = try file.attrAt(0);
    var records = file.recordIterator();
    try std.testing.expectError(
        error.UnsupportedLayout,
        decodeSample((try records.next()).?, attr, .{}),
    );
}

test "record and arbitrary-byte parsing are bounded and make progress" {
    const bad_record = [_]u8{ 9, 0, 0, 0, 0, 0, 7, 0 };
    var records = RecordIterator{
        .data = &bad_record,
        .endian = .little,
        .max_records = 1,
    };
    try std.testing.expectError(error.InvalidFormat, records.next());

    const unknown_record = [_]u8{ 123, 0, 0, 0, 0, 0, 8, 0 };
    records = .{
        .data = &unknown_record,
        .endian = .little,
        .max_records = 1,
    };
    const unknown_view = (try records.next()).?;
    try std.testing.expectEqual(@as(u32, 123), unknown_view.type);
    try std.testing.expectEqual(@as(usize, 0), unknown_view.payload.len);

    var data: [160]u8 = undefined;
    var seed: u32 = 7;
    for (&data) |*byte| {
        seed = seed *% 1664525 +% 1013904223;
        byte.* = @truncate(seed >> 24);
    }
    for (0..data.len + 1) |length| {
        if (parse(
            data[0..length],
            .{
                .max_bytes = data.len,
                .max_sections = 8,
                .max_attrs = 8,
                .max_records = 8,
                .max_items = 16,
            },
        )) |file| {
            var iterator = file.recordIterator();
            var count: usize = 0;
            while (count < 9) : (count += 1) {
                if (iterator.next()) |record| {
                    if (record == null) break;
                } else |_| break;
            }
            try std.testing.expect(count < 9);
        } else |_| {}
    }
}
