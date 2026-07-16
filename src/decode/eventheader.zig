//! Allocation-free decoder for the EventHeader envelope and payload metadata.

const std = @import("std");
const bytes = @import("bytes.zig");

pub const Error = bytes.Error;
pub const Endian = bytes.Endian;
pub const Limits = bytes.Limits;

pub const header_size = 8;
pub const extension_header_size = 4;
pub const hard_max_depth = 32;

pub const Flags = struct {
    pub const pointer64: u8 = 0x01;
    pub const little_endian: u8 = 0x02;
    pub const extension: u8 = 0x04;
    pub const known: u8 = pointer64 | little_endian | extension;
};

pub const ExtensionKind = struct {
    pub const metadata: u16 = 1;
    pub const activity: u16 = 2;
    pub const chain: u16 = 0x8000;
    pub const value_mask: u16 = 0x7fff;
};

pub const Encoding = enum(u8) {
    structure = 1,
    value8 = 2,
    value16 = 3,
    value32 = 4,
    value64 = 5,
    value128 = 6,
    zstring_char8 = 7,
    zstring_char16 = 8,
    zstring_char32 = 9,
    string_length16_char8 = 10,
    string_length16_char16 = 11,
    string_length16_char32 = 12,
    binary_length16_char8 = 13,
};

pub const Format = enum(u8) {
    default = 0,
    unsigned_int = 1,
    signed_int = 2,
    hex_int = 3,
    errno = 4,
    pid = 5,
    time = 6,
    boolean = 7,
    float = 8,
    hex_bytes = 9,
    string8 = 10,
    string_utf = 11,
    string_utf_bom = 12,
    string_xml = 13,
    string_json = 14,
    uuid = 15,
    port = 16,
    ip_address = 17,
    ip_address_obsolete = 18,
    _,
};

pub const Array = union(enum) {
    scalar,
    fixed: u16,
    variable,
};

pub const Header = struct {
    flags: u8,
    version: u8,
    id: u16,
    tag: u16,
    opcode: u8,
    level: u8,
    endian: Endian,
    pointer_size: u8,
};

pub const Activity = struct {
    id: []const u8,
    related_id: ?[]const u8,
};

pub const MetadataField = struct {
    attributed_name: []const u8,
    name: []const u8,
    encoding: Encoding,
    /// Format value exactly as declared in metadata.
    format: Format,
    raw_format: u8,
    /// Supported semantic format after applying encoding defaults.
    effective_format: Format,
    tag: u16,
    array: Array,
    child_count: u8,
    depth: usize = 0,
};

pub const Metadata = struct {
    data: []const u8,
    attributed_name: []const u8,
    name: []const u8,
    fields_data: []const u8,
    endian: Endian,

    pub fn fieldIterator(self: Metadata, limits: Limits) Error!FieldIterator {
        if (limits.max_depth > hard_max_depth) {
            // Larger limits remain usable; the fixed stack is the actual ceiling.
        }
        return .{
            .metadata = self,
            .limits = limits,
        };
    }
};

pub const ExtensionClass = enum {
    metadata,
    activity,
    unknown,
};

pub const Extension = struct {
    kind: u16,
    chained: bool,
    class: ExtensionClass,
    data: []const u8,
};

pub const Event = struct {
    data: []const u8,
    header: Header,
    extensions_data: []const u8,
    metadata: ?Metadata,
    activity: ?Activity,
    payload: []const u8,
    limits: Limits,

    pub fn parse(data: []const u8, limits: Limits) Error!Event {
        if (data.len > limits.max_bytes) return error.LimitExceeded;
        const header = try parseHeader(data);
        const flags = header.flags;
        const endian = header.endian;
        var cursor = bytes.Cursor.init(data, endian);
        cursor.position = header_size;

        var metadata: ?Metadata = null;
        var activity: ?Activity = null;
        const extension_start = cursor.position;
        var extension_end = extension_start;
        if (flags & Flags.extension != 0) {
            var extension_count: usize = 0;
            while (true) {
                if (extension_count >= limits.max_extensions) {
                    return error.LimitExceeded;
                }
                const current_extension_start = cursor.position;
                const size = try cursor.readU16();
                const raw_kind = try cursor.readU16();
                const kind = raw_kind & ExtensionKind.value_mask;
                const chained = raw_kind & ExtensionKind.chain != 0;
                if (kind == 0) return error.InvalidFormat;
                if (try extensionKindSeen(
                    data[extension_start..current_extension_start],
                    endian,
                    kind,
                )) {
                    return error.InvalidFormat;
                }
                extension_count += 1;

                const extension_data = try cursor.readSlice(size);
                switch (kind) {
                    ExtensionKind.metadata => {
                        metadata = try parseMetadata(extension_data, endian, limits);
                    },
                    ExtensionKind.activity => {
                        if (extension_data.len != 16 and extension_data.len != 32) {
                            return error.InvalidFormat;
                        }
                        activity = .{
                            .id = extension_data[0..16],
                            .related_id = if (extension_data.len == 32)
                                extension_data[16..32]
                            else
                                null,
                        };
                    },
                    else => {},
                }
                extension_end = cursor.position;
                if (!chained) break;
            }
        }

        return .{
            .data = data,
            .header = header,
            .extensions_data = data[extension_start..extension_end],
            .metadata = metadata,
            .activity = activity,
            .payload = data[extension_end..],
            .limits = limits,
        };
    }

    pub fn extensionIterator(self: Event) ExtensionIterator {
        return .{
            .cursor = bytes.Cursor.init(self.extensions_data, self.header.endian),
        };
    }

    pub fn payloadIterator(self: Event) Error!PayloadIterator {
        const metadata = self.metadata orelse return error.MetadataMissing;
        if (self.limits.max_depth > hard_max_depth) {
            // The configured value is allowed; malformed data still cannot exceed
            // the fixed, documented implementation ceiling.
        }
        return .{
            .metadata = metadata,
            .payload = self.payload,
            .limits = self.limits,
            .endian = self.header.endian,
        };
    }
};

pub fn parse(data: []const u8, limits: Limits) Error!Event {
    return Event.parse(data, limits);
}

pub fn parseHeader(data: []const u8) Error!Header {
    if (data.len < header_size) return error.Truncated;
    const flags = data[0];
    if (flags & ~Flags.known != 0) return error.UnsupportedLayout;
    const endian: Endian = if (flags & Flags.little_endian != 0)
        .little
    else
        .big;
    var cursor = bytes.Cursor.init(data[0..header_size], endian);
    return .{
        .flags = try cursor.readByte(),
        .version = try cursor.readByte(),
        .id = try cursor.readU16(),
        .tag = try cursor.readU16(),
        .opcode = try cursor.readByte(),
        .level = try cursor.readByte(),
        .endian = endian,
        .pointer_size = if (flags & Flags.pointer64 != 0) 8 else 4,
    };
}

pub const ExtensionIterator = struct {
    cursor: bytes.Cursor,

    pub fn next(self: *ExtensionIterator) Error!?Extension {
        if (self.cursor.atEnd()) return null;
        const size = try self.cursor.readU16();
        const raw_kind = try self.cursor.readU16();
        const kind = raw_kind & ExtensionKind.value_mask;
        if (kind == 0) return error.InvalidFormat;
        return .{
            .kind = kind,
            .chained = raw_kind & ExtensionKind.chain != 0,
            .class = switch (kind) {
                ExtensionKind.metadata => .metadata,
                ExtensionKind.activity => .activity,
                else => .unknown,
            },
            .data = try self.cursor.readSlice(size),
        };
    }
};

pub const FieldIterator = struct {
    metadata: Metadata,
    limits: Limits,
    position: usize = 0,
    field_count: usize = 0,
    stack: [hard_max_depth]usize = undefined,
    stack_len: usize = 0,

    pub fn next(self: *FieldIterator) Error!?MetadataField {
        while (self.stack_len != 0 and self.stack[self.stack_len - 1] == 0) {
            self.stack_len -= 1;
        }
        if (self.position == self.metadata.fields_data.len) {
            self.stack_len = 0;
            return null;
        }
        if (self.stack_len != 0) self.stack[self.stack_len - 1] -= 1;

        var parsed = try parseFieldAt(
            self.metadata.fields_data,
            self.position,
            self.metadata.endian,
        );
        self.position = parsed.next;
        parsed.field.depth = self.stack_len;
        self.field_count = try bytes.checkedAdd(self.field_count, 1);
        if (self.field_count > self.limits.max_fields or
            self.field_count > self.limits.max_items)
        {
            return error.LimitExceeded;
        }

        if (parsed.field.encoding == .structure) {
            const child_depth = try bytes.checkedAdd(self.stack_len, 1);
            if (child_depth > self.limits.max_depth or child_depth > hard_max_depth) {
                return error.LimitExceeded;
            }
            self.stack[self.stack_len] = parsed.field.child_count;
            self.stack_len += 1;
        }
        return parsed.field;
    }
};

pub const Integer = union(enum) {
    unsigned: u64,
    signed: i64,
};

pub const PayloadItemKind = enum {
    value,
    array,
    structure_begin,
    structure_end,
};

pub const PayloadItem = struct {
    field: MetadataField,
    kind: PayloadItemKind,
    depth: usize,
    array_index: ?usize,
    count: usize,
    raw: []const u8,
    integer: ?Integer,
};

const FrameState = enum {
    begin,
    fields,
    end,
};

const StructFrame = struct {
    field: MetadataField,
    schema_start: usize,
    schema_end: usize,
    schema_position: usize,
    child_count: usize,
    children_done: usize,
    instance_count: usize,
    instance_index: usize,
    state: FrameState,
};

const ComplexArray = struct {
    field: MetadataField,
    element_count: usize,
    next_index: usize,
};

pub const PayloadIterator = struct {
    metadata: Metadata,
    payload: []const u8,
    limits: Limits,
    endian: Endian,
    metadata_position: usize = 0,
    payload_position: usize = 0,
    work_count: usize = 0,
    complex_array: ?ComplexArray = null,
    stack: [hard_max_depth]StructFrame = undefined,
    stack_len: usize = 0,

    pub fn next(self: *PayloadIterator) Error!?PayloadItem {
        while (true) {
            if (self.complex_array) |*array| {
                if (array.next_index == array.element_count) {
                    self.complex_array = null;
                    continue;
                }
                const index = array.next_index;
                const item = try self.decodeComplexArrayElement(
                    array.field,
                    index,
                    array.element_count,
                );
                array.next_index += 1;
                return item;
            }

            if (self.stack_len != 0) {
                var frame = &self.stack[self.stack_len - 1];
                switch (frame.state) {
                    .begin => {
                        try self.spendWork();
                        frame.state = if (frame.instance_count == 0) .end else .fields;
                        return .{
                            .field = frame.field,
                            .kind = .structure_begin,
                            .depth = frame.field.depth,
                            .array_index = structureArrayIndex(frame),
                            .count = frame.instance_count,
                            .raw = "",
                            .integer = null,
                        };
                    },
                    .fields => {
                        if (frame.schema_position == frame.schema_end) {
                            frame.state = .end;
                            continue;
                        }
                        if (frame.children_done == frame.child_count) {
                            if (frame.schema_position != frame.schema_end) {
                                return error.InvalidFormat;
                            }
                            frame.state = .end;
                            continue;
                        }
                        try self.spendWork();
                        var parsed = try parseFieldAt(
                            self.metadata.fields_data,
                            frame.schema_position,
                            self.endian,
                        );
                        parsed.field.depth = frame.field.depth + 1;
                        frame.children_done += 1;
                        if (parsed.field.encoding == .structure) {
                            const child_end = try skipFields(
                                self.metadata.fields_data,
                                parsed.next,
                                parsed.field.child_count,
                                parsed.field.depth + 1,
                                self.endian,
                                self.limits,
                                &self.work_count,
                            );
                            frame.schema_position = child_end;
                            try self.pushStructure(parsed.field, parsed.next, child_end);
                            continue;
                        }
                        frame.schema_position = parsed.next;
                        return try self.decodeValue(parsed.field);
                    },
                    .end => {
                        try self.spendWork();
                        const result = PayloadItem{
                            .field = frame.field,
                            .kind = .structure_end,
                            .depth = frame.field.depth,
                            .array_index = structureArrayIndex(frame),
                            .count = frame.instance_count,
                            .raw = "",
                            .integer = null,
                        };
                        if (frame.instance_count == 0 or
                            frame.instance_index + 1 == frame.instance_count)
                        {
                            self.stack_len -= 1;
                        } else {
                            frame.instance_index += 1;
                            frame.schema_position = frame.schema_start;
                            frame.children_done = 0;
                            frame.state = .begin;
                        }
                        return result;
                    },
                }
            }

            if (self.metadata_position == self.metadata.fields_data.len) return null;
            try self.spendWork();
            var parsed = try parseFieldAt(
                self.metadata.fields_data,
                self.metadata_position,
                self.endian,
            );
            parsed.field.depth = 0;
            if (parsed.field.encoding == .structure) {
                const child_end = try skipFields(
                    self.metadata.fields_data,
                    parsed.next,
                    parsed.field.child_count,
                    1,
                    self.endian,
                    self.limits,
                    &self.work_count,
                );
                self.metadata_position = child_end;
                try self.pushStructure(parsed.field, parsed.next, child_end);
                continue;
            }
            self.metadata_position = parsed.next;
            return try self.decodeValue(parsed.field);
        }
    }

    pub fn remainingPayload(self: *const PayloadIterator) []const u8 {
        return self.payload[self.payload_position..];
    }

    fn pushStructure(
        self: *PayloadIterator,
        field: MetadataField,
        schema_start: usize,
        schema_end: usize,
    ) Error!void {
        if (self.stack_len >= self.limits.max_depth or
            self.stack_len >= hard_max_depth)
        {
            return error.LimitExceeded;
        }
        const count = try self.readArrayCount(field.array);
        self.stack[self.stack_len] = .{
            .field = field,
            .schema_start = schema_start,
            .schema_end = schema_end,
            .schema_position = schema_start,
            .child_count = field.child_count,
            .children_done = 0,
            .instance_count = count,
            .instance_index = 0,
            .state = .begin,
        };
        self.stack_len += 1;
    }

    fn decodeValue(
        self: *PayloadIterator,
        field: MetadataField,
    ) Error!PayloadItem {
        if (field.encoding == .structure) return error.InvalidFormat;

        if (isComplexEncoding(field.encoding)) {
            const count = try self.readArrayCount(field.array);
            if (field.array == .scalar) {
                try self.spendWork();
                const value = try self.readComplexValue(field);
                return .{
                    .field = value.field,
                    .kind = .value,
                    .depth = field.depth,
                    .array_index = null,
                    .count = value.unit_count,
                    .raw = value.raw,
                    .integer = try decodeInteger(
                        value.raw,
                        self.endian,
                        value.field.effective_format,
                    ),
                };
            }

            if (count == 0) {
                try self.spendWork();
                return .{
                    .field = field,
                    .kind = .array,
                    .depth = field.depth,
                    .array_index = null,
                    .count = 0,
                    .raw = "",
                    .integer = null,
                };
            }

            const first = try self.decodeComplexArrayElement(field, 0, count);
            self.complex_array = .{
                .field = field,
                .element_count = count,
                .next_index = 1,
            };
            return first;
        }

        const element_size: usize = switch (field.encoding) {
            .value8 => 1,
            .value16 => 2,
            .value32 => 4,
            .value64 => 8,
            .value128 => 16,
            else => return error.UnsupportedEncoding,
        };
        const count = try self.readArrayCount(field.array);
        const length = try bytes.checkedMul(element_size, count);
        try self.spendWork();
        const raw = try self.readPayload(length);
        var integer: ?Integer = null;
        if (field.array == .scalar and element_size <= 8) {
            integer = try decodeInteger(
                raw,
                self.endian,
                field.effective_format,
            );
        }
        return .{
            .field = field,
            .kind = if (field.array == .scalar) .value else .array,
            .depth = field.depth,
            .array_index = null,
            .count = count,
            .raw = raw,
            .integer = integer,
        };
    }

    fn decodeComplexArrayElement(
        self: *PayloadIterator,
        field: MetadataField,
        index: usize,
        count: usize,
    ) Error!PayloadItem {
        try self.spendWork();
        const value = try self.readComplexValue(field);
        return .{
            .field = value.field,
            .kind = .array,
            .depth = field.depth,
            .array_index = index,
            .count = count,
            .raw = value.raw,
            .integer = try decodeInteger(
                value.raw,
                self.endian,
                value.field.effective_format,
            ),
        };
    }

    const ComplexValue = struct {
        field: MetadataField,
        raw: []const u8,
        unit_count: usize,
    };

    fn readComplexValue(
        self: *PayloadIterator,
        original_field: MetadataField,
    ) Error!ComplexValue {
        var field = original_field;
        const unit_size: usize = switch (field.encoding) {
            .zstring_char8, .string_length16_char8, .binary_length16_char8 => 1,
            .zstring_char16, .string_length16_char16 => 2,
            .zstring_char32, .string_length16_char32 => 4,
            else => return error.UnsupportedEncoding,
        };

        var raw: []const u8 = undefined;
        var unit_count: usize = undefined;
        switch (field.encoding) {
            .zstring_char8, .zstring_char16, .zstring_char32 => {
                const start = self.payload_position;
                if (start > self.payload.len) return error.Truncated;
                const remaining = self.payload.len - start;
                var byte_count: usize = 0;
                while (byte_count <= remaining and
                    unit_size <= remaining - byte_count)
                {
                    const unit = self.payload[start + byte_count .. start + byte_count + unit_size];
                    var is_zero = true;
                    for (unit) |byte| is_zero = is_zero and byte == 0;
                    if (is_zero) {
                        raw = self.payload[start .. start + byte_count];
                        self.payload_position = start + byte_count + unit_size;
                        unit_count = byte_count / unit_size;
                        break;
                    }
                    byte_count += unit_size;
                } else return error.Truncated;
            },
            .string_length16_char8,
            .string_length16_char16,
            .string_length16_char32,
            .binary_length16_char8,
            => {
                if (self.payload_position > self.payload.len or
                    self.payload.len - self.payload_position < 2)
                {
                    return error.Truncated;
                }
                var length_cursor = bytes.Cursor.init(
                    self.payload[self.payload_position .. self.payload_position + 2],
                    self.endian,
                );
                unit_count = try length_cursor.readU16();
                const byte_count = try bytes.checkedMul(unit_count, unit_size);
                const total = try bytes.checkedAdd(2, byte_count);
                const encoded = try self.readPayload(total);
                raw = encoded[2..];
            },
            else => unreachable,
        }

        if (field.encoding == .string_length16_char8 or
            field.encoding == .binary_length16_char8)
        {
            field.effective_format = dynamicEffectiveFormat(field, raw.len);
        }
        return .{
            .field = field,
            .raw = raw,
            .unit_count = unit_count,
        };
    }

    fn readArrayCount(self: *PayloadIterator, array: Array) Error!usize {
        return switch (array) {
            .scalar => 1,
            .fixed => |count| count,
            .variable => try self.readPayloadU16(),
        };
    }

    fn readPayloadU16(self: *PayloadIterator) Error!u16 {
        const raw = try self.readPayload(2);
        var cursor = bytes.Cursor.init(raw, self.endian);
        return cursor.readU16();
    }

    fn readPayload(self: *PayloadIterator, length: usize) Error![]const u8 {
        if (self.payload_position > self.payload.len or
            length > self.payload.len - self.payload_position)
        {
            return error.Truncated;
        }
        const start = self.payload_position;
        self.payload_position += length;
        return self.payload[start..self.payload_position];
    }

    fn spendWork(self: *PayloadIterator) Error!void {
        if (self.work_count >= self.limits.max_items) {
            return error.LimitExceeded;
        }
        self.work_count += 1;
    }
};

const ParsedField = struct {
    field: MetadataField,
    next: usize,
};

fn parseMetadata(data: []const u8, endian: Endian, limits: Limits) Error!Metadata {
    var cursor = bytes.Cursor.init(data, endian);
    const attributed_name = try cursor.readUntilByte(0);
    const name = baseName(attributed_name);
    if (name.len == 0) return error.InvalidFormat;
    const metadata = Metadata{
        .data = data,
        .attributed_name = attributed_name,
        .name = name,
        .fields_data = data[cursor.position..],
        .endian = endian,
    };
    var iterator = try metadata.fieldIterator(limits);
    while (try iterator.next()) |_| {}
    return metadata;
}

fn extensionKindSeen(
    extensions: []const u8,
    endian: Endian,
    wanted: u16,
) Error!bool {
    var cursor = bytes.Cursor.init(extensions, endian);
    while (!cursor.atEnd()) {
        const size = try cursor.readU16();
        const raw_kind = try cursor.readU16();
        if (raw_kind & ExtensionKind.value_mask == wanted) return true;
        try cursor.skip(size);
    }
    return false;
}

fn parseFieldAt(data: []const u8, position: usize, endian: Endian) Error!ParsedField {
    if (position > data.len) return error.Truncated;
    var cursor = bytes.Cursor.init(data, endian);
    cursor.position = position;

    const attributed_name = try cursor.readUntilByte(0);
    const name = baseName(attributed_name);
    if (name.len == 0) return error.InvalidFormat;
    const encoded = try cursor.readByte();
    const raw_encoding = encoded & 0x1f;
    const array_bits = encoded & 0x60;
    if (array_bits == 0x60) return error.UnsupportedLayout;

    const encoding: Encoding = switch (raw_encoding) {
        1 => .structure,
        2 => .value8,
        3 => .value16,
        4 => .value32,
        5 => .value64,
        6 => .value128,
        7 => .zstring_char8,
        8 => .zstring_char16,
        9 => .zstring_char32,
        10 => .string_length16_char8,
        11 => .string_length16_char16,
        12 => .string_length16_char32,
        13 => .binary_length16_char8,
        else => return error.UnsupportedEncoding,
    };

    var raw_format: u8 = 0;
    var tag: u16 = 0;
    if (encoded & 0x80 != 0) {
        const format_and_tag = try cursor.readByte();
        raw_format = format_and_tag & 0x7f;
        if (format_and_tag & 0x80 != 0) tag = try cursor.readU16();
    }

    const child_count: u8 = if (encoding == .structure) raw_format else 0;
    if (encoding == .structure and (encoded & 0x80 == 0 or child_count == 0)) {
        return error.InvalidFormat;
    }
    const format: Format = if (encoding == .structure)
        .default
    else
        @enumFromInt(raw_format);
    const effective_format = if (encoding == .structure)
        Format.default
    else
        normalizeFormat(encoding, format);

    const array: Array = switch (array_bits) {
        0 => .scalar,
        0x20 => blk: {
            const count = try cursor.readU16();
            if (count == 0) return error.InvalidFormat;
            break :blk .{ .fixed = count };
        },
        0x40 => .variable,
        else => unreachable,
    };

    return .{
        .field = .{
            .attributed_name = attributed_name,
            .name = name,
            .encoding = encoding,
            .format = format,
            .raw_format = raw_format,
            .effective_format = effective_format,
            .tag = tag,
            .array = array,
            .child_count = child_count,
        },
        .next = cursor.position,
    };
}

fn formatCompatible(encoding: Encoding, format: Format) bool {
    if (format == .default) return true;
    if (!isKnownFormat(format)) return false;
    if (encoding == .string_length16_char8 or
        encoding == .binary_length16_char8)
    {
        return true;
    }
    const is_numeric = encoding == .value8 or encoding == .value16 or
        encoding == .value32 or encoding == .value64;
    return switch (format) {
        .default => true,
        .unsigned_int, .signed_int, .hex_int => is_numeric,
        .errno, .pid => encoding == .value32,
        .time => encoding == .value32 or encoding == .value64,
        .boolean => encoding == .value8 or
            encoding == .value16 or
            encoding == .value32,
        .float => encoding == .value32 or encoding == .value64,
        .hex_bytes => encoding != .structure,
        .string8 => encoding == .value8 or encoding == .zstring_char8,
        .string_utf => encoding == .value16 or encoding == .value32 or
            isCharacterEncoding(encoding),
        .string_utf_bom, .string_xml, .string_json => isCharacterEncoding(encoding),
        .uuid => encoding == .value128,
        .port => encoding == .value16,
        .ip_address, .ip_address_obsolete => encoding == .value32 or
            encoding == .value128,
        else => false,
    };
}

fn isKnownFormat(format: Format) bool {
    return switch (format) {
        .default,
        .unsigned_int,
        .signed_int,
        .hex_int,
        .errno,
        .pid,
        .time,
        .boolean,
        .float,
        .hex_bytes,
        .string8,
        .string_utf,
        .string_utf_bom,
        .string_xml,
        .string_json,
        .uuid,
        .port,
        .ip_address,
        .ip_address_obsolete,
        => true,
        else => false,
    };
}

fn isCharacterEncoding(encoding: Encoding) bool {
    return switch (encoding) {
        .zstring_char8,
        .zstring_char16,
        .zstring_char32,
        .string_length16_char8,
        .string_length16_char16,
        .string_length16_char32,
        => true,
        else => false,
    };
}

fn isComplexEncoding(encoding: Encoding) bool {
    return switch (encoding) {
        .zstring_char8,
        .zstring_char16,
        .zstring_char32,
        .string_length16_char8,
        .string_length16_char16,
        .string_length16_char32,
        .binary_length16_char8,
        => true,
        else => false,
    };
}

fn defaultFormat(encoding: Encoding) Format {
    return switch (encoding) {
        .structure => .default,
        .value8, .value16, .value32, .value64 => .unsigned_int,
        .value128, .binary_length16_char8 => .hex_bytes,
        .zstring_char8,
        .zstring_char16,
        .zstring_char32,
        .string_length16_char8,
        .string_length16_char16,
        .string_length16_char32,
        => .string_utf,
    };
}

fn normalizeFormat(encoding: Encoding, format: Format) Format {
    if (format == .ip_address_obsolete and
        formatCompatible(encoding, format))
    {
        return .ip_address;
    }
    if (format == .default or !formatCompatible(encoding, format)) {
        return defaultFormat(encoding);
    }
    return format;
}

fn dynamicEffectiveFormat(field: MetadataField, byte_count: usize) Format {
    const format = field.effective_format;
    switch (format) {
        .hex_bytes,
        .string8,
        .string_utf,
        .string_utf_bom,
        .string_xml,
        .string_json,
        => return format,
        else => {},
    }
    if (byte_count == 0) return format;
    const value_encoding: Encoding = switch (byte_count) {
        1 => .value8,
        2 => .value16,
        4 => .value32,
        8 => .value64,
        16 => .value128,
        else => return defaultFormat(field.encoding),
    };
    return if (formatCompatible(value_encoding, format))
        format
    else
        defaultFormat(field.encoding);
}

fn skipFields(
    data: []const u8,
    start: usize,
    count: usize,
    depth: usize,
    endian: Endian,
    limits: Limits,
    work_count: *usize,
) Error!usize {
    if (depth > limits.max_depth or depth > hard_max_depth) {
        return error.LimitExceeded;
    }
    var position = start;
    var seen: usize = 0;
    while (seen < count) : (seen += 1) {
        if (position == data.len) return position;
        if (work_count.* >= limits.max_items) return error.LimitExceeded;
        work_count.* += 1;
        const parsed = try parseFieldAt(data, position, endian);
        position = parsed.next;
        if (parsed.field.encoding == .structure) {
            position = try skipFields(
                data,
                position,
                parsed.field.child_count,
                depth + 1,
                endian,
                limits,
                work_count,
            );
        }
    }
    return position;
}

fn decodeInteger(raw: []const u8, endian: Endian, format: Format) Error!?Integer {
    switch (format) {
        .float,
        .hex_bytes,
        .string8,
        .string_utf,
        .string_utf_bom,
        .string_xml,
        .string_json,
        .uuid,
        .ip_address,
        .ip_address_obsolete,
        => return null,
        else => {},
    }
    var cursor = bytes.Cursor.init(
        raw,
        if (format == .port) .big else endian,
    );
    if (format == .signed_int or format == .pid or format == .time) {
        return .{ .signed = switch (raw.len) {
            1 => try cursor.readInt(i8),
            2 => try cursor.readInt(i16),
            4 => try cursor.readInt(i32),
            8 => try cursor.readInt(i64),
            else => return null,
        } };
    }
    return .{ .unsigned = switch (raw.len) {
        1 => try cursor.readInt(u8),
        2 => try cursor.readInt(u16),
        4 => try cursor.readInt(u32),
        8 => try cursor.readInt(u64),
        else => return null,
    } };
}

fn structureArrayIndex(frame: *const StructFrame) ?usize {
    return switch (frame.field.array) {
        .scalar => null,
        .fixed, .variable => if (frame.instance_count == 0)
            null
        else
            frame.instance_index,
    };
}

fn baseName(attributed_name: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, attributed_name, ';') orelse
        attributed_name.len;
    return attributed_name[0..end];
}

test "decodes literal producer header metadata tag and scalar payload" {
    const event_bytes = [_]u8{
        0x07, 0x01, 0x45, 0x23, 0x89, 0x67, 0x02, 0x04,
        0x11, 0x00, 0x01, 0x00, 'G',  'o',  'l',  'd',
        'e',  'n',  0,    'v',  'a',  'l',  'u',  'e',
        0,    0x84, 0x83, 0x34, 0x12, 0x01, 0xef, 0xcd,
        0xab,
    };
    const event = try parse(&event_bytes, .{});
    try std.testing.expectEqual(Endian.little, event.header.endian);
    try std.testing.expectEqual(@as(u16, 0x2345), event.header.id);
    try std.testing.expectEqualStrings("Golden", event.metadata.?.name);

    var fields = try event.metadata.?.fieldIterator(.{});
    const metadata_field = (try fields.next()).?;
    try std.testing.expectEqualStrings("value", metadata_field.name);
    try std.testing.expectEqual(@as(u16, 0x1234), metadata_field.tag);
    try std.testing.expect((try fields.next()) == null);

    var payload = try event.payloadIterator();
    const item = (try payload.next()).?;
    try std.testing.expectEqual(
        Integer{ .unsigned = 0xabcdef01 },
        item.integer.?,
    );
    try std.testing.expect((try payload.next()) == null);
    try std.testing.expectEqual(@as(usize, 0), payload.remainingPayload().len);
}

test "header-only parsing remains available without metadata" {
    const event_bytes = [_]u8{
        0x03, 2,    0x34, 0x12, 0x78, 0x56, 1, 4,
        0xaa, 0xbb,
    };
    const header = try parseHeader(&event_bytes);
    try std.testing.expectEqual(@as(u16, 0x1234), header.id);
    try std.testing.expectEqual(@as(u16, 0x5678), header.tag);
    const event = try parse(&event_bytes, .{});
    try std.testing.expect(event.metadata == null);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, event.payload);
    try std.testing.expectError(error.MetadataMissing, event.payloadIterator());

    const extension_bytes = [_]u8{
        0x07, 0, 0,  0, 0,    0,    0, 4,
        1,    0, 99, 0, 0xcc, 0xdd,
    };
    const extension_event = try parse(&extension_bytes, .{});
    try std.testing.expect(extension_event.metadata == null);
    try std.testing.expectEqualSlices(u8, &.{0xdd}, extension_event.payload);
    var extensions = extension_event.extensionIterator();
    try std.testing.expectEqual(
        ExtensionClass.unknown,
        (try extensions.next()).?.class,
    );
    try std.testing.expectError(
        error.MetadataMissing,
        extension_event.payloadIterator(),
    );
}

test "decodes chained activity arrays and nested struct arrays" {
    const metadata =
        "Nested\x00" ++
        "tagged\x00" ++ [_]u8{ 0x84, 0x83, 0x34, 0x12 } ++
        "fixed\x00" ++ [_]u8{ 0x23, 0x03, 0x00 } ++
        "dynamic\x00" ++ [_]u8{0x42} ++
        "points\x00" ++ [_]u8{ 0xa1, 0x02, 0x02, 0x00 } ++
        "x\x00" ++ [_]u8{0x02} ++
        "inner\x00" ++ [_]u8{ 0x81, 0x01 } ++
        "y\x00" ++ [_]u8{0x02} ++
        "groups\x00" ++ [_]u8{ 0xc1, 0x01 } ++
        "value\x00" ++ [_]u8{0x03};
    const activity = [_]u8{0xaa} ** 16;
    const metadata_length: u16 = metadata.len;
    const event_bytes =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 16, 0, 2, 0x80 } ++ activity ++
        [_]u8{
            @truncate(metadata_length),
            @truncate(metadata_length >> 8),
            1,
            0,
        } ++ metadata ++
        [_]u8{
            0x78, 0x56, 0x34, 0x12, // tagged
            1, 0, 2, 0, 3, 0, // fixed value16[3]
            2, 0, 9, 10, // variable value8[2]
            7, 17, 8, 18, // fixed nested struct[2]
            2,    0, // variable struct count
            0x11, 0x11,
            0x22, 0x22,
        };

    const event = try parse(event_bytes, .{});
    try std.testing.expectEqualSlices(u8, &activity, event.activity.?.id);

    var extensions = event.extensionIterator();
    try std.testing.expectEqual(ExtensionClass.activity, (try extensions.next()).?.class);
    try std.testing.expectEqual(ExtensionClass.metadata, (try extensions.next()).?.class);
    try std.testing.expect((try extensions.next()) == null);

    var iterator = try event.payloadIterator();
    const tagged = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u16, 0x1234), tagged.field.tag);
    const fixed = (try iterator.next()).?;
    try std.testing.expectEqual(PayloadItemKind.array, fixed.kind);
    try std.testing.expectEqual(@as(usize, 3), fixed.count);

    const dynamic = (try iterator.next()).?;
    try std.testing.expectEqual(PayloadItemKind.array, dynamic.kind);
    try std.testing.expectEqual(@as(usize, 2), dynamic.count);
    try std.testing.expectEqualSlices(u8, &.{ 9, 10 }, dynamic.raw);

    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 7), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 17), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);
    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 8), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 18), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);

    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 0x1111), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);
    try std.testing.expectEqual(PayloadItemKind.structure_begin, (try iterator.next()).?.kind);
    try std.testing.expectEqual(@as(u64, 0x2222), (try iterator.next()).?.integer.?.unsigned);
    try std.testing.expectEqual(PayloadItemKind.structure_end, (try iterator.next()).?.kind);
    try std.testing.expect((try iterator.next()) == null);
}

test "big-endian counted binary and truncation are checked" {
    const metadata = "Big\x00blob\x00" ++ [_]u8{13};
    const event_bytes =
        [_]u8{ 0x05, 0, 0x12, 0x34, 0, 0, 0, 4 } ++
        [_]u8{ 0, metadata.len, 0, 1 } ++ metadata ++
        [_]u8{ 0, 3, 'a', 'b', 'c' };
    const event = try parse(event_bytes, .{});
    try std.testing.expectEqual(Endian.big, event.header.endian);
    var iterator = try event.payloadIterator();
    const item = (try iterator.next()).?;
    try std.testing.expectEqualSlices(u8, "abc", item.raw);

    const truncated = event_bytes[0 .. event_bytes.len - 1];
    const short_event = try parse(truncated, .{});
    var short_iterator = try short_event.payloadIterator();
    try std.testing.expectError(error.Truncated, short_iterator.next());
}

test "decodes every variable-sized string encoding" {
    const metadata =
        "Strings\x00" ++
        "z8\x00" ++ [_]u8{7} ++
        "z16\x00" ++ [_]u8{8} ++
        "z32\x00" ++ [_]u8{9} ++
        "c8\x00" ++ [_]u8{10} ++
        "c16\x00" ++ [_]u8{11} ++
        "c32\x00" ++ [_]u8{12} ++
        "bin\x00" ++ [_]u8{13};
    const metadata_length: u16 = metadata.len;
    const event_bytes =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{
            @truncate(metadata_length),
            @truncate(metadata_length >> 8),
            1,
            0,
        } ++ metadata ++
        [_]u8{
            'a', 0,
            'b', 0,
            0,   0,
            'c', 0,
            0,   0,
            0,   0,
            0,   0,
            2,   0,
            'd', 'e',
            2,   0,
            'f', 0,
            'g', 0,
            1,   0,
            'h', 0,
            0,   0,
            3,   0,
            1,   2,
            3,
        };

    const event = try parse(event_bytes, .{});
    var iterator = try event.payloadIterator();
    const expected = [_][]const u8{
        "a",
        &.{ 'b', 0 },
        &.{ 'c', 0, 0, 0 },
        "de",
        &.{ 'f', 0, 'g', 0 },
        &.{ 'h', 0, 0, 0 },
        &.{ 1, 2, 3 },
    };
    for (expected) |value| {
        const item = (try iterator.next()).?;
        try std.testing.expectEqual(PayloadItemKind.value, item.kind);
        try std.testing.expectEqualSlices(u8, value, item.raw);
    }
    try std.testing.expect((try iterator.next()) == null);
    try std.testing.expectEqual(@as(usize, 0), iterator.remainingPayload().len);
}

test "decodes big-endian char16 and char32 strings" {
    const metadata =
        "BigStrings\x00" ++
        "z16\x00" ++ [_]u8{8} ++
        "c32\x00" ++ [_]u8{12};
    const event_bytes =
        [_]u8{ 0x05, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 0, metadata.len, 0, 1 } ++ metadata ++
        [_]u8{
            0, 'A', 0, 0,
            0, 1,   0, 0,
            0, 'B',
        };
    const event = try parse(event_bytes, .{});
    var iterator = try event.payloadIterator();
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 'A' },
        (try iterator.next()).?.raw,
    );
    try std.testing.expectEqualSlices(
        u8,
        &.{ 0, 0, 0, 'B' },
        (try iterator.next()).?.raw,
    );
    try std.testing.expect((try iterator.next()) == null);
}

test "iterates arrays of complex values including empty arrays" {
    const metadata =
        "Arrays\x00" ++
        "z8\x00" ++ [_]u8{ 0x27, 2, 0 } ++
        "c16\x00" ++ [_]u8{0x4b} ++
        "empty\x00" ++ [_]u8{0x4d};
    const metadata_length: u16 = metadata.len;
    const event_bytes =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{
            @truncate(metadata_length),
            @truncate(metadata_length >> 8),
            1,
            0,
        } ++ metadata ++
        [_]u8{
            'a', 0, 'b', 'b', 0,
            2,   0, 1,   0,   'x',
            0,   2, 0,   'y', 0,
            'z', 0, 0,   0,
        };
    const event = try parse(event_bytes, .{});
    var iterator = try event.payloadIterator();

    const z0 = (try iterator.next()).?;
    try std.testing.expectEqual(PayloadItemKind.array, z0.kind);
    try std.testing.expectEqual(@as(?usize, 0), z0.array_index);
    try std.testing.expectEqual(@as(usize, 2), z0.count);
    try std.testing.expectEqualSlices(u8, "a", z0.raw);
    const z1 = (try iterator.next()).?;
    try std.testing.expectEqual(@as(?usize, 1), z1.array_index);
    try std.testing.expectEqualSlices(u8, "bb", z1.raw);

    const c0 = (try iterator.next()).?;
    try std.testing.expectEqual(@as(?usize, 0), c0.array_index);
    try std.testing.expectEqualSlices(u8, &.{ 'x', 0 }, c0.raw);
    const c1 = (try iterator.next()).?;
    try std.testing.expectEqual(@as(?usize, 1), c1.array_index);
    try std.testing.expectEqualSlices(u8, &.{ 'y', 0, 'z', 0 }, c1.raw);

    const empty = (try iterator.next()).?;
    try std.testing.expectEqual(PayloadItemKind.array, empty.kind);
    try std.testing.expectEqual(@as(usize, 0), empty.count);
    try std.testing.expect(empty.array_index == null);
    try std.testing.expect((try iterator.next()) == null);
}

test "uses signed semantics network ports and resilient format fallback" {
    const metadata =
        "Semantics\x00" ++
        "signed\x00" ++ [_]u8{ 0x82, 2 } ++
        "pid\x00" ++ [_]u8{ 0x84, 5 } ++
        "time\x00" ++ [_]u8{ 0x85, 6 } ++
        "port\x00" ++ [_]u8{ 0x83, 16 } ++
        "oldip\x00" ++ [_]u8{ 0x84, 18 } ++
        "unknown\x00" ++ [_]u8{ 0x83, 99 } ++
        "baduuid\x00" ++ [_]u8{ 0x82, 15 };
    const metadata_length: u16 = metadata.len;
    const event_bytes =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{
            @truncate(metadata_length),
            @truncate(metadata_length >> 8),
            1,
            0,
        } ++ metadata ++
        [_]u8{
            0xff,
            0xfe,
            0xff,
            0xff,
            0xff,
            0xfd,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0x12,
            0x34,
            127,
            0,
            0,
            1,
            0x34,
            0x12,
            0xaa,
        };
    const event = try parse(event_bytes, .{});
    var iterator = try event.payloadIterator();

    const signed = (try iterator.next()).?;
    try std.testing.expectEqual(Integer{ .signed = -1 }, signed.integer.?);
    try std.testing.expectEqualSlices(u8, &.{0xff}, signed.raw);
    try std.testing.expectEqual(
        Integer{ .signed = -2 },
        (try iterator.next()).?.integer.?,
    );
    try std.testing.expectEqual(
        Integer{ .signed = -3 },
        (try iterator.next()).?.integer.?,
    );
    try std.testing.expectEqual(
        Integer{ .unsigned = 0x1234 },
        (try iterator.next()).?.integer.?,
    );

    const old_ip = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u8, 18), old_ip.field.raw_format);
    try std.testing.expectEqual(Format.ip_address_obsolete, old_ip.field.format);
    try std.testing.expectEqual(Format.ip_address, old_ip.field.effective_format);
    try std.testing.expect(old_ip.integer == null);

    const unknown = (try iterator.next()).?;
    try std.testing.expectEqual(@as(u8, 99), unknown.field.raw_format);
    try std.testing.expectEqual(@as(u8, 99), @intFromEnum(unknown.field.format));
    try std.testing.expectEqual(Format.unsigned_int, unknown.field.effective_format);
    try std.testing.expectEqual(
        Integer{ .unsigned = 0x1234 },
        unknown.integer.?,
    );

    const incompatible = (try iterator.next()).?;
    try std.testing.expectEqual(Format.uuid, incompatible.field.format);
    try std.testing.expectEqual(
        Format.unsigned_int,
        incompatible.field.effective_format,
    );
    try std.testing.expectEqual(
        Integer{ .unsigned = 0xaa },
        incompatible.integer.?,
    );
}

test "implicit structure ends traverse metadata and payload safely" {
    const metadata =
        "Implicit\x00" ++
        "outer\x00" ++ [_]u8{ 0x81, 5 } ++
        "value\x00" ++ [_]u8{2};
    const metadata_length: u16 = metadata.len;
    const event_bytes =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{
            @truncate(metadata_length),
            @truncate(metadata_length >> 8),
            1,
            0,
        } ++ metadata ++ [_]u8{42};
    const event = try parse(event_bytes, .{});

    var fields = try event.metadata.?.fieldIterator(.{});
    try std.testing.expectEqual(@as(usize, 0), (try fields.next()).?.depth);
    try std.testing.expectEqual(@as(usize, 1), (try fields.next()).?.depth);
    try std.testing.expect((try fields.next()) == null);

    var payload = try event.payloadIterator();
    try std.testing.expectEqual(
        PayloadItemKind.structure_begin,
        (try payload.next()).?.kind,
    );
    try std.testing.expectEqual(
        Integer{ .unsigned = 42 },
        (try payload.next()).?.integer.?,
    );
    try std.testing.expectEqual(
        PayloadItemKind.structure_end,
        (try payload.next()).?.kind,
    );
    try std.testing.expect((try payload.next()) == null);

    const malformed_metadata = "Bad\x00outer\x00" ++ [_]u8{ 0x81, 2 } ++ "child";
    const malformed =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ malformed_metadata.len, 0, 1, 0 } ++ malformed_metadata;
    try std.testing.expectError(error.Truncated, parse(malformed, .{}));
}

test "payload and schema traversal obey a single work budget" {
    const complex_metadata = "Budget\x00values\x00" ++ [_]u8{0x47};
    const complex =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ complex_metadata.len, 0, 1, 0 } ++ complex_metadata ++
        [_]u8{ 0xff, 0xff, 0 };
    const complex_event = try parse(complex, .{ .max_items = 2 });
    var complex_payload = try complex_event.payloadIterator();
    try std.testing.expect((try complex_payload.next()) != null);
    try std.testing.expectError(error.LimitExceeded, complex_payload.next());

    const empty_metadata = "Budget\x00empty\x00" ++ [_]u8{0x42};
    const empty =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ empty_metadata.len, 0, 1, 0 } ++ empty_metadata ++
        [_]u8{ 0, 0 };
    const empty_event = try parse(empty, .{ .max_items = 1 });
    var empty_payload = try empty_event.payloadIterator();
    try std.testing.expectError(error.LimitExceeded, empty_payload.next());

    const struct_metadata = "Budget\x00empty_struct\x00" ++ [_]u8{ 0xc1, 1 };
    const empty_struct =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ struct_metadata.len, 0, 1, 0 } ++ struct_metadata ++
        [_]u8{ 0, 0 };
    const struct_event = try parse(empty_struct, .{ .max_items = 2 });
    var struct_payload = try struct_event.payloadIterator();
    try std.testing.expectEqual(
        PayloadItemKind.structure_begin,
        (try struct_payload.next()).?.kind,
    );
    try std.testing.expectError(error.LimitExceeded, struct_payload.next());

    const fields_metadata =
        "Budget\x00" ++
        "one\x00" ++ [_]u8{2} ++
        "two\x00" ++ [_]u8{2};
    const fields_event =
        [_]u8{ 0x07, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ fields_metadata.len, 0, 1, 0 } ++ fields_metadata;
    try std.testing.expectError(
        error.LimitExceeded,
        parse(fields_event, .{ .max_items = 1 }),
    );
}

test "rejects duplicate malformed and unsupported extension or metadata layouts" {
    const unknown =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 3, 0, 99, 0x80, 'a', 'b', 'c' } ++
        [_]u8{ 2, 0, 1, 0, 'e', 0 };
    const unknown_event = try parse(&unknown, .{});
    var extensions = unknown_event.extensionIterator();
    const unknown_extension = (try extensions.next()).?;
    try std.testing.expectEqual(ExtensionClass.unknown, unknown_extension.class);
    try std.testing.expectEqualSlices(u8, "abc", unknown_extension.data);

    const duplicate =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 2, 0, 1, 0x80, 'a', 0 } ++
        [_]u8{ 2, 0, 1, 0, 'b', 0 };
    try std.testing.expectError(error.InvalidFormat, parse(&duplicate, .{}));

    const unsupported =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 5, 0, 1, 0, 'e', 0, 'x', 0, 14 };
    try std.testing.expectError(error.UnsupportedEncoding, parse(&unsupported, .{}));

    const incompatible =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 6, 0, 1, 0, 'e', 0, 'x', 0, 0x82, 15 };
    const incompatible_event = try parse(&incompatible, .{});
    var incompatible_fields = try incompatible_event.metadata.?.fieldIterator(.{});
    const incompatible_field = (try incompatible_fields.next()).?;
    try std.testing.expectEqual(Format.uuid, incompatible_field.format);
    try std.testing.expectEqual(
        Format.unsigned_int,
        incompatible_field.effective_format,
    );

    const broken_chain =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{ 2, 0, 1, 0x80, 'e', 0 };
    try std.testing.expectError(error.Truncated, parse(&broken_chain, .{}));

    const nested_metadata =
        "e\x00" ++
        "outer\x00" ++ [_]u8{ 0x81, 1 } ++
        "inner\x00" ++ [_]u8{ 0x81, 1 } ++
        "leaf\x00" ++ [_]u8{2};
    const nested_length: u16 = nested_metadata.len;
    const too_deep =
        [_]u8{ 7, 0, 0, 0, 0, 0, 0, 4 } ++
        [_]u8{
            @truncate(nested_length),
            @truncate(nested_length >> 8),
            1,
            0,
        } ++ nested_metadata;
    try std.testing.expectError(
        error.LimitExceeded,
        parse(too_deep, .{ .max_depth = 1 }),
    );
}

test "bounded arbitrary EventHeader input never panics or loops" {
    var data: [128]u8 = undefined;
    var seed: u32 = 0x12345678;
    for (&data) |*byte| {
        seed = seed *% 22695477 +% 1;
        byte.* = @truncate(seed >> 20);
    }
    for (0..data.len + 1) |length| {
        if (parse(
            data[0..length],
            .{
                .max_bytes = data.len,
                .max_fields = 16,
                .max_extensions = 4,
                .max_depth = 4,
                .max_items = 32,
            },
        )) |event| {
            if (event.payloadIterator()) |iterator_value| {
                var iterator = iterator_value;
                var steps: usize = 0;
                while (steps < 64) : (steps += 1) {
                    if (iterator.next()) |item| {
                        if (item == null) break;
                    } else |_| break;
                }
                try std.testing.expect(steps < 64);
            } else |_| {}
        } else |_| {}
    }
}
