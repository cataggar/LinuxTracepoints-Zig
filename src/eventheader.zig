//! Comptime EventHeader schema validation and wire encoding.
//!
//! This module only builds constant EventHeader and extension bytes. Provider
//! registration and payload writing are intentionally separate concerns.

const std = @import("std");
const builtin = @import("builtin");

pub const header_size = 8;
pub const extension_prefix_size = 4;

pub const HeaderFlags = struct {
    pub const pointer64: u8 = 0x01;
    pub const little_endian: u8 = 0x02;
    pub const extension: u8 = 0x04;
};

pub const ExtensionKind = struct {
    pub const metadata: u16 = 1;
    pub const activity: u16 = 2;
    pub const chain: u16 = 0x8000;
};

pub const carray_flag: u8 = 0x20;
pub const varray_flag: u8 = 0x40;
pub const format_present_flag: u8 = 0x80;
pub const tag_present_flag: u8 = 0x80;

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

    pub const struct_ = Encoding.structure;
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
};

/// Typed arity makes the reserved CArray|VArray combination unrepresentable.
pub const Array = union(enum) {
    scalar,
    fixed: u16,
    variable,
};

pub const Attribute = struct {
    name: []const u8,
    value: []const u8,
};

pub const Field = struct {
    name: []const u8,
    attributes: []const Attribute = &.{},
    encoding: Encoding,
    format: Format = .default,
    tag: u16 = 0,
    array: Array = .scalar,
    children: []const Field = &.{},
};

pub const EventSpec = struct {
    name: []const u8,
    attributes: []const Attribute = &.{},
    id: u16 = 0,
    version: u8 = 0,
    tag: u16 = 0,
    opcode: u8 = 0,
    level: u8,
    fields: []const Field = &.{},
};

pub const ActivityId = [16]u8;

/// Maximum event bytes accepted by the EventHeader implementations.
pub const event_size_limit = 65535;

/// Microsoft implementations reserve 52 bytes for the write index, header,
/// activity/related extension, and metadata prefix, plus 16 bytes of margin.
/// Using the same conservative reserve keeps future payload writers below the
/// EventHeader 64KB limit regardless of whether activity IDs are supplied.
pub const conservative_event_overhead = 52 + 16;

/// Returns the exact native-target EventHeader bytes.
pub fn encodeHeader(comptime spec: EventSpec, comptime has_extensions: bool) [header_size]u8 {
    validateEventSpec(spec);

    var result: [header_size]u8 = undefined;
    result[0] = targetFlags(has_extensions);
    result[1] = spec.version;
    putU16(result[2..4], spec.id);
    putU16(result[4..6], spec.tag);
    result[6] = spec.opcode;
    result[7] = spec.level;
    return result;
}

/// Returns an ActivityId extension, or an empty array when `activity_id` is
/// null. A related ID without an activity ID is rejected at comptime.
pub fn encodeActivityExtension(
    comptime activity_id: ?ActivityId,
    comptime related_id: ?ActivityId,
    comptime chained: bool,
) [activityExtensionLength(activity_id, related_id)]u8 {
    var result: [activityExtensionLength(activity_id, related_id)]u8 = undefined;
    if (activity_id) |activity| {
        const data_length: u16 = if (related_id == null) 16 else 32;
        putU16(result[0..2], data_length);
        putU16(
            result[2..4],
            ExtensionKind.activity | if (chained) ExtensionKind.chain else 0,
        );
        @memcpy(result[4..20], activity[0..]);
        if (related_id) |related| @memcpy(result[20..36], related[0..]);
    }
    return result;
}

pub fn activityExtensionLength(
    comptime activity_id: ?ActivityId,
    comptime related_id: ?ActivityId,
) usize {
    if (activity_id == null) {
        if (related_id != null) {
            @compileError("related activity ID requires an activity ID");
        }
        return 0;
    }
    return extension_prefix_size + 16 + if (related_id == null) 0 else 16;
}

/// Builds and validates one static EventHeader event definition.
///
/// Zig array lengths are part of their type, so each instantiation returns a
/// namespace whose constants have lengths specialized for `spec`.
pub fn EventDefinition(comptime spec: EventSpec) type {
    validateEventSpec(spec);
    const data_length = metadataDataLength(spec);
    if (data_length > std.math.maxInt(u16)) {
        @compileError("EventHeader metadata data exceeds 65535 bytes");
    }
    if (data_length > event_size_limit - conservative_event_overhead) {
        @compileError("EventHeader metadata leaves no room within the conservative event-size limit");
    }

    return struct {
        pub const metadata_length: u16 = @intCast(data_length);
        pub const header = encodeHeader(spec, true);
        pub const header_without_extensions = encodeHeader(spec, false);
        pub const metadata_data = encodeMetadataData(spec);
        pub const metadata_extension = encodeMetadataExtension(spec, false);
        pub const chained_metadata_extension = encodeMetadataExtension(spec, true);
        pub const max_payload_bytes: usize =
            event_size_limit - conservative_event_overhead - data_length;

        pub fn headerBytes(comptime has_extensions: bool) [header_size]u8 {
            return encodeHeader(spec, has_extensions);
        }

        pub fn metadataExtension(comptime chained: bool) [extension_prefix_size + data_length]u8 {
            return encodeMetadataExtension(spec, chained);
        }
    };
}

fn targetFlags(comptime has_extensions: bool) u8 {
    return (if (@sizeOf(usize) == 8) HeaderFlags.pointer64 else 0) |
        (if (builtin.cpu.arch.endian() == .little) HeaderFlags.little_endian else 0) |
        (if (has_extensions) HeaderFlags.extension else 0);
}

fn validateEventSpec(comptime spec: EventSpec) void {
    validateName("event", spec.name);
    validateAttributes("event", spec.attributes);
    if (spec.level == 0) @compileError("EventHeader event level must be nonzero");
    for (spec.fields) |field| validateField(field);
}

fn validateField(comptime field: Field) void {
    validateName("field", field.name);
    validateAttributes("field", field.attributes);

    if (field.encoding == .structure) {
        if (field.children.len == 0 or field.children.len > 127) {
            @compileError("EventHeader struct must have 1 through 127 immediate children");
        }
        if (field.format != .default) {
            @compileError("EventHeader struct format is its child count and cannot be specified");
        }
        switch (field.array) {
            .scalar, .variable => {},
            .fixed => |count| {
                if (count == 0) {
                    @compileError("EventHeader fixed array length must be 1 through 65535");
                }
            },
        }
        for (field.children) |child| validateField(child);
        return;
    }

    if (field.children.len != 0) {
        @compileError("only EventHeader struct fields may have children");
    }
    switch (field.array) {
        .scalar, .variable => {},
        .fixed => |count| {
            if (count == 0) {
                @compileError("EventHeader fixed array length must be 1 through 65535");
            }
        },
    }
    if (!formatCompatible(field.encoding, field.format)) {
        @compileError("EventHeader field format is incompatible with its encoding");
    }
}

fn validateName(comptime kind: []const u8, comptime name: []const u8) void {
    if (name.len == 0) @compileError("EventHeader " ++ kind ++ " name must not be empty");
    if (!std.unicode.utf8ValidateSlice(name)) {
        @compileError("EventHeader " ++ kind ++ " name must be valid UTF-8");
    }
    for (name) |byte| {
        if (byte == 0) @compileError("EventHeader " ++ kind ++ " name must not contain NUL");
        if (byte == ';') @compileError("EventHeader " ++ kind ++ " name must not contain ';'");
    }
}

fn validateAttributes(comptime owner: []const u8, comptime attributes: []const Attribute) void {
    for (attributes) |attribute| {
        if (attribute.name.len == 0) {
            @compileError("EventHeader " ++ owner ++ " attribute name must not be empty");
        }
        if (!std.unicode.utf8ValidateSlice(attribute.name)) {
            @compileError("EventHeader " ++ owner ++ " attribute name must be valid UTF-8");
        }
        if (!std.unicode.utf8ValidateSlice(attribute.value)) {
            @compileError("EventHeader " ++ owner ++ " attribute value must be valid UTF-8");
        }
        for (attribute.name) |byte| {
            if (byte == 0) @compileError("EventHeader attribute name must not contain NUL");
            if (byte == ';' or byte == '=') {
                @compileError("EventHeader attribute name must not contain ';' or '='");
            }
        }
        for (attribute.value) |byte| {
            if (byte == 0) @compileError("EventHeader attribute value must not contain NUL");
        }
    }
}

/// Compatibility follows eventheader.h:
/// - the two length16-char8 encodings accept every format;
/// - numeric formats accept only their documented ValueN widths;
/// - string formats accept matching Value/Char widths;
/// - HexBytes accepts every non-struct encoding.
fn formatCompatible(comptime encoding: Encoding, comptime format: Format) bool {
    if (format == .default) return true;
    if (encoding == .string_length16_char8 or encoding == .binary_length16_char8) return true;

    return switch (format) {
        .default => true,
        .unsigned_int, .signed_int, .hex_int => isValueRange(encoding, .value8, .value64),
        .errno, .pid => encoding == .value32,
        .time => encoding == .value32 or encoding == .value64,
        .boolean => isValueRange(encoding, .value8, .value32),
        .float => encoding == .value32 or encoding == .value64,
        .hex_bytes => true,
        .string8 => encoding == .value8 or encoding == .zstring_char8,
        .string_utf => encoding == .value16 or
            encoding == .value32 or
            isCharacterEncoding(encoding),
        .string_utf_bom, .string_xml, .string_json => isCharacterEncoding(encoding),
        .uuid => encoding == .value128,
        .port => encoding == .value16,
        .ip_address => encoding == .value32 or encoding == .value128,
    };
}

fn isValueRange(comptime encoding: Encoding, comptime first: Encoding, comptime last: Encoding) bool {
    return @intFromEnum(encoding) >= @intFromEnum(first) and
        @intFromEnum(encoding) <= @intFromEnum(last);
}

fn isCharacterEncoding(comptime encoding: Encoding) bool {
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

fn metadataDataLength(comptime spec: EventSpec) usize {
    var length = attributedStringLength(spec.name, spec.attributes);
    for (spec.fields) |field| length += fieldMetadataLength(field);
    return length;
}

fn fieldMetadataLength(comptime field: Field) usize {
    var length = attributedStringLength(field.name, field.attributes) + 1;
    const needs_format = field.encoding == .structure or field.format != .default or field.tag != 0;
    if (needs_format) length += 1;
    if (field.tag != 0) length += 2;
    switch (field.array) {
        .fixed => length += 2,
        .scalar, .variable => {},
    }
    for (field.children) |child| length += fieldMetadataLength(child);
    return length;
}

fn attributedStringLength(comptime name: []const u8, comptime attributes: []const Attribute) usize {
    var length = name.len + 1;
    for (attributes) |attribute| {
        length += 2 + attribute.name.len + escapedValueLength(attribute.value);
    }
    return length;
}

fn escapedValueLength(comptime value: []const u8) usize {
    var length = value.len;
    for (value) |byte| {
        if (byte == ';') length += 1;
    }
    return length;
}

fn encodeMetadataData(comptime spec: EventSpec) [metadataDataLength(spec)]u8 {
    var result: [metadataDataLength(spec)]u8 = undefined;
    var position: usize = 0;
    putAttributedString(result[0..], &position, spec.name, spec.attributes);
    for (spec.fields) |field| putField(result[0..], &position, field);
    std.debug.assert(position == result.len);
    return result;
}

fn encodeMetadataExtension(
    comptime spec: EventSpec,
    comptime chained: bool,
) [extension_prefix_size + metadataDataLength(spec)]u8 {
    const data_length = metadataDataLength(spec);
    var result: [extension_prefix_size + data_length]u8 = undefined;
    putU16(result[0..2], @intCast(data_length));
    putU16(
        result[2..4],
        ExtensionKind.metadata | if (chained) ExtensionKind.chain else 0,
    );
    const data = encodeMetadataData(spec);
    @memcpy(result[4..], data[0..]);
    return result;
}

fn putField(output: []u8, position: *usize, comptime field: Field) void {
    putAttributedString(output, position, field.name, field.attributes);

    const needs_format = field.encoding == .structure or field.format != .default or field.tag != 0;
    var encoding = @intFromEnum(field.encoding);
    switch (field.array) {
        .scalar => {},
        .fixed => encoding |= carray_flag,
        .variable => encoding |= varray_flag,
    }
    if (needs_format) encoding |= format_present_flag;
    putByte(output, position, encoding);

    if (needs_format) {
        var format: u8 = if (field.encoding == .structure)
            @intCast(field.children.len)
        else
            @intFromEnum(field.format);
        if (field.tag != 0) format |= tag_present_flag;
        putByte(output, position, format);
    }
    if (field.tag != 0) putU16At(output, position, field.tag);
    switch (field.array) {
        .fixed => |count| putU16At(output, position, count),
        .scalar, .variable => {},
    }
    for (field.children) |child| putField(output, position, child);
}

fn putAttributedString(
    output: []u8,
    position: *usize,
    comptime name: []const u8,
    comptime attributes: []const Attribute,
) void {
    for (name) |byte| putByte(output, position, byte);
    for (attributes) |attribute| {
        putByte(output, position, ';');
        for (attribute.name) |byte| putByte(output, position, byte);
        putByte(output, position, '=');
        for (attribute.value) |byte| {
            putByte(output, position, byte);
            if (byte == ';') putByte(output, position, ';');
        }
    }
    putByte(output, position, 0);
}

fn putByte(output: []u8, position: *usize, byte: u8) void {
    output[position.*] = byte;
    position.* += 1;
}

fn putU16At(output: []u8, position: *usize, value: u16) void {
    putU16(output[position.* .. position.* + 2], value);
    position.* += 2;
}

fn putU16(output: []u8, value: u16) void {
    if (builtin.cpu.arch.endian() == .little) {
        output[0] = @truncate(value);
        output[1] = @truncate(value >> 8);
    } else {
        output[0] = @truncate(value >> 8);
        output[1] = @truncate(value);
    }
}

test "header golden bytes" {
    const Definition = EventDefinition(.{
        .name = "header",
        .id = 0x1234,
        .version = 2,
        .tag = 0xfedc,
        .opcode = 1,
        .level = 4,
    });

    if (@sizeOf(usize) == 8 and builtin.cpu.arch.endian() == .little) {
        try std.testing.expectEqualSlices(
            u8,
            &.{ 0x07, 0x02, 0x34, 0x12, 0xdc, 0xfe, 0x01, 0x04 },
            &Definition.header,
        );
    }
}

test "metadata golden scalar format tag array struct and nested child" {
    const Definition = EventDefinition(.{
        .name = "event",
        .level = 5,
        .fields = &.{
            .{ .name = "default", .encoding = .value8 },
            .{ .name = "tagged", .encoding = .value32, .format = .hex_int, .tag = 0x1234 },
            .{ .name = "fixed", .encoding = .value16, .array = .{ .fixed = 3 } },
            .{
                .name = "outer",
                .encoding = .structure,
                .tag = 0xabcd,
                .children = &.{
                    .{ .name = "child", .encoding = .value64 },
                    .{
                        .name = "nested",
                        .encoding = .structure,
                        .children = &.{
                            .{ .name = "leaf", .encoding = .value8 },
                        },
                    },
                },
            },
        },
    });

    const tag_34_12 = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0x34, 0x12 }
    else
        [_]u8{ 0x12, 0x34 };
    const tag_cd_ab = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0xcd, 0xab }
    else
        [_]u8{ 0xab, 0xcd };
    const array_three = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0x03, 0x00 }
    else
        [_]u8{ 0x00, 0x03 };

    const expected = "event\x00" ++
        "default\x00" ++ [_]u8{2} ++
        "tagged\x00" ++ [_]u8{ 0x84, 0x83 } ++ tag_34_12 ++
        "fixed\x00" ++ [_]u8{0x23} ++ array_three ++
        "outer\x00" ++ [_]u8{ 0x81, 0x82 } ++ tag_cd_ab ++
        "child\x00" ++ [_]u8{5} ++
        "nested\x00" ++ [_]u8{ 0x81, 0x01 } ++
        "leaf\x00" ++ [_]u8{2};

    try std.testing.expectEqual(expected.len, Definition.metadata_length);
    try std.testing.expectEqualSlices(u8, expected[0..], &Definition.metadata_data);
    try std.testing.expectEqualSlices(u8, &Definition.metadata_data, Definition.metadata_extension[4..]);

    const terminal_prefix = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ @truncate(expected.len), @truncate(expected.len >> 8), 0x01, 0x00 }
    else
        [_]u8{ @truncate(expected.len >> 8), @truncate(expected.len), 0x00, 0x01 };
    const chained_prefix = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ @truncate(expected.len), @truncate(expected.len >> 8), 0x01, 0x80 }
    else
        [_]u8{ @truncate(expected.len >> 8), @truncate(expected.len), 0x80, 0x01 };
    try std.testing.expectEqualSlices(u8, &terminal_prefix, Definition.metadata_extension[0..4]);
    try std.testing.expectEqualSlices(u8, &chained_prefix, Definition.chained_metadata_extension[0..4]);
}

test "attributes escape semicolons" {
    const Definition = EventDefinition(.{
        .name = "event",
        .attributes = &.{
            .{ .name = "group", .value = "a;b" },
            .{ .name = "empty", .value = "" },
        },
        .level = 4,
        .fields = &.{
            .{
                .name = "field",
                .attributes = &.{.{ .name = "unit", .value = "m;s" }},
                .encoding = .value32,
            },
        },
    });
    try std.testing.expectEqualSlices(
        u8,
        "event;group=a;;b;empty=\x00field;unit=m;;s\x00" ++ [_]u8{4},
        &Definition.metadata_data,
    );
}

test "struct arrays encode array flags and fixed count" {
    const Definition = EventDefinition(.{
        .name = "struct_arrays",
        .level = 4,
        .fields = &.{
            .{
                .name = "fixed",
                .encoding = .structure,
                .array = .{ .fixed = 2 },
                .children = &.{.{ .name = "value", .encoding = .value8 }},
            },
            .{
                .name = "variable",
                .encoding = .structure,
                .array = .variable,
                .children = &.{.{ .name = "value", .encoding = .value16 }},
            },
        },
    });
    const fixed_count = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0x02, 0x00 }
    else
        [_]u8{ 0x00, 0x02 };
    const expected = "struct_arrays\x00" ++
        "fixed\x00" ++ [_]u8{ 0xa1, 0x01 } ++ fixed_count ++
        "value\x00" ++ [_]u8{0x02} ++
        "variable\x00" ++ [_]u8{ 0xc1, 0x01 } ++
        "value\x00" ++ [_]u8{0x03};

    try std.testing.expectEqualSlices(u8, expected[0..], &Definition.metadata_data);
}

test "activity extension bytes and chain" {
    const activity: ActivityId = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const related: ActivityId = .{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const terminal = encodeActivityExtension(activity, null, false);
    const chained = encodeActivityExtension(activity, related, true);

    const terminal_prefix = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0x10, 0x00, 0x02, 0x00 }
    else
        [_]u8{ 0x00, 0x10, 0x00, 0x02 };
    const chained_prefix = if (builtin.cpu.arch.endian() == .little)
        [_]u8{ 0x20, 0x00, 0x02, 0x80 }
    else
        [_]u8{ 0x00, 0x20, 0x80, 0x02 };

    try std.testing.expectEqualSlices(u8, &terminal_prefix, terminal[0..4]);
    try std.testing.expectEqualSlices(u8, &activity, terminal[4..20]);
    try std.testing.expectEqualSlices(u8, &chained_prefix, chained[0..4]);
    try std.testing.expectEqualSlices(u8, &activity, chained[4..20]);
    try std.testing.expectEqualSlices(u8, &related, chained[20..36]);
}

test "positive schema validation and helpers are comptime" {
    const Definition = EventDefinition(.{
        .name = "validated",
        .level = 1,
        .fields = &.{
            .{ .name = "dynamic", .encoding = .binary_length16_char8, .format = .uuid, .array = .variable },
        },
    });
    comptime {
        std.debug.assert(Definition.metadata_length == Definition.metadata_data.len);
        std.debug.assert(Definition.metadata_extension.len == extension_prefix_size + Definition.metadata_length);
        std.debug.assert(Definition.max_payload_bytes + Definition.metadata_length + conservative_event_overhead == event_size_limit);
        std.debug.assert(Definition.chained_metadata_extension[2] != Definition.metadata_extension[2] or
            Definition.chained_metadata_extension[3] != Definition.metadata_extension[3]);
    }
}
