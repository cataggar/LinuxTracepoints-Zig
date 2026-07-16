//! Parser and raw-field resolver for tracefs event `format` files.
//!
//! C declarations and `print fmt` are intentionally treated as opaque text.

const std = @import("std");
const bytes = @import("bytes.zig");

pub const Error = bytes.Error;
pub const Endian = bytes.Endian;
pub const Limits = bytes.Limits;

pub const Scope = enum {
    common,
    user,
};

pub const Location = enum {
    @"inline",
    data_loc32,
    rel_loc32,
    rest,
};

pub const Scalar = union(enum) {
    unsigned: u64,
    signed: i64,
};

pub const Field = struct {
    declaration: []const u8,
    name: []const u8,
    scope: Scope,
    offset: usize,
    size: usize,
    signed: bool,
    signed_present: bool,
    location: Location,

    pub fn resolveBytes(
        self: Field,
        event: []const u8,
        endian: Endian,
    ) Error![]const u8 {
        switch (self.location) {
            .@"inline" => return locationRange(event, self.offset, self.size),
            .rest => {
                if (self.offset > event.len) return error.InvalidLocation;
                return event[self.offset..];
            },
            .data_loc32, .rel_loc32 => {
                if (self.size != 4) return error.InvalidFormat;
                const locator_bytes = locationRange(event, self.offset, 4) catch {
                    return error.InvalidLocation;
                };
                var cursor = bytes.Cursor.init(locator_bytes, endian);
                const locator = try cursor.readU32();
                const length: usize = @intCast(locator >> 16);
                var offset: usize = @intCast(locator & 0xffff);
                if (self.location == .rel_loc32) {
                    offset = try bytes.checkedAdd(
                        try bytes.checkedAdd(self.offset, self.size),
                        offset,
                    );
                }
                return locationRange(event, offset, length);
            },
        }
    }

    pub fn resolveScalar(
        self: Field,
        event: []const u8,
        endian: Endian,
    ) Error!Scalar {
        if (self.location != .@"inline") return error.UnsupportedLayout;
        const raw = try self.resolveBytes(event, endian);
        var cursor = bytes.Cursor.init(raw, endian);
        if (self.signed) {
            return .{ .signed = switch (raw.len) {
                1 => try cursor.readInt(i8),
                2 => try cursor.readInt(i16),
                4 => try cursor.readInt(i32),
                8 => try cursor.readInt(i64),
                else => return error.UnsupportedLayout,
            } };
        }
        return .{ .unsigned = switch (raw.len) {
            1 => try cursor.readInt(u8),
            2 => try cursor.readInt(u16),
            4 => try cursor.readInt(u32),
            8 => try cursor.readInt(u64),
            else => return error.UnsupportedLayout,
        } };
    }
};

pub const OwnedFormat = struct {
    allocator: std.mem.Allocator,
    backing: []u8,
    name: []const u8,
    id: u32,
    fields: []Field,
    common_field_count: usize,
    print_fmt: []const u8,

    pub fn parse(
        allocator: std.mem.Allocator,
        input: []const u8,
        limits: Limits,
    ) Error!OwnedFormat {
        if (input.len > limits.max_bytes) return error.LimitExceeded;

        const backing = try allocator.dupe(u8, input);
        errdefer allocator.free(backing);

        var scan = ParseState{};
        var field_count: usize = 0;
        var line_position: usize = 0;
        while (nextLine(backing, &line_position)) |line| {
            const trimmed = trimHorizontal(line);
            if (isFieldLine(trimmed)) {
                field_count = try bytes.checkedAdd(field_count, 1);
                if (field_count > limits.max_fields) return error.LimitExceeded;
            }
            try scan.observeNonField(trimmed);
        }
        try scan.finish();

        const fields = try allocator.alloc(Field, field_count);
        errdefer allocator.free(fields);

        var state = ParseState{};
        line_position = 0;
        var field_index: usize = 0;
        var common_count: usize = 0;
        while (nextLine(backing, &line_position)) |line| {
            const trimmed = trimHorizontal(line);
            if (isFieldLine(trimmed)) {
                if (!state.in_format) return error.InvalidFormat;
                const parsed = try parseFieldLine(
                    trimmed,
                    if (state.user_fields) .user else .common,
                );
                fields[field_index] = parsed;
                if (parsed.scope == .common) common_count += 1;
                field_index += 1;
                state.saw_field = true;
            } else {
                try state.observeNonField(trimmed);
            }
        }
        try state.finish();

        // Some producers omit the blank common/user separator. In that case,
        // the conventional common_* prefix is the least-surprising split.
        if (!state.saw_user_separator) {
            common_count = 0;
            var reached_user = false;
            for (fields) |*field| {
                if (!reached_user and std.mem.startsWith(u8, field.name, "common_")) {
                    field.scope = .common;
                    common_count += 1;
                } else {
                    reached_user = true;
                    field.scope = .user;
                }
            }
        }

        return .{
            .allocator = allocator,
            .backing = backing,
            .name = state.name.?,
            .id = state.id.?,
            .fields = fields,
            .common_field_count = common_count,
            .print_fmt = state.print_fmt orelse "",
        };
    }

    pub fn deinit(self: *OwnedFormat) void {
        self.allocator.free(self.fields);
        self.allocator.free(self.backing);
        self.* = undefined;
    }

    pub fn commonFields(self: *const OwnedFormat) []const Field {
        return self.fields[0..self.common_field_count];
    }

    pub fn userFields(self: *const OwnedFormat) []const Field {
        return self.fields[self.common_field_count..];
    }

    pub fn findField(self: *const OwnedFormat, name: []const u8) ?*const Field {
        for (self.fields) |*field| {
            if (std.mem.eql(u8, field.name, name)) return field;
        }
        return null;
    }
};

pub const Format = OwnedFormat;

pub fn parse(
    allocator: std.mem.Allocator,
    input: []const u8,
    limits: Limits,
) Error!OwnedFormat {
    return OwnedFormat.parse(allocator, input, limits);
}

const ParseState = struct {
    name: ?[]const u8 = null,
    id: ?u32 = null,
    print_fmt: ?[]const u8 = null,
    in_format: bool = false,
    saw_field: bool = false,
    user_fields: bool = false,
    saw_user_separator: bool = false,

    fn observeNonField(self: *ParseState, line: []const u8) Error!void {
        if (line.len == 0) {
            if (self.in_format and self.saw_field and !self.user_fields) {
                self.user_fields = true;
                self.saw_user_separator = true;
            }
            return;
        }
        if (std.mem.eql(u8, line, "format:")) {
            if (self.in_format) return error.InvalidFormat;
            self.in_format = true;
            return;
        }
        if (propertyValue(line, "name:")) |value| {
            if (self.name != null or value.len == 0) return error.InvalidFormat;
            self.name = value;
            return;
        }
        if (propertyValue(line, "ID:")) |value| {
            if (self.id != null) return error.InvalidFormat;
            const parsed = try parseUnsigned(value, u32);
            self.id = parsed;
            return;
        }
        if (propertyValue(line, "print fmt:")) |value| {
            if (self.print_fmt != null) return error.InvalidFormat;
            self.print_fmt = value;
        }
    }

    fn finish(self: ParseState) Error!void {
        if (self.name == null or self.id == null or !self.in_format) {
            return error.InvalidFormat;
        }
    }
};

fn parseFieldLine(line: []const u8, initial_scope: Scope) Error!Field {
    var declaration: ?[]const u8 = null;
    var offset: ?usize = null;
    var size: ?usize = null;
    var signed = false;
    var signed_present = false;

    var position: usize = 0;
    while (position < line.len) {
        const start = position;
        while (position < line.len and line[position] != ';') position += 1;
        const property = trimHorizontal(line[start..position]);
        if (position < line.len) position += 1;
        if (property.len == 0) continue;

        const colon = std.mem.indexOfScalar(u8, property, ':') orelse
            return error.InvalidFormat;
        const key = trimHorizontal(property[0..colon]);
        const value = trimHorizontal(property[colon + 1 ..]);
        if (std.mem.eql(u8, key, "field") or std.mem.eql(u8, key, "field special")) {
            if (declaration != null or value.len == 0) return error.InvalidFormat;
            declaration = value;
        } else if (std.mem.eql(u8, key, "offset")) {
            if (offset != null) return error.InvalidFormat;
            offset = try parseUnsigned(value, usize);
        } else if (std.mem.eql(u8, key, "size")) {
            if (size != null) return error.InvalidFormat;
            size = try parseUnsigned(value, usize);
        } else if (std.mem.eql(u8, key, "signed")) {
            if (signed_present) return error.InvalidFormat;
            const value_int = try parseUnsigned(value, u8);
            if (value_int > 1) return error.InvalidFormat;
            signed = value_int != 0;
            signed_present = true;
        }
    }

    const field_declaration = declaration orelse return error.InvalidFormat;
    const field_offset = offset orelse return error.InvalidFormat;
    const field_size = size orelse return error.InvalidFormat;
    const field_name = extractFieldName(field_declaration) orelse
        return error.InvalidFormat;
    const has_data_loc = containsIdentifier(field_declaration, "__data_loc");
    const has_rel_loc = containsIdentifier(field_declaration, "__rel_loc");
    if (has_data_loc and has_rel_loc) return error.InvalidFormat;

    const location: Location = if (has_data_loc)
        .data_loc32
    else if (has_rel_loc)
        .rel_loc32
    else if (field_size == 0)
        .rest
    else
        .@"inline";
    if ((location == .data_loc32 or location == .rel_loc32) and field_size != 4) {
        return error.InvalidFormat;
    }

    return .{
        .declaration = field_declaration,
        .name = field_name,
        .scope = initial_scope,
        .offset = field_offset,
        .size = field_size,
        .signed = signed,
        .signed_present = signed_present,
        .location = location,
    };
}

fn nextLine(input: []const u8, position: *usize) ?[]const u8 {
    if (position.* >= input.len) return null;
    const start = position.*;
    while (position.* < input.len and input[position.*] != '\n') position.* += 1;
    var end = position.*;
    if (position.* < input.len) position.* += 1;
    if (end > start and input[end - 1] == '\r') end -= 1;
    return input[start..end];
}

fn trimHorizontal(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t");
}

fn propertyValue(line: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, prefix)) return null;
    return trimHorizontal(line[prefix.len..]);
}

fn isFieldLine(line: []const u8) bool {
    return std.mem.startsWith(u8, line, "field:") or
        std.mem.startsWith(u8, line, "field special:");
}

fn parseUnsigned(value: []const u8, comptime T: type) Error!T {
    if (value.len == 0) return error.InvalidFormat;
    var base: u8 = 10;
    var position: usize = 0;
    if (value.len > 2 and value[0] == '0' and (value[1] == 'x' or value[1] == 'X')) {
        base = 16;
        position = 2;
    }
    if (position == value.len) return error.InvalidFormat;

    var result: T = 0;
    while (position < value.len) : (position += 1) {
        const digit: u8 = if (value[position] >= '0' and value[position] <= '9')
            value[position] - '0'
        else if (base == 16 and value[position] >= 'a' and value[position] <= 'f')
            value[position] - 'a' + 10
        else if (base == 16 and value[position] >= 'A' and value[position] <= 'F')
            value[position] - 'A' + 10
        else
            return error.InvalidFormat;
        if (digit >= base) return error.InvalidFormat;
        const typed_digit: T = digit;
        const typed_base: T = base;
        if (result > (std.math.maxInt(T) - typed_digit) / typed_base) {
            return error.IntegerOverflow;
        }
        result = result * typed_base + typed_digit;
    }
    return result;
}

fn extractFieldName(declaration: []const u8) ?[]const u8 {
    var result: ?[]const u8 = null;
    var position: usize = 0;
    var bracket_depth: usize = 0;
    var paren_depth: usize = 0;
    while (position < declaration.len) {
        const ch = declaration[position];
        if (ch == '[') {
            bracket_depth += 1;
            position += 1;
        } else if (ch == ']' and bracket_depth != 0) {
            bracket_depth -= 1;
            position += 1;
        } else if (ch == '(') {
            paren_depth += 1;
            position += 1;
        } else if (ch == ')' and paren_depth != 0) {
            paren_depth -= 1;
            position += 1;
        } else if (isIdentStart(ch)) {
            const start = position;
            position += 1;
            while (position < declaration.len and isIdentContinue(declaration[position])) {
                position += 1;
            }
            const identifier = declaration[start..position];
            if (bracket_depth == 0 and paren_depth == 0 and
                !isDeclarationKeyword(identifier))
            {
                result = identifier;
            }
        } else {
            position += 1;
        }
    }
    return result;
}

fn containsIdentifier(declaration: []const u8, wanted: []const u8) bool {
    var position: usize = 0;
    while (position < declaration.len) {
        if (!isIdentStart(declaration[position])) {
            position += 1;
            continue;
        }
        const start = position;
        position += 1;
        while (position < declaration.len and isIdentContinue(declaration[position])) {
            position += 1;
        }
        if (std.mem.eql(u8, declaration[start..position], wanted)) return true;
    }
    return false;
}

fn isDeclarationKeyword(identifier: []const u8) bool {
    const keywords = [_][]const u8{
        "const",     "volatile",      "signed", "unsigned",
        "short",     "long",          "int",    "char",
        "struct",    "union",         "enum",   "__data_loc",
        "__rel_loc", "__attribute__", "void",
    };
    for (keywords) |keyword| {
        if (std.mem.eql(u8, identifier, keyword)) return true;
    }
    return false;
}

fn isIdentStart(ch: u8) bool {
    return std.ascii.isAlphabetic(ch) or ch == '_';
}

fn isIdentContinue(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '_';
}

fn locationRange(data: []const u8, offset: usize, length: usize) Error![]const u8 {
    if (offset > data.len or length > data.len - offset) {
        return error.InvalidLocation;
    }
    return data[offset .. offset + length];
}

test "parses CRLF common and user fields while preserving opaque text" {
    const text =
        "name: demo\r\n" ++
        "ID: 42\r\n" ++
        "format:\r\n" ++
        "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\r\n" ++
        "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\r\n" ++
        "\r\n" ++
        "\tfield:char message[8];\toffset:8;\tsize:8;\tsigned:0;\r\n" ++
        "\tfield:opaque_t unknown;\toffset:16;\tsize:3;\tsigned:0;\r\n" ++
        "\r\n" ++
        "print fmt: \"pid=%d\", REC->common_pid\r\n";
    var format = try OwnedFormat.parse(std.testing.allocator, text, .{});
    defer format.deinit();

    try std.testing.expectEqualStrings("demo", format.name);
    try std.testing.expectEqual(@as(u32, 42), format.id);
    try std.testing.expectEqual(@as(usize, 2), format.commonFields().len);
    try std.testing.expectEqual(@as(usize, 2), format.userFields().len);
    try std.testing.expectEqualStrings("opaque_t unknown", format.fields[3].declaration);
    try std.testing.expectEqualStrings(
        "\"pid=%d\", REC->common_pid",
        format.print_fmt,
    );
}

test "resolves signed inline data_loc rel_loc and rest fields" {
    const text =
        "name: locs\nID: 7\nformat:\n" ++
        "\tfield:s16 common_value; offset:0; size:2; signed:1;\n\n" ++
        "\tfield:__data_loc char[] absolute; offset:4; size:4; signed:0;\n" ++
        "\tfield:__rel_loc char[] relative; offset:8; size:4; signed:0;\n" ++
        "\tfield:u8 tail[]; offset:20; size:0; signed:0;\n" ++
        "print fmt: \"opaque\"\n";
    var format = try OwnedFormat.parse(std.testing.allocator, text, .{});
    defer format.deinit();

    const event = [_]u8{
        0xfe, 0xff, 0, 0,
        16, 0, 2, 0, // absolute: offset 16, length 2
        4,   0,   3,   0, // relative: end 12 + 4, length 3
        0,   0,   0,   0,
        'a', 'b', 'c', 0,
        'x', 'y',
    };
    try std.testing.expectEqual(
        Scalar{ .signed = -2 },
        try format.fields[0].resolveScalar(&event, .little),
    );
    try std.testing.expectEqualSlices(
        u8,
        "ab",
        try format.fields[1].resolveBytes(&event, .little),
    );
    try std.testing.expectEqualSlices(
        u8,
        "abc",
        try format.fields[2].resolveBytes(&event, .little),
    );
    try std.testing.expectEqualSlices(
        u8,
        "xy",
        try format.fields[3].resolveBytes(&event, .little),
    );

    const be_locator = [_]u8{ 0, 2, 0, 16 } ++ [_]u8{0} ** 12 ++ "ok".*;
    const be_field = Field{
        .declaration = "__data_loc char[] value",
        .name = "value",
        .scope = .user,
        .offset = 0,
        .size = 4,
        .signed = false,
        .signed_present = true,
        .location = .data_loc32,
    };
    try std.testing.expectEqualSlices(
        u8,
        "ok",
        try be_field.resolveBytes(&be_locator, .big),
    );
}

test "malformed and arbitrary formats return bounded errors without panic" {
    try std.testing.expectError(
        error.InvalidFormat,
        OwnedFormat.parse(std.testing.allocator, "name: x\nformat:\n", .{}),
    );
    var tiny_storage: [1]u8 = undefined;
    var tiny = std.heap.FixedBufferAllocator.init(&tiny_storage);
    try std.testing.expectError(
        error.OutOfMemory,
        OwnedFormat.parse(
            tiny.allocator(),
            "name: x\nID: 1\nformat:\n",
            .{},
        ),
    );

    var data: [96]u8 = undefined;
    var seed: u32 = 1;
    for (&data) |*byte| {
        seed = seed *% 1103515245 +% 12345;
        byte.* = @truncate(seed >> 16);
    }
    for (0..data.len + 1) |length| {
        if (OwnedFormat.parse(
            std.testing.allocator,
            data[0..length],
            .{ .max_bytes = data.len, .max_fields = 8 },
        )) |parsed| {
            var format = parsed;
            format.deinit();
        } else |_| {}
    }
}
