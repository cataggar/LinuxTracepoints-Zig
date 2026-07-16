//! Checked byte-slice primitives shared by the portable decoders.

const std = @import("std");

pub const Error = error{
    Truncated,
    IntegerOverflow,
    InvalidSection,
    InvalidLocation,
    InvalidFormat,
    LimitExceeded,
    UnsupportedEncoding,
    UnsupportedLayout,
    UnsupportedPipeMode,
    AmbiguousLayout,
    MetadataMissing,
    OutOfMemory,
};

pub const Limits = struct {
    max_bytes: usize = 64 * 1024 * 1024,
    max_sections: usize = 256,
    max_attrs: usize = 4096,
    max_records: usize = 1_000_000,
    max_fields: usize = 4096,
    max_extensions: usize = 64,
    max_depth: usize = 16,
    max_items: usize = 1_000_000,
};

pub const Endian = std.builtin.Endian;

pub fn checkedAdd(first: usize, second: usize) Error!usize {
    if (second > std.math.maxInt(usize) - first) return error.IntegerOverflow;
    return first + second;
}

pub fn checkedMul(first: usize, second: usize) Error!usize {
    if (first != 0 and second > std.math.maxInt(usize) / first) {
        return error.IntegerOverflow;
    }
    return first * second;
}

pub fn checkedAlignForward(value: usize, alignment: usize) Error!usize {
    if (alignment == 0 or alignment & (alignment - 1) != 0) {
        return error.InvalidFormat;
    }
    const mask = alignment - 1;
    const sum = try checkedAdd(value, mask);
    return sum & ~mask;
}

pub fn checkedUsize(value: anytype) Error!usize {
    const Value = @TypeOf(value);
    const info = @typeInfo(Value);
    switch (info) {
        .int => |int_info| {
            if (int_info.signedness == .signed and value < 0) {
                return error.IntegerOverflow;
            }
        },
        .comptime_int => {
            if (value < 0) return error.IntegerOverflow;
        },
        else => @compileError("checkedUsize requires an integer"),
    }
    if (value > std.math.maxInt(usize)) return error.IntegerOverflow;
    return @intCast(value);
}

pub fn checkedRange(
    data: []const u8,
    offset: usize,
    length: usize,
) Error![]const u8 {
    if (offset > data.len or length > data.len - offset) return error.Truncated;
    return data[offset .. offset + length];
}

pub const Cursor = struct {
    data: []const u8,
    position: usize = 0,
    endian: Endian,

    pub fn init(data: []const u8, endian: Endian) Cursor {
        return .{ .data = data, .endian = endian };
    }

    pub fn remaining(self: Cursor) usize {
        return if (self.position <= self.data.len)
            self.data.len - self.position
        else
            0;
    }

    pub fn atEnd(self: Cursor) bool {
        return self.position >= self.data.len;
    }

    pub fn readSlice(self: *Cursor, length: usize) Error![]const u8 {
        if (self.position > self.data.len or
            length > self.data.len - self.position)
        {
            return error.Truncated;
        }
        const start = self.position;
        self.position += length;
        return self.data[start..self.position];
    }

    pub fn skip(self: *Cursor, length: usize) Error!void {
        _ = try self.readSlice(length);
    }

    pub fn alignForward(self: *Cursor, alignment: usize) Error!void {
        if (self.position > self.data.len) return error.Truncated;
        const aligned = try checkedAlignForward(self.position, alignment);
        if (aligned > self.data.len) return error.Truncated;
        self.position = aligned;
    }

    pub fn readByte(self: *Cursor) Error!u8 {
        return (try self.readSlice(1))[0];
    }

    pub fn readInt(self: *Cursor, comptime T: type) Error!T {
        const info = @typeInfo(T);
        if (info != .int) @compileError("Cursor.readInt requires an integer type");
        if (@bitSizeOf(T) == 0 or @bitSizeOf(T) % 8 != 0) {
            @compileError("Cursor.readInt requires a byte-complete integer type");
        }

        const bit_size = @bitSizeOf(T);
        const byte_size = bit_size / 8;
        const U = std.meta.Int(.unsigned, bit_size);
        const input = try self.readSlice(byte_size);
        var value: U = 0;
        switch (self.endian) {
            .little => {
                for (input, 0..) |byte, index| {
                    value |= @as(U, byte) << @intCast(index * 8);
                }
            },
            .big => {
                for (input, 0..) |byte, index| {
                    const shift: std.math.Log2Int(U) =
                        @intCast((input.len - 1 - index) * 8);
                    value |= @as(U, byte) << shift;
                }
            },
        }
        return @bitCast(value);
    }

    pub fn readU16(self: *Cursor) Error!u16 {
        return self.readInt(u16);
    }

    pub fn readU32(self: *Cursor) Error!u32 {
        return self.readInt(u32);
    }

    pub fn readU64(self: *Cursor) Error!u64 {
        return self.readInt(u64);
    }

    pub fn readUntilByte(self: *Cursor, delimiter: u8) Error![]const u8 {
        if (self.position > self.data.len) return error.Truncated;
        const start = self.position;
        while (self.position != self.data.len) {
            if (self.data[self.position] == delimiter) {
                const result = self.data[start..self.position];
                self.position += 1;
                return result;
            }
            self.position += 1;
        }
        return error.Truncated;
    }

    pub fn subcursor(self: *Cursor, length: usize) Error!Cursor {
        return .init(try self.readSlice(length), self.endian);
    }
};

pub fn readIntAt(
    comptime T: type,
    data: []const u8,
    offset: usize,
    endian: Endian,
) Error!T {
    const info = @typeInfo(T);
    if (info != .int) @compileError("readIntAt requires an integer type");
    if (@bitSizeOf(T) == 0 or @bitSizeOf(T) % 8 != 0) {
        @compileError("readIntAt requires a byte-complete integer type");
    }
    var cursor = Cursor.init(
        try checkedRange(data, offset, @bitSizeOf(T) / 8),
        endian,
    );
    return cursor.readInt(T);
}

test "cursor reads both endian orders and never advances on truncation" {
    var little = Cursor.init(&.{ 0x34, 0x12, 0x78 }, .little);
    try std.testing.expectEqual(@as(u16, 0x1234), try little.readU16());
    const before = little.position;
    try std.testing.expectError(error.Truncated, little.readU16());
    try std.testing.expectEqual(before, little.position);

    var big = Cursor.init(&.{ 0x12, 0x34, 0x56, 0x78 }, .big);
    try std.testing.expectEqual(@as(u32, 0x12345678), try big.readU32());
}

test "cursor reads byte-complete arbitrary-width integers without storage padding" {
    const input = [_]u8{ 0x12, 0x34, 0x56, 0xaa };

    var little = Cursor.init(&input, .little);
    try std.testing.expectEqual(@as(u24, 0x563412), try little.readInt(u24));
    try std.testing.expectEqual(@as(usize, 3), little.position);
    try std.testing.expectEqual(@as(u8, 0xaa), try little.readByte());

    var big = Cursor.init(input[0..3], .big);
    try std.testing.expectEqual(@as(u24, 0x123456), try big.readInt(u24));
    try std.testing.expectEqual(
        @as(u24, 0x123456),
        try readIntAt(u24, &input, 0, .big),
    );

    var short = Cursor.init(input[0..2], .little);
    try std.testing.expectError(error.Truncated, short.readInt(u24));
    try std.testing.expectEqual(@as(usize, 0), short.position);
}

test "checked arithmetic range alignment and conversion" {
    try std.testing.expectEqual(@as(usize, 24), try checkedMul(6, 4));
    try std.testing.expectError(
        error.IntegerOverflow,
        checkedMul(std.math.maxInt(usize), 2),
    );
    try std.testing.expectEqual(@as(usize, 16), try checkedAlignForward(9, 8));
    try std.testing.expectError(error.InvalidFormat, checkedAlignForward(3, 3));
    try std.testing.expectError(error.Truncated, checkedRange(&.{ 1, 2 }, 1, 2));
    try std.testing.expectError(error.IntegerOverflow, checkedUsize(@as(i8, -1)));
}

test "bounded arbitrary cursor operations make progress or return an error" {
    var storage: [64]u8 = undefined;
    var seed: u32 = 0x9e3779b9;
    for (&storage) |*byte| {
        seed = seed *% 1664525 +% 1013904223;
        byte.* = @truncate(seed >> 24);
    }

    for (0..storage.len + 1) |length| {
        var cursor = Cursor.init(storage[0..length], if (length & 1 == 0) .little else .big);
        var operations: usize = 0;
        while (!cursor.atEnd() and operations < 128) : (operations += 1) {
            const before = cursor.position;
            const amount = @as(usize, storage[cursor.position] & 7);
            cursor.skip(amount) catch break;
            if (amount == 0) {
                _ = cursor.readByte() catch break;
            }
            try std.testing.expect(cursor.position > before);
        }
        try std.testing.expect(operations < 128);
    }
}
