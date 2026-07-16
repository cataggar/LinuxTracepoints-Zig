const std = @import("std");
const decode = @import("linux_tracepoints_decode");

export fn linuxTracepointsDecodePortableProbe(value: u16) u16 {
    const input = [_]u8{ @truncate(value), @truncate(value >> 8) };
    var cursor = decode.bytes.Cursor.init(&input, .little);
    return cursor.readU16() catch 0;
}

export fn linuxTracepointsDecodePortableParsers(
    input: [*]const u8,
    length: usize,
) usize {
    const data = input[0..length];
    var decoded: usize = 0;

    if (decode.eventheader.parse(data, .{ .max_bytes = 4096 })) |event| {
        var fields = event.payloadIterator() catch return decoded;
        if ((fields.next() catch null) != null) decoded += 1;
    } else |_| {}

    if (decode.perf_data.parse(data, .{ .max_bytes = 4096 })) |file| {
        var records = file.recordIterator();
        if (records.next() catch null) |record| {
            decoded += 1;
            if (file.attrAt(0) catch null) |attr| {
                _ = decode.perf_data.decodeSample(record, attr, .{}) catch null;
            }
        }
        var index_storage: [4096]u8 = undefined;
        var index_fixed = std.heap.FixedBufferAllocator.init(&index_storage);
        if (decode.perf_data.SessionIndex.init(
            index_fixed.allocator(),
            &file,
            .{ .max_bytes = 4096 },
        )) |index_value| {
            var index = index_value;
            index.deinit();
        } else |_| {}
    } else |_| {}

    var storage: [4096]u8 = undefined;
    var fixed = std.heap.FixedBufferAllocator.init(&storage);
    if (decode.tracefs_format.parse(
        fixed.allocator(),
        data,
        .{ .max_bytes = 4096 },
    )) |parsed| {
        var format = parsed;
        decoded += format.fields.len;
        format.deinit();
    } else |_| {}

    return decoded;
}
