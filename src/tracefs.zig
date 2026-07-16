const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("linux_tracepoints supports Linux targets only");
    }
}

pub const OpenError = error{
    AccessDenied,
    CloseFailed,
    InputOutput,
    InvalidPath,
    MountInfoLineTooLong,
    MountInfoMalformed,
    NameTooLong,
    ProcessFdQuotaExceeded,
    SymLinkLoop,
    SystemFdQuotaExceeded,
    SystemResources,
    Unexpected,
    UserEventsUnavailable,
};

const CandidateOpenError = OpenError || error{NotFound};
const conventional_paths = [_][*:0]const u8{
    "/sys/kernel/tracing/user_events_data",
    "/sys/kernel/debug/tracing/user_events_data",
};
const mountinfo_path = "/proc/self/mountinfo";

const System = struct {
    fn openat(dirfd: i32, path: [*:0]const u8, flags: linux.O, mode: linux.mode_t) usize {
        return linux.openat(dirfd, path, flags, mode);
    }

    fn read(fd: linux.fd_t, buffer: [*]u8, len: usize) usize {
        return linux.read(fd, buffer, len);
    }

    fn close(fd: linux.fd_t) usize {
        return linux.close(fd);
    }
};

pub fn openUserEventsData() OpenError!linux.fd_t {
    return openUserEventsDataWith(System);
}

pub fn openUserEventsDataAt(path: [:0]const u8) OpenError!linux.fd_t {
    return openCandidateWith(System, path.ptr) catch |err| switch (err) {
        error.NotFound => error.UserEventsUnavailable,
        else => |open_err| open_err,
    };
}

fn openUserEventsDataWith(comptime Sys: type) OpenError!linux.fd_t {
    for (conventional_paths) |path| {
        return openCandidateWith(Sys, path) catch |err| switch (err) {
            error.NotFound => continue,
            else => |open_err| return open_err,
        };
    }

    const mountinfo_fd = openReadOnlyWith(Sys, mountinfo_path) catch |err| switch (err) {
        error.NotFound => return error.UserEventsUnavailable,
        else => |open_err| return open_err,
    };

    const discovered_fd = discoverMountedTracefsWith(Sys, mountinfo_fd) catch |err| {
        if (linux.errno(Sys.close(mountinfo_fd)) != .SUCCESS) return error.CloseFailed;
        return err;
    };

    if (linux.errno(Sys.close(mountinfo_fd)) != .SUCCESS) {
        if (discovered_fd) |fd| _ = Sys.close(fd);
        return error.CloseFailed;
    }

    return discovered_fd orelse error.UserEventsUnavailable;
}

fn discoverMountedTracefsWith(
    comptime Sys: type,
    mountinfo_fd: linux.fd_t,
) OpenError!?linux.fd_t {
    var read_buffer: [4096]u8 = undefined;
    var line_buffer: [4096]u8 = undefined;
    var line_len: usize = 0;
    var candidate_buffer: [linux.PATH_MAX:0]u8 = undefined;
    var debugfs_candidate: [linux.PATH_MAX:0]u8 = undefined;
    var debugfs_candidate_len: ?usize = null;

    while (true) {
        const read_len = while (true) {
            const result = Sys.read(mountinfo_fd, &read_buffer, read_buffer.len);
            switch (linux.errno(result)) {
                .SUCCESS => break result,
                .INTR => continue,
                .ACCES, .PERM => return error.AccessDenied,
                .IO => return error.InputOutput,
                .NOMEM, .NOBUFS => return error.SystemResources,
                else => return error.Unexpected,
            }
        };

        if (read_len == 0) {
            if (line_len != 0) {
                if (try openFromMountInfoLine(
                    Sys,
                    line_buffer[0..line_len],
                    &candidate_buffer,
                    &debugfs_candidate,
                    &debugfs_candidate_len,
                )) |fd| return fd;
            }

            if (debugfs_candidate_len) |len| {
                const path: [:0]const u8 = debugfs_candidate[0..len :0];
                return openCandidateWith(Sys, path.ptr) catch |err| switch (err) {
                    error.NotFound => null,
                    else => |open_err| open_err,
                };
            }
            return null;
        }

        for (read_buffer[0..read_len]) |byte| {
            if (byte == '\n') {
                if (try openFromMountInfoLine(
                    Sys,
                    line_buffer[0..line_len],
                    &candidate_buffer,
                    &debugfs_candidate,
                    &debugfs_candidate_len,
                )) |fd| return fd;
                line_len = 0;
                continue;
            }

            if (line_len == line_buffer.len) return error.MountInfoLineTooLong;
            line_buffer[line_len] = byte;
            line_len += 1;
        }
    }
}

fn openFromMountInfoLine(
    comptime Sys: type,
    line: []const u8,
    candidate_buffer: *[linux.PATH_MAX:0]u8,
    debugfs_candidate: *[linux.PATH_MAX:0]u8,
    debugfs_candidate_len: *?usize,
) OpenError!?linux.fd_t {
    const candidate = try candidateFromMountInfoLine(line, candidate_buffer) orelse return null;
    switch (candidate.kind) {
        .tracefs => {
            return openCandidateWith(Sys, candidate.path.ptr) catch |err| switch (err) {
                error.NotFound => null,
                else => |open_err| open_err,
            };
        },
        .debugfs => {
            if (debugfs_candidate_len.* == null) {
                @memcpy(debugfs_candidate[0..candidate.path.len], candidate.path);
                debugfs_candidate[candidate.path.len] = 0;
                debugfs_candidate_len.* = candidate.path.len;
            }
            return null;
        },
    }
}

const MountKind = enum {
    tracefs,
    debugfs,
};

const Candidate = struct {
    kind: MountKind,
    path: [:0]const u8,
};

fn candidateFromMountInfoLine(
    line: []const u8,
    output: *[linux.PATH_MAX:0]u8,
) OpenError!?Candidate {
    var tokens = std.mem.tokenizeScalar(u8, line, ' ');
    var field_index: usize = 0;
    var root: ?[]const u8 = null;
    var mount_point: ?[]const u8 = null;
    var fs_type: ?[]const u8 = null;

    while (tokens.next()) |token| : (field_index += 1) {
        if (field_index == 3) root = token;
        if (field_index == 4) mount_point = token;
        if (field_index >= 6 and std.mem.eql(u8, token, "-")) {
            fs_type = tokens.next() orelse return error.MountInfoMalformed;
            break;
        }
    }

    const mount_root = root orelse return error.MountInfoMalformed;
    const mount = mount_point orelse return error.MountInfoMalformed;
    const filesystem = fs_type orelse return error.MountInfoMalformed;
    const kind: MountKind = if (std.mem.eql(u8, filesystem, "tracefs"))
        .tracefs
    else if (std.mem.eql(u8, filesystem, "debugfs"))
        .debugfs
    else
        return null;

    const filesystem_target = switch (kind) {
        .tracefs => "/user_events_data",
        .debugfs => "/tracing/user_events_data",
    };
    var root_buffer: [linux.PATH_MAX:0]u8 = undefined;
    const root_len = try decodeMountPath(mount_root, &root_buffer);
    const relative_target = targetRelativeToRoot(
        root_buffer[0..root_len],
        filesystem_target,
    ) orelse return null;

    var len = try decodeMountPath(mount, output);
    if (relative_target.len != 0 and (len == 0 or output[len - 1] != '/')) {
        if (len == output.len) return error.NameTooLong;
        output[len] = '/';
        len += 1;
    }

    if (relative_target.len >= output.len - len) return error.NameTooLong;
    @memcpy(output[len .. len + relative_target.len], relative_target);
    len += relative_target.len;
    output[len] = 0;

    return .{
        .kind = kind,
        .path = output[0..len :0],
    };
}

fn targetRelativeToRoot(root_untrimmed: []const u8, target: []const u8) ?[]const u8 {
    if (root_untrimmed.len == 0 or root_untrimmed[0] != '/') return null;

    var root = root_untrimmed;
    while (root.len > 1 and root[root.len - 1] == '/') {
        root = root[0 .. root.len - 1];
    }

    if (std.mem.eql(u8, root, "/")) return target[1..];
    if (std.mem.eql(u8, root, target)) return target[target.len..];
    if (target.len > root.len and
        std.mem.startsWith(u8, target, root) and
        target[root.len] == '/')
    {
        return target[root.len + 1 ..];
    }
    return null;
}

fn decodeMountPath(encoded: []const u8, output: *[linux.PATH_MAX:0]u8) OpenError!usize {
    var source_index: usize = 0;
    var output_index: usize = 0;

    while (source_index < encoded.len) {
        if (output_index == output.len) return error.NameTooLong;

        if (encoded[source_index] != '\\') {
            output[output_index] = encoded[source_index];
            source_index += 1;
            output_index += 1;
            continue;
        }

        if (source_index + 4 > encoded.len) return error.MountInfoMalformed;
        const escape = encoded[source_index + 1 .. source_index + 4];
        output[output_index] = if (std.mem.eql(u8, escape, "040"))
            ' '
        else if (std.mem.eql(u8, escape, "011"))
            '\t'
        else if (std.mem.eql(u8, escape, "012"))
            '\n'
        else if (std.mem.eql(u8, escape, "134"))
            '\\'
        else
            return error.MountInfoMalformed;
        source_index += 4;
        output_index += 1;
    }

    return output_index;
}

fn openCandidateWith(comptime Sys: type, path: [*:0]const u8) CandidateOpenError!linux.fd_t {
    return openWithFlags(Sys, path, .{ .ACCMODE = .RDWR, .CLOEXEC = true });
}

fn openReadOnlyWith(comptime Sys: type, path: [*:0]const u8) CandidateOpenError!linux.fd_t {
    return openWithFlags(Sys, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true });
}

fn openWithFlags(
    comptime Sys: type,
    path: [*:0]const u8,
    flags: linux.O,
) CandidateOpenError!linux.fd_t {
    while (true) {
        const result = Sys.openat(linux.AT.FDCWD, path, flags, 0);
        switch (linux.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            .NOENT, .NOTDIR => return error.NotFound,
            .ACCES, .PERM, .ROFS => return error.AccessDenied,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NAMETOOLONG => return error.NameTooLong,
            .NOMEM => return error.SystemResources,
            .INVAL, .ISDIR => return error.InvalidPath,
            .LOOP => return error.SymLinkLoop,
            else => return error.Unexpected,
        }
    }
}

test "parses tracefs and debugfs mountinfo entries" {
    var output: [linux.PATH_MAX:0]u8 = undefined;

    const tracefs = (try candidateFromMountInfoLine(
        "36 29 0:32 / /sys/kernel/tracing rw,nosuid shared:7 - tracefs tracefs rw",
        &output,
    )).?;
    try std.testing.expectEqual(MountKind.tracefs, tracefs.kind);
    try std.testing.expectEqualStrings(
        "/sys/kernel/tracing/user_events_data",
        tracefs.path,
    );

    const debugfs = (try candidateFromMountInfoLine(
        "37 29 0:33 / /sys/kernel/debug rw,nosuid - debugfs debugfs rw",
        &output,
    )).?;
    try std.testing.expectEqual(MountKind.debugfs, debugfs.kind);
    try std.testing.expectEqualStrings(
        "/sys/kernel/debug/tracing/user_events_data",
        debugfs.path,
    );
}

test "decodes escaped mount paths and matches exact filesystem types" {
    var output: [linux.PATH_MAX:0]u8 = undefined;

    const escaped = (try candidateFromMountInfoLine(
        "36 29 0:32 / /run/my\\040traces rw - tracefs tracefs rw",
        &output,
    )).?;
    try std.testing.expectEqualStrings(
        "/run/my traces/user_events_data",
        escaped.path,
    );

    try std.testing.expectEqual(
        null,
        try candidateFromMountInfoLine(
            "36 29 0:32 / /trace rw - nottracefs none rw",
            &output,
        ),
    );
}

test "projects targets through bind-mounted filesystem roots" {
    var output: [linux.PATH_MAX:0]u8 = undefined;

    const debugfs_subtree = (try candidateFromMountInfoLine(
        "37 29 0:33 /tracing /run/tracing rw - debugfs debugfs rw",
        &output,
    )).?;
    try std.testing.expectEqualStrings(
        "/run/tracing/user_events_data",
        debugfs_subtree.path,
    );

    const event_file = (try candidateFromMountInfoLine(
        "36 29 0:32 /user_events_data /run/user-event rw - tracefs tracefs rw",
        &output,
    )).?;
    try std.testing.expectEqualStrings("/run/user-event", event_file.path);

    try std.testing.expectEqual(
        null,
        try candidateFromMountInfoLine(
            "36 29 0:32 /instances/demo /run/demo rw - tracefs tracefs rw",
            &output,
        ),
    );
}

test "rejects malformed mountinfo entries" {
    var output: [linux.PATH_MAX:0]u8 = undefined;

    try std.testing.expectError(
        error.MountInfoMalformed,
        candidateFromMountInfoLine("36 29 0:32 / /trace rw", &output),
    );
    try std.testing.expectError(
        error.MountInfoMalformed,
        candidateFromMountInfoLine(
            "36 29 0:32 / /run/bad\\999 rw - tracefs tracefs rw",
            &output,
        ),
    );
}
