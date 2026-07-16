//! Comptime-generated EventHeader providers.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const abi = @import("abi/linux.zig");
const eventheader = @import("eventheader.zig");
const user_events = @import("user_events.zig");

comptime {
    if (builtin.os.tag != .linux) {
        @compileError("linux_tracepoints supports Linux targets only");
    }
}

pub const eventheader_registration_schema =
    "u8 eventheader_flags; u8 version; u16 id; u16 tag; u8 opcode; u8 level";
pub const eventheader_name_max = 256;
pub const max_nesting = 16;

pub const Value128 = [16]u8;

pub const ScalarKind = enum {
    u8,
    u16,
    u32,
    u64,
    i8,
    i16,
    i32,
    i64,
    f32,
    f64,
    value128,
    boolean,
};

pub const FixedScalarArray = struct {
    element: ScalarKind,
    count: u16,
};

pub const VariableScalarArray = struct {
    element: ScalarKind,
    max: u16,
};

pub const FixedStructArray = struct {
    fields: []const FieldSpec,
    count: u16,
};

pub const VariableStructArray = struct {
    fields: []const FieldSpec,
    max: u16,
};

pub const FieldKind = union(enum) {
    u8,
    u16,
    u32,
    u64,
    i8,
    i16,
    i32,
    i64,
    f32,
    f64,
    value128,
    boolean,
    utf8: u16,
    binary: u16,
    fixed_array: FixedScalarArray,
    variable_array: VariableScalarArray,
    structure: []const FieldSpec,
    fixed_struct_array: FixedStructArray,
    variable_struct_array: VariableStructArray,

    // Reserved so unsupported encodings fail with a focused diagnostic.
    zstring8,
    utf16: u16,
    utf32: u16,
    string_array: u16,
};

pub const FieldSpec = struct {
    name: []const u8,
    kind: FieldKind,
    attributes: []const eventheader.Attribute = &.{},
    format: ?eventheader.Format = null,
    tag: u16 = 0,
};

pub const EventSpec = struct {
    symbol: []const u8,
    name: ?[]const u8 = null,
    id: u16 = 0,
    version: u8 = 0,
    tag: u16 = 0,
    opcode: u8 = 0,
    level: u8,
    keyword: u64 = 0,
    group: ?[]const u8 = null,
    options: ?[]const u8 = null,
    attributes: []const eventheader.Attribute = &.{},
    fields: []const FieldSpec = &.{},
};

pub const ProviderSpec = struct {
    name: []const u8,
    group: []const u8 = "",
    options: []const u8 = "",
    registration_flags: abi.RegistrationFlags = .{},
    events: []const EventSpec,
};

pub const Field = FieldSpec;
pub const Event = EventSpec;
pub const Spec = ProviderSpec;
pub const Scalar = ScalarKind;

pub const EventSet = struct {
    level: u8,
    keyword: u64,
    group: []const u8,
    options: []const u8,
    suffix: []const u8,
    registration_name: []const u8,
    registration_args: [:0]const u8,
};

pub const WriteOptions = struct {
    activity: ?*const eventheader.ActivityId = null,
    related: ?*const eventheader.ActivityId = null,
};

pub const WriteError = user_events.EventWriteError || error{
    ActivityRequired,
    EventTooLarge,
    FieldTooLong,
    TooManyIovecs,
};

pub const RegisterAllError =
    user_events.DataFileOpenError ||
    user_events.EventRegisterError ||
    error{
        LifecycleBusy,
        RegistrationActive,
        RollbackFailed,
    };

pub const UnregisterAllError =
    user_events.EventUnregisterError ||
    user_events.DataFileCloseError ||
    error{LifecycleBusy};

/// Generates one provider namespace from a fully-comptime specification.
pub fn Provider(comptime provider_spec: ProviderSpec) type {
    @setEvalBranchQuota(2_000_000);
    validateProviderSpec(provider_spec);

    const GeneratedEventId = makeEventId(provider_spec.events);
    const set_count = uniqueSetCount(provider_spec);
    const generated_sets = makeEventSets(provider_spec);
    const generated_event_to_set = makeEventToSet(provider_spec);

    return struct {
        const Self = @This();

        pub const spec = provider_spec;
        pub const EventId = GeneratedEventId;
        pub const event_set_count = set_count;
        pub const unique_set_count = set_count;
        pub const event_sets = generated_sets;
        pub const event_to_set = generated_event_to_set;

        pub fn Payload(comptime event_id: EventId) type {
            return payloadStruct(provider_spec.events[@intFromEnum(event_id)].fields);
        }

        pub fn Definition(comptime event_id: EventId) type {
            return eventDefinition(provider_spec.events[@intFromEnum(event_id)]);
        }

        pub fn eventSet(comptime event_id: EventId) EventSet {
            return generated_sets[generated_event_to_set[@intFromEnum(event_id)]];
        }

        /// Address-stable owner for the provider's descriptor and EventSets.
        ///
        /// Initialize in final storage and do not copy after registration starts.
        /// `registerAll` registers in EventSet order. `unregisterAll` unregisters
        /// in reverse order and is idempotent after complete cleanup.
        pub const Instance = struct {
            data_file: user_events.DataFile = .{},
            events: [set_count]user_events.Event =
                [_]user_events.Event{.{}} ** set_count,
            lifecycle_busy: std.atomic.Value(bool) = .init(false),
            last_cleanup_error: ?anyerror = null,

            /// Opens `user_events_data` and registers every EventSet in order.
            /// Repeating this before complete cleanup returns
            /// `error.RegistrationActive`. A partial failure rolls back in
            /// reverse order; `error.RollbackFailed` means cleanup must be
            /// retried with `unregisterAll`.
            pub fn registerAll(self: *Instance) RegisterAllError!void {
                try self.beginLifecycle();
                defer self.endLifecycle();

                try self.prepareRegistration();
                try self.data_file.open();
                return self.registerOpenedWith(
                    registerOne,
                    unregisterOne,
                    closeOne,
                );
            }

            /// Equivalent to `registerAll`, using an explicit tracefs data path.
            pub fn registerAllPath(
                self: *Instance,
                path: [:0]const u8,
            ) RegisterAllError!void {
                try self.beginLifecycle();
                defer self.endLifecycle();

                try self.prepareRegistration();
                try self.data_file.openPath(path);
                return self.registerOpenedWith(
                    registerOne,
                    unregisterOne,
                    closeOne,
                );
            }

            /// Unregisters every EventSet in reverse order, then closes the data
            /// file. Calling this on a fully-unregistered instance is a no-op.
            /// All unregisters are attempted; the first error is returned and a
            /// later call may retry the remaining cleanup.
            pub fn unregisterAll(self: *Instance) UnregisterAllError!void {
                try self.beginLifecycle();
                defer self.endLifecycle();

                return self.unregisterOpenedWith(unregisterOne, closeOne);
            }

            fn unregisterOpenedWith(
                self: *Instance,
                comptime unregisterFn: anytype,
                comptime closeFn: anytype,
            ) UnregisterAllError!void {
                var first_error: ?user_events.EventUnregisterError = null;
                var index = self.events.len;
                while (index != 0) {
                    index -= 1;
                    unregisterFn(&self.events[index]) catch |err| {
                        if (first_error == null) first_error = err;
                    };
                }

                if (first_error) |err| return err;
                try closeFn(&self.data_file);
            }

            /// Returns the underlying cleanup error after `RollbackFailed`.
            pub fn cleanupError(self: *const Instance) ?anyerror {
                return self.last_cleanup_error;
            }

            pub inline fn isEnabled(
                self: *const Instance,
                comptime event_id: EventId,
            ) bool {
                const set_index = generated_event_to_set[@intFromEnum(event_id)];
                return self.events[set_index].isEnabled();
            }

            pub inline fn writePtr(
                self: *const Instance,
                comptime event_id: EventId,
                payload: *const Payload(event_id),
                options: WriteOptions,
            ) WriteError!user_events.WriteOutcome {
                return self.writePtrWith(
                    event_id,
                    payload,
                    options,
                    submitManaged,
                );
            }

            fn writePtrWith(
                self: *const Instance,
                comptime event_id: EventId,
                payload: *const Payload(event_id),
                options: WriteOptions,
                comptime submit: anytype,
            ) WriteError!user_events.WriteOutcome {
                const set_index = generated_event_to_set[@intFromEnum(event_id)];
                const managed_event = &self.events[set_index];
                if (!managed_event.isEnabled()) return .disabled;
                return EventWriter(
                    provider_spec,
                    @intFromEnum(event_id),
                ).emit(managed_event, payload, options, submit);
            }

            pub inline fn write(
                self: *const Instance,
                comptime event_id: EventId,
                payload: Payload(event_id),
                options: WriteOptions,
            ) WriteError!user_events.WriteOutcome {
                return self.writePtr(event_id, &payload, options);
            }

            pub inline fn writeLazy(
                self: *const Instance,
                comptime event_id: EventId,
                context: anytype,
                comptime builder: anytype,
                options: WriteOptions,
            ) WriteError!user_events.WriteOutcome {
                return self.writeLazyWith(
                    event_id,
                    context,
                    builder,
                    options,
                    submitManaged,
                );
            }

            fn writeLazyWith(
                self: *const Instance,
                comptime event_id: EventId,
                context: anytype,
                comptime builder: anytype,
                options: WriteOptions,
                comptime submit: anytype,
            ) WriteError!user_events.WriteOutcome {
                if (!self.isEnabled(event_id)) return .disabled;

                const payload = @call(.always_inline, builder, .{context});
                if (@TypeOf(payload) != Payload(event_id)) {
                    @compileError("writeLazy builder must return Provider.Payload(event_id)");
                }
                return self.writePtrWith(event_id, &payload, options, submit);
            }

            fn prepareRegistration(self: *Instance) error{RegistrationActive}!void {
                self.last_cleanup_error = null;
                if (self.data_file.isOpen()) return error.RegistrationActive;
                for (&self.events) |*managed_event| {
                    if (managed_event.isRegistered()) return error.RegistrationActive;
                }
            }

            fn registerOpenedWith(
                self: *Instance,
                comptime registerFn: anytype,
                comptime unregisterFn: anytype,
                comptime closeFn: anytype,
            ) RegisterAllError!void {
                for (&self.events, 0..) |*managed_event, index| {
                    registerFn(
                        managed_event,
                        &self.data_file,
                        provider_spec.registration_flags,
                        generated_sets[index].registration_args,
                    ) catch |err| {
                        if (!self.rollbackRegistrationWith(
                            index,
                            unregisterFn,
                            closeFn,
                        )) {
                            return error.RollbackFailed;
                        }
                        return err;
                    };
                }
            }

            fn rollbackRegistrationWith(
                self: *Instance,
                registered_count: usize,
                comptime unregisterFn: anytype,
                comptime closeFn: anytype,
            ) bool {
                var cleanup_ok = true;
                var index = registered_count;
                while (index != 0) {
                    index -= 1;
                    unregisterFn(&self.events[index]) catch |err| {
                        cleanup_ok = false;
                        if (self.last_cleanup_error == null) {
                            self.last_cleanup_error = err;
                        }
                    };
                }

                if (cleanup_ok) {
                    closeFn(&self.data_file) catch |err| {
                        cleanup_ok = false;
                        if (self.last_cleanup_error == null) {
                            self.last_cleanup_error = err;
                        }
                    };
                }
                return cleanup_ok;
            }

            fn registerAllWith(
                self: *Instance,
                comptime openFn: anytype,
                comptime registerFn: anytype,
                comptime unregisterFn: anytype,
                comptime closeFn: anytype,
            ) RegisterAllError!void {
                try self.beginLifecycle();
                defer self.endLifecycle();

                try self.prepareRegistration();
                try openFn(&self.data_file);
                return self.registerOpenedWith(
                    registerFn,
                    unregisterFn,
                    closeFn,
                );
            }

            fn unregisterAllWith(
                self: *Instance,
                comptime unregisterFn: anytype,
                comptime closeFn: anytype,
            ) UnregisterAllError!void {
                try self.beginLifecycle();
                defer self.endLifecycle();
                return self.unregisterOpenedWith(unregisterFn, closeFn);
            }

            fn registerOne(
                managed_event: *user_events.Event,
                data_file: *user_events.DataFile,
                flags: abi.RegistrationFlags,
                name_args: [:0]const u8,
            ) user_events.EventRegisterError!void {
                return managed_event.register(data_file, 0, flags, name_args);
            }

            fn unregisterOne(
                managed_event: *user_events.Event,
            ) user_events.EventUnregisterError!void {
                return managed_event.unregister();
            }

            fn closeOne(
                data_file: *user_events.DataFile,
            ) user_events.DataFileCloseError!void {
                return data_file.close();
            }

            fn beginLifecycle(self: *Instance) error{LifecycleBusy}!void {
                if (self.lifecycle_busy.cmpxchgStrong(
                    false,
                    true,
                    .acquire,
                    .monotonic,
                ) != null) {
                    return error.LifecycleBusy;
                }
            }

            fn endLifecycle(self: *Instance) void {
                self.lifecycle_busy.store(false, .release);
            }
        };
    };
}

fn submitManaged(
    managed_event: *const user_events.Event,
    vectors: []user_events.Iovec,
) user_events.EventWriteError!user_events.WriteOutcome {
    return managed_event.writev(vectors);
}

fn EventWriter(comptime provider_spec: ProviderSpec, comptime event_index: usize) type {
    @setEvalBranchQuota(200_000);
    const event_spec = provider_spec.events[event_index];
    const PayloadType = payloadStruct(event_spec.fields);
    const Definition = eventDefinition(event_spec);
    const vector_capacity = maximumEventIovecs(event_spec.fields);
    const prefix_capacity = maximumPrefixes(event_spec.fields);
    const boolean_capacity = maximumBooleanBytes(
        event_spec.fields,
        Definition.max_payload_bytes,
    );

    return struct {
        fn emit(
            managed_event: *const user_events.Event,
            payload: *const PayloadType,
            options: WriteOptions,
            comptime submit: anytype,
        ) WriteError!user_events.WriteOutcome {
            if (options.related != null and options.activity == null) {
                return error.ActivityRequired;
            }

            var vectors: [vector_capacity]user_events.Iovec = undefined;
            var prefixes: [prefix_capacity]u16 = undefined;
            var booleans: [boolean_capacity]u8 = undefined;
            var state: EncodeState(
                vector_capacity,
                prefix_capacity,
                boolean_capacity,
            ) = .{
                .vectors = &vectors,
                .prefixes = &prefixes,
                .booleans = &booleans,
                .max_payload_bytes = Definition.max_payload_bytes,
            };

            vectors[0] = .{ .base = "".ptr, .len = 0 };
            state.vector_count = 1;
            try state.addStatic(&Definition.header);

            var activity_extension: [36]u8 = undefined;
            if (options.activity) |activity| {
                const activity_length = encodeActivityExtension(
                    &activity_extension,
                    activity,
                    options.related,
                );
                try state.addStatic(activity_extension[0..activity_length]);
            }

            try state.addStatic(&Definition.metadata_extension);
            try encodeFields(&state, event_spec.fields, payload);
            return @call(
                .always_inline,
                submit,
                .{ managed_event, vectors[0..state.vector_count] },
            );
        }
    };
}

fn maximumEventIovecs(comptime fields: []const FieldSpec) usize {
    return cappedAdd(4, maximumFieldIovecs(fields), user_events.max_iovecs);
}

fn maximumFieldIovecs(comptime fields: []const FieldSpec) usize {
    var total: usize = 0;
    for (fields) |field| {
        total = cappedAdd(total, maximumKindIovecs(field.kind), user_events.max_iovecs);
    }
    return total;
}

fn maximumKindIovecs(comptime kind: FieldKind) usize {
    return switch (kind) {
        .u8,
        .u16,
        .u32,
        .u64,
        .i8,
        .i16,
        .i32,
        .i64,
        .f32,
        .f64,
        .value128,
        .boolean,
        .fixed_array,
        => 1,
        .utf8, .binary, .variable_array => 2,
        .structure => |fields| maximumFieldIovecs(fields),
        .fixed_struct_array => |array| cappedMultiply(
            array.count,
            maximumFieldIovecs(array.fields),
            user_events.max_iovecs,
        ),
        .variable_struct_array => |array| cappedAdd(
            1,
            cappedMultiply(
                array.max,
                maximumFieldIovecs(array.fields),
                user_events.max_iovecs,
            ),
            user_events.max_iovecs,
        ),
        .zstring8, .utf16, .utf32, .string_array => @compileError(
            "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported",
        ),
    };
}

fn maximumPrefixes(comptime fields: []const FieldSpec) usize {
    var total: usize = 0;
    for (fields) |field| {
        total = cappedAdd(total, maximumKindPrefixes(field.kind), user_events.max_iovecs);
    }
    return total;
}

fn maximumKindPrefixes(comptime kind: FieldKind) usize {
    return switch (kind) {
        .utf8, .binary, .variable_array => 1,
        .structure => |fields| maximumPrefixes(fields),
        .fixed_struct_array => |array| cappedMultiply(
            array.count,
            maximumPrefixes(array.fields),
            user_events.max_iovecs,
        ),
        .variable_struct_array => |array| cappedAdd(
            1,
            cappedMultiply(
                array.max,
                maximumPrefixes(array.fields),
                user_events.max_iovecs,
            ),
            user_events.max_iovecs,
        ),
        .zstring8, .utf16, .utf32, .string_array => @compileError(
            "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported",
        ),
        else => 0,
    };
}

fn maximumBooleanBytes(comptime fields: []const FieldSpec, comptime cap: usize) usize {
    var total: usize = 0;
    for (fields) |field| {
        total = cappedAdd(total, maximumKindBooleanBytes(field.kind, cap), cap);
    }
    return total;
}

fn maximumKindBooleanBytes(comptime kind: FieldKind, comptime cap: usize) usize {
    return switch (kind) {
        .boolean => @min(1, cap),
        .fixed_array => |array| if (array.element == .boolean)
            @min(array.count, cap)
        else
            0,
        .variable_array => |array| if (array.element == .boolean)
            @min(array.max, cap)
        else
            0,
        .structure => |fields| maximumBooleanBytes(fields, cap),
        .fixed_struct_array => |array| cappedMultiply(
            array.count,
            maximumBooleanBytes(array.fields, cap),
            cap,
        ),
        .variable_struct_array => |array| cappedMultiply(
            array.max,
            maximumBooleanBytes(array.fields, cap),
            cap,
        ),
        .zstring8, .utf16, .utf32, .string_array => @compileError(
            "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported",
        ),
        else => 0,
    };
}

fn cappedAdd(comptime first: usize, comptime second: usize, comptime cap: usize) usize {
    if (first >= cap or second >= cap or first > cap - second) return cap;
    return first + second;
}

fn cappedMultiply(
    comptime first: usize,
    comptime second: usize,
    comptime cap: usize,
) usize {
    if (first == 0 or second == 0) return 0;
    if (first >= cap or second >= cap or first > cap / second) return cap;
    return first * second;
}

fn EncodeState(
    comptime vector_capacity: usize,
    comptime prefix_capacity: usize,
    comptime boolean_capacity: usize,
) type {
    return struct {
        const State = @This();

        vectors: *[vector_capacity]user_events.Iovec,
        prefixes: *[prefix_capacity]u16,
        booleans: *[boolean_capacity]u8,
        vector_count: usize = 0,
        prefix_count: usize = 0,
        boolean_count: usize = 0,
        payload_bytes: usize = 0,
        max_payload_bytes: usize,

        fn addStatic(self: *State, bytes: []const u8) WriteError!void {
            return self.addVector(bytes);
        }

        fn addPayload(self: *State, bytes: []const u8) WriteError!void {
            if (bytes.len > self.max_payload_bytes -| self.payload_bytes) {
                return error.EventTooLarge;
            }
            self.payload_bytes += bytes.len;
            return self.addVector(bytes);
        }

        fn addPrefix(self: *State, value: u16) WriteError!void {
            if (self.prefix_count == self.prefixes.len) {
                return error.TooManyIovecs;
            }
            const index = self.prefix_count;
            self.prefix_count += 1;
            self.prefixes[index] = value;
            return self.addPayload(std.mem.asBytes(&self.prefixes[index]));
        }

        fn addBoolean(self: *State, value: bool) WriteError!void {
            if (self.boolean_count == self.booleans.len) {
                return error.EventTooLarge;
            }
            const index = self.boolean_count;
            self.boolean_count += 1;
            self.booleans[index] = @intFromBool(value);
            return self.addPayload(self.booleans[index .. index + 1]);
        }

        fn addBooleans(self: *State, values: anytype) WriteError!void {
            if (values.len > self.max_payload_bytes -| self.payload_bytes or
                values.len > self.booleans.len -| self.boolean_count)
            {
                return error.EventTooLarge;
            }
            const start = self.boolean_count;
            for (values) |value| {
                self.booleans[self.boolean_count] = @intFromBool(value);
                self.boolean_count += 1;
            }
            self.payload_bytes += values.len;
            return self.addVector(self.booleans[start..self.boolean_count]);
        }

        fn addVector(self: *State, bytes: []const u8) WriteError!void {
            if (bytes.len == 0) return;
            if (self.vector_count == self.vectors.len) {
                return error.TooManyIovecs;
            }
            self.vectors[self.vector_count] = .{
                .base = bytes.ptr,
                .len = bytes.len,
            };
            self.vector_count += 1;
        }
    };
}

fn encodeFields(
    state: anytype,
    comptime fields: []const FieldSpec,
    payload: *const payloadStruct(fields),
) WriteError!void {
    inline for (fields) |field| {
        try encodeField(state, field, &@field(payload.*, field.name));
    }
}

fn encodeField(
    state: anytype,
    comptime field: FieldSpec,
    value: *const payloadFieldType(field.kind),
) WriteError!void {
    switch (field.kind) {
        .u8,
        .u16,
        .u32,
        .u64,
        .i8,
        .i16,
        .i32,
        .i64,
        .f32,
        .f64,
        .value128,
        => try state.addPayload(std.mem.asBytes(value)),
        .boolean => try state.addBoolean(value.*),
        .utf8, .binary => |max| {
            const bytes = value.*;
            if (bytes.len > max or bytes.len > std.math.maxInt(u16)) {
                return error.FieldTooLong;
            }
            try state.addPrefix(@intCast(bytes.len));
            try state.addPayload(bytes);
        },
        .fixed_array => |array| {
            if (array.element == .boolean) {
                try state.addBooleans(value.*[0..]);
            } else {
                try state.addPayload(std.mem.asBytes(value));
            }
        },
        .variable_array => |array| {
            const values = value.*;
            if (values.len > array.max or values.len > std.math.maxInt(u16)) {
                return error.FieldTooLong;
            }
            try state.addPrefix(@intCast(values.len));
            if (array.element == .boolean) {
                try state.addBooleans(values);
            } else {
                try state.addPayload(std.mem.sliceAsBytes(values));
            }
        },
        .structure => |children| {
            try encodeFields(state, children, value);
        },
        .fixed_struct_array => |array| {
            inline for (0..array.count) |index| {
                try encodeFields(state, array.fields, &value.*[index]);
            }
        },
        .variable_struct_array => |array| {
            const values = value.*;
            if (values.len > array.max or values.len > std.math.maxInt(u16)) {
                return error.FieldTooLong;
            }
            try state.addPrefix(@intCast(values.len));
            for (values) |*element| {
                try encodeFields(state, array.fields, element);
            }
        },
        .zstring8, .utf16, .utf32, .string_array => {
            @compileError("zstrings, UTF-16/UTF-32 strings, and string arrays are not supported");
        },
    }
}

fn encodeActivityExtension(
    output: *[36]u8,
    activity: *const eventheader.ActivityId,
    related: ?*const eventheader.ActivityId,
) usize {
    const data_length: u16 = if (related == null) 16 else 32;
    const kind = eventheader.ExtensionKind.activity | eventheader.ExtensionKind.chain;
    @memcpy(output[0..2], std.mem.asBytes(&data_length));
    @memcpy(output[2..4], std.mem.asBytes(&kind));
    @memcpy(output[4..20], activity);
    if (related) |related_id| {
        @memcpy(output[20..36], related_id);
        return 36;
    }
    return 20;
}

fn payloadStruct(comptime fields: []const FieldSpec) type {
    var field_names: [fields.len][]const u8 = undefined;
    var field_types: [fields.len]type = undefined;
    var field_attributes: [fields.len]std.builtin.Type.StructField.Attributes = undefined;
    for (fields, 0..) |field, index| {
        field_names[index] = field.name;
        field_types[index] = payloadFieldType(field.kind);
        field_attributes[index] = .{};
    }
    return @Struct(.auto, null, &field_names, &field_types, &field_attributes);
}

fn payloadFieldType(comptime kind: FieldKind) type {
    return switch (kind) {
        .u8 => u8,
        .u16 => u16,
        .u32 => u32,
        .u64 => u64,
        .i8 => i8,
        .i16 => i16,
        .i32 => i32,
        .i64 => i64,
        .f32 => f32,
        .f64 => f64,
        .value128 => Value128,
        .boolean => bool,
        .utf8, .binary => []const u8,
        .fixed_array => |array| [array.count]scalarType(array.element),
        .variable_array => |array| []const scalarType(array.element),
        .structure => |fields| payloadStruct(fields),
        .fixed_struct_array => |array| [array.count]payloadStruct(array.fields),
        .variable_struct_array => |array| []const payloadStruct(array.fields),
        .zstring8, .utf16, .utf32, .string_array => @compileError(
            "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported",
        ),
    };
}

fn scalarType(comptime scalar: ScalarKind) type {
    return switch (scalar) {
        .u8 => u8,
        .u16 => u16,
        .u32 => u32,
        .u64 => u64,
        .i8 => i8,
        .i16 => i16,
        .i32 => i32,
        .i64 => i64,
        .f32 => f32,
        .f64 => f64,
        .value128 => Value128,
        .boolean => bool,
    };
}

fn eventDefinition(comptime event_spec: EventSpec) type {
    const lowered_fields = lowerFields(event_spec.fields);
    return eventheader.EventDefinition(.{
        .name = event_spec.name orelse event_spec.symbol,
        .attributes = event_spec.attributes,
        .id = event_spec.id,
        .version = event_spec.version,
        .tag = event_spec.tag,
        .opcode = event_spec.opcode,
        .level = event_spec.level,
        .fields = &lowered_fields,
    });
}

fn lowerFields(comptime fields: []const FieldSpec) [fields.len]eventheader.Field {
    var result: [fields.len]eventheader.Field = undefined;
    for (fields, 0..) |field, index| {
        result[index] = lowerField(field);
    }
    return result;
}

fn lowerField(comptime field: FieldSpec) eventheader.Field {
    const Base = struct {
        fn make(
            comptime encoding: eventheader.Encoding,
            comptime array: eventheader.Array,
            comptime children: []const eventheader.Field,
            comptime natural_format: eventheader.Format,
        ) eventheader.Field {
            return .{
                .name = field.name,
                .attributes = field.attributes,
                .encoding = encoding,
                .format = field.format orelse natural_format,
                .tag = field.tag,
                .array = array,
                .children = children,
            };
        }
    };

    return switch (field.kind) {
        .u8 => Base.make(.value8, .scalar, &.{}, .default),
        .u16 => Base.make(.value16, .scalar, &.{}, .default),
        .u32 => Base.make(.value32, .scalar, &.{}, .default),
        .u64 => Base.make(.value64, .scalar, &.{}, .default),
        .i8 => Base.make(.value8, .scalar, &.{}, .signed_int),
        .i16 => Base.make(.value16, .scalar, &.{}, .signed_int),
        .i32 => Base.make(.value32, .scalar, &.{}, .signed_int),
        .i64 => Base.make(.value64, .scalar, &.{}, .signed_int),
        .f32 => Base.make(.value32, .scalar, &.{}, .float),
        .f64 => Base.make(.value64, .scalar, &.{}, .float),
        .value128 => Base.make(.value128, .scalar, &.{}, .default),
        .boolean => Base.make(.value8, .scalar, &.{}, .boolean),
        .utf8 => Base.make(.string_length16_char8, .scalar, &.{}, .default),
        .binary => Base.make(.binary_length16_char8, .scalar, &.{}, .default),
        .fixed_array => |array| Base.make(
            scalarEncoding(array.element),
            .{ .fixed = array.count },
            &.{},
            scalarFormat(array.element),
        ),
        .variable_array => |array| Base.make(
            scalarEncoding(array.element),
            .variable,
            &.{},
            scalarFormat(array.element),
        ),
        .structure => |children| blk: {
            const lowered = lowerFields(children);
            break :blk Base.make(.structure, .scalar, &lowered, .default);
        },
        .fixed_struct_array => |array| blk: {
            const lowered = lowerFields(array.fields);
            break :blk Base.make(
                .structure,
                .{ .fixed = array.count },
                &lowered,
                .default,
            );
        },
        .variable_struct_array => |array| blk: {
            const lowered = lowerFields(array.fields);
            break :blk Base.make(.structure, .variable, &lowered, .default);
        },
        .zstring8, .utf16, .utf32, .string_array => @compileError(
            "zstrings, UTF-16/UTF-32 strings, and string arrays are not supported",
        ),
    };
}

fn scalarEncoding(comptime scalar: ScalarKind) eventheader.Encoding {
    return switch (scalar) {
        .u8, .i8, .boolean => .value8,
        .u16, .i16 => .value16,
        .u32, .i32, .f32 => .value32,
        .u64, .i64, .f64 => .value64,
        .value128 => .value128,
    };
}

fn scalarFormat(comptime scalar: ScalarKind) eventheader.Format {
    return switch (scalar) {
        .u8, .u16, .u32, .u64 => .default,
        .i8, .i16, .i32, .i64 => .signed_int,
        .f32, .f64 => .float,
        .value128 => .default,
        .boolean => .boolean,
    };
}

fn makeEventId(comptime events: []const EventSpec) type {
    var field_names: [events.len][]const u8 = undefined;
    var field_values: [events.len]u16 = undefined;
    for (events, 0..) |event_spec, index| {
        field_names[index] = event_spec.symbol;
        field_values[index] = @intCast(index);
    }
    return @Enum(u16, .exhaustive, &field_names, &field_values);
}

fn uniqueSetCount(comptime provider_spec: ProviderSpec) usize {
    var count: usize = 0;
    for (provider_spec.events, 0..) |_, index| {
        if (isFirstSetOccurrence(provider_spec, index)) count += 1;
    }
    return count;
}

fn makeEventSets(
    comptime provider_spec: ProviderSpec,
) [uniqueSetCount(provider_spec)]EventSet {
    var result: [uniqueSetCount(provider_spec)]EventSet = undefined;
    var output_index: usize = 0;
    for (provider_spec.events, 0..) |_, event_index| {
        if (isFirstSetOccurrence(provider_spec, event_index)) {
            result[output_index] = makeEventSet(provider_spec, event_index);
            output_index += 1;
        }
    }
    return result;
}

fn makeEventToSet(
    comptime provider_spec: ProviderSpec,
) [provider_spec.events.len]usize {
    var result: [provider_spec.events.len]usize = undefined;
    var representative_events: [provider_spec.events.len]usize = undefined;
    var set_count: usize = 0;

    for (&result, 0..) |*set_index, event_index| {
        var matched_set: ?usize = null;
        for (representative_events[0..set_count], 0..) |representative, candidate_set| {
            if (sameEventSet(provider_spec, representative, event_index)) {
                matched_set = candidate_set;
                break;
            }
        }

        if (matched_set) |existing_set| {
            set_index.* = existing_set;
        } else {
            representative_events[set_count] = event_index;
            set_index.* = set_count;
            set_count += 1;
        }
    }
    return result;
}

fn isFirstSetOccurrence(
    comptime provider_spec: ProviderSpec,
    comptime event_index: usize,
) bool {
    for (0..event_index) |previous| {
        if (sameEventSet(provider_spec, previous, event_index)) return false;
    }
    return true;
}

fn sameEventSet(
    comptime provider_spec: ProviderSpec,
    comptime first_index: usize,
    comptime second_index: usize,
) bool {
    const first = provider_spec.events[first_index];
    const second = provider_spec.events[second_index];
    return first.level == second.level and
        first.keyword == second.keyword and
        std.mem.eql(
            u8,
            effectiveGroup(provider_spec, first),
            effectiveGroup(provider_spec, second),
        ) and
        std.mem.eql(
            u8,
            effectiveOptions(provider_spec, first),
            effectiveOptions(provider_spec, second),
        );
}

fn makeEventSet(
    comptime provider_spec: ProviderSpec,
    comptime event_index: usize,
) EventSet {
    const event_spec = provider_spec.events[event_index];
    const group = effectiveGroup(provider_spec, event_spec);
    const options = effectiveOptions(provider_spec, event_spec);
    const suffix_storage = mergeOptions(group, options);
    const suffix: []const u8 = &suffix_storage;
    const name = std.fmt.comptimePrint(
        "{s}_L{x}K{x}{s}",
        .{ provider_spec.name, event_spec.level, event_spec.keyword, suffix },
    );
    const args = std.fmt.comptimePrint(
        "{s} {s}",
        .{ name, eventheader_registration_schema },
    );

    return .{
        .level = event_spec.level,
        .keyword = event_spec.keyword,
        .group = group,
        .options = options,
        .suffix = suffix,
        .registration_name = name,
        .registration_args = args,
    };
}

fn effectiveGroup(
    comptime provider_spec: ProviderSpec,
    comptime event_spec: EventSpec,
) []const u8 {
    return event_spec.group orelse provider_spec.group;
}

fn effectiveOptions(
    comptime provider_spec: ProviderSpec,
    comptime event_spec: EventSpec,
) []const u8 {
    return event_spec.options orelse provider_spec.options;
}

fn mergeOptions(
    comptime group: []const u8,
    comptime options: []const u8,
) [options.len + if (group.len == 0) 0 else group.len + 1]u8 {
    var result: [options.len + if (group.len == 0) 0 else group.len + 1]u8 =
        undefined;
    if (group.len == 0) {
        @memcpy(&result, options);
        return result;
    }

    var input: usize = 0;
    var output: usize = 0;
    var inserted_group = false;
    while (input < options.len) {
        const option_start = input;
        input += 1;
        while (input < options.len and !std.ascii.isUpper(options[input])) {
            input += 1;
        }

        if (!inserted_group and options[option_start] > 'G') {
            result[output] = 'G';
            output += 1;
            @memcpy(result[output .. output + group.len], group);
            output += group.len;
            inserted_group = true;
        }
        @memcpy(result[output .. output + input - option_start], options[option_start..input]);
        output += input - option_start;
    }

    if (!inserted_group) {
        result[output] = 'G';
        output += 1;
        @memcpy(result[output .. output + group.len], group);
        output += group.len;
    }
    std.debug.assert(output == result.len);
    return result;
}

fn validateProviderSpec(comptime provider_spec: ProviderSpec) void {
    validateProviderName(provider_spec.name);
    validateGroup(provider_spec.group);
    validateOptions(provider_spec.options);

    if (provider_spec.events.len == 0) {
        @compileError("provider must define at least one event");
    }
    if (provider_spec.events.len > std.math.maxInt(u16) + 1) {
        @compileError("provider may define at most 65536 events");
    }

    for (provider_spec.events, 0..) |event_spec, event_index| {
        validateZigIdentifier("event symbol", event_spec.symbol);
        if (event_spec.level == 0) {
            @compileError("provider event level must be nonzero");
        }
        validateGroup(effectiveGroup(provider_spec, event_spec));
        validateOptions(effectiveOptions(provider_spec, event_spec));
        validateFields(event_spec.fields, 0);

        for (provider_spec.events[0..event_index]) |previous| {
            if (std.mem.eql(u8, previous.symbol, event_spec.symbol)) {
                @compileError("duplicate provider event symbol: " ++ event_spec.symbol);
            }
        }

        const Definition = eventDefinition(event_spec);
        _ = Definition.metadata_length;
    }

    const sets = makeEventSets(provider_spec);
    for (sets) |set| {
        if (set.registration_name.len >= eventheader_name_max) {
            @compileError("EventHeader registration name must be less than 256 bytes");
        }
        if (set.registration_args.len > user_events.max_registration_description_len) {
            @compileError("user_events registration description exceeds the kernel limit");
        }
    }
}

fn validateProviderName(comptime name: []const u8) void {
    if (name.len == 0) @compileError("provider name must not be empty");
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
            @compileError("provider name must contain only ASCII letters, digits, and '_'");
        }
    }
}

fn validateGroup(comptime group: []const u8) void {
    for (group) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte)) {
            @compileError("EventHeader group must contain only lowercase ASCII letters and digits");
        }
    }
}

fn validateOptions(comptime options: []const u8) void {
    var index: usize = 0;
    var previous_type: u8 = 0;
    while (index < options.len) {
        const option_type = options[index];
        if (!std.ascii.isUpper(option_type)) {
            @compileError("EventHeader option must start with an uppercase ASCII letter");
        }
        if (option_type <= previous_type) {
            @compileError("EventHeader options must have unique, alphabetically sorted types");
        }
        if (option_type == 'G') {
            @compileError("specify the EventHeader G option through the group field");
        }
        previous_type = option_type;
        index += 1;
        while (index < options.len and !std.ascii.isUpper(options[index])) {
            if (!std.ascii.isLower(options[index]) and !std.ascii.isDigit(options[index])) {
                @compileError("EventHeader option values must use lowercase ASCII letters or digits");
            }
            index += 1;
        }
    }
}

fn validateFields(
    comptime fields: []const FieldSpec,
    comptime depth: usize,
) void {
    if (depth > max_nesting) {
        @compileError("provider field nesting exceeds the supported depth of 16");
    }
    if (depth != 0 and (fields.len == 0 or fields.len > 127)) {
        @compileError("EventHeader struct must have 1 through 127 immediate fields");
    }

    for (fields, 0..) |field, field_index| {
        validateZigIdentifier("field name", field.name);
        for (fields[0..field_index]) |previous| {
            if (std.mem.eql(u8, previous.name, field.name)) {
                @compileError("duplicate provider field name: " ++ field.name);
            }
        }

        switch (field.kind) {
            .fixed_array => |array| {
                if (array.count == 0) {
                    @compileError("fixed scalar array count must be nonzero");
                }
            },
            .variable_array => |array| {
                if (array.max == 0) {
                    @compileError("variable scalar array maximum must be nonzero");
                }
            },
            .structure => |children| {
                if (field.format != null) {
                    @compileError("struct fields cannot specify an EventHeader format");
                }
                validateFields(children, depth + 1);
            },
            .fixed_struct_array => |array| {
                if (field.format != null) {
                    @compileError("struct fields cannot specify an EventHeader format");
                }
                if (array.count == 0) {
                    @compileError("fixed struct array count must be nonzero");
                }
                validateFields(array.fields, depth + 1);
            },
            .variable_struct_array => |array| {
                if (field.format != null) {
                    @compileError("struct fields cannot specify an EventHeader format");
                }
                if (array.max == 0) {
                    @compileError("variable struct array maximum must be nonzero");
                }
                validateFields(array.fields, depth + 1);
            },
            .utf8, .binary => |max| {
                if (max == 0) {
                    @compileError("bounded string and binary maxima must be nonzero");
                }
            },
            .zstring8, .utf16, .utf32, .string_array => {
                @compileError("zstrings, UTF-16/UTF-32 strings, and string arrays are not supported");
            },
            else => {},
        }
    }
}

fn validateZigIdentifier(comptime kind: []const u8, comptime name: []const u8) void {
    if (name.len == 0) @compileError(kind ++ " must not be empty");
    if (!std.ascii.isAlphabetic(name[0]) and name[0] != '_') {
        @compileError(kind ++ " must start with an ASCII letter or '_': " ++ name);
    }
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') {
            @compileError(kind ++ " must contain only ASCII letters, digits, and '_': " ++ name);
        }
    }
    const source = std.fmt.comptimePrint("{s}", .{name});
    var tokenizer = std.zig.Tokenizer.init(source);
    const token = tokenizer.next();
    if (token.tag != .identifier or token.loc.start != 0 or token.loc.end != name.len or
        tokenizer.next().tag != .eof)
    {
        @compileError(kind ++ " must be a valid bare Zig identifier: " ++ name);
    }
}

const generated_test_spec: ProviderSpec = .{
    .name = "Zig_Generated",
    .group = "core",
    .options = "A1",
    .events = &.{
        .{
            .symbol = "first",
            .name = "FirstEvent",
            .level = 4,
            .keyword = 0x2a,
            .fields = &.{
                .{ .name = "count", .kind = .u32 },
                .{
                    .name = "nested",
                    .kind = .{ .structure = &.{
                        .{ .name = "ok", .kind = .boolean },
                        .{ .name = "amount", .kind = .i64 },
                    } },
                },
            },
        },
        .{
            .symbol = "second",
            .name = "SecondEvent",
            .level = 4,
            .keyword = 0x2a,
            .fields = &.{
                .{
                    .name = "values",
                    .kind = .{ .fixed_array = .{ .element = .u16, .count = 3 } },
                },
            },
        },
        .{
            .symbol = "other",
            .level = 5,
            .keyword = 0,
            .group = "other",
            .options = "Z9",
            .fields = &.{
                .{
                    .name = "items",
                    .kind = .{ .variable_struct_array = .{
                        .max = 4,
                        .fields = &.{
                            .{ .name = "id", .kind = .u8 },
                        },
                    } },
                },
            },
        },
    },
};

const GeneratedTestProvider = Provider(generated_test_spec);

fn makeScalingEvents(comptime count: usize) [count]EventSpec {
    @setEvalBranchQuota(200_000);
    var events: [count]EventSpec = undefined;
    for (&events, 0..) |*event_spec, index| {
        event_spec.* = .{
            .symbol = std.fmt.comptimePrint("event_{d}", .{index}),
            .level = @intCast(index % 255 + 1),
            .keyword = index,
        };
    }
    return events;
}

const scaling_events = makeScalingEvents(128);
const ScalingProvider = Provider(.{
    .name = "Zig_Scaling",
    .events = &scaling_events,
});

test "EventSet mapping scales without repeated first-occurrence scans" {
    try std.testing.expectEqual(@as(usize, scaling_events.len), ScalingProvider.event_set_count);
    inline for (ScalingProvider.event_to_set, 0..) |set_index, event_index| {
        try std.testing.expectEqual(event_index, set_index);
    }
}

test "generated event enum payloads nested types and EventSet names" {
    try std.testing.expectEqual(@as(u16, 0), @intFromEnum(GeneratedTestProvider.EventId.first));
    try std.testing.expectEqual(@as(u16, 2), @intFromEnum(GeneratedTestProvider.EventId.other));

    const First = GeneratedTestProvider.Payload(.first);
    const Nested = @FieldType(First, "nested");
    try std.testing.expect(First == @TypeOf(First{
        .count = 1,
        .nested = .{ .ok = true, .amount = -2 },
    }));
    try std.testing.expect(@FieldType(First, "count") == u32);
    try std.testing.expect(@FieldType(Nested, "ok") == bool);
    try std.testing.expect(@FieldType(Nested, "amount") == i64);

    const Second = GeneratedTestProvider.Payload(.second);
    try std.testing.expect(@FieldType(Second, "values") == [3]u16);
    const Other = GeneratedTestProvider.Payload(.other);
    try std.testing.expect(@FieldType(
        @typeInfo(@FieldType(Other, "items")).pointer.child,
        "id",
    ) == u8);

    try std.testing.expectEqual(@as(usize, 2), GeneratedTestProvider.event_set_count);
    try std.testing.expectEqualSlices(
        u8,
        "Zig_Generated_L4K2aA1Gcore",
        GeneratedTestProvider.event_sets[0].registration_name,
    );
    try std.testing.expectEqualSlices(
        u8,
        "Zig_Generated_L5K0GotherZ9",
        GeneratedTestProvider.event_sets[1].registration_name,
    );
    try std.testing.expectEqual(
        GeneratedTestProvider.event_to_set[0],
        GeneratedTestProvider.event_to_set[1],
    );
    try std.testing.expectEqualStrings(
        "Zig_Generated_L4K2aA1Gcore " ++ eventheader_registration_schema,
        GeneratedTestProvider.event_sets[0].registration_args,
    );
    try std.testing.expectEqualSlices(
        u8,
        "FirstEvent\x00" ++
            "count\x00" ++ [_]u8{0x04} ++
            "nested\x00" ++ [_]u8{ 0x81, 0x02 } ++
            "ok\x00" ++ [_]u8{ 0x82, 0x07 } ++
            "amount\x00" ++ [_]u8{ 0x85, 0x02 },
        &GeneratedTestProvider.Definition(.first).metadata_data,
    );
}

const wire_test_spec: ProviderSpec = .{
    .name = "Zig_Wire",
    .events = &.{
        .{
            .symbol = "everything",
            .name = "Everything",
            .id = 0x1234,
            .version = 2,
            .tag = 0x5678,
            .opcode = 1,
            .level = 4,
            .keyword = 1,
            .fields = &.{
                .{ .name = "number", .kind = .u32 },
                .{ .name = "ratio", .kind = .f64 },
                .{ .name = "ready", .kind = .boolean },
                .{ .name = "identifier", .kind = .value128 },
                .{ .name = "message", .kind = .{ .utf8 = 16 } },
                .{ .name = "blob", .kind = .{ .binary = 16 } },
                .{
                    .name = "fixed",
                    .kind = .{ .fixed_array = .{ .element = .u16, .count = 2 } },
                },
                .{
                    .name = "fixed_flags",
                    .kind = .{ .fixed_array = .{ .element = .boolean, .count = 3 } },
                },
                .{
                    .name = "dynamic_flags",
                    .kind = .{ .variable_array = .{ .element = .boolean, .max = 4 } },
                },
                .{
                    .name = "dynamic",
                    .kind = .{ .variable_array = .{ .element = .i32, .max = 3 } },
                },
                .{
                    .name = "nested",
                    .kind = .{ .structure = &.{
                        .{ .name = "ok", .kind = .boolean },
                        .{ .name = "amount", .kind = .u64 },
                    } },
                },
                .{
                    .name = "points",
                    .kind = .{ .fixed_struct_array = .{
                        .count = 2,
                        .fields = &.{
                            .{ .name = "x", .kind = .i16 },
                            .{ .name = "y", .kind = .i16 },
                        },
                    } },
                },
                .{
                    .name = "samples",
                    .kind = .{ .variable_struct_array = .{
                        .max = 2,
                        .fields = &.{
                            .{ .name = "code", .kind = .u8 },
                            .{ .name = "text", .kind = .{ .utf8 = 4 } },
                        },
                    } },
                },
            },
        },
    },
};

const WireTestProvider = Provider(wire_test_spec);

const golden_test_spec: ProviderSpec = .{
    .name = "Zig_Golden",
    .events = &.{.{
        .symbol = "golden",
        .name = "Golden",
        .id = 0x2345,
        .version = 1,
        .tag = 0x6789,
        .opcode = 2,
        .level = 4,
        .fields = &.{.{ .name = "value", .kind = .u32 }},
    }},
};

const GoldenTestProvider = Provider(golden_test_spec);

const CapturedIovecs = struct {
    var bytes: [8192]u8 = undefined;
    var len: usize = 0;
    var calls: usize = 0;
    var write_index: u32 = 0;

    fn reset(index: u32) void {
        len = 0;
        calls = 0;
        write_index = index;
    }

    fn submit(
        _: *const user_events.Event,
        vectors: []user_events.Iovec,
    ) user_events.EventWriteError!user_events.WriteOutcome {
        calls += 1;
        std.debug.assert(vectors.len >= 3);
        std.debug.assert(vectors[0].len == 0);
        append(std.mem.asBytes(&write_index));
        for (vectors[1..]) |vector| append(vector.base[0..vector.len]);
        return .written;
    }

    fn append(value: []const u8) void {
        std.debug.assert(value.len <= bytes.len - len);
        @memcpy(bytes[len .. len + value.len], value);
        len += value.len;
    }
};

const ExpectedBytes = struct {
    bytes: [8192]u8 = undefined,
    len: usize = 0,

    fn append(self: *ExpectedBytes, value: []const u8) void {
        std.debug.assert(value.len <= self.bytes.len - self.len);
        @memcpy(self.bytes[self.len .. self.len + value.len], value);
        self.len += value.len;
    }

    fn appendU16(self: *ExpectedBytes, value: u16) void {
        self.append(std.mem.asBytes(&value));
    }
};

// Independent literals derived from Microsoft's EventHeader ABI declaration:
// https://github.com/microsoft/LinuxTracepoints/blob/main/libeventheader-tracepoint/include/eventheader/eventheader.h
// The complete frame follows the Rust writer's write-index/header/activity/
// metadata/payload ordering:
// https://github.com/microsoft/LinuxTracepoints-Rust/blob/main/eventheader/src/_internal.rs
const golden_header_le64 = [_]u8{
    0x07, 0x01, 0x45, 0x23, 0x89, 0x67, 0x02, 0x04,
};

const golden_metadata_extension_le64 = [_]u8{
    0x0e, 0x00, 0x01, 0x00,
    0x47, 0x6f, 0x6c, 0x64,
    0x65, 0x6e, 0x00, 0x76,
    0x61, 0x6c, 0x75, 0x65,
    0x00, 0x04,
};

const golden_provider_frame_le64 = [_]u8{
    // Native user_events write index.
    0xd4, 0xc3, 0xb2, 0xa1,
    // EventHeader.
    0x07, 0x01, 0x45, 0x23,
    0x89, 0x67, 0x02, 0x04,
    // Chained activity extension with activity and related IDs.
    0x20, 0x00, 0x02, 0x80,
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f,
    // Terminal metadata extension: "Golden", then uint32 "value".
    0x0e, 0x00, 0x01, 0x00,
    0x47, 0x6f, 0x6c, 0x64,
    0x65, 0x6e, 0x00, 0x76,
    0x61, 0x6c, 0x75, 0x65,
    0x00, 0x04,
    // uint32 payload.
    0x01, 0xef,
    0xcd, 0xab,
};

test "literal little-endian 64-bit EventHeader golden vectors" {
    if (@sizeOf(usize) != 8 or builtin.cpu.arch.endian() != .little) return;

    const Definition = GoldenTestProvider.Definition(.golden);
    try std.testing.expectEqualSlices(u8, &golden_header_le64, &Definition.header);
    try std.testing.expectEqualSlices(
        u8,
        &golden_metadata_extension_le64,
        &Definition.metadata_extension,
    );

    const activity: eventheader.ActivityId = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const related: eventheader.ActivityId = .{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    const payload: GoldenTestProvider.Payload(.golden) = .{
        .value = 0xabcdef01,
    };
    var event: user_events.Event = .{};
    CapturedIovecs.reset(0xa1b2c3d4);
    _ = try EventWriter(golden_test_spec, 0).emit(
        &event,
        &payload,
        .{ .activity = &activity, .related = &related },
        CapturedIovecs.submit,
    );
    try std.testing.expectEqualSlices(
        u8,
        &golden_provider_frame_le64,
        CapturedIovecs.bytes[0..CapturedIovecs.len],
    );
}

const WirePayloadStorage = struct {
    payload: WireTestProvider.Payload(.everything),
    dynamic: [2]i32,
    samples: [2]@typeInfo(@FieldType(
        WireTestProvider.Payload(.everything),
        "samples",
    )).pointer.child,
    dynamic_flags: [2]bool,

    fn init(self: *WirePayloadStorage) void {
        self.dynamic = .{ -7, 9 };
        self.dynamic_flags = .{ false, true };
        self.samples = .{
            .{ .code = 3, .text = "one" },
            .{ .code = 4, .text = "two" },
        };
        self.payload = .{
            .number = 0x12345678,
            .ratio = 1.5,
            .ready = true,
            .identifier = .{
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            },
            .message = "hello",
            .blob = &.{ 0xaa, 0xbb, 0xcc },
            .fixed = .{ 0x1122, 0x3344 },
            .fixed_flags = .{ true, false, true },
            .dynamic_flags = self.dynamic_flags[0..],
            .dynamic = self.dynamic[0..],
            .nested = .{ .ok = false, .amount = 0x0102030405060708 },
            .points = .{
                .{ .x = -1, .y = 2 },
                .{ .x = -3, .y = 4 },
            },
            .samples = self.samples[0..],
        };
    }
};

fn appendExpectedPayload(
    expected: *ExpectedBytes,
    payload: *const WireTestProvider.Payload(.everything),
) void {
    expected.append(std.mem.asBytes(&payload.number));
    expected.append(std.mem.asBytes(&payload.ratio));
    expected.append(&.{@intFromBool(payload.ready)});
    expected.append(&payload.identifier);
    expected.appendU16(@intCast(payload.message.len));
    expected.append(payload.message);
    expected.appendU16(@intCast(payload.blob.len));
    expected.append(payload.blob);
    expected.append(std.mem.asBytes(&payload.fixed));
    for (payload.fixed_flags) |value| expected.append(&.{@intFromBool(value)});
    expected.appendU16(@intCast(payload.dynamic_flags.len));
    for (payload.dynamic_flags) |value| expected.append(&.{@intFromBool(value)});
    expected.appendU16(@intCast(payload.dynamic.len));
    expected.append(std.mem.sliceAsBytes(payload.dynamic));
    expected.append(&.{@intFromBool(payload.nested.ok)});
    expected.append(std.mem.asBytes(&payload.nested.amount));
    for (&payload.points) |*point| {
        expected.append(std.mem.asBytes(&point.x));
        expected.append(std.mem.asBytes(&point.y));
    }
    expected.appendU16(@intCast(payload.samples.len));
    for (payload.samples) |*sample| {
        expected.append(std.mem.asBytes(&sample.code));
        expected.appendU16(@intCast(sample.text.len));
        expected.append(sample.text);
    }
}

test "captured generated iovecs match golden bytes without activity" {
    const Definition = WireTestProvider.Definition(.everything);
    var storage: WirePayloadStorage = undefined;
    storage.init();
    CapturedIovecs.reset(0xa1b2c3d4);
    var event: user_events.Event = .{};

    try std.testing.expectEqual(
        user_events.WriteOutcome.written,
        try EventWriter(wire_test_spec, 0).emit(
            &event,
            &storage.payload,
            .{},
            CapturedIovecs.submit,
        ),
    );

    var expected: ExpectedBytes = .{};
    expected.append(std.mem.asBytes(&CapturedIovecs.write_index));
    expected.append(&Definition.header);
    expected.append(&Definition.metadata_extension);
    appendExpectedPayload(&expected, &storage.payload);

    try std.testing.expectEqual(@as(usize, 1), CapturedIovecs.calls);
    try std.testing.expectEqualSlices(
        u8,
        expected.bytes[0..expected.len],
        CapturedIovecs.bytes[0..CapturedIovecs.len],
    );
}

test "captured generated iovecs match activity and related extension order" {
    const Definition = WireTestProvider.Definition(.everything);
    const activity: eventheader.ActivityId = .{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    };
    const related: eventheader.ActivityId = .{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    };
    var storage: WirePayloadStorage = undefined;
    storage.init();
    CapturedIovecs.reset(29);
    var event: user_events.Event = .{};

    _ = try EventWriter(wire_test_spec, 0).emit(
        &event,
        &storage.payload,
        .{ .activity = &activity, .related = &related },
        CapturedIovecs.submit,
    );

    var expected: ExpectedBytes = .{};
    expected.append(std.mem.asBytes(&CapturedIovecs.write_index));
    expected.append(&Definition.header);
    expected.appendU16(32);
    expected.appendU16(eventheader.ExtensionKind.activity | eventheader.ExtensionKind.chain);
    expected.append(&activity);
    expected.append(&related);
    expected.append(&Definition.metadata_extension);
    appendExpectedPayload(&expected, &storage.payload);

    try std.testing.expectEqualSlices(
        u8,
        expected.bytes[0..expected.len],
        CapturedIovecs.bytes[0..CapturedIovecs.len],
    );
}

const limits_test_spec: ProviderSpec = .{
    .name = "Zig_Limits",
    .events = &.{
        .{
            .symbol = "bounded",
            .level = 4,
            .fields = &.{
                .{ .name = "text", .kind = .{ .utf8 = 5 } },
                .{
                    .name = "values",
                    .kind = .{ .variable_array = .{ .element = .u16, .max = 2 } },
                },
            },
        },
        .{
            .symbol = "large",
            .level = 4,
            .fields = &.{
                .{ .name = "data", .kind = .{ .binary = 65535 } },
            },
        },
        .{
            .symbol = "many",
            .level = 4,
            .fields = &.{
                .{
                    .name = "items",
                    .kind = .{ .variable_struct_array = .{
                        .max = 2000,
                        .fields = &.{
                            .{ .name = "value", .kind = .u8 },
                        },
                    } },
                },
            },
        },
    },
};

const LimitsTestProvider = Provider(limits_test_spec);

const RejectSubmit = struct {
    var calls: usize = 0;

    fn submit(
        _: *const user_events.Event,
        _: []user_events.Iovec,
    ) user_events.EventWriteError!user_events.WriteOutcome {
        calls += 1;
        return .written;
    }
};

test "runtime field event and iovec limits reject before submission" {
    var event: user_events.Event = .{};

    var bounded: LimitsTestProvider.Payload(.bounded) = .{
        .text = "123456",
        .values = &.{ 1, 2 },
    };
    RejectSubmit.calls = 0;
    try std.testing.expectError(
        error.FieldTooLong,
        EventWriter(limits_test_spec, 0).emit(
            &event,
            &bounded,
            .{},
            RejectSubmit.submit,
        ),
    );

    bounded.text = "ok";
    bounded.values = &.{ 1, 2, 3 };
    try std.testing.expectError(
        error.FieldTooLong,
        EventWriter(limits_test_spec, 0).emit(
            &event,
            &bounded,
            .{},
            RejectSubmit.submit,
        ),
    );

    const oversized = [_]u8{0xaa} ** 65535;
    var large: LimitsTestProvider.Payload(.large) = .{ .data = &oversized };
    try std.testing.expectError(
        error.EventTooLarge,
        EventWriter(limits_test_spec, 1).emit(
            &event,
            &large,
            .{},
            RejectSubmit.submit,
        ),
    );

    const Item = @typeInfo(@FieldType(
        LimitsTestProvider.Payload(.many),
        "items",
    )).pointer.child;
    const items = [_]Item{.{ .value = 1 }} ** 1021;
    var many: LimitsTestProvider.Payload(.many) = .{ .items = &items };
    try std.testing.expectError(
        error.TooManyIovecs,
        EventWriter(limits_test_spec, 2).emit(
            &event,
            &many,
            .{},
            RejectSubmit.submit,
        ),
    );

    const activity: eventheader.ActivityId = [_]u8{0} ** 16;
    try std.testing.expectError(
        error.ActivityRequired,
        EventWriter(limits_test_spec, 0).emit(
            &event,
            &bounded,
            .{ .related = &activity },
            RejectSubmit.submit,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), RejectSubmit.calls);
}

test "disabled generated writes invoke neither builder nor submit" {
    const LazyBuilder = struct {
        fn build(calls: *usize) GeneratedTestProvider.Payload(.first) {
            calls.* += 1;
            return .{
                .count = 1,
                .nested = .{ .ok = true, .amount = 2 },
            };
        }
    };
    const Submit = struct {
        var calls: usize = 0;

        fn call(
            _: *const user_events.Event,
            _: []user_events.Iovec,
        ) user_events.EventWriteError!user_events.WriteOutcome {
            calls += 1;
            return .written;
        }
    };

    var instance: GeneratedTestProvider.Instance = .{};
    var builder_calls: usize = 0;
    Submit.calls = 0;
    try std.testing.expectEqual(
        user_events.WriteOutcome.disabled,
        try instance.writeLazyWith(
            .first,
            &builder_calls,
            LazyBuilder.build,
            .{},
            Submit.call,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), builder_calls);
    try std.testing.expectEqual(@as(usize, 0), Submit.calls);

    const payload: GeneratedTestProvider.Payload(.first) = .{
        .count = 3,
        .nested = .{ .ok = false, .amount = 4 },
    };
    try std.testing.expectEqual(
        user_events.WriteOutcome.disabled,
        try instance.writePtrWith(.first, &payload, .{}, Submit.call),
    );
    try std.testing.expectEqual(@as(usize, 0), Submit.calls);
}

const LifecycleTestProvider = Provider(.{
    .name = "Zig_Lifecycle",
    .events = &.{
        .{ .symbol = "first", .level = 3 },
        .{ .symbol = "second", .level = 4 },
        .{ .symbol = "third", .level = 5 },
    },
});

const FakeProviderLifecycle = struct {
    var register_calls: usize = 0;
    var unregister_calls: usize = 0;
    var close_calls: usize = 0;
    var fail_registration: ?usize = null;
    var fail_unregister_mask: u8 = 0;
    var fail_close: bool = false;
    var enable_addresses: [LifecycleTestProvider.event_set_count]usize = undefined;
    var unregister_order: [16]usize = undefined;

    fn reset() void {
        register_calls = 0;
        unregister_calls = 0;
        close_calls = 0;
        fail_registration = null;
        fail_unregister_mask = 0;
        fail_close = false;
        enable_addresses = @splat(0);
    }

    fn clearCleanupLog() void {
        unregister_calls = 0;
        close_calls = 0;
    }

    fn open(data_file: *user_events.DataFile) user_events.DataFileOpenError!void {
        data_file.fd.store(10, .release);
    }

    fn registerOne(
        managed_event: *user_events.Event,
        data_file: *user_events.DataFile,
        flags: abi.RegistrationFlags,
        name_args: [:0]const u8,
    ) user_events.EventRegisterError!void {
        return user_events.testing.registerEventWith(
            managed_event,
            data_file,
            0,
            flags,
            name_args,
            registerRaw,
        );
    }

    fn registerRaw(
        _: linux.fd_t,
        enable_word: *align(@sizeOf(u32)) u32,
        _: u5,
        _: abi.RegistrationFlags,
        _: [:0]const u8,
    ) user_events.RegisterError!u32 {
        const call = register_calls;
        register_calls += 1;
        if (fail_registration == call) return error.PermissionDenied;
        enable_addresses[call] = @intFromPtr(enable_word);
        return @intCast(100 + call);
    }

    fn unregisterOne(
        managed_event: *user_events.Event,
    ) user_events.EventUnregisterError!void {
        return user_events.testing.unregisterEventWith(
            managed_event,
            unregisterRaw,
        );
    }

    fn unregisterRaw(
        _: linux.fd_t,
        enable_word: *align(@sizeOf(u32)) u32,
        _: u5,
    ) user_events.UnregisterError!void {
        const address = @intFromPtr(enable_word);
        const event_index = for (enable_addresses, 0..) |candidate, index| {
            if (candidate == address) break index;
        } else unreachable;
        unregister_order[unregister_calls] = event_index;
        unregister_calls += 1;
        if (fail_unregister_mask & (@as(u8, 1) << @intCast(event_index)) != 0) {
            return error.PermissionDenied;
        }
    }

    fn closeOne(
        data_file: *user_events.DataFile,
    ) user_events.DataFileCloseError!void {
        if (!data_file.isOpen()) return;
        if (data_file.registeredEventCount() != 0) {
            return error.EventsStillRegistered;
        }
        close_calls += 1;
        data_file.fd.store(-1, .release);
        if (fail_close) return error.InputOutput;
    }
};

test "registration failures roll back every successful position in reverse" {
    inline for (0..LifecycleTestProvider.event_set_count) |fail_position| {
        var instance: LifecycleTestProvider.Instance = .{};
        FakeProviderLifecycle.reset();
        FakeProviderLifecycle.fail_registration = fail_position;

        try std.testing.expectError(
            error.PermissionDenied,
            instance.registerAllWith(
                FakeProviderLifecycle.open,
                FakeProviderLifecycle.registerOne,
                FakeProviderLifecycle.unregisterOne,
                FakeProviderLifecycle.closeOne,
            ),
        );
        try std.testing.expectEqual(
            fail_position + 1,
            FakeProviderLifecycle.register_calls,
        );
        try std.testing.expectEqual(
            fail_position,
            FakeProviderLifecycle.unregister_calls,
        );
        for (0..fail_position) |cleanup_index| {
            try std.testing.expectEqual(
                fail_position - cleanup_index - 1,
                FakeProviderLifecycle.unregister_order[cleanup_index],
            );
        }
        try std.testing.expectEqual(@as(usize, 1), FakeProviderLifecycle.close_calls);
        try std.testing.expect(!instance.data_file.isOpen());
        try std.testing.expectEqual(@as(u32, 0), instance.data_file.registeredEventCount());
        for (&instance.events) |*event| try std.testing.expect(!event.isRegistered());
    }
}

test "cleanup attempts all events and closes only after retry succeeds" {
    var instance: LifecycleTestProvider.Instance = .{};
    FakeProviderLifecycle.reset();
    try instance.registerAllWith(
        FakeProviderLifecycle.open,
        FakeProviderLifecycle.registerOne,
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );

    FakeProviderLifecycle.clearCleanupLog();
    FakeProviderLifecycle.fail_unregister_mask = 0b101;
    try std.testing.expectError(
        error.PermissionDenied,
        instance.unregisterAllWith(
            FakeProviderLifecycle.unregisterOne,
            FakeProviderLifecycle.closeOne,
        ),
    );
    try std.testing.expectEqual(@as(usize, 3), FakeProviderLifecycle.unregister_calls);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 2, 1, 0 },
        FakeProviderLifecycle.unregister_order[0..3],
    );
    try std.testing.expectEqual(@as(usize, 0), FakeProviderLifecycle.close_calls);
    try std.testing.expect(instance.data_file.isOpen());
    try std.testing.expectEqual(@as(u32, 2), instance.data_file.registeredEventCount());

    FakeProviderLifecycle.fail_unregister_mask = 0;
    try instance.unregisterAllWith(
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
    try std.testing.expectEqual(@as(usize, 5), FakeProviderLifecycle.unregister_calls);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 2, 0 },
        FakeProviderLifecycle.unregister_order[3..5],
    );
    try std.testing.expectEqual(@as(usize, 1), FakeProviderLifecycle.close_calls);
    try std.testing.expect(!instance.data_file.isOpen());

    try instance.unregisterAllWith(
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
    try std.testing.expectEqual(@as(usize, 5), FakeProviderLifecycle.unregister_calls);
    try std.testing.expectEqual(@as(usize, 1), FakeProviderLifecycle.close_calls);
}

test "rollback and close failures retain retryable cleanup state" {
    var rollback_instance: LifecycleTestProvider.Instance = .{};
    FakeProviderLifecycle.reset();
    FakeProviderLifecycle.fail_registration = 2;
    FakeProviderLifecycle.fail_unregister_mask = 0b010;
    try std.testing.expectError(
        error.RollbackFailed,
        rollback_instance.registerAllWith(
            FakeProviderLifecycle.open,
            FakeProviderLifecycle.registerOne,
            FakeProviderLifecycle.unregisterOne,
            FakeProviderLifecycle.closeOne,
        ),
    );
    try std.testing.expectEqual(error.PermissionDenied, rollback_instance.cleanupError().?);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 1, 0 },
        FakeProviderLifecycle.unregister_order[0..2],
    );
    try std.testing.expect(rollback_instance.data_file.isOpen());
    try std.testing.expectEqual(
        @as(u32, 1),
        rollback_instance.data_file.registeredEventCount(),
    );
    try std.testing.expectEqual(@as(usize, 0), FakeProviderLifecycle.close_calls);

    FakeProviderLifecycle.fail_unregister_mask = 0;
    try rollback_instance.unregisterAllWith(
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
    try std.testing.expect(!rollback_instance.data_file.isOpen());

    var close_instance: LifecycleTestProvider.Instance = .{};
    FakeProviderLifecycle.reset();
    try close_instance.registerAllWith(
        FakeProviderLifecycle.open,
        FakeProviderLifecycle.registerOne,
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
    FakeProviderLifecycle.clearCleanupLog();
    FakeProviderLifecycle.fail_close = true;
    try std.testing.expectError(
        error.InputOutput,
        close_instance.unregisterAllWith(
            FakeProviderLifecycle.unregisterOne,
            FakeProviderLifecycle.closeOne,
        ),
    );
    try std.testing.expect(!close_instance.data_file.isOpen());
    try std.testing.expectEqual(
        @as(u32, 0),
        close_instance.data_file.registeredEventCount(),
    );

    FakeProviderLifecycle.fail_close = false;
    try close_instance.unregisterAllWith(
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
    try std.testing.expectEqual(@as(usize, 1), FakeProviderLifecycle.close_calls);
    try std.testing.expect(!close_instance.data_file.isOpen());
}

test "provider lifecycle contention returns busy using atomic handshakes" {
    const Blocking = struct {
        var entered: std.atomic.Value(bool) = .init(false);
        var release: std.atomic.Value(bool) = .init(false);
        var result: std.atomic.Value(u8) = .init(0);

        fn open(data_file: *user_events.DataFile) user_events.DataFileOpenError!void {
            data_file.fd.store(10, .release);
            entered.store(true, .release);
            while (!release.load(.acquire)) {
                std.atomic.spinLoopHint();
                std.Thread.yield() catch {};
            }
        }

        fn register(instance: *LifecycleTestProvider.Instance) void {
            instance.registerAllWith(
                open,
                FakeProviderLifecycle.registerOne,
                FakeProviderLifecycle.unregisterOne,
                FakeProviderLifecycle.closeOne,
            ) catch {
                result.store(2, .release);
                return;
            };
            result.store(1, .release);
        }
    };

    var instance: LifecycleTestProvider.Instance = .{};
    FakeProviderLifecycle.reset();
    Blocking.entered.store(false, .monotonic);
    Blocking.release.store(false, .monotonic);
    Blocking.result.store(0, .monotonic);

    const registering = try std.Thread.spawn(.{}, Blocking.register, .{&instance});
    while (!Blocking.entered.load(.acquire)) {
        std.atomic.spinLoopHint();
        std.Thread.yield() catch {};
    }
    try std.testing.expectError(
        error.LifecycleBusy,
        instance.registerAllWith(
            FakeProviderLifecycle.open,
            FakeProviderLifecycle.registerOne,
            FakeProviderLifecycle.unregisterOne,
            FakeProviderLifecycle.closeOne,
        ),
    );
    Blocking.release.store(true, .release);
    registering.join();
    try std.testing.expectEqual(@as(u8, 1), Blocking.result.load(.acquire));

    try instance.unregisterAllWith(
        FakeProviderLifecycle.unregisterOne,
        FakeProviderLifecycle.closeOne,
    );
}
