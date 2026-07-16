const tracepoints = @import("linux_tracepoints");

comptime {
    _ = tracepoints.provider.Provider(.{
        .name = "Valid",
        .events = &.{.{
            .symbol = "event",
            .level = 4,
            .fields = &.{.{
                .name = "n01",
                .kind = .{ .structure = &.{.{
                    .name = "n02",
                    .kind = .{ .structure = &.{.{
                        .name = "n03",
                        .kind = .{ .structure = &.{.{
                            .name = "n04",
                            .kind = .{ .structure = &.{.{
                                .name = "n05",
                                .kind = .{ .structure = &.{.{
                                    .name = "n06",
                                    .kind = .{ .structure = &.{.{
                                        .name = "n07",
                                        .kind = .{ .structure = &.{.{
                                            .name = "n08",
                                            .kind = .{ .structure = &.{.{
                                                .name = "n09",
                                                .kind = .{ .structure = &.{.{
                                                    .name = "n10",
                                                    .kind = .{ .structure = &.{.{
                                                        .name = "n11",
                                                        .kind = .{ .structure = &.{.{
                                                            .name = "n12",
                                                            .kind = .{ .structure = &.{.{
                                                                .name = "n13",
                                                                .kind = .{ .structure = &.{.{
                                                                    .name = "n14",
                                                                    .kind = .{ .structure = &.{.{
                                                                        .name = "n15",
                                                                        .kind = .{ .structure = &.{.{
                                                                            .name = "n16",
                                                                            .kind = .{ .structure = &.{.{
                                                                                .name = "n17",
                                                                                .kind = .{ .structure = &.{.{
                                                                                    .name = "leaf",
                                                                                    .kind = .u8,
                                                                                }} },
                                                                            }} },
                                                                        }} },
                                                                    }} },
                                                                }} },
                                                            }} },
                                                        }} },
                                                    }} },
                                                }} },
                                            }} },
                                        }} },
                                    }} },
                                }} },
                            }} },
                        }} },
                    }} },
                }} },
            }},
        }},
    });
}
