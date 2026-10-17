// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");

pub const rng = @import("rng.zig");
pub const rnd_driver = @import("rnd_driver.zig");
pub const callback = @import("callback.zig");
pub const testutil = @import("testutil.zig");
pub const printtable = @import("printtable.zig");
pub const result_merge = @import("result_merge.zig");
pub const kat = @import("kat.zig");
pub const main_harness = @import("main_harness.zig");

extern fn scTestCppMain(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int;

pub export fn main(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int {
    std.debug.maybeEnableSegfaultHandler();
    return scTestCppMain(argc, argv);
}

comptime {
    _ = rng;
    _ = rnd_driver;
    _ = callback;
    _ = testutil;
    _ = printtable;
    _ = result_merge;
    _ = kat;
    _ = main_harness;
}
