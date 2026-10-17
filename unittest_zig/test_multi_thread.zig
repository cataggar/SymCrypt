// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const rng = @import("rng.zig");
const selftest = @import("test_selftest.zig");

pub export var g_fExitMultithreadTest: u8 = 0;
pub export var g_nMultithreadTestsRun: u64 = 0;

pub export fn runTestThread(seed: ?*anyopaque) callconv(.c) void {
    var r: rng.Rng = undefined;
    rng.scTestRngInit(&r);
    defer rng.scTestRngDeinit(&r);

    var nTests: usize = 0;
    while (selftest.g_selfTests[nTests].f != null) : (nTests += 1) {}

    const seedBytes: [*]const u8 = @ptrCast(&seed);
    rng.scTestRngReset(&r, seedBytes, @sizeOf(?*anyopaque));

    var nRun: u64 = 0;
    while (g_fExitMultithreadTest == 0) {
        const t = rng.scTestRngSizet(&r, nTests);
        const fnPtr: selftest.SelftestFn = @ptrCast(@alignCast(selftest.g_selfTests[t].f.?));
        fnPtr();
        nRun += 1;
    }

    _ = @atomicRmw(u64, &g_nMultithreadTestsRun, .Add, nRun, .seq_cst);
}
