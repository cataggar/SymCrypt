// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const rng = @import("rng.zig");
const h = @import("main_harness.zig");

pub const RNDD_TEST_FN = *const fn () callconv(.c) void;

const FunctionRecord = struct {
    func: RNDD_TEST_FN,
    name: [*:0]u8,
    count: i64,
    weight: u32,
};

const N_BUCKETS: usize = 1 << 12;

var g_aBucket: [N_BUCKETS]*FunctionRecord = undefined;
var g_totalWeight: u32 = 0;

var g_testFunctions: std.ArrayListUnmanaged(*FunctionRecord) = .empty;
var g_initFunctions: std.ArrayListUnmanaged(*FunctionRecord) = .empty;
var g_cleanupFunctions: std.ArrayListUnmanaged(*FunctionRecord) = .empty;
var g_invariantFunctions: std.ArrayListUnmanaged(*FunctionRecord) = .empty;
var g_invariantFunctionsUsed: bool = false;

fn recomputeBuckets() void {
    var b: u32 = 0;
    var w: u32 = 0;

    h.check(g_totalWeight < (1 << 16), "Too much total weight, could lead to overflow");

    for (g_testFunctions.items) |rec| {
        w += rec.weight;
        while (w * N_BUCKETS > g_totalWeight * b) {
            h.check(b < N_BUCKETS, "?");
            g_aBucket[b] = rec;
            b += 1;
        }
    }
}

pub export fn rnddRegisterTestFunction(func: RNDD_TEST_FN, name: [*:0]u8, weight: u32) callconv(.c) void {
    const rec = std.heap.c_allocator.create(FunctionRecord) catch h.fatal("Out of memory", .{});
    rec.* = .{
        .func = func,
        .name = name,
        .count = 0,
        .weight = weight,
    };
    g_testFunctions.append(std.heap.c_allocator, rec) catch h.fatal("Out of memory", .{});
    g_totalWeight += weight;
}

pub export fn rnddRegisterInitFunction(func: RNDD_TEST_FN) callconv(.c) void {
    const rec = std.heap.c_allocator.create(FunctionRecord) catch h.fatal("Out of memory", .{});
    rec.* = .{
        .func = func,
        .name = undefined,
        .count = 0,
        .weight = 0,
    };
    g_initFunctions.append(std.heap.c_allocator, rec) catch h.fatal("Out of memory", .{});
}

pub export fn rnddRegisterCleanupFunction(func: RNDD_TEST_FN) callconv(.c) void {
    const rec = std.heap.c_allocator.create(FunctionRecord) catch h.fatal("Out of memory", .{});
    rec.* = .{
        .func = func,
        .name = undefined,
        .count = 0,
        .weight = 0,
    };
    g_cleanupFunctions.append(std.heap.c_allocator, rec) catch h.fatal("Out of memory", .{});
}

pub export fn rnddRegisterInvariantFunction(func: RNDD_TEST_FN) callconv(.c) void {
    const rec = std.heap.c_allocator.create(FunctionRecord) catch h.fatal("Out of memory", .{});
    rec.* = .{
        .func = func,
        .name = undefined,
        .count = 0,
        .weight = 0,
    };
    g_invariantFunctions.append(std.heap.c_allocator, rec) catch h.fatal("Out of memory", .{});
    g_invariantFunctionsUsed = true;
}

pub export fn getTimeInMs() callconv(.c) u64 {
    var ts: std.c.timespec = undefined;
    _ = std.c.clock_gettime(std.c.CLOCK.MONOTONIC, &ts);
    return @as(u64, @intCast(@divTrunc(ts.nsec, 1000000))) + (@as(u64, @intCast(ts.sec)) * 1000);
}

pub export fn rnddRunTest(nSeconds: u32, nThreads: u32) callconv(.c) void {
    h.zdprint("\n", .{});
    recomputeBuckets();

    h.check(0 < nThreads and nThreads <= 1, "?");
    h.check(0 < nSeconds and nSeconds < 100, "Invalid test duration");

    for (g_initFunctions.items) |rec| {
        rec.func();
    }

    const timeLimit: u64 = getTimeInMs() + @as(u64, nSeconds) * 1000;

    while (true) {
        for (0..1000) |_| {
            const c: usize = rng.scTestRngUint32(&rng.g_rng) & (N_BUCKETS - 1);
            h.zdprint("{s: >21}:", .{std.mem.span(g_aBucket[c].name)});
            g_aBucket[c].func();
            _ = @atomicRmw(i64, &g_aBucket[c].count, .Add, 1, .seq_cst);

            if (g_invariantFunctionsUsed) {
                for (g_invariantFunctions.items) |rec| {
                    rec.func();
                }
            }
            h.zdprint("\n", .{});
        }
        if (getTimeInMs() >= timeLimit) break;
    }

    h.zprint("\n", .{});
    for (g_testFunctions.items) |rec| {
        const cnt = @atomicLoad(i64, &rec.count, .seq_cst);
        h.zprint("{s: >30} : {d: >8}\n", .{ std.mem.span(rec.name), cnt });
    }
    h.ziprint("\n", .{});

    for (g_cleanupFunctions.items) |rec| {
        rec.func();
    }
}
