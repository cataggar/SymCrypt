// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

pub const ResultMerge = struct {
    handle: ?*anyopaque = null,

    pub fn init() ResultMerge {
        return .{ .handle = scTestResultMergeCreate() };
    }

    pub fn deinit(self: *ResultMerge) void {
        if (self.handle) |h_ptr| {
            scTestResultMergeDestroy(h_ptr);
            self.handle = null;
        }
    }

    pub fn addResult(self: *ResultMerge, pImp: *anyopaque, data: []const u8) void {
        if (self.handle == null) {
            self.handle = scTestResultMergeCreate();
        }
        scTestResultMergeAddAlgImp(self.handle, pImp, data.ptr, data.len);
    }

    pub fn getResult(self: *ResultMerge, pbResult: []u8) void {
        scTestResultMergeGetResult(self.handle, pbResult.ptr, pbResult.len, 1);
    }

    pub fn getResultEx(self: *ResultMerge, pbResult: []u8, countInvocation: bool) void {
        scTestResultMergeGetResult(self.handle, pbResult.ptr, pbResult.len, @intFromBool(countInvocation));
    }
};

const SingleResult = struct {
    pAlgImp: *anyopaque,
    impName: [*:0]const u8,
    algName: [*:0]const u8,
    pNumResults: *u64,
    pNumErrorDisagree: *u64,
    pNumErrorNoMajority: *u64,
    data: []u8,
};

const ResultMergeState = struct {
    results: std.ArrayListUnmanaged(SingleResult) = .empty,

    fn clear(self: *ResultMergeState) void {
        for (self.results.items) |r| {
            std.heap.c_allocator.free(r.data);
        }
        self.results.clearRetainingCapacity();
    }

    fn deinit(self: *ResultMergeState) void {
        self.clear();
        self.results.deinit(std.heap.c_allocator);
    }
};

pub export fn scTestResultMergeCreate() callconv(.c) ?*anyopaque {
    const state = std.heap.c_allocator.create(ResultMergeState) catch h.fatal("Out of memory in scTestResultMergeCreate", .{});
    state.* = .{};
    return state;
}

pub export fn scTestResultMergeDestroy(handle: ?*anyopaque) callconv(.c) void {
    const state: *ResultMergeState = @ptrCast(@alignCast(handle orelse return));
    state.deinit();
    std.heap.c_allocator.destroy(state);
}

pub export fn scTestResultMergeAddResult(
    handle: ?*anyopaque,
    pAlgImp: *anyopaque,
    impName: [*:0]const u8,
    algName: [*:0]const u8,
    pNumResults: *u64,
    pNumErrorDisagree: *u64,
    pNumErrorNoMajority: *u64,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void {
    const state: *ResultMergeState = @ptrCast(@alignCast(handle orelse return));
    const data_copy = std.heap.c_allocator.dupe(u8, pbData[0..cbData]) catch h.fatal("Out of memory in scTestResultMergeAddResult", .{});
    state.results.append(std.heap.c_allocator, .{
        .pAlgImp = pAlgImp,
        .impName = impName,
        .algName = algName,
        .pNumResults = pNumResults,
        .pNumErrorDisagree = pNumErrorDisagree,
        .pNumErrorNoMajority = pNumErrorNoMajority,
        .data = data_copy,
    }) catch h.fatal("Out of memory in scTestResultMergeAddResult", .{});
}

pub export fn scTestResultMergeGetResult(
    handle: ?*anyopaque,
    pbResult: [*]u8,
    cbResult: usize,
    countInvocation: c_int,
) callconv(.c) void {
    const state: *ResultMergeState = @ptrCast(@alignCast(handle orelse return));
    @memset(pbResult[0..cbResult], 0);

    const nResults = state.results.items.len;
    h.check(nResults != 0, "No results present");

    var maxAgree: usize = 0;
    const agreeCounts = std.heap.c_allocator.alloc(usize, nResults) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(agreeCounts);
    @memset(agreeCounts, 0);

    for (state.results.items, 0..) |r_i, i| {
        for (state.results.items) |r_j| {
            if (std.mem.eql(u8, r_i.data, r_j.data)) {
                agreeCounts[i] += 1;
                maxAgree = @max(maxAgree, agreeCounts[i]);
            }
        }
    }

    var chosen: ?[]const u8 = null;
    var resultFound = false;

    for (state.results.items, 0..) |r_i, i| {
        if (countInvocation != 0) {
            r_i.pNumResults.* += 1;
        }
        if (agreeCounts[i] * 2 > nResults) {
            chosen = r_i.data;
            resultFound = true;
        } else if (maxAgree * 2 > nResults) {
            r_i.pNumErrorDisagree.* += 1;
        } else {
            r_i.pNumErrorNoMajority.* += 1;
        }
    }

    if (!resultFound) {
        h.zprint("No majority result amongst\n", .{});
        for (state.results.items) |r_i| {
            for (r_i.data) |b| {
                h.zprint("{x:0>2}", .{b});
            }
            h.zprint(" from {s: >5}/{s}\n", .{ std.mem.span(r_i.impName), std.mem.span(r_i.algName) });
        }
        h.zprint("Picking first one\n", .{});
        chosen = state.results.items[0].data;
    }

    const res_slice = chosen.?;
    h.check(res_slice.len == cbResult, "Final result has wrong length");
    @memcpy(pbResult[0..cbResult], res_slice);

    state.clear();
}
