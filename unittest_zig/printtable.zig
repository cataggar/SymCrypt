// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

const Entry = struct {
    row: []u8,
    col: []u8,
    val: []u8,
};

pub const PrintTableState = struct {
    rows: std.ArrayListUnmanaged([]u8) = .empty,
    cols: std.ArrayListUnmanaged([]u8) = .empty,
    entries: std.ArrayListUnmanaged(Entry) = .empty,

    pub fn deinit(self: *PrintTableState) void {
        self.clear();
        self.rows.deinit(std.heap.c_allocator);
        self.cols.deinit(std.heap.c_allocator);
        self.entries.deinit(std.heap.c_allocator);
    }

    pub fn clear(self: *PrintTableState) void {
        for (self.rows.items) |r| std.heap.c_allocator.free(r);
        self.rows.clearRetainingCapacity();

        for (self.cols.items) |c| std.heap.c_allocator.free(c);
        self.cols.clearRetainingCapacity();

        for (self.entries.items) |e| {
            std.heap.c_allocator.free(e.row);
            std.heap.c_allocator.free(e.col);
            std.heap.c_allocator.free(e.val);
        }
        self.entries.clearRetainingCapacity();
    }

    pub fn addItemSlice(self: *PrintTableState, row: []const u8, col: []const u8, item: []const u8) void {
        const alloc = std.heap.c_allocator;

        var row_exists = false;
        for (self.rows.items) |r| {
            if (std.mem.eql(u8, r, row)) {
                row_exists = true;
                break;
            }
        }
        if (!row_exists) {
            const r1 = alloc.dupe(u8, row) catch h.fatal("Out of memory in PrintTable", .{});
            self.rows.append(alloc, r1) catch h.fatal("Out of memory in PrintTable", .{});
        }

        var col_exists = false;
        for (self.cols.items) |c| {
            if (std.mem.eql(u8, c, col)) {
                col_exists = true;
                break;
            }
        }
        if (!col_exists) {
            const c1 = alloc.dupe(u8, col) catch h.fatal("Out of memory in PrintTable", .{});
            self.cols.append(alloc, c1) catch h.fatal("Out of memory in PrintTable", .{});
        }

        for (self.entries.items) |*e| {
            if (std.mem.eql(u8, e.row, row) and std.mem.eql(u8, e.col, col)) {
                alloc.free(e.val);
                e.val = alloc.dupe(u8, item) catch h.fatal("Out of memory in PrintTable", .{});
                return;
            }
        }

        const r2 = alloc.dupe(u8, row) catch h.fatal("Out of memory in PrintTable", .{});
        const c2 = alloc.dupe(u8, col) catch h.fatal("Out of memory in PrintTable", .{});
        const v2 = alloc.dupe(u8, item) catch h.fatal("Out of memory in PrintTable", .{});
        self.entries.append(alloc, .{ .row = r2, .col = c2, .val = v2 }) catch h.fatal("Out of memory in PrintTable", .{});
    }
};

fn formatNumber(buf: []u8, v_in: f64) []const u8 {
    if (v_in < 0) {
        var sub_buf: [64]u8 = undefined;
        const sub = formatNumber(&sub_buf, -v_in);
        return std.fmt.bufPrint(buf, "-{s}", .{sub}) catch unreachable;
    }
    if (std.math.isNan(v_in)) {
        return std.fmt.bufPrint(buf, "NAN  ", .{}) catch unreachable;
    }
    h.check(v_in < 1e24, "Number too large");

    var v = v_in;
    const fSmallInt = @floor(v) == v and v < 10000.0;
    var s: usize = 0;
    while (v >= 10000.0) {
        v /= 1000.0;
        s += 1;
    }

    const suffixes = " kMGTPEZ";
    const suffix = suffixes[s];

    if (v < 1.0 and !fSmallInt) {
        const iv: u32 = @intFromFloat(1000.0 * v);
        return std.fmt.bufPrint(buf, " .{d:0>3}{c}", .{ iv, suffix }) catch unreachable;
    } else if (v < 10.0 and !fSmallInt) {
        const whole: u32 = @intFromFloat(@floor(v));
        const frac: u32 = @intFromFloat(100.0 * @mod(v, 1.0));
        return std.fmt.bufPrint(buf, " {d}.{d:0>2}{c}", .{ whole, frac, suffix }) catch unreachable;
    } else if (v < 100.0 and !fSmallInt) {
        const whole: u32 = @intFromFloat(@floor(v));
        const frac: u32 = @intFromFloat(10.0 * @mod(v, 1.0));
        return std.fmt.bufPrint(buf, " {d: >2}.{d:0>1}{c}", .{ whole, frac, suffix }) catch unreachable;
    } else if (v < 1000.0) {
        const whole: u32 = @intFromFloat(@floor(v));
        return std.fmt.bufPrint(buf, "  {d: >3}{c}", .{ whole, suffix }) catch unreachable;
    } else {
        const whole: u32 = @intFromFloat(@floor(v));
        return std.fmt.bufPrint(buf, " {d: >4}{c}", .{ whole, suffix }) catch unreachable;
    }
}

pub export fn scTestPrintTableCreate() callconv(.c) ?*anyopaque {
    const state = std.heap.c_allocator.create(PrintTableState) catch h.fatal("Out of memory in scTestPrintTableCreate", .{});
    state.* = .{};
    return state;
}

pub export fn scTestPrintTableDestroy(handle: ?*anyopaque) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    state.deinit();
    std.heap.c_allocator.destroy(state);
}

pub export fn scTestPrintTableClear(handle: ?*anyopaque) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    state.clear();
}

pub export fn scTestPrintTableAddItemStr(
    handle: ?*anyopaque,
    row_ptr: [*]const u8,
    row_len: usize,
    col_ptr: [*]const u8,
    col_len: usize,
    item_ptr: [*]const u8,
    item_len: usize,
) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    state.addItemSlice(row_ptr[0..row_len], col_ptr[0..col_len], item_ptr[0..item_len]);
}

pub export fn scTestPrintTableAddItemU64(
    handle: ?*anyopaque,
    row_ptr: [*]const u8,
    row_len: usize,
    col_ptr: [*]const u8,
    col_len: usize,
    value: u64,
) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    var buf: [64]u8 = undefined;
    const formatted = std.fmt.bufPrint(&buf, "{d}", .{value}) catch unreachable;
    state.addItemSlice(row_ptr[0..row_len], col_ptr[0..col_len], formatted);
}

pub export fn scTestPrintTableAddItemNonZero(
    handle: ?*anyopaque,
    row_ptr: [*]const u8,
    row_len: usize,
    col_ptr: [*]const u8,
    col_len: usize,
    value: u64,
) callconv(.c) void {
    if (value != 0) {
        scTestPrintTableAddItemU64(handle, row_ptr, row_len, col_ptr, col_len, value);
    }
}

pub export fn scTestPrintTableAddItemPerf(
    handle: ?*anyopaque,
    row_ptr: [*]const u8,
    row_len: usize,
    col_ptr: [*]const u8,
    col_len: usize,
    perByte: f64,
    overhead: f64,
    range: f64,
) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    const intOverhead = @floor(overhead + 0.5);
    const intRange = @floor(range + 0.5);

    var full_buf: [256]u8 = undefined;
    var pos: usize = 0;

    var sep: []const u8 = "";
    if (perByte != 0.0) {
        var b1: [64]u8 = undefined;
        const part = std.fmt.bufPrint(full_buf[pos..], "{s}n", .{formatNumber(&b1, perByte)}) catch unreachable;
        pos += part.len;
        sep = "+";
    }
    if (overhead != 0.0) {
        var b2: [64]u8 = undefined;
        const part = std.fmt.bufPrint(full_buf[pos..], "{s}{s}", .{ sep, formatNumber(&b2, intOverhead) }) catch unreachable;
        pos += part.len;
        sep = "+-";
    } else {
        const part = std.fmt.bufPrint(full_buf[pos..], "     ", .{}) catch unreachable;
        pos += part.len;
        sep = "+-";
    }

    if (h.g_showPerfRangeInfo != 0) {
        if (range != 0.0) {
            var b3: [64]u8 = undefined;
            const part = std.fmt.bufPrint(full_buf[pos..], "{s}{s}", .{ sep, formatNumber(&b3, intRange) }) catch unreachable;
            pos += part.len;
        } else {
            const part = std.fmt.bufPrint(full_buf[pos..], "      ", .{}) catch unreachable;
            pos += part.len;
        }
    }

    state.addItemSlice(row_ptr[0..row_len], col_ptr[0..col_len], full_buf[0..pos]);
}

fn lessThanSlice(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

pub export fn scTestPrintTablePrint(handle: ?*anyopaque, heading_ptr: [*]const u8, heading_len: usize) callconv(.c) void {
    const state: *PrintTableState = @ptrCast(@alignCast(handle orelse return));
    const heading = heading_ptr[0..heading_len];

    std.mem.sort([]u8, state.rows.items, {}, lessThanSlice);
    std.mem.sort([]u8, state.cols.items, {}, lessThanSlice);

    const nCols = state.cols.items.len;
    const nRows = state.rows.items.len;
    if (nCols == 0) {
        return;
    }

    const colSize = std.heap.c_allocator.alloc(usize, nCols + 1) catch h.fatal("Out of memory in scTestPrintTablePrint", .{});
    defer std.heap.c_allocator.free(colSize);
    @memset(colSize, 0);

    for (state.rows.items) |r| {
        colSize[0] = @max(colSize[0], r.len + 1);
    }

    for (state.cols.items, 0..) |c, idx| {
        colSize[idx + 1] = @max(colSize[idx + 1], c.len);
    }

    for (0..nRows) |r_idx| {
        const r = state.rows.items[r_idx];
        for (0..nCols) |c_idx| {
            const c = state.cols.items[c_idx];
            var s: usize = 0;
            for (state.entries.items) |e| {
                if (std.mem.eql(u8, e.row, r) and std.mem.eql(u8, e.col, c)) {
                    s = e.val.len;
                    break;
                }
            }
            colSize[c_idx + 1] = @max(colSize[c_idx + 1], s);
        }
    }

    h.zprint("\n{s}:\n", .{heading});

    printRightPadded("", colSize[0]);
    var totalWidth: usize = colSize[0];
    for (state.cols.items, 0..) |c, idx| {
        h.zprint(" ", .{});
        printRightPadded(c, colSize[idx + 1]);
        totalWidth += colSize[idx + 1] + 1;
    }
    h.zprint("\n", .{});
    for (0..totalWidth) |_| {
        h.zprint("=", .{});
    }
    h.zprint("\n", .{});

    for (state.rows.items) |r| {
        printRightPadded(r, colSize[0] - 1);
        h.zprint(":", .{});
        for (state.cols.items, 0..) |c, idx| {
            var val: []const u8 = "";
            for (state.entries.items) |e| {
                if (std.mem.eql(u8, e.row, r) and std.mem.eql(u8, e.col, c)) {
                    val = e.val;
                    break;
                }
            }
            h.zprint(" ", .{});
            printRightPadded(val, colSize[idx + 1]);
        }
        h.zprint("\n", .{});
    }
}

fn printLeftPadded(s: []const u8, width: usize) void {
    h.zprint("{s}", .{s});
    if (width > s.len) {
        var spaces: [256]u8 = @splat(' ');
        var rem = width - s.len;
        while (rem > 0) {
            const chunk = @min(rem, spaces.len);
            h.zprint("{s}", .{spaces[0..chunk]});
            rem -= chunk;
        }
    }
}

fn printRightPadded(s: []const u8, width: usize) void {
    if (width > s.len) {
        var spaces: [256]u8 = @splat(' ');
        var rem = width - s.len;
        while (rem > 0) {
            const chunk = @min(rem, spaces.len);
            h.zprint("{s}", .{spaces[0..chunk]});
            rem -= chunk;
        }
    }
    h.zprint("{s}", .{s});
}
