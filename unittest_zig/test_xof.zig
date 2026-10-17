// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const MAX_XOF_RESULT_SIZE: usize = 1024;
const MAX_XOF_INPUT_BLOCK_SIZE: usize = 200;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

extern fn scTestGetXofImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

extern fn scTestXofImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestXofImpInit(pImp: *anyopaque) callconv(.c) void;
extern fn scTestXofImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestXofImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestXofImpExtract(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
extern fn scTestXofImpXof(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

const XofMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*XofMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetXofImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(XofMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *XofMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn inputBlockLen(self: *XofMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestXofImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn xof(self: *XofMultiImp, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_XOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_XOF_RESULT_SIZE, "XOF result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestXofImpXof(imp, pbData, cbData, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn init(self: *XofMultiImp) void {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            scTestXofImpInit(imp);
        }
    }

    fn append(self: *XofMultiImp, pbData: ?[*]const u8, cbData: usize) void {
        for (self.m_comps.items) |imp| {
            scTestXofImpAppend(imp, pbData, cbData);
        }
    }

    fn result(self: *XofMultiImp, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_XOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_XOF_RESULT_SIZE, "XOF result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestXofImpResult(imp, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn extract(self: *XofMultiImp, pbResult: [*]u8, cbResult: usize, bWipe: bool) void {
        var buf: [MAX_XOF_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_XOF_RESULT_SIZE, "XOF result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestXofImpExtract(imp, &buf, cbResult, if (bWipe) 1 else 0);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }
};

fn testXofSingle(
    pXof: *XofMultiImp,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var res: [MAX_XOF_RESULT_SIZE]u8 = undefined;
    h.check(cbResult <= MAX_XOF_RESULT_SIZE, "Result len error");
    @memset(&res, 0);

    pXof.xof(pbData, cbData, &res, cbResult);
    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong XOF result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }

    @memset(&res, 0);
    pXof.init();
    var pb: [*]const u8 = pbData;
    var bytesLeft = cbData;

    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pXof.append(pb, todo);
        pb += todo;
        bytesLeft -= todo;
    }

    var pbRes: [*]u8 = &res;
    bytesLeft = cbResult;
    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pXof.extract(pbRes, todo, false);
        pbRes += todo;
        bytesLeft -= todo;
    }

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong XOF result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }
}

fn testXofMonteCarlo(
    pXof: *XofMultiImp,
    pbSeed: [*]const u8,
    cbSeed: usize,
    uMinOutputBytes: usize,
    uMaxOutputBytes: usize,
    uIteration: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var md: [MAX_XOF_RESULT_SIZE]u8 = undefined;
    const range = uMaxOutputBytes - uMinOutputBytes + 1;
    var outputLength = uMaxOutputBytes;

    h.check3(cbResult <= MAX_XOF_RESULT_SIZE, "Xof result too large at line {d}", line);

    if (cbSeed >= 16) {
        @memcpy(md[0..16], pbSeed[0..16]);
    } else {
        @memcpy(md[0..cbSeed], pbSeed[0..cbSeed]);
        @memset(md[cbSeed..16], 0);
    }

    var j: usize = 0;
    while (j <= uIteration) : (j += 1) {
        for (0..1000) |_| {
            pXof.xof(&md, 16, &md, outputLength);
            if (outputLength < 16) {
                @memset(md[outputLength..16], 0);
            }
            const rightmost_output_bits = std.mem.readInt(u16, md[outputLength - 2 ..][0..2], .big);
            outputLength = uMinOutputBytes + (rightmost_output_bits % range);
        }
    }

    if (!std.mem.eql(u8, md[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong MonteCarlo result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(md[0..cbResult]);
        h.zprint("\n", .{});
        pXof.m_nErrorKatFailure += 1;
    }
}

fn testXofRandom(
    pXof: *XofMultiImp,
    rrep: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    const RND_BUF_SIZE: usize = 1 << 12;
    var buf: [RND_BUF_SIZE]u8 = undefined;
    var res: [64]u8 = undefined;
    var local_rng: rng.Rng = undefined;
    rng.scTestRngInit(&local_rng);
    defer rng.scTestRngDeinit(&local_rng);

    rng.scTestRngReset(&local_rng, pXof.m_algorithmName.ptr, pXof.m_algorithmName.len);

    const bufSize: usize = pXof.inputBlockLen() * 4;
    h.check(bufSize <= buf.len, "Input block len too large");

    @memset(&buf, 0);
    const cbHash = cbResult;
    h.check(cbHash <= res.len, "Hash result too long");

    for (0..rrep) |_| {
        const destIdx = rng.scTestRngSizet(&local_rng, bufSize);
        const nAppends = rng.scTestRngByte(&local_rng) % 5;
        var pos: usize = 0;
        var len: usize = 0;

        if (nAppends == 0) {
            rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
            pXof.xof(buf[pos..].ptr, len, &res, cbHash);
        } else {
            pXof.init();
            for (0..nAppends) |_| {
                rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
                pXof.append(buf[pos..].ptr, len);
            }
            pXof.result(&res, cbHash);
        }

        if (destIdx + cbHash <= bufSize) {
            @memcpy(buf[destIdx .. destIdx + cbHash], res[0..cbHash]);
        } else {
            len = bufSize - destIdx;
            @memcpy(buf[destIdx .. destIdx + len], res[0..len]);
            @memcpy(buf[0 .. cbHash - len], res[len..cbHash]);
        }
    }

    pXof.xof(&buf, bufSize, &res, cbHash);
    if (cbResult != 0) {
        if (!std.mem.eql(u8, res[0..cbHash], pbResult[0..cbHash])) {
            h.zprint("Wrong XOF result in line {d}. \nExpected ", .{line});
            h.printHex(pbResult[0..cbResult]);
            h.zprint("\nGot      ", .{});
            h.printHex(res[0..cbResult]);
            h.zprint("\n", .{});
            pXof.m_nErrorKatFailure += 1;
        }
    }
}

fn testXofKats() void {
    var katXof = kat.ZigKatReader.init("kat_xof.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pXofMultiImp: ?*XofMultiImp = null;
    defer if (pXofMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katXof.getKatItem(&katItem);
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pXofMultiImp) |p| {
                p.deinit();
                pXofMultiImp = null;
            }
            pXofMultiImp = XofMultiImp.initNew(katItem.categoryName);
            skipData = (pXofMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pXof = pXofMultiImp.?;
            if (katItem.isFieldPresent("minimumoutputlengthbits")) {
                const minOutputBytes: usize = @intCast(@divTrunc(katItem.parseInteger("minimumoutputlengthbits"), 8));
                const maxOutputBytes: usize = @intCast(@divTrunc(katItem.parseInteger("maximumoutputlengthbits"), 8));
                const iteration: usize = @intCast(katItem.parseInteger("count"));
                const outputSize: usize = @intCast(@divTrunc(katItem.parseInteger("outputlen"), 8));

                const katSeed = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katSeed);
                const katOutput = katItem.parseData("output");
                defer std.heap.c_allocator.free(katOutput);
                h.check3(outputSize == katOutput.len, "Outputlen does not match the length of the output at line {d}", katXof.kat.m_line);

                testXofMonteCarlo(pXof, katSeed.ptr, katSeed.len, minOutputBytes, maxOutputBytes, iteration, katOutput.ptr, katOutput.len, katXof.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("rnd")) {
                h.check3(katItem.dataItems.items.len == 2, "Too many items in RND record ending at line {d}", katXof.kat.m_line);
                const rrep: usize = @intCast(katItem.parseInteger("rrep"));
                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                testXofRandom(pXof, rrep, katRnd.ptr, katRnd.len, katXof.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("output")) {
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katMD = katItem.parseData("output");
                defer std.heap.c_allocator.free(katMD);

                if (katItem.isFieldPresent("outputlen")) {
                    const katLen = @divTrunc(katItem.parseInteger("outputlen"), 8);
                    h.check3(katLen == @as(i64, @intCast(katMD.len)), "Outputlen does not match the length of the output at line {d}", katXof.kat.m_line);
                }

                testXofSingle(pXof, katMsg.ptr, katMsg.len, katMD.ptr, katMD.len, katXof.kat.m_line);
                continue;
            }
            h.fatal("Unknown data record ending at line {d}", .{katXof.kat.m_line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testXof() callconv(.c) void {
    testXofKats();
}

pub export fn testXofAlgorithms() callconv(.c) void {
    testXof();
}
