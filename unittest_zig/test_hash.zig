// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const MAX_HASH_SIZE: usize = 64;
const MAX_INPUT_BLOCK_SIZE: usize = 256;
const MAX_PARALLEL_HASH_STATES: usize = 32;
const MAX_PARALLEL_HASH_OPERATIONS: usize = 128;
const SYMCRYPT_HASH_MAX_DATA_BIGNESS: usize = 1 << 11;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const BCRYPT_HASH_OPERATION_HASH_DATA: c_int = 1;
const BCRYPT_HASH_OPERATION_FINISH_HASH: c_int = 2;

pub const BCRYPT_MULTI_HASH_OPERATION = extern struct {
    iHash: u32,
    hashOperation: c_int,
    pbBuffer: ?[*]u8,
    cbBuffer: u32,
};

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptHash(pHash: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn SymCryptHashInit(pHash: *const anyopaque, pState: *anyopaque) callconv(.c) void;
extern fn SymCryptHashAppend(pHash: *const anyopaque, pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn SymCryptHashResult(pHash: *const anyopaque, pState: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

extern fn scTestGetHashImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestGetParallelHashImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

extern fn scTestHashImpResultLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestHashImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestHashImpInit(pImp: *anyopaque) callconv(.c) void;
extern fn scTestHashImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestHashImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestHashImpHash(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestHashImpInitWithLongMessage(pImp: *anyopaque, nBytes: u64) callconv(.c) i32;
extern fn scTestHashImpExportSymCryptFormat(pImp: *anyopaque, pbResult: [*]u8, cbResultBufferSize: usize, pcbResult: *usize) callconv(.c) i32;

extern fn scTestParHashImpResultLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestParHashImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestParHashImpSymCryptHash(pImp: *anyopaque) callconv(.c) *const anyopaque;
extern fn scTestParHashImpInit(pImp: *anyopaque, nHashes: usize) callconv(.c) void;
extern fn scTestParHashImpProcess(pImp: *anyopaque, pOperations: [*]BCRYPT_MULTI_HASH_OPERATION, nOperations: usize) callconv(.c) void;
extern fn scTestParHashImpInitWithLongMessage(pImp: *anyopaque, nBytes: u64) callconv(.c) i32;

const HashMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*HashMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetHashImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(HashMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *HashMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn resultLen(self: *HashMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestHashImpResultLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent result len");
            res = v;
        }
        return res;
    }

    fn inputBlockLen(self: *HashMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestHashImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn hash(self: *HashMultiImp, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_HASH_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_HASH_SIZE, "Hash result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestHashImpHash(imp, pbData, cbData, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn init(self: *HashMultiImp) void {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            scTestHashImpInit(imp);
        }
    }

    fn append(self: *HashMultiImp, pbData: ?[*]const u8, cbData: usize) void {
        for (self.m_comps.items) |imp| {
            scTestHashImpAppend(imp, pbData, cbData);
        }
    }

    fn result(self: *HashMultiImp, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_HASH_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_HASH_SIZE, "Hash result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestHashImpResult(imp, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn initWithLongMessage(self: *HashMultiImp, nBytes: u64) i32 {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            if (scTestHashImpInitWithLongMessage(imp, nBytes) == 0) {
                self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            }
        }
        return if (self.m_comps.items.len == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn exportSymCryptFormat(self: *HashMultiImp, pbResult: [*]u8, cbResultBufferSize: usize, pcbResult: *usize) i32 {
        var buf: [512]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);
        var size: usize = std.math.maxInt(usize);
        var sizeTmp: usize = undefined;

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, buf.len);
            if (scTestHashImpExportSymCryptFormat(imp, &buf, buf.len, &sizeTmp) >= 0) {
                scTestResultMergeAddAlgImp(res, imp, &buf, sizeTmp);
                size = sizeTmp;
            }
        }

        h.check(size != std.math.maxInt(usize) and size <= cbResultBufferSize, "Funny export sizes");
        pcbResult.* = size;
        rm.scTestResultMergeGetResult(res, pbResult, size, 1);
        return STATUS_SUCCESS;
    }
};

const ParallelHashMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*ParallelHashMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetParallelHashImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(ParallelHashMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *ParallelHashMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn resultLen(self: *ParallelHashMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestParHashImpResultLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent result len");
            res = v;
        }
        return res;
    }

    fn inputBlockLen(self: *ParallelHashMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestParHashImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn symCryptHash(self: *ParallelHashMultiImp) *const anyopaque {
        var res: ?*const anyopaque = null;
        for (self.m_imps.items) |imp| {
            res = scTestParHashImpSymCryptHash(imp);
            break;
        }
        return res.?;
    }

    fn init(self: *ParallelHashMultiImp, nHashes: usize) void {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            scTestParHashImpInit(imp, nHashes);
        }
    }

    fn process(self: *ParallelHashMultiImp, pOperations: [*]BCRYPT_MULTI_HASH_OPERATION, nOperations: usize) void {
        const cbResult = self.resultLen();
        if (nOperations == 0) return;

        var results: [MAX_PARALLEL_HASH_OPERATIONS]?*anyopaque = undefined;
        var buf: [MAX_PARALLEL_HASH_OPERATIONS][MAX_HASH_SIZE]u8 = undefined;
        var op: [MAX_PARALLEL_HASH_OPERATIONS]BCRYPT_MULTI_HASH_OPERATION = undefined;

        h.check(nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "Too many parallel hash operations");

        for (0..nOperations) |i| {
            results[i] = rm.scTestResultMergeCreate();
        }
        defer {
            for (0..nOperations) |i| {
                rm.scTestResultMergeDestroy(results[i]);
            }
        }

        for (self.m_comps.items) |imp| {
            @memset(std.mem.asBytes(&buf), 0xcd);
            @memcpy(op[0..nOperations], pOperations[0..nOperations]);
            for (0..nOperations) |j| {
                if (op[j].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH) {
                    op[j].pbBuffer = &buf[j];
                    h.check(op[j].cbBuffer == cbResult, "Wrong parallel hash result size");
                }
            }

            scTestParHashImpProcess(imp, &op, nOperations);

            for (0..nOperations) |j| {
                if (pOperations[j].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH) {
                    scTestResultMergeAddAlgImp(results[j], imp, &buf[j], cbResult);
                }
            }
        }

        for (0..nOperations) |i| {
            if (pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH) {
                rm.scTestResultMergeGetResult(results[i], pOperations[i].pbBuffer.?, pOperations[i].cbBuffer, 1);
            }
        }
    }

    fn initWithLongMessage(self: *ParallelHashMultiImp, nBytes: u64) i32 {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            if (scTestParHashImpInitWithLongMessage(imp, nBytes) == 0) {
                self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            }
        }
        return if (self.m_comps.items.len == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }
};

fn testHashSingle(
    pHash: *HashMultiImp,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var res: [MAX_HASH_SIZE]u8 = undefined;

    h.check(pHash.resultLen() == cbResult, "Result len error");
    @memset(&res, 0);

    pHash.hash(pbData, cbData, &res, cbResult);
    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong hash result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pHash.m_nErrorKatFailure += 1;
    }

    @memset(&res, 0);
    pHash.init();
    var pb: [*]const u8 = pbData;
    var bytesLeft = cbData;

    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pHash.append(pb, todo);
        pb += todo;
        bytesLeft -= todo;
    }
    pHash.result(&res, cbResult);

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong hash result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pHash.m_nErrorKatFailure += 1;
    }
}

fn testHashRandom(
    pHash: *HashMultiImp,
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

    rng.scTestRngReset(&local_rng, pHash.m_algorithmName.ptr, pHash.m_algorithmName.len);

    const bufSize: usize = pHash.inputBlockLen() * 4;
    h.check(bufSize <= buf.len, "Input block len too large");

    @memset(&buf, 0);
    const cbHash: usize = pHash.resultLen();
    h.check(cbHash <= res.len, "Hash result too long");

    for (0..rrep) |_| {
        const destIdx = rng.scTestRngSizet(&local_rng, bufSize);
        const nAppends = rng.scTestRngByte(&local_rng) % 5;
        var pos: usize = 0;
        var len: usize = 0;

        if (nAppends == 0) {
            rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
            pHash.hash(buf[pos..].ptr, len, &res, cbHash);
        } else {
            pHash.init();
            for (0..nAppends) |_| {
                rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
                pHash.append(buf[pos..].ptr, len);
            }
            pHash.result(&res, cbHash);
        }

        if (destIdx + cbHash <= bufSize) {
            @memcpy(buf[destIdx .. destIdx + cbHash], res[0..cbHash]);
        } else {
            len = bufSize - destIdx;
            @memcpy(buf[destIdx .. destIdx + len], res[0..len]);
            @memcpy(buf[0 .. cbHash - len], res[len..cbHash]);
        }
    }

    pHash.hash(&buf, bufSize, &res, cbHash);
    if (cbResult != 0) {
        h.check3(cbResult == cbHash, "Wrong result length in line {d}", line);
        if (!std.mem.eql(u8, res[0..cbHash], pbResult[0..cbHash])) {
            h.zprint("Wrong hash result in line {d}. \nExpected ", .{line});
            h.printHex(pbResult[0..cbResult]);
            h.zprint("\nGot      ", .{});
            h.printHex(res[0..cbResult]);
            h.zprint("\n", .{});
            pHash.m_nErrorKatFailure += 1;
        }
    }
}

fn testLongMessage(
    pHash: *HashMultiImp,
    maxLen: i32,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var data: [2 * MAX_INPUT_BLOCK_SIZE]u8 = undefined;
    var res: [MAX_HASH_SIZE]u8 = undefined;
    var tmp: [MAX_HASH_SIZE]u8 = undefined;

    const blockSize = pHash.inputBlockLen();
    const resultLen = pHash.resultLen();

    h.check(blockSize <= MAX_INPUT_BLOCK_SIZE, "Block size too large");
    h.check(resultLen <= MAX_HASH_SIZE, "Result size too large");
    h.check(cbResult == resultLen, "Invalid result length");

    @memset(&data, 'a');
    h.check(10 <= maxLen and maxLen <= 63, "Invalid maxLen parameter in KAT file");

    var results: std.ArrayListUnmanaged(u8) = .empty;
    defer results.deinit(std.heap.c_allocator);

    var len: i32 = 10;
    while (len <= maxLen) : (len += 1) {
        const boundary: u64 = @as(u64, 1) << @intCast(len);
        const startLen: u64 = boundary - blockSize;
        const nBytes: usize = 2 * blockSize;

        h.check(pHash.initWithLongMessage(startLen) == 0, "No initialization implementation succeeded");
        pHash.append(&data, nBytes);
        pHash.result(&res, cbResult);

        h.check(pHash.initWithLongMessage(startLen) == 0, "No initialization implementation succeeded");
        for (0..nBytes) |_| {
            pHash.append(&data, 1);
        }
        pHash.result(&tmp, cbResult);
        h.check(std.mem.eql(u8, tmp[0..cbResult], res[0..cbResult]), "Inconsistent long message hash result");

        h.check(pHash.initWithLongMessage(startLen) == 0, "No initialization implementation succeeded");
        var rem = nBytes;
        while (rem > 0) {
            const step = @min(@as(usize, 5), rem);
            pHash.append(&data, step);
            rem -= step;
        }
        pHash.result(&tmp, cbResult);
        h.check(std.mem.eql(u8, tmp[0..cbResult], res[0..cbResult]), "Inconsistent long message hash result");

        results.appendSlice(std.heap.c_allocator, res[0..cbResult]) catch h.fatal("Out of memory", .{});
    }

    pHash.hash(results.items.ptr, results.items.len, &res, cbResult);

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong long hash result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});

        for (pHash.m_comps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, 1);
        }
    }
}

fn testLongMessageConsistency(pHash: *HashMultiImp, nInputBlocks: usize, line: i64) void {
    var res1: [MAX_HASH_SIZE]u8 = undefined;
    var res2: [MAX_HASH_SIZE]u8 = undefined;

    const blockLen = pHash.inputBlockLen();
    const resultLen = pHash.resultLen();

    h.check3(nInputBlocks > 64, "Length not large enough in line {d}", line);
    h.check(blockLen > 0, "Invalid blockLen");
    h.check(resultLen <= MAX_HASH_SIZE, "Invalid resultLen");

    const cbBuf = nInputBlocks * blockLen - blockLen / 3;
    const pBuf = std.heap.c_allocator.alloc(u8, cbBuf) catch h.fatal("?", .{});
    defer std.heap.c_allocator.free(pBuf);

    h.fillRandom(pBuf) catch h.fatal("?", .{});

    pHash.hash(pBuf.ptr, cbBuf, &res1, resultLen);

    var cbData = cbBuf;
    var pbData: [*]const u8 = pBuf.ptr;
    pHash.init();
    while (cbData > 0) {
        const len = @min(cbData, blockLen);
        pHash.append(pbData, len);
        pbData += len;
        cbData -= len;
    }
    pHash.result(&res2, resultLen);

    h.check3(std.mem.eql(u8, res1[0..resultLen], res2[0..resultLen]), "Long message consistency failure in line {d}", line);
}

fn testExport(
    pHash: *HashMultiImp,
    pbExport: [*]const u8,
    cbExport: usize,
    line: i64,
) void {
    var msg1: [1657]u8 = undefined;
    var msg2: [1234]u8 = undefined;
    var exportBlob: [1024]u8 = undefined;
    var exportLen: usize = 0;

    for (0..msg1.len) |i| {
        msg1[i] = @truncate(i);
    }

    h.fillRandom(&msg2) catch h.fatal("?", .{});

    pHash.init();
    pHash.append(&msg1, msg1.len);
    h.check(pHash.exportSymCryptFormat(&exportBlob, exportBlob.len, &exportLen) == 0, "SymCryptExport failed");

    if (exportLen != cbExport or !std.mem.eql(u8, exportBlob[0..exportLen], pbExport[0..cbExport])) {
        h.zprint("Wrong export blob in line {d}. \nExpected ", .{line});
        h.printHex(pbExport[0..cbExport]);
        h.zprint("\nGot      ", .{});
        h.printHex(exportBlob[0..exportLen]);
        h.zprint("\n", .{});
        pHash.m_nErrorKatFailure += 1;
    }

    pHash.append(&msg2, msg2.len);
    pHash.result(&msg2, pHash.resultLen());
}

fn testHashKats() void {
    var katHash = kat.ZigKatReader.init("kat_hash.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pHashMultiImp: ?*HashMultiImp = null;
    defer if (pHashMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katHash.getKatItem(&katItem);
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pHashMultiImp) |p| {
                p.deinit();
                pHashMultiImp = null;
            }
            pHashMultiImp = HashMultiImp.initNew(katItem.categoryName);
            skipData = (pHashMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pHash = pHashMultiImp.?;
            if (katItem.isFieldPresent("md")) {
                var katLen: i64 = -1;
                if (katItem.isFieldPresent("len")) {
                    katLen = katItem.parseInteger("len");
                }
                const expectedItems: usize = if (katLen == -1) 2 else 3;
                h.check3(katItem.dataItems.items.len == expectedItems, "Too many items in MD record ending at line {d}", katHash.kat.m_line);
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katMd = katItem.parseData("md");
                defer std.heap.c_allocator.free(katMd);
                if (katLen != -1) {
                    h.check3(katLen == @as(i64, @intCast(katMsg.len * 8)), "Data length does not match 'Len' value in record ending at line {d}", katHash.kat.m_line);
                }

                testHashSingle(pHash, katMsg.ptr, katMsg.len, katMd.ptr, katMd.len, katHash.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("rnd")) {
                h.check3(katItem.dataItems.items.len == 2, "Too many items in RND record ending at line {d}", katHash.kat.m_line);
                const rrep: usize = @intCast(katItem.parseInteger("rrep"));
                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                testHashRandom(pHash, rrep, katRnd.ptr, katRnd.len, katHash.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("long")) {
                h.check3(katItem.dataItems.items.len == 2, "Wrong number of items in LONG record at line {d}", katHash.kat.m_line);
                const maxLen: i32 = @intCast(katItem.parseInteger("len"));
                const katLong = katItem.parseData("long");
                defer std.heap.c_allocator.free(katLong);
                testLongMessage(pHash, maxLen, katLong.ptr, katLong.len, katHash.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("medium")) {
                h.check3(katItem.dataItems.items.len == 1, "Wrong number of items in MEDIUM record at line {d}", katHash.kat.m_line);
                const nInputBlocks: usize = @intCast(katItem.parseInteger("medium"));
                testLongMessageConsistency(pHash, nInputBlocks, katHash.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("export")) {
                h.check3(katItem.dataItems.items.len == 1, "Wrong number of items in EXPORT record at line {d}", katHash.kat.m_line);
                const katExport = katItem.parseData("export");
                defer std.heap.c_allocator.free(katExport);
                testExport(pHash, katExport.ptr, katExport.len, katHash.kat.m_line);
                continue;
            }
            h.fatal("Unknown data record ending at line {d}", .{katHash.kat.m_line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

fn testParallelHash(sep: *[]const u8, algName: []const u8) bool {
    const pParHashMultiImp = ParallelHashMultiImp.initNew(algName) orelse return false;
    defer pParHashMultiImp.deinit();

    h.ziprint("{s}{s}", .{ sep.*, algName });
    sep.* = ", ";

    const MAX_PAR_HASHES: usize = MAX_PARALLEL_HASH_STATES;
    const MAX_PAR_OPS: usize = MAX_PARALLEL_HASH_OPERATIONS;
    const BUF_SIZE: usize = 1 << 20;

    const pSymCryptHash = pParHashMultiImp.symCryptHash();
    const cbHash = pParHashMultiImp.resultLen();
    const cbInputBlock = pParHashMultiImp.inputBlockLen();

    var state: [MAX_PAR_HASHES][512]u8 align(16) = undefined;
    var op: [MAX_PAR_OPS]BCRYPT_MULTI_HASH_OPERATION = undefined;
    var res1: [MAX_PAR_OPS][MAX_HASH_SIZE]u8 = undefined;
    var res2: [MAX_PAR_OPS][MAX_HASH_SIZE]u8 = undefined;

    const pBuf = std.heap.c_allocator.alloc(u8, BUF_SIZE) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pBuf);

    for (0..BUF_SIZE) |i| {
        pBuf[i] = @truncate(i *% 253 +% (i >> 8));
    }

    // 1-hash, empty input
    pParHashMultiImp.init(1);
    SymCryptHashInit(pSymCryptHash, &state[0]);
    SymCryptHashResult(pSymCryptHash, &state[0], &res1[0], cbHash);
    op[0].iHash = 0;
    op[0].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
    op[0].pbBuffer = &res2[0];
    op[0].cbBuffer = @intCast(cbHash);
    pParHashMultiImp.process(&op, 1);
    h.check(std.mem.eql(u8, res1[0][0..cbHash], res2[0][0..cbHash]), "Single empty parallel hash fails");

    // 8-parallel test with "abc"
    pParHashMultiImp.init(8);
    var nOps: usize = 0;
    for (0..8) |i| {
        SymCryptHashInit(pSymCryptHash, &state[i]);
        SymCryptHashAppend(pSymCryptHash, &state[i], "abc", 3);
        SymCryptHashResult(pSymCryptHash, &state[i], &res1[i], cbHash);
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[nOps].pbBuffer = @constCast("abc".ptr);
        op[nOps].cbBuffer = 3;
        nOps += 1;
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[nOps].pbBuffer = &res2[i];
        op[nOps].cbBuffer = @intCast(cbHash);
        nOps += 1;
    }
    pParHashMultiImp.process(&op, nOps);
    for (0..8) |i| {
        h.check(std.mem.eql(u8, res1[i][0..cbHash], res2[i][0..cbHash]), "8x'abc' parallel hash fails");
    }

    // 8-parallel test with input block length
    pParHashMultiImp.init(8);
    nOps = 0;
    for (0..8) |i| {
        SymCryptHashInit(pSymCryptHash, &state[i]);
        SymCryptHashAppend(pSymCryptHash, &state[i], pBuf.ptr, cbInputBlock);
        SymCryptHashResult(pSymCryptHash, &state[i], &res1[i], cbHash);
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[nOps].pbBuffer = pBuf.ptr;
        op[nOps].cbBuffer = @intCast(cbInputBlock);
        nOps += 1;
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[nOps].pbBuffer = &res2[i];
        op[nOps].cbBuffer = @intCast(cbHash);
        nOps += 1;
    }
    pParHashMultiImp.process(&op, nOps);
    for (0..8) |i| {
        h.check(std.mem.eql(u8, res1[i][0..cbHash], res2[i][0..cbHash]), "8xblocklen parallel hash fails");
    }

    // 2-parallel test with different sizes
    pParHashMultiImp.init(2);
    nOps = 0;
    for (0..2) |i| {
        SymCryptHashInit(pSymCryptHash, &state[i]);
        SymCryptHashAppend(pSymCryptHash, &state[i], pBuf.ptr, i * cbInputBlock);
        SymCryptHashResult(pSymCryptHash, &state[i], &res1[i], cbHash);
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
        op[nOps].pbBuffer = pBuf.ptr;
        op[nOps].cbBuffer = @intCast(i * cbInputBlock);
        nOps += 1;
        op[nOps].iHash = @intCast(i);
        op[nOps].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
        op[nOps].pbBuffer = &res2[i];
        op[nOps].cbBuffer = @intCast(cbHash);
        nOps += 1;
    }
    pParHashMultiImp.process(&op, nOps);
    for (0..2) |i| {
        h.check(std.mem.eql(u8, res1[i][0..cbHash], res2[i][0..cbHash]), "2x parallel hash fails");
    }

    // 4-parallel test with multiple finish operations
    pParHashMultiImp.init(4);
    nOps = 0;
    for (0..4) |i| {
        SymCryptHashInit(pSymCryptHash, &state[i]);
    }
    for (0..4) |i| {
        for (0..i + 1) |j| {
            SymCryptHashAppend(pSymCryptHash, &state[j], pBuf.ptr + i * j, j * cbInputBlock + i * 50);
            SymCryptHashResult(pSymCryptHash, &state[j], &res1[4 * i + j], cbHash);

            op[nOps].iHash = @intCast(j);
            op[nOps].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
            op[nOps].pbBuffer = pBuf.ptr + i * j;
            op[nOps].cbBuffer = @intCast(j * cbInputBlock + i * 50);
            nOps += 1;
            op[nOps].iHash = @intCast(j);
            op[nOps].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            op[nOps].pbBuffer = &res2[4 * i + j];
            op[nOps].cbBuffer = @intCast(cbHash);
            nOps += 1;
        }
    }
    pParHashMultiImp.process(&op, nOps);
    for (0..4) |i| {
        for (0..i + 1) |j| {
            h.check(std.mem.eql(u8, res1[4 * i + j][0..cbHash], res2[4 * i + j][0..cbHash]), "4x parallel hash fails");
        }
    }

    // Single-call all hashes same size
    for (0..400) |_| {
        const nHashes = rng.scTestRngSizet(&rng.g_rng, MAX_PAR_HASHES + 1);
        const cbData = rng.scTestRngSizetNonUniform(&rng.g_rng, 1 << 16, 256, 1);

        pParHashMultiImp.init(nHashes);
        for (0..nHashes) |i| {
            SymCryptHashInit(pSymCryptHash, &state[i]);
            op[2 * i].iHash = @intCast(i);
            op[2 * i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
            op[2 * i].pbBuffer = pBuf.ptr + i;
            op[2 * i].cbBuffer = @intCast(cbData);
            SymCryptHashAppend(pSymCryptHash, &state[i], op[2 * i].pbBuffer, op[2 * i].cbBuffer);

            op[2 * i + 1].iHash = @intCast(i);
            op[2 * i + 1].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
            op[2 * i + 1].pbBuffer = &res2[i];
            op[2 * i + 1].cbBuffer = @intCast(cbHash);
            SymCryptHashResult(pSymCryptHash, &state[i], &res1[i], cbHash);
        }
        pParHashMultiImp.process(&op, 2 * nHashes);
        for (0..nHashes) |i| {
            h.check(std.mem.eql(u8, res1[i][0..cbHash], res2[i][0..cbHash]), "Parallel same-size hash fails");
        }
    }

    // Test of random mutations
    for (0..3000) |_| {
        const nHashes = rng.scTestRngSizet(&rng.g_rng, MAX_PAR_HASHES + 1);
        var nOpsRnd = rng.scTestRngSizet(&rng.g_rng, MAX_PAR_OPS + 1);
        if (nHashes == 0) {
            nOpsRnd = 0;
        }
        pParHashMultiImp.init(nHashes);
        for (0..nHashes) |i| {
            SymCryptHashInit(pSymCryptHash, &state[i]);
        }

        for (0..nOpsRnd) |i| {
            const idx = rng.scTestRngSizet(&rng.g_rng, nHashes);
            op[i].iHash = @intCast(idx);
            if ((rng.scTestRngByte(&rng.g_rng) & 5) != 0) {
                var pos: usize = 0;
                var len: usize = 0;
                rng.scTestRngRandomSubRange(&rng.g_rng, 1 << 12, &pos, &len);
                op[i].hashOperation = BCRYPT_HASH_OPERATION_HASH_DATA;
                op[i].pbBuffer = pBuf.ptr + pos;
                op[i].cbBuffer = @intCast(len);
                SymCryptHashAppend(pSymCryptHash, &state[idx], pBuf.ptr + pos, len);
            } else {
                op[i].hashOperation = BCRYPT_HASH_OPERATION_FINISH_HASH;
                op[i].pbBuffer = &res2[i];
                op[i].cbBuffer = @intCast(cbHash);
                SymCryptHashResult(pSymCryptHash, &state[idx], &res1[i], cbHash);
            }
        }
        pParHashMultiImp.process(&op, nOpsRnd);
        for (0..nOpsRnd) |i| {
            if (op[i].hashOperation == BCRYPT_HASH_OPERATION_FINISH_HASH) {
                h.check(std.mem.eql(u8, res1[i][0..cbHash], res2[i][0..cbHash]), "Parallel hash differs from sequential hash");
            }
        }
    }

    return true;
}

pub export fn testHash() callconv(.c) void {
    testHashKats();

    var sep: []const u8 = "    ";
    var doneAnything = false;
    if (testParallelHash(&sep, "ParSha256")) doneAnything = true;
    if (testParallelHash(&sep, "ParSha384")) doneAnything = true;
    if (testParallelHash(&sep, "ParSha512")) doneAnything = true;
    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testHashAlgorithms() callconv(.c) void {
    testHash();
}
