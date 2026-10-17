// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const MAX_MAC_SIZE: usize = 64;
const MAX_INPUT_BLOCK_SIZE: usize = 128;
const SYMCRYPT_MARVIN32_RESULT_SIZE: usize = 8;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const SCTEST_DYNSYM_FUNCTION_PTR: u32 = 1;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptGetMarvin32DefaultSeed() callconv(.c) *const anyopaque;
extern fn SymCryptMarvin32(pSeed: *const anyopaque, pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern fn getDynamicSymbolPointerFromString(hModule: ?*anyopaque, pSymbolName: [*:0]const u8, symbolType: u32) callconv(.c) ?*anyopaque;
extern fn initVectorRegisters() callconv(.c) void;
extern fn verifyVectorRegisters() callconv(.c) void;

extern fn scTestGetMacImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

extern fn scTestMacImpResultLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestMacImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestMacImpInit(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32;
extern fn scTestMacImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestMacImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestMacImpMac(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) i32;

const MacMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*MacMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetMacImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(MacMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *MacMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn resultLen(self: *MacMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestMacImpResultLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent result len");
            res = v;
        }
        return res;
    }

    fn inputBlockLen(self: *MacMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestMacImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn mac(
        self: *MacMultiImp,
        pbKey: ?[*]const u8,
        cbKey: usize,
        pbData: ?[*]const u8,
        cbData: usize,
        pbResult: [*]u8,
        cbResult: usize,
    ) i32 {
        var buf: [MAX_MAC_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_MAC_SIZE, "MAC result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            if (scTestMacImpMac(imp, pbKey, cbKey, pbData, cbData, &buf, cbResult) >= 0) {
                scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
            }
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
        return STATUS_SUCCESS;
    }

    fn init(self: *MacMultiImp, pbKey: ?[*]const u8, cbKey: usize) i32 {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            if (scTestMacImpInit(imp, pbKey, cbKey) >= 0) {
                self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            }
        }
        return if (self.m_comps.items.len == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn append(self: *MacMultiImp, pbData: ?[*]const u8, cbData: usize) void {
        for (self.m_comps.items) |imp| {
            scTestMacImpAppend(imp, pbData, cbData);
        }
    }

    fn result(self: *MacMultiImp, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_MAC_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_MAC_SIZE, "MAC result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestMacImpResult(imp, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }
};

fn testMacSingle(
    pMac: *MacMultiImp,
    pbKeyIn: [*]const u8,
    cbKey: usize,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var res: [MAX_MAC_SIZE]u8 = undefined;

    h.check3(pMac.resultLen() == cbResult, "Result len error at line {d}", line);
    @memset(&res, 0);

    const pbKey: ?[*]const u8 = if (cbKey == 0) null else pbKeyIn;

    var status = pMac.mac(pbKey, cbKey, pbData, cbData, &res, cbResult);
    if (status == 0) {
        if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
            h.zprint("Wrong MAC result in line {d}. \nExpected ", .{line});
            h.printHex(pbResult[0..cbResult]);
            h.zprint("\nGot      ", .{});
            h.printHex(res[0..cbResult]);
            h.zprint("\n", .{});
            pMac.m_nErrorKatFailure += 1;
        }
    }

    @memset(&res, 0);
    status = pMac.init(pbKey, cbKey);
    if (status != 0) {
        return;
    }

    var pb: [*]const u8 = pbData;
    var bytesLeft = cbData;

    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pMac.append(pb, todo);
        pb += todo;
        bytesLeft -= todo;
    }
    pMac.result(&res, cbResult);

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong incremental MAC result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pMac.m_nErrorKatFailure += 1;
    }
}

fn testMacRandom(
    pMac: *MacMultiImp,
    rrep: usize,
    keyLen: usize,
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

    rng.scTestRngReset(&local_rng, pMac.m_algorithmName.ptr, pMac.m_algorithmName.len);

    const bufSize: usize = @max(64, pMac.inputBlockLen() * 4);
    h.check(bufSize <= buf.len, "Input block len too large");

    @memset(&buf, 'N');
    const cbMac: usize = pMac.resultLen();
    h.check(cbMac <= res.len, "Hash result too long");

    for (0..rrep) |_| {
        const keyIdx = rng.scTestRngSizet(&local_rng, bufSize);
        var cbKey: usize = 0;
        if (keyLen == std.math.maxInt(usize)) {
            cbKey = rng.scTestRngSizetNonUniform(&local_rng, bufSize - keyIdx, 64, 2);
        } else {
            cbKey = keyLen;
        }

        const destIdx = rng.scTestRngSizet(&local_rng, bufSize);
        const nAppends = rng.scTestRngByte(&local_rng) % 5;
        var pos: usize = 0;
        var len: usize = 0;

        if (nAppends == 0) {
            rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
            const status = pMac.mac(buf[keyIdx..].ptr, cbKey, buf[pos..].ptr, len, &res, cbMac);
            h.check(status == 0, "All MAC implementations failed in random MAC test");
        } else {
            const status = pMac.init(buf[keyIdx..].ptr, cbKey);
            h.check(status == 0, "All MAC implementations failed in random MAC test");
            for (0..nAppends) |_| {
                rng.scTestRngRandomSubRange(&local_rng, bufSize, &pos, &len);
                pMac.append(buf[pos..].ptr, len);
            }
            pMac.result(&res, cbMac);
        }

        if (destIdx + cbMac <= bufSize) {
            @memcpy(buf[destIdx .. destIdx + cbMac], res[0..cbMac]);
        } else {
            len = bufSize - destIdx;
            @memcpy(buf[destIdx .. destIdx + len], res[0..len]);
            @memcpy(buf[0 .. cbMac - len], res[len..cbMac]);
        }
    }

    h.check(pMac.mac(&buf, if (keyLen == std.math.maxInt(usize)) 0 else keyLen, &buf, bufSize, &res, cbMac) == 0, "MAC failure");
    if (cbResult != 0) {
        h.check3(cbResult == cbMac, "Wrong result length in line {d}", line);
        if (!std.mem.eql(u8, res[0..cbMac], pbResult[0..cbMac])) {
            h.zprint("Wrong hash result in line {d}. \nExpected ", .{line});
            h.printHex(pbResult[0..cbResult]);
            h.zprint("\nGot      ", .{});
            h.printHex(res[0..cbResult]);
            h.zprint("\n", .{});
            pMac.m_nErrorKatFailure += 1;
        }
    }
}

fn testMacConsistency(pMac: *MacMultiImp, cbKey: usize, megaBytes: i64, line: i64) void {
    const cbBuf: usize = 1 << 20;
    h.check(megaBytes > 0, "?");
    h.check3(megaBytes <= 1000, "Consistency check will take too long in line {d}", line);

    const pbBuf = std.heap.c_allocator.alloc(u8, cbBuf) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pbBuf);

    var i: i64 = 0;
    while (i < megaBytes) : (i += 1) {
        h.fillRandom(pbBuf) catch {};
        _ = pMac.mac(pbBuf.ptr, cbKey, pbBuf.ptr + cbKey, cbBuf - cbKey, pbBuf.ptr, pMac.resultLen());
        @memset(pbBuf[0..cbKey], 0xff);
        _ = pMac.mac(pbBuf.ptr, cbKey, pbBuf.ptr + cbKey, cbBuf - cbKey, pbBuf.ptr, pMac.resultLen());
    }
}

fn testMacKats() void {
    var katMac = kat.ZigKatReader.init("kat_mac.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pMacMultiImp: ?*MacMultiImp = null;
    defer if (pMacMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katMac.getKatItem(&katItem);
        const line = katItem.line;
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pMacMultiImp) |p| {
                p.deinit();
                pMacMultiImp = null;
            }
            pMacMultiImp = MacMultiImp.initNew(katItem.categoryName);
            skipData = (pMacMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pMac = pMacMultiImp.?;
            if (katItem.isFieldPresent("mac")) {
                var nFields: usize = 3;
                var katKlen: i64 = -1;

                if (katItem.isFieldPresent("klen")) {
                    katKlen = katItem.parseInteger("klen");
                    nFields += 1;
                }
                if (katItem.isFieldPresent("tlen")) {
                    h.check3(pMac.resultLen() == @as(usize, @intCast(katItem.parseInteger("tlen"))), "Wrong Tlen field in record at line {d}", line);
                    nFields += 1;
                }
                if (katItem.isFieldPresent("count")) {
                    nFields += 1;
                }

                h.check3(katItem.dataItems.items.len == nFields, "Too many items in MD record at line {d}", line);
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katMacVal = katItem.parseData("mac");
                defer std.heap.c_allocator.free(katMacVal);
                const katKey = katItem.parseData("key");
                defer std.heap.c_allocator.free(katKey);
                if (katKlen >= 0) {
                    h.check3(@as(usize, @intCast(katKlen)) == katKey.len, "Klen & Key fields disagree at line {d}", line);
                }

                testMacSingle(pMac, katKey.ptr, katKey.len, katMsg.ptr, katMsg.len, katMacVal.ptr, katMacVal.len, line);
                continue;
            }
            if (katItem.isFieldPresent("rnd")) {
                var keyLen: usize = std.math.maxInt(usize);
                h.check3(katItem.dataItems.items.len <= 3, "Too many items in RND record at line {d}", line);
                const rrep: usize = @intCast(katItem.parseInteger("rrep"));
                if (katItem.isFieldPresent("keylen")) {
                    keyLen = @intCast(katItem.parseInteger("keylen"));
                } else {
                    h.check3(katItem.dataItems.items.len == 2, "Unknown item in RNG record at line {d}", line);
                }
                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                testMacRandom(pMac, rrep, keyLen, katRnd.ptr, katRnd.len, line);
                continue;
            }
            if (katItem.isFieldPresent("consistencymb")) {
                var keyLen: usize = std.math.maxInt(usize);
                h.check3(katItem.dataItems.items.len <= 2, "Too many items in Consistency record at line {d}", line);
                const megabytes = katItem.parseInteger("consistencymb");
                if (katItem.isFieldPresent("keylen")) {
                    keyLen = @intCast(katItem.parseInteger("keylen"));
                } else {
                    h.check3(katItem.dataItems.items.len == 2, "Unknown item in consistency record at line {d}", line);
                }
                testMacConsistency(pMac, keyLen, megabytes, line);
                continue;
            }
            h.fatal("Unknown data record at line {d}", .{line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testMac() callconv(.c) void {
    testMacKats();

    var buf: [SYMCRYPT_MARVIN32_RESULT_SIZE]u8 = undefined;
    initVectorRegisters();
    const defaultSeed = SymCryptGetMarvin32DefaultSeed();
    verifyVectorRegisters();
    initVectorRegisters();
    SymCryptMarvin32(defaultSeed, "Marvin", 6, &buf);
    verifyVectorRegisters();

    if (h.g_dynamicSymCryptModuleHandle) |dynHandle| {
        var bufDynamic: [SYMCRYPT_MARVIN32_RESULT_SIZE]u8 = undefined;
        h.g_useDynamicFunctionsInTestCall = 1;
        const pGetSeedFn = getDynamicSymbolPointerFromString(dynHandle, "SymCryptGetMarvin32DefaultSeed", SCTEST_DYNSYM_FUNCTION_PTR);
        h.check(pGetSeedFn != null, "Could not find SymCryptGetMarvin32DefaultSeed Function");
        const getSeedFn: *const fn () callconv(.c) *const anyopaque = @ptrCast(@alignCast(pGetSeedFn.?));

        const pMarvinFn = getDynamicSymbolPointerFromString(dynHandle, "SymCryptMarvin32", SCTEST_DYNSYM_FUNCTION_PTR);
        h.check(pMarvinFn != null, "Could not find SymCryptMarvin32 Function");
        const marvinFn: *const fn (*const anyopaque, [*]const u8, usize, [*]u8) callconv(.c) void = @ptrCast(@alignCast(pMarvinFn.?));

        const dynSeed = getSeedFn();
        marvinFn(dynSeed, "Marvin", 6, &bufDynamic);
        h.g_useDynamicFunctionsInTestCall = 0;
        h.check(std.mem.eql(u8, &buf, &bufDynamic), "Static and dynamic Marvin32 mismatch!");
    }
}

pub export fn testMacAlgorithms() callconv(.c) void {
    testMac();
}
