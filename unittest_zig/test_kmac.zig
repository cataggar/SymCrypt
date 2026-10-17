// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const MAX_KMAC_RESULT_SIZE: usize = 1024;
const MAX_KMAC_INPUT_BLOCK_SIZE: usize = 200;
const SYMCRYPT_SHA3_256_RESULT_SIZE: usize = 32;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha3_256Init(pState: *anyopaque) callconv(.c) void;
extern fn SymCryptSha3_256Append(pState: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha3_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;

extern fn scTestGetKmacImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestResultMergeAddAlgImp(resMergeHandle: ?*anyopaque, pImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;

extern fn scTestKmacImpInputBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestKmacImpInit(pImp: *anyopaque, pbCustomizationStr: ?[*]const u8, cbCustomizationStr: usize, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) void;
extern fn scTestKmacImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestKmacImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestKmacImpExtract(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
extern fn scTestKmacImpMac(pImp: *anyopaque, pbCustomizationStr: ?[*]const u8, cbCustomizationStr: usize, pbKey: ?[*]const u8, cbKey: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
extern fn scTestKmacImpXof(pImp: *anyopaque, pbCustomizationStr: ?[*]const u8, cbCustomizationStr: usize, pbKey: ?[*]const u8, cbKey: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

const KmacMultiImp = struct {
    m_algorithmName: []u8,
    m_imps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_nErrorKatFailure: u64 = 0,

    fn initNew(algName: []const u8) ?*KmacMultiImp {
        var imp_buf: [64]*anyopaque = undefined;
        const count = scTestGetKmacImps(algName.ptr, algName.len, &imp_buf, imp_buf.len);
        if (count == 0) return null;

        const self = std.heap.c_allocator.create(KmacMultiImp) catch h.fatal("Out of memory", .{});
        self.* = .{
            .m_algorithmName = std.heap.c_allocator.dupe(u8, algName) catch h.fatal("Out of memory", .{}),
        };
        const n = @min(count, imp_buf.len);
        self.m_imps.appendSlice(std.heap.c_allocator, imp_buf[0..n]) catch h.fatal("Out of memory", .{});
        return self;
    }

    fn deinit(self: *KmacMultiImp) void {
        for (self.m_imps.items) |imp| {
            scTestAlgImpAddErrorKatFailure(imp, self.m_nErrorKatFailure);
        }
        self.m_imps.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
        std.heap.c_allocator.free(self.m_algorithmName);
        std.heap.c_allocator.destroy(self);
    }

    fn inputBlockLen(self: *KmacMultiImp) usize {
        var res: usize = std.math.maxInt(usize);
        for (self.m_imps.items) |imp| {
            const v = scTestKmacImpInputBlockLen(imp);
            h.check(res == std.math.maxInt(usize) or res == v, "Inconsistent input block len");
            res = v;
        }
        return res;
    }

    fn mac(
        self: *KmacMultiImp,
        pbCustomizationStr: ?[*]const u8,
        cbCustomizationStr: usize,
        pbKey: ?[*]const u8,
        cbKey: usize,
        pbData: ?[*]const u8,
        cbData: usize,
        pbResult: [*]u8,
        cbResult: usize,
    ) void {
        var buf: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_KMAC_RESULT_SIZE, "KMAC result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestKmacImpMac(imp, pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn xof(
        self: *KmacMultiImp,
        pbCustomizationStr: ?[*]const u8,
        cbCustomizationStr: usize,
        pbKey: ?[*]const u8,
        cbKey: usize,
        pbData: ?[*]const u8,
        cbData: usize,
        pbResult: [*]u8,
        cbResult: usize,
    ) void {
        var buf: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_KMAC_RESULT_SIZE, "KMAC result too large");

        for (self.m_imps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestKmacImpXof(imp, pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn init(
        self: *KmacMultiImp,
        pbCustomizationStr: ?[*]const u8,
        cbCustomizationStr: usize,
        pbKey: ?[*]const u8,
        cbKey: usize,
    ) void {
        self.m_comps.clearRetainingCapacity();
        for (self.m_imps.items) |imp| {
            self.m_comps.append(std.heap.c_allocator, imp) catch h.fatal("Out of memory", .{});
            scTestKmacImpInit(imp, pbCustomizationStr, cbCustomizationStr, pbKey, cbKey);
        }
    }

    fn append(self: *KmacMultiImp, pbData: ?[*]const u8, cbData: usize) void {
        for (self.m_comps.items) |imp| {
            scTestKmacImpAppend(imp, pbData, cbData);
        }
    }

    fn result(self: *KmacMultiImp, pbResult: [*]u8, cbResult: usize) void {
        var buf: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_KMAC_RESULT_SIZE, "KMAC result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestKmacImpResult(imp, &buf, cbResult);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }

    fn extract(self: *KmacMultiImp, pbResult: [*]u8, cbResult: usize, bWipe: bool) void {
        var buf: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
        const res = rm.scTestResultMergeCreate();
        defer rm.scTestResultMergeDestroy(res);

        h.check(cbResult <= MAX_KMAC_RESULT_SIZE, "KMAC result too large");

        for (self.m_comps.items) |imp| {
            SymCryptWipe(&buf, cbResult);
            scTestKmacImpExtract(imp, &buf, cbResult, if (bWipe) 1 else 0);
            scTestResultMergeAddAlgImp(res, imp, &buf, cbResult);
        }

        rm.scTestResultMergeGetResult(res, pbResult, cbResult, 1);
    }
};

fn testKmacSingle(
    pKmac: *KmacMultiImp,
    pbCustomizationStr: [*]const u8,
    cbCustomizationStr: usize,
    pbKey: [*]const u8,
    cbKey: usize,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    bXofMode: bool,
    line: i64,
) void {
    var res: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
    h.check(cbResult <= MAX_KMAC_RESULT_SIZE, "Result len error");
    @memset(&res, 0);

    if (bXofMode) {
        pKmac.xof(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, &res, cbResult);
    } else {
        pKmac.mac(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, &res, cbResult);
    }
    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong KMAC result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pKmac.m_nErrorKatFailure += 1;
    }

    @memset(&res, 0);
    pKmac.init(pbCustomizationStr, cbCustomizationStr, pbKey, cbKey);
    var pb: [*]const u8 = pbData;
    var bytesLeft = cbData;

    while (bytesLeft > 0) {
        const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
        pKmac.append(pb, todo);
        pb += todo;
        bytesLeft -= todo;
    }

    if (bXofMode) {
        var pbRes: [*]u8 = &res;
        bytesLeft = cbResult;
        while (bytesLeft > 0) {
            const todo = rng.scTestRngSizetNonUniform(&rng.g_rng, bytesLeft + 1, 32, 2);
            pKmac.extract(pbRes, todo, false);
            pbRes += todo;
            bytesLeft -= todo;
        }
    } else {
        pKmac.result(&res, cbResult);
    }

    if (!std.mem.eql(u8, res[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong KMAC result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(res[0..cbResult]);
        h.zprint("\n", .{});
        pKmac.m_nErrorKatFailure += 1;
    }
}

fn testKmacRange(
    pKmac: *KmacMultiImp,
    cbMessage: usize,
    cbKey: usize,
    cbCustomStr: usize,
    cbOutput: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    const MAX_INPUT_SIZE: usize = 3 * 200;
    var input: [MAX_INPUT_SIZE]u8 = undefined;
    var key: [MAX_INPUT_SIZE]u8 = undefined;
    var customStr: [MAX_INPUT_SIZE]u8 = undefined;

    for (0..MAX_INPUT_SIZE) |i| {
        input[i] = @as(u8, @truncate(i)) | 0x80;
        key[i] = @truncate('K' + i);
        customStr[i] = @truncate('S' + i);
    }

    h.check(cbMessage <= MAX_INPUT_SIZE, "Max Message size too large");
    h.check(cbKey <= MAX_INPUT_SIZE, "Max Key size too large");
    h.check(cbCustomStr <= MAX_INPUT_SIZE, "Max Customization string size too large");
    h.check(cbOutput <= MAX_KMAC_RESULT_SIZE, "Output size too large");
    h.check(cbResult == SYMCRYPT_SHA3_256_RESULT_SIZE, "Result must be a SHA3-256 hash");

    var output: [MAX_KMAC_RESULT_SIZE]u8 = undefined;
    var result: [SYMCRYPT_SHA3_256_RESULT_SIZE]u8 = undefined;

    var sha3state: [512]u8 align(16) = undefined;
    SymCryptSha3_256Init(&sha3state);

    for (0..cbMessage + 1) |mlen| {
        for (0..cbKey + 1) |klen| {
            for (0..cbCustomStr + 1) |slen| {
                pKmac.mac(&customStr, slen, &key, klen, &input, mlen, &output, cbOutput);
                SymCryptSha3_256Append(&sha3state, &output, cbOutput);
            }
        }
    }

    SymCryptSha3_256Result(&sha3state, &result);

    if (!std.mem.eql(u8, result[0..cbResult], pbResult[0..cbResult])) {
        h.zprint("Wrong KMAC Range test result in line {d}. \nExpected ", .{line});
        h.printHex(pbResult[0..cbResult]);
        h.zprint("\nGot      ", .{});
        h.printHex(result[0..cbResult]);
        h.zprint("\n", .{});
        pKmac.m_nErrorKatFailure += 1;
    }
}

fn testKmacKats() void {
    var katKmac = kat.ZigKatReader.init("kat_kmac.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything = false;

    var pKmacMultiImp: ?*KmacMultiImp = null;
    defer if (pKmacMultiImp) |p| p.deinit();
    var skipData = true;

    while (true) {
        katKmac.getKatItem(&katItem);
        if (katItem.type == kat.KAT_TYPE_END) break;

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            if (pKmacMultiImp) |p| {
                p.deinit();
                pKmacMultiImp = null;
            }
            pKmacMultiImp = KmacMultiImp.initNew(katItem.categoryName);
            skipData = (pKmacMultiImp == null);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (katItem.type == kat.KAT_TYPE_DATASET and !skipData) {
            const pKmac = pKmacMultiImp.?;
            if (katItem.isFieldPresent("range")) {
                var katMaxInputSize: usize = 0;
                var katMaxKeySize: usize = 0;
                var katMaxCustomStrSize: usize = 0;

                if (katItem.isFieldPresent("maxinputsize")) {
                    katMaxInputSize = @intCast(katItem.parseInteger("maxinputsize"));
                }
                if (katItem.isFieldPresent("maxkeysize")) {
                    katMaxKeySize = @intCast(katItem.parseInteger("maxkeysize"));
                }
                if (katItem.isFieldPresent("maxcustomstrsize")) {
                    katMaxCustomStrSize = @intCast(katItem.parseInteger("maxcustomstrsize"));
                }

                h.check3((katMaxInputSize != 0 or katMaxKeySize != 0 or katMaxCustomStrSize != 0), "Invalid range test record ending at line {d}", katKmac.kat.m_line);

                const katOutputSize: usize = @intCast(katItem.parseInteger("outputsize"));
                const katRange = katItem.parseData("range");
                defer std.heap.c_allocator.free(katRange);

                testKmacRange(pKmac, katMaxInputSize, katMaxKeySize, katMaxCustomStrSize, katOutputSize, katRange.ptr, katRange.len, katKmac.kat.m_line);
                continue;
            }
            if (katItem.isFieldPresent("output")) {
                h.check3(katItem.dataItems.items.len == 5, "Invalid number of items in KAT record ending at line {d}", katKmac.kat.m_line);
                const katKey = katItem.parseData("key");
                defer std.heap.c_allocator.free(katKey);
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katS = katItem.parseData("customstr");
                defer std.heap.c_allocator.free(katS);
                const katLen = katItem.parseInteger("outputlen");
                const katOutput = katItem.parseData("output");
                defer std.heap.c_allocator.free(katOutput);

                if (katLen != 0) {
                    h.check3(@divTrunc(katLen, 8) == @as(i64, @intCast(katOutput.len)), "L does not match the length of the output at line {d}", katKmac.kat.m_line);
                }

                testKmacSingle(pKmac, katS.ptr, katS.len, katKey.ptr, katKey.len, katMsg.ptr, katMsg.len, katOutput.ptr, katOutput.len, katLen == 0, katKmac.kat.m_line);
                continue;
            }
            h.fatal("Unknown data record ending at line {d}", .{katKmac.kat.m_line});
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }
}

pub export fn testKmac() callconv(.c) void {
    testKmacKats();
}

pub export fn testKmacAlgorithms() callconv(.c) void {
    testKmac();
}
