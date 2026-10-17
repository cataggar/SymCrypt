// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");
const sc_imp = @import("sc_implementations.zig");

const types = struct {
    pub const SYMCRYPT_CALL: std.builtin.CallingConvention = .c;

    pub const SYMCRYPT_ERROR = enum(c_int) {
        SYMCRYPT_NO_ERROR = 0,
        _,
    };

    pub const SYMCRYPT_RNG_AES_STATE = extern struct {
        keyAndV: [32 + 16]u8 align(16),
        previousBlock: [16]u8,
        requestCounter: u64,
        fips140_2Check: u8,
        magic: usize,
    };
    pub const PSYMCRYPT_RNG_AES_STATE = *SYMCRYPT_RNG_AES_STATE;
};

const check = h.check;
const check3 = h.check3;
const check4 = h.check4;
const check5 = h.check5;

const STATUS_SUCCESS: i32 = 0;

const KAT_TYPE_CATEGORY: c_int = 0;
const KAT_TYPE_DATASET: c_int = 1;
const KAT_TYPE_END: c_int = 2;

const MAX_IMPS = 32;

extern fn getCustomResource(resourceName: [*:0]const u8, resourceType: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn scTestKatGetNextItem(pKat: *anyopaque, pKatItem: *anyopaque) callconv(.c) void;
extern fn scTestKatFreeParsedData(ptr: [*]u8, len: usize) callconv(.c) void;
extern fn scTestKatDestroy(pKat: *anyopaque) callconv(.c) void;
extern fn scTestKatItemCreate() callconv(.c) ?*anyopaque;
extern fn scTestKatItemDestroy(pItem: *anyopaque) callconv(.c) void;
extern fn scTestKatItemType(pItem: *const anyopaque) callconv(.c) c_int;
extern fn scTestKatItemLine(pItem: *const anyopaque) callconv(.c) i64;
extern fn scTestKatItemCategory(pItem: *const anyopaque, pLen: *usize) callconv(.c) [*]const u8;
extern fn scTestKatItemDataCount(pItem: *const anyopaque) callconv(.c) usize;
extern fn scTestKatIsFieldPresent(pItem: *anyopaque, name: [*:0]const u8) callconv(.c) u32;
extern fn scTestKatParseInteger(pItem: *anyopaque, name: [*:0]const u8) callconv(.c) i64;
extern fn scTestKatParseDataAlloc(pItem: *anyopaque, name: [*:0]const u8, pOutLen: *usize) callconv(.c) [*]u8;
extern fn scTestKatReportWrongData(
    algName: [*:0]const u8,
    name: [*:0]const u8,
    pbExpected: [*]const u8,
    cbExpected: usize,
    pbActual: [*]const u8,
    cbActual: usize,
    line: i64,
) callconv(.c) void;

extern fn scTestResultMergeAddAlgImp(mergeHandle: *anyopaque, pAlgImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestAlgImpIncKatFailure(pAlgImp: *anyopaque, delta: u64) callconv(.c) void;

extern fn scTestGetRngSp800_90Imps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestRngSp800_90Instantiate(pImp: *anyopaque, pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) i32;
extern fn scTestRngSp800_90Reseed(pImp: *anyopaque, pbEntropy: [*]const u8, cbEntropy: usize) callconv(.c) i32;
extern fn scTestRngSp800_90Generate(pImp: *anyopaque, pbData: [*]u8, cbData: usize) callconv(.c) void;

extern fn SymCryptRngAesInstantiate(
    pRngState: types.PSYMCRYPT_RNG_AES_STATE,
    pcbSeedMaterial: ?[*]const u8,
    cbSeedMaterial: usize,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;
extern fn SymCryptRngAesGenerate(
    pRngState: types.PSYMCRYPT_RNG_AES_STATE,
    pbRandom: [*]u8,
    cbRandom: usize,
) callconv(types.SYMCRYPT_CALL) void;

const KatBuf = struct {
    ptr: [*]u8,
    len: usize,

    fn parse(pItem: *anyopaque, name: [*:0]const u8) KatBuf {
        var len: usize = 0;
        const ptr = scTestKatParseDataAlloc(pItem, name, &len);
        return .{ .ptr = ptr, .len = len };
    }

    fn deinit(self: KatBuf) void {
        scTestKatFreeParsedData(self.ptr, self.len);
    }
};

const RngSp800_90MultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) RngSp800_90MultiImp {
        var self = RngSp800_90MultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetRngSp800_90Imps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *RngSp800_90MultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const RngSp800_90MultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn instantiate(self: *RngSp800_90MultiImp, pbEntropy: ?[*]const u8, cbEntropy: usize) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestRngSp800_90Instantiate(imp, pbEntropy, cbEntropy) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) 1 else STATUS_SUCCESS;
    }

    fn reseed(self: *RngSp800_90MultiImp, pbEntropy: [*]const u8, cbEntropy: usize) i32 {
        const res = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(res);

        for (self.m_comps[0..self.m_nComps]) |imp| {
            const status = scTestRngSp800_90Reseed(imp, pbEntropy, cbEntropy);
            const s: u32 = if (status == STATUS_SUCCESS) 1 else 0;
            scTestResultMergeAddAlgImp(res, imp, @ptrCast(&s), @sizeOf(u32));
        }

        var uStatus: u32 = 0;
        result_merge.scTestResultMergeGetResult(res, @ptrCast(&uStatus), @sizeOf(u32), 0);
        return if (uStatus == 1) STATUS_SUCCESS else 1;
    }

    fn generate(self: *RngSp800_90MultiImp, pbData: [*]u8, cbData: usize) void {
        const res = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(res);

        const d_buf = std.heap.c_allocator.alloc(u8, @max(cbData, 1)) catch unreachable;
        defer std.heap.c_allocator.free(d_buf);

        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(d_buf[0..cbData], 'd');
            scTestRngSp800_90Generate(imp, d_buf.ptr, cbData);
            scTestResultMergeAddAlgImp(res, imp, d_buf.ptr, cbData);
        }

        result_merge.scTestResultMergeGetResult(res, pbData, cbData, 1);
    }
};

const g_abInstantiateEntropyInputPlusNonce = [_]u8{
    // Entropy input
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

    // Nonce
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
};

const g_abOutput1 = [32]u8{
    0xE6, 0x86, 0xDD, 0x55, 0xF7, 0x58, 0xFD, 0x91,
    0xBA, 0x7C, 0xB7, 0x26, 0xFE, 0x0B, 0x57, 0x3A,
    0x18, 0x0A, 0xB6, 0x74, 0x39, 0xFF, 0xBD, 0xFE,
    0x5E, 0xC2, 0x8F, 0xB3, 0x7A, 0x16, 0xA5, 0x3B,
};

const g_abOutput2 = [32]u8{
    0x8D, 0xA6, 0xCC, 0x59, 0xE7, 0x03, 0xCE, 0xD0,
    0x7D, 0x58, 0xD9, 0x6E, 0x5B, 0x6D, 0x78, 0x36,
    0xC3, 0x25, 0x99, 0x73, 0x5B, 0x73, 0x4F, 0x88,
    0xC1, 0xA7, 0x3B, 0x53, 0xC7, 0xA6, 0xD8, 0x2E,
};

fn testAesCtrDrbgDetailedVectors() void {
    var rng: types.SYMCRYPT_RNG_AES_STATE = undefined;
    var buf: [32]u8 = undefined;

    if (h.g_useDynamicFunctionsInTestCall != 0) {
        if (sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptRngAesInstantiate", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptRngAesGenerate", .function_ptr) == null)
        {
            h.print("    skipped\n");
            return;
        }
    }

    _ = sc_imp.callSymCrypt(
        "SymCryptRngAesInstantiate",
        @TypeOf(&SymCryptRngAesInstantiate),
        &SymCryptRngAesInstantiate,
        .{ &rng, &g_abInstantiateEntropyInputPlusNonce, g_abInstantiateEntropyInputPlusNonce.len },
    );

    sc_imp.callSymCrypt(
        "SymCryptRngAesGenerate",
        @TypeOf(&SymCryptRngAesGenerate),
        &SymCryptRngAesGenerate,
        .{ &rng, &buf, buf.len },
    );

    check(std.mem.eql(u8, &buf, &g_abOutput1), "Wrong output of AES_CTR_DRBG");

    sc_imp.callSymCrypt(
        "SymCryptRngAesGenerate",
        @TypeOf(&SymCryptRngAesGenerate),
        &SymCryptRngAesGenerate,
        .{ &rng, &buf, buf.len },
    );

    check(std.mem.eql(u8, &buf, &g_abOutput2), "Wrong output of AES_CTR_DRBG 2");
}

fn testAesCtrDrbgSingle(
    pRng: *RngSp800_90MultiImp,
    pbEntropy: [*]const u8,
    cbEntropy: usize,
    pbReseed: [*]const u8,
    cbReseed: usize,
    pbRes: [*]const u8,
    cbRes: usize,
    generateAfterInstantiate: i64,
    line: u64,
) void {
    var buf: [64]u8 = undefined;

    check3(cbRes <= buf.len, "RNG result size too large in record on line %lld", line);
    check3(
        generateAfterInstantiate == -1 or generateAfterInstantiate <= @as(i64, buf.len),
        "RNG result size too large in record -2- on line %lld",
        line,
    );

    _ = pRng.instantiate(pbEntropy, cbEntropy);

    if (generateAfterInstantiate > 0) {
        pRng.generate(&buf, @intCast(generateAfterInstantiate));
    }

    _ = pRng.reseed(pbReseed, cbReseed);

    pRng.generate(&buf, cbRes);

    if (!std.mem.eql(u8, buf[0..cbRes], pbRes[0..cbRes])) {
        scTestKatReportWrongData("AesCtrDrbg", "data", pbRes, cbRes, &buf, cbRes, @intCast(line));
        pRng.m_nErrorKatFailure += 1;
    }
}

fn testRngs() void {
    const pKatRng = getCustomResource("kat_rng.dat", "KAT_RNG");
    if (pKatRng == null) return;
    defer scTestKatDestroy(pKatRng.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var optMultiImp: ?RngSp800_90MultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var doneAnything: bool = false;
    var generateAfterInstantiate: i64 = -1;
    var sep: [*:0]const u8 = "    ";

    while (true) {
        scTestKatGetNextItem(pKatRng.?, katItem);
        const itemType = scTestKatItemType(katItem);
        const line: u64 = @intCast(scTestKatItemLine(katItem));

        if (itemType == KAT_TYPE_END) {
            break;
        }

        if (itemType == KAT_TYPE_CATEGORY) {
            var catLen: usize = 0;
            const catPtr = scTestKatItemCategory(katItem, &catLen);
            const catSlice = catPtr[0..catLen];

            if (optMultiImp) |*imp| {
                imp.deinit();
            }
            optMultiImp = RngSp800_90MultiImp.init(catSlice);
            generateAfterInstantiate = -1;

            skipData = (optMultiImp.?.m_nImps == 0);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ std.mem.span(sep), std.mem.span(@as([*:0]const u8, @ptrCast(&optMultiImp.?.m_algorithmName))) });
                sep = ", ";
                doneAnything = true;
            }
        }

        if (itemType == KAT_TYPE_DATASET and !skipData) {
            const pImp = &optMultiImp.?;
            if (scTestKatIsFieldPresent(katItem, "entropyinput") != 0) {
                const katEntropyInput = KatBuf.parse(katItem, "entropyinput");
                defer katEntropyInput.deinit();
                const katNonce = KatBuf.parse(katItem, "nonce");
                defer katNonce.deinit();
                const katReseed = KatBuf.parse(katItem, "entropyinputreseed");
                defer katReseed.deinit();
                const katRes = KatBuf.parse(katItem, "returnedbits");
                defer katRes.deinit();

                const cbEntropy = katEntropyInput.len + katNonce.len;
                const pbEntropy = std.heap.c_allocator.alloc(u8, @max(cbEntropy, 1)) catch unreachable;
                defer std.heap.c_allocator.free(pbEntropy);
                @memcpy(pbEntropy[0..katEntropyInput.len], katEntropyInput.ptr[0..katEntropyInput.len]);
                @memcpy(pbEntropy[katEntropyInput.len..cbEntropy], katNonce.ptr[0..katNonce.len]);

                testAesCtrDrbgSingle(
                    pImp,
                    pbEntropy.ptr,
                    cbEntropy,
                    katReseed.ptr,
                    katReseed.len,
                    katRes.ptr,
                    katRes.len,
                    generateAfterInstantiate,
                    line,
                );
                continue;
            }

            if (scTestKatIsFieldPresent(katItem, "generateafterinstantiate") != 0) {
                generateAfterInstantiate = scTestKatParseInteger(katItem, "generateafterinstantiate");
                continue;
            }

            h.fatal("Unknown data record ending at line {d}", .{line});
        }
    }

    if (doneAnything) {
        h.iprint("\n");
    }
}

pub export fn testAesCtrDrbg() callconv(.c) void {
    h.print("    testAesCtrDrbgDetailedVectors static\n");
    testAesCtrDrbgDetailedVectors();

    if (h.g_dynamicSymCryptModuleHandle != null) {
        h.print("    testAesCtrDrbgDetailedVectors dynamic\n");
        h.g_useDynamicFunctionsInTestCall = 1;
        testAesCtrDrbgDetailedVectors();
        h.g_useDynamicFunctionsInTestCall = 0;
    }

    testRngs();
}
