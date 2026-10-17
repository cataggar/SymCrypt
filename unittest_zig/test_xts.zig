// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");

const check = h.check;
const check3 = h.check3;
const iprint = h.iprint;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const SYMCRYPT_AES_BLOCK_SIZE: usize = 16;
const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x100;

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

extern fn scTestGetXtsImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestXtsSetKey(pImp: *anyopaque, pbKey: [*]const u8, cbKey: usize, flags: u32) callconv(.c) i32;
extern fn scTestXtsEncrypt(pImp: *anyopaque, cbDataUnit: usize, tweak: u64, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) i32;
extern fn scTestXtsDecrypt(pImp: *anyopaque, cbDataUnit: usize, tweak: u64, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) i32;
extern fn scTestXtsEncryptWith128bTweak(pImp: *anyopaque, cbDataUnit: usize, pbTweak: [*]const u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) i32;
extern fn scTestXtsDecryptWith128bTweak(pImp: *anyopaque, cbDataUnit: usize, pbTweak: [*]const u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) i32;

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

const XtsMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,
    m_operateInPlace: bool = false,

    fn init(algName: []const u8) XtsMultiImp {
        var self = XtsMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetXtsImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        self.m_operateInPlace = false;
        return self;
    }

    fn deinit(self: *XtsMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const XtsMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn setKey(self: *XtsMultiImp, pbKey: [*]const u8, cbKey: usize, flags: u32) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestXtsSetKey(imp, pbKey, cbKey, flags) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn encrypt(
        self: *XtsMultiImp,
        cbDataUnit: usize,
        tweak: u64,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) i32 {
        var bufData: [(1 << 14) + 1]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);

        check(cbData <= bufData.len, "Buffer too small");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');
            const pbInternalSrc: [*]const u8 = if (self.m_operateInPlace) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;
            const status = scTestXtsEncrypt(imp, cbDataUnit, tweak, pbInternalSrc, &bufData, cbData);
            check(bufData[cbData] == 'd', "?");
            if (status >= 0) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
                res = STATUS_SUCCESS;
            }
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
        return res;
    }

    fn decrypt(
        self: *XtsMultiImp,
        cbDataUnit: usize,
        tweak: u64,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) i32 {
        var bufData: [(1 << 14) + 1]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);

        check(cbData <= bufData.len, "Buffer too small");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');
            const pbInternalSrc: [*]const u8 = if (self.m_operateInPlace) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;
            const status = scTestXtsDecrypt(imp, cbDataUnit, tweak, pbInternalSrc, &bufData, cbData);
            check(bufData[cbData] == 'd', "?");
            if (status >= 0) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
                res = STATUS_SUCCESS;
            }
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
        return res;
    }

    fn encryptWith128bTweak(
        self: *XtsMultiImp,
        cbDataUnit: usize,
        pbTweak: [*]const u8,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) i32 {
        var bufData: [(1 << 14) + 1]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);

        check(cbData <= bufData.len, "Buffer too small");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');
            const pbInternalSrc: [*]const u8 = if (self.m_operateInPlace) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;
            const status = scTestXtsEncryptWith128bTweak(imp, cbDataUnit, pbTweak, pbInternalSrc, &bufData, cbData);
            check(bufData[cbData] == 'd', "?");
            if (status != STATUS_NOT_SUPPORTED) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
                res = STATUS_SUCCESS;
            }
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
        return res;
    }

    fn decryptWith128bTweak(
        self: *XtsMultiImp,
        cbDataUnit: usize,
        pbTweak: [*]const u8,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) i32 {
        var bufData: [(1 << 14) + 1]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);

        check(cbData <= bufData.len, "Buffer too small");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');
            const pbInternalSrc: [*]const u8 = if (self.m_operateInPlace) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;
            const status = scTestXtsDecryptWith128bTweak(imp, cbDataUnit, pbTweak, pbInternalSrc, &bufData, cbData);
            check(bufData[cbData] == 'd', "?");
            if (status != STATUS_NOT_SUPPORTED) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
                res = STATUS_SUCCESS;
            }
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
        return res;
    }
};

extern fn SymCryptSha256(pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

fn katXtsSingle(
    pImp: *XtsMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    cbDataUnit: u64,
    tweak: u64,
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    line: u64,
) void {
    var bufData: [512]u8 = undefined;

    check3(cbPlaintext <= bufData.len, "Buffer too small, need %lld bytes", cbPlaintext);
    check3(cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line);
    check3(cbDataUnit <= (1 << 16), "cbDataUnit too large in line %lld", line);

    check(pImp.setKey(pbKey, cbKey, SYMCRYPT_FLAG_KEY_NO_FIPS) == 0, "Error in setting key");

    // Do single encryption
    @memset(&bufData, 0);
    _ = pImp.encrypt(@intCast(cbDataUnit), tweak, pbPlaintext, &bufData, cbPlaintext);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext mismatch in line %lld", line);

    // Do single decryption
    @memset(&bufData, 0);
    _ = pImp.decrypt(@intCast(cbDataUnit), tweak, pbCiphertext, &bufData, cbCiphertext);
    check3(std.mem.eql(u8, bufData[0..cbCiphertext], pbPlaintext[0..cbCiphertext]), "Plaintext mismatch in line %lld", line);
}

fn testXtsRandom(
    pImp: *XtsMultiImp,
    rrep: usize,
    keyLen: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: u64,
) void {
    const rng_mod = @import("rng.zig");
    var buf1: [1 << 14]u8 = undefined;
    var buf2: [1 << 14]u8 = undefined;
    var buf3: [1 << 14]u8 = undefined;

    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    const algNameSize = pImp.m_algorithmNameLen;
    check(algNameSize < buf1.len - @sizeOf(u64), "Algorithm name too long");
    @memcpy(buf1[0..algNameSize], pImp.m_algorithmName[0..algNameSize]);
    std.mem.writeInt(u64, buf1[algNameSize..][0..8], @as(u64, keyLen), .little);
    rng_mod.scTestRngReset(&rng, &buf1, algNameSize + @sizeOf(u64));

    const bufSize = buf1.len;
    check(bufSize > keyLen, "?");

    @memset(&buf1, 0);

    for (0..rrep) |_| {
        const keyIdx = rng.sizet(bufSize - keyLen);
        check3(pImp.setKey(buf1[keyIdx..].ptr, keyLen, SYMCRYPT_FLAG_KEY_NO_FIPS) == 0, "Key setting failure, line %lld", line);

        const cbDataUnit = SYMCRYPT_AES_BLOCK_SIZE + rng.sizet(8192);
        check(cbDataUnit < bufSize, "Data unit size too large");
        const maxDataUnits = bufSize / cbDataUnit;
        const nDataUnits = rng.sizet(maxDataUnits + 1);
        const cbData = nDataUnits * cbDataUnit;

        check(cbData <= bufSize, "?");

        const dataIdx = rng.sizet(bufSize - cbData + 1);
        const pbData: [*]u8 = buf1[dataIdx..].ptr;

        if ((rng.byte() & 3) != 0) {
            var tweak: u64 = @as(u64, 1) << @intCast(rng.sizet(64));
            tweak +%= @as(u64, rng.sizet(1 + 4 * nDataUnits)) -% @as(u64, 2 * nDataUnits);

            check3(pImp.encrypt(cbDataUnit, tweak, pbData, &buf2, cbData) >= 0, "Encrypt failure, line %lld", line);
            check3(pImp.decrypt(cbDataUnit, tweak, &buf2, &buf3, cbData) >= 0, "Decrypt failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], pbData[0..cbData]), "Encrypt/Decrypt mismatch, line %lld", line);

            pImp.m_operateInPlace = true;
            check3(pImp.encrypt(cbDataUnit, tweak, &buf3, &buf3, cbData) >= 0, "In-place encrypt failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], buf2[0..cbData]), "In-place/Out-of-place Encrypt mismatch, line %lld", line);

            check3(pImp.decrypt(cbDataUnit, tweak, &buf3, &buf3, cbData) >= 0, "In-place decrypt failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], pbData[0..cbData]), "In-place Encrypt/Decrypt mismatch, line %lld", line);
            pImp.m_operateInPlace = false;

            if (nDataUnits > 1) {
                for (0..5) |_| {
                    const nSubUnits = rng.sizet(nDataUnits);
                    const cbSubUnits = nSubUnits * cbDataUnit;
                    const unitOffset = rng.sizet(nDataUnits - nSubUnits + 1);
                    const cbOffset = unitOffset * cbDataUnit;
                    check(unitOffset + nSubUnits <= nDataUnits, "?");

                    check3(pImp.encrypt(cbDataUnit, tweak +% unitOffset, pbData + cbOffset, &buf3, cbSubUnits) >= 0, "Encrypt failure, line %lld", line);
                    check3(std.mem.eql(u8, buf3[0..cbSubUnits], buf2[cbOffset .. cbOffset + cbSubUnits]), "Partial Encrypt mismatch, line %lld", line);

                    check3(pImp.decrypt(cbDataUnit, tweak +% unitOffset, buf2[cbOffset..].ptr, &buf3, cbSubUnits) >= 0, "Decrypt failure, line %lld", line);
                    check3(std.mem.eql(u8, buf3[0..cbSubUnits], pbData[cbOffset .. cbOffset + cbSubUnits]), "Partial Decrypt mismatch, line %lld", line);
                }
            }
        } else {
            const tweakPower = rng.sizet(128);
            var tweakLow: u64 = @as(u64, 1) << @intCast(tweakPower & 63);
            var tweakHigh: u64 = 0;

            if ((tweakPower & 64) != 0) {
                tweakHigh = tweakLow;
                tweakLow = 0;
            }

            tweakLow +%= @as(u64, rng.sizet(1 + 4 * nDataUnits)) -% @as(u64, 2 * nDataUnits);
            if (@as(i64, @bitCast(tweakLow)) < 0) {
                tweakHigh -%= 1;
            }

            var tweak: [SYMCRYPT_AES_BLOCK_SIZE]u8 = undefined;
            std.mem.writeInt(u64, tweak[0..8], tweakLow, .little);
            std.mem.writeInt(u64, tweak[8..16], tweakHigh, .little);

            check3(pImp.encryptWith128bTweak(cbDataUnit, &tweak, pbData, &buf2, cbData) >= 0, "EncryptWith128bTweak failure, line %lld", line);
            check3(pImp.decryptWith128bTweak(cbDataUnit, &tweak, &buf2, &buf3, cbData) >= 0, "DecryptWith128bTweak failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], pbData[0..cbData]), "EncryptWith128bTweak/DecryptWith128bTweak mismatch, line %lld", line);

            pImp.m_operateInPlace = true;
            check3(pImp.encryptWith128bTweak(cbDataUnit, &tweak, &buf3, &buf3, cbData) >= 0, "In-place encrypt failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], buf2[0..cbData]), "In-place/Out-of-place EncryptWith128bTweak mismatch, line %lld", line);

            check3(pImp.decryptWith128bTweak(cbDataUnit, &tweak, &buf3, &buf3, cbData) >= 0, "In-place decrypt failure, line %lld", line);
            check3(std.mem.eql(u8, buf3[0..cbData], pbData[0..cbData]), "In-place EncryptWith128bTweak/DecryptWith128bTweak mismatch, line %lld", line);
            pImp.m_operateInPlace = false;

            if (nDataUnits > 1) {
                for (0..5) |_| {
                    const nSubUnits = rng.sizet(nDataUnits);
                    const cbSubUnits = nSubUnits * cbDataUnit;
                    const unitOffset = rng.sizet(nDataUnits - nSubUnits + 1);
                    const cbOffset = unitOffset * cbDataUnit;
                    check(unitOffset + nSubUnits <= nDataUnits, "?");

                    const newLow = tweakLow +% unitOffset;
                    const carry: u64 = if (newLow < tweakLow) 1 else 0;
                    std.mem.writeInt(u64, tweak[0..8], newLow, .little);
                    std.mem.writeInt(u64, tweak[8..16], tweakHigh +% carry, .little);

                    check3(pImp.encryptWith128bTweak(cbDataUnit, &tweak, pbData + cbOffset, &buf3, cbSubUnits) >= 0, "EncryptWith128bTweak failure, line %lld", line);
                    check3(std.mem.eql(u8, buf3[0..cbSubUnits], buf2[cbOffset .. cbOffset + cbSubUnits]), "Partial EncryptWith128bTweak mismatch, line %lld", line);

                    check3(pImp.decryptWith128bTweak(cbDataUnit, &tweak, buf2[cbOffset..].ptr, &buf3, cbSubUnits) >= 0, "DecryptWith128bTweak failure, line %lld", line);
                    check3(std.mem.eql(u8, buf3[0..cbSubUnits], pbData[cbOffset .. cbOffset + cbSubUnits]), "Partial DecryptWith128bTweak mismatch, line %lld", line);
                }
            }
        }

        @memcpy(pbData[0..cbData], buf2[0..cbData]);
    }

    SymCryptSha256(&buf1, bufSize, &buf2);
    if (!std.mem.eql(u8, buf2[0..cbResult], pbResult[0..cbResult])) {
        scTestKatReportWrongData(pImp.algNameZ(), "Random test outcome", pbResult, cbResult, &buf2, cbResult, @intCast(line));
        pImp.m_nErrorKatFailure += 1;
    }
}

fn testXtsKats() void {
    const pKatXts = getCustomResource("kat_xts.dat", "KAT_XTS");
    if (pKatXts == null) return;
    defer scTestKatDestroy(pKatXts.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var line: u64 = 0;
    var optMultiImp: ?XtsMultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var sep: [*:0]const u8 = "    ";
    var doneAnything: bool = false;

    while (true) {
        scTestKatGetNextItem(pKatXts.?, katItem);
        const itemType = scTestKatItemType(katItem);
        line = @intCast(scTestKatItemLine(katItem));

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
            optMultiImp = XtsMultiImp.init(catSlice);
            skipData = (optMultiImp.?.m_nImps == 0);
            if (!skipData) {
                iprint("%s%s", sep, optMultiImp.?.algNameZ());
                sep = ", ";
                doneAnything = true;
            }
        }

        if (itemType == KAT_TYPE_DATASET and !skipData) {
            const pImp = &optMultiImp.?;
            if (scTestKatIsFieldPresent(katItem, "ciphertext") != 0) {
                const katKey = KatBuf.parse(katItem, "key");
                defer katKey.deinit();
                const katPlaintext = KatBuf.parse(katItem, "plaintext");
                defer katPlaintext.deinit();
                const katCiphertext = KatBuf.parse(katItem, "ciphertext");
                defer katCiphertext.deinit();
                const tweak: u64 = @bitCast(scTestKatParseInteger(katItem, "tweak"));

                katXtsSingle(
                    pImp,
                    katKey.ptr,
                    katKey.len,
                    katPlaintext.len,
                    tweak,
                    katPlaintext.ptr,
                    katPlaintext.len,
                    katCiphertext.ptr,
                    katCiphertext.len,
                    line,
                );
            } else if (scTestKatIsFieldPresent(katItem, "rnd") != 0) {
                check3(scTestKatItemDataCount(katItem) <= 4, "Wrong # items in RND record ending at line %lld", line);
                const rrep: usize = @intCast(scTestKatParseInteger(katItem, "rrep"));
                const keyLen: usize = @intCast(scTestKatParseInteger(katItem, "keylen"));
                const katRnd = KatBuf.parse(katItem, "rnd");
                defer katRnd.deinit();
                testXtsRandom(pImp, rrep, keyLen, katRnd.ptr, katRnd.len, line);
            } else {
                h.fatal("Unknown data record ending at line {d}", .{line});
            }
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

pub export fn testXtsAlgorithms() callconv(.c) void {
    testXtsKats();
}

pub export fn testXts() callconv(.c) void {
    testXtsAlgorithms();
}
