// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");

const check = h.check;
const check3 = h.check3;
const check4 = h.check4;
const iprint = h.iprint;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const SYMCRYPT_KEYWRAP_BLOCK_LEN: usize = 8;

const KAT_TYPE_CATEGORY: c_int = 0;
const KAT_TYPE_DATASET: c_int = 1;
const KAT_TYPE_END: c_int = 2;

const MAX_IMPS = 32;
const MAX_SIZES = 512;

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

extern fn scTestGetKeyWrapImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestKeyWrapGetMinPlaintextSize(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestKeyWrapGetMaxPlaintextSize(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestKeyWrapGetPlaintextSizeIncrement(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestKeyWrapGetKeySizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestKeyWrapSetKey(pImp: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) i32;
extern fn scTestKeyWrapEncrypt(pImp: *anyopaque, pbSrc: [*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) i32;
extern fn scTestKeyWrapDecrypt(pImp: *anyopaque, pbSrc: [*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) i32;

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

fn addUniqueSorted(sizes: *[MAX_SIZES]usize, count: *usize, val: usize) void {
    var i: usize = 0;
    while (i < count.*) : (i += 1) {
        if (sizes[i] == val) return;
        if (sizes[i] > val) break;
    }
    check(count.* < MAX_SIZES, "Too many sizes");
    var j: usize = count.*;
    while (j > i) : (j -= 1) {
        sizes[j] = sizes[j - 1];
    }
    sizes[i] = val;
    count.* += 1;
}

const KeyWrapMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) KeyWrapMultiImp {
        var self = KeyWrapMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetKeyWrapImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *KeyWrapMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const KeyWrapMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn getMinPlaintextSize(self: *const KeyWrapMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestKeyWrapGetMinPlaintextSize(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn getMaxPlaintextSize(self: *const KeyWrapMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestKeyWrapGetMaxPlaintextSize(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn getPlaintextSizeIncrement(self: *const KeyWrapMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestKeyWrapGetPlaintextSizeIncrement(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn getKeySizes(self: *const KeyWrapMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestKeyWrapGetKeySizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn setKey(self: *KeyWrapMultiImp, pbKey: [*]const u8, cbKey: usize) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestKeyWrapSetKey(imp, pbKey, cbKey) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn encrypt(
        self: *KeyWrapMultiImp,
        pbSrc: [*]const u8,
        cbSrc: usize,
        pbDst: [*]u8,
        cbDst: usize,
        pcbResult: *usize,
    ) i32 {
        var bufData: [1024]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        var cbResult: usize = 0;

        check(cbDst < bufData.len, "Buffer too small");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbDst + 1], 'd');
            const status = scTestKeyWrapEncrypt(imp, pbSrc, cbSrc, &bufData, cbDst, &cbResult);
            check(bufData[cbDst] == 'd', "?");
            if (status >= 0) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbResult);
                res = STATUS_SUCCESS;
            }
        }

        result_merge.scTestResultMergeGetResult(resData, pbDst, cbResult, 1);
        pcbResult.* = cbResult;

        return res;
    }

    fn decrypt(
        self: *KeyWrapMultiImp,
        pbSrc: [*]const u8,
        cbSrc: usize,
        pbDst: [*]u8,
        cbDst: usize,
        pcbResult: *usize,
    ) i32 {
        var bufData: [1024]u8 = undefined;
        var statusBuf: [4]u8 = undefined;
        const resStatus = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resStatus);
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        var cbResult: usize = 0;

        check(cbDst < bufData.len, "Buffer too small");

        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbDst + 1], 'd');
            const status = scTestKeyWrapDecrypt(imp, pbSrc, cbSrc, &bufData, cbDst, &cbResult);
            check(bufData[cbDst] == 'd', "?");
            if (status == STATUS_NOT_SUPPORTED) {
                continue;
            }
            std.mem.writeInt(i32, &statusBuf, status, .little);
            scTestResultMergeAddAlgImp(resStatus, imp, &statusBuf, statusBuf.len);
            scTestResultMergeAddAlgImp(resData, imp, &bufData, cbResult);
        }

        result_merge.scTestResultMergeGetResult(resStatus, &statusBuf, statusBuf.len, 1);
        const status = std.mem.readInt(i32, &statusBuf, .little);

        if (status >= 0) {
            check(cbResult <= cbDst, "Buffer too small");
            result_merge.scTestResultMergeGetResult(resData, pbDst, cbResult, 0);
            pcbResult.* = cbResult;
        }

        return status;
    }
};

fn katKeyWrapSingle(
    pImp: *KeyWrapMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    line: u64,
) void {
    var bufData: [1024]u8 = undefined;
    var cbDstComputed: usize = 0;

    check3(cbPlaintext <= bufData.len, "Buffer too small, need %lld bytes", cbPlaintext);
    check3(cbCiphertext <= bufData.len, "Buffer too small, need %lld bytes", cbCiphertext);

    check(pImp.setKey(pbKey, cbKey) >= 0, "Error in setting key");

    // Do single encryption
    @memset(&bufData, 0);

    var status = pImp.encrypt(pbPlaintext, cbPlaintext, &bufData, cbCiphertext, &cbDstComputed);
    check(status >= 0, "Encryption error");
    check3(std.mem.eql(u8, bufData[0..cbCiphertext], pbCiphertext[0..cbCiphertext]), "Ciphertext mismatch in line %lld", line);

    // Do single decryption
    status = pImp.decrypt(pbCiphertext, cbCiphertext, &bufData, cbPlaintext, &cbDstComputed);
    check(status >= 0, "Decryption error");
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbPlaintext[0..cbPlaintext]), "Plaintext mismatch in line %lld", line);

    // Check decryption of corrupted ciphertext fails
    @memcpy(bufData[0..cbCiphertext], pbCiphertext[0..cbCiphertext]);
    const bitIndex = h.g_rng.sizet(cbCiphertext * 8);
    bufData[bitIndex / 8] ^= (@as(u8, 1) << @intCast(bitIndex & 7));
    status = pImp.decrypt(&bufData, cbCiphertext, &bufData, cbPlaintext, &cbDstComputed);
    check(status < 0, "No decryption error for corrupted ciphertext");
}

fn testKeyWrapRandom(
    pImp: *KeyWrapMultiImp,
    rrep: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: u64,
) void {
    const rng_mod = @import("rng.zig");
    const bufSize: usize = 1 << 10;
    const cbMaxPaddingAmount: usize = 16;
    var buf: [bufSize]u8 = @splat(0);
    var tmp1: [bufSize]u8 = undefined;
    var tmp2: [bufSize]u8 = undefined;
    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    rng_mod.scTestRngReset(&rng, &pImp.m_algorithmName, pImp.m_algorithmNameLen);

    const cbPlaintextMin = pImp.getMinPlaintextSize();
    const cbPlaintextMax = pImp.getMaxPlaintextSize();
    const cbPlaintextIncrement = pImp.getPlaintextSizeIncrement();
    var keySizes: [MAX_SIZES]usize = undefined;
    const nKeySizes = pImp.getKeySizes(&keySizes);

    for (0..rrep) |_| {
        const cbKey = keySizes[rng.sizet(nKeySizes)];
        check(cbKey <= bufSize, "??");

        const keyIdx = rng.sizet(bufSize - cbKey);
        check3(pImp.setKey(buf[keyIdx..].ptr, cbKey) >= 0, "Key setting failure, line %lld", line);

        var cbData = rng.sizetRange(cbPlaintextMin, @min(cbPlaintextMax, bufSize - cbMaxPaddingAmount));
        cbData = cbPlaintextIncrement * (cbData / cbPlaintextIncrement);
        const srcIdx = rng.sizet(bufSize - cbData);
        const dstIdx = rng.sizet(bufSize - cbMaxPaddingAmount - cbData);
        var cbEncrypted: usize = 0;

        var status = pImp.encrypt(buf[srcIdx..].ptr, cbData, &tmp1, cbData + cbMaxPaddingAmount, &cbEncrypted);
        check3(status >= 0, "Encryption failure, line %lld", line);

        const errorBitIdx = rng.sizet(cbEncrypted * 8);
        tmp1[errorBitIdx >> 3] ^= (@as(u8, 1) << @intCast(errorBitIdx & 7));
        var cbDecrypted: usize = 0;

        status = pImp.decrypt(&tmp1, cbEncrypted, &tmp2, cbData, &cbDecrypted);
        check3(status < 0, "No decryption error, line %lld", line);

        tmp1[errorBitIdx >> 3] ^= (@as(u8, 1) << @intCast(errorBitIdx & 7));

        status = pImp.decrypt(&tmp1, cbEncrypted, &tmp2, cbData, &cbDecrypted);
        check3(status >= 0, "Decryption error, line %lld", line);
        check3(cbDecrypted == cbData, "Decryption size mismatch, line %lld", line);
        check3(std.mem.eql(u8, tmp2[0..cbData], buf[srcIdx .. srcIdx + cbData]), "Decryption mismatch, line %lld", line);

        @memcpy(buf[dstIdx .. dstIdx + cbData], tmp1[0..cbData]);
    }

    @memset(tmp1[0..cbResult], 0);
    for (0..bufSize) |i| {
        tmp1[i % cbResult] ^= buf[i];
    }

    if (!std.mem.eql(u8, tmp1[0..cbResult], pbResult[0..cbResult])) {
        scTestKatReportWrongData(pImp.algNameZ(), "Random test outcome", pbResult, cbResult, &tmp1, cbResult, @intCast(line));
        pImp.m_nErrorKatFailure += 1;
    }
}

fn testKeyWrapKats() void {
    const pKatKeyWrap = getCustomResource("kat_keywrap.dat", "KAT_KEY_WRAP");
    if (pKatKeyWrap == null) return;
    defer scTestKatDestroy(pKatKeyWrap.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var line: u64 = 0;
    var optMultiImp: ?KeyWrapMultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var sep: [*:0]const u8 = "    ";
    var doneAnything: bool = false;

    while (true) {
        scTestKatGetNextItem(pKatKeyWrap.?, katItem);
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
            optMultiImp = KeyWrapMultiImp.init(catSlice);
            skipData = (optMultiImp.?.m_nImps == 0);
            if (!skipData) {
                h.ziprint("{s}{s}", .{ std.mem.span(sep), std.mem.span(optMultiImp.?.algNameZ()) });
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

                katKeyWrapSingle(
                    pImp,
                    katKey.ptr,
                    katKey.len,
                    katPlaintext.ptr,
                    katPlaintext.len,
                    katCiphertext.ptr,
                    katCiphertext.len,
                    line,
                );
            } else if (scTestKatIsFieldPresent(katItem, "rnd") != 0) {
                check3(scTestKatItemDataCount(katItem) == 2, "Wrong # items in RND record ending at line %lld", line);
                const rrep: usize = @intCast(scTestKatParseInteger(katItem, "rrep"));
                const katRnd = KatBuf.parse(katItem, "rnd");
                defer katRnd.deinit();
                testKeyWrapRandom(pImp, rrep, katRnd.ptr, katRnd.len, line);
            } else {
                h.fatal("Unknown data record ending at line {d}", .{line});
            }
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

pub export fn testKeyWrapAlgorithms() callconv(.c) void {
    testKeyWrapKats();
}

pub export fn testKeyWrap() callconv(.c) void {
    testKeyWrapAlgorithms();
}
