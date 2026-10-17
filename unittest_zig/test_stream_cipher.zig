// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");

const check = h.check;
const check3 = h.check3;
const iprint = h.iprint;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

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

extern fn scTestGetStreamCipherImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestStreamCipherGetNonceSizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestStreamCipherGetKeySizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestStreamCipherSetKey(pImp: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) i32;
extern fn scTestStreamCipherSetNonce(pImp: *anyopaque, pbNonce: [*]const u8, cbNonce: usize) callconv(.c) i32;
extern fn scTestStreamCipherIsRandomAccess(pImp: *anyopaque) callconv(.c) u32;
extern fn scTestStreamCipherSetOffset(pImp: *anyopaque, offset: u64) callconv(.c) void;
extern fn scTestStreamCipherEncrypt(pImp: *anyopaque, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

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

const StreamCipherMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) StreamCipherMultiImp {
        var self = StreamCipherMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetStreamCipherImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *StreamCipherMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const StreamCipherMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn getNonceSizes(self: *const StreamCipherMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestStreamCipherGetNonceSizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn getKeySizes(self: *const StreamCipherMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestStreamCipherGetKeySizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn setNonce(self: *StreamCipherMultiImp, pbNonce: ?[*]const u8, cbNonce: usize) i32 {
        const dummy: [1]u8 = .{0};
        const p: [*]const u8 = if (pbNonce) |ptr| ptr else &dummy;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            check(scTestStreamCipherSetNonce(imp, p, cbNonce) >= 0, "SetNonce failure");
        }
        return STATUS_SUCCESS;
    }

    fn setKey(self: *StreamCipherMultiImp, pbKey: [*]const u8, cbKey: usize) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestStreamCipherSetKey(imp, pbKey, cbKey) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn isRandomAccess(self: *const StreamCipherMultiImp) bool {
        const res = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(res);
        var b: u32 = 0;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            b = if (scTestStreamCipherIsRandomAccess(imp) != 0) 1 else 0;
            scTestResultMergeAddAlgImp(res, imp, @ptrCast(&b), @sizeOf(u32));
        }
        result_merge.scTestResultMergeGetResult(res, @ptrCast(&b), @sizeOf(u32), 0);
        return b != 0;
    }

    fn setOffset(self: *StreamCipherMultiImp, offset: u64) void {
        for (self.m_comps[0..self.m_nComps]) |imp| {
            scTestStreamCipherSetOffset(imp, offset);
        }
    }

    fn encrypt(self: *StreamCipherMultiImp, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) void {
        var bufData: [1024]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);

        check(cbData <= bufData.len, "Buffer too small");

        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0..cbData], 0);
            scTestStreamCipherEncrypt(imp, pbSrc, &bufData, cbData);
            scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
        }

        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
    }
};

fn katStreamCipherSingle(
    pImp: *StreamCipherMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    pbNonce: ?[*]const u8,
    cbNonce: usize,
    offset: u64,
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    line: u64,
) void {
    var bufData: [512]u8 = undefined;

    check3(cbPlaintext < bufData.len, "Buffer too small, need %lld bytes", cbPlaintext);
    check3(cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line);

    check(pImp.setKey(pbKey, cbKey) == 0, "Error in setting key");
    check(pImp.setNonce(pbNonce, cbNonce) == 0, "Error setting nonce");
    if (offset != 0) {
        pImp.setOffset(offset);
    }

    // Do single encryption
    @memset(&bufData, 0);

    pImp.encrypt(pbPlaintext, &bufData, cbPlaintext);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext mismatch in line %lld", line);

    // Do encryption piecewise
    check(pImp.setKey(pbKey, cbKey) == 0, "Error in setting key 2");
    check(pImp.setNonce(pbNonce, cbNonce) == 0, "Error setting nonce 2");
    if (offset != 0) {
        pImp.setOffset(offset);
    }

    @memset(&bufData, 0);
    var pos: usize = 0;
    while (pos < cbPlaintext) {
        const nBytes = h.g_rng.sizetNonUniform((cbPlaintext - pos) + 1, 4, 1);
        pImp.encrypt(pbPlaintext + pos, bufData[pos..].ptr, nBytes);
        pos += nBytes;
    }
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext 2 mismatch in line %lld", line);

    // Do random-access checks
    if (pImp.isRandomAccess()) {
        for (0..10) |_| {
            const cbBytes = h.g_rng.sizet(cbPlaintext + 1);
            const rpos = h.g_rng.sizet(cbPlaintext - cbBytes + 1);
            pImp.setOffset(offset + rpos);
            pImp.encrypt(pbPlaintext + rpos, &bufData, cbBytes);
            check3(std.mem.eql(u8, bufData[0..cbBytes], pbCiphertext[rpos .. rpos + cbBytes]), "Partial ciphertext mismatch in line %lld", line);
        }
    }
}

fn testStreamCipherRandom(
    pImp: *StreamCipherMultiImp,
    rrep: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: u64,
) void {
    const rng_mod = @import("rng.zig");
    var buf: [1024]u8 = undefined;
    var resBuf: [16]u8 = undefined;
    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    const algNameSize = pImp.m_algorithmNameLen;
    check(algNameSize < buf.len - @sizeOf(u64), "Algorithm name too long");
    @memcpy(buf[0..algNameSize], pImp.m_algorithmName[0..algNameSize]);
    rng_mod.scTestRngReset(&rng, &buf, algNameSize);

    const bufSize = buf.len;
    @memset(&buf, 0);

    var keySize: [MAX_SIZES]usize = undefined;
    const nKeySizes = pImp.getKeySizes(&keySize);
    var nonceSize: [MAX_SIZES]usize = undefined;
    const nNonceSizes = pImp.getNonceSizes(&nonceSize);

    for (0..rrep) |_| {
        const keyLen = keySize[rng.sizet(nKeySizes)];
        const keyIdx = rng.sizet(bufSize - keyLen);

        check3(pImp.setKey(buf[keyIdx..].ptr, keyLen) >= 0, "Key setting failure, line %lld", line);

        if (nNonceSizes > 0) {
            const nonceLen = nonceSize[rng.sizet(nNonceSizes)];
            const nonceIdx = rng.sizet(bufSize - nonceLen);
            check3(pImp.setNonce(buf[nonceIdx..].ptr, nonceLen) >= 0, "Nonce setting failure, line %lld", line);
        }

        var nPieces = @as(usize, rng.byte());
        nPieces = 1 + nPieces % 5;

        for (0..nPieces) |_| {
            var pos: usize = 0;
            var len: usize = 0;
            rng.randomSubRange(bufSize, &pos, &len);
            if (pImp.isRandomAccess()) {
                pImp.setOffset(@intCast(rng.sizet(1 << 12)));
            }
            pImp.encrypt(buf[pos..].ptr, buf[pos..].ptr, len);
        }
    }

    @memset(&resBuf, 0);
    for (0..bufSize) |i| {
        resBuf[i % resBuf.len] ^= buf[i];
    }

    check3(cbResult == resBuf.len, "Result size is wrong in line %lld", line);
    if (!std.mem.eql(u8, &resBuf, pbResult[0..resBuf.len])) {
        scTestKatReportWrongData(pImp.algNameZ(), "Random test outcome", pbResult, cbResult, &resBuf, cbResult, @intCast(line));
        pImp.m_nErrorKatFailure += 1;
    }
}

fn testStreamCipherKats() void {
    const pKatStreamCipher = getCustomResource("kat_streamcipher.dat", "KAT_STREAM_CIPHER");
    if (pKatStreamCipher == null) return;
    defer scTestKatDestroy(pKatStreamCipher.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var line: u64 = 0;
    var optMultiImp: ?StreamCipherMultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var sep: [*:0]const u8 = "    ";
    var doneAnything: bool = false;

    while (true) {
        scTestKatGetNextItem(pKatStreamCipher.?, katItem);
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
            optMultiImp = StreamCipherMultiImp.init(catSlice);
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

                var optNonce: ?KatBuf = null;
                defer if (optNonce) |n| n.deinit();

                if (scTestKatIsFieldPresent(katItem, "nonce") != 0) {
                    optNonce = KatBuf.parse(katItem, "nonce");
                }

                var offset: u64 = 0;
                if (scTestKatIsFieldPresent(katItem, "offset") != 0) {
                    offset = @intCast(scTestKatParseInteger(katItem, "offset"));
                }

                const noncePtr: ?[*]const u8 = if (optNonce) |n| n.ptr else null;
                const nonceLen: usize = if (optNonce) |n| n.len else 0;

                katStreamCipherSingle(
                    pImp,
                    katKey.ptr,
                    katKey.len,
                    noncePtr,
                    nonceLen,
                    offset,
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
                testStreamCipherRandom(pImp, rrep, katRnd.ptr, katRnd.len, line);
            } else {
                h.fatal("Unknown data record ending at line {d}", .{line});
            }
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

pub export fn testStreamCipherAlgorithms() callconv(.c) void {
    testStreamCipherKats();
}

pub export fn testStreamCipher() callconv(.c) void {
    testStreamCipherAlgorithms();
}
