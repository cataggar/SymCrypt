// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");

const check = h.check;
const check3 = h.check3;
const check4 = h.check4;
const iprint = h.iprint;
const vprint = h.vprint;
const print = h.print;

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

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

extern fn scTestIsAlgorithmPresent(name_ptr: [*]const u8, name_len: usize, isPrefix: u32) callconv(.c) u32;
extern fn scTestResultMergeAddAlgImp(mergeHandle: *anyopaque, pAlgImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestAlgImpIncKatFailure(pAlgImp: *anyopaque, delta: u64) callconv(.c) void;

extern fn scTestGetBlockCipherImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestBlockCipherMsgBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestBlockCipherChainBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestBlockCipherCoreBlockLen(pImp: *anyopaque) callconv(.c) usize;
extern fn scTestBlockCipherSetKey(pImp: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) i32;
extern fn scTestBlockCipherEncrypt(pImp: *anyopaque, pbChain: ?[*]u8, cbChain: usize, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
extern fn scTestBlockCipherDecrypt(pImp: *anyopaque, pbChain: ?[*]u8, cbChain: usize, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

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

    fn slice(self: KatBuf) []const u8 {
        return self.ptr[0..self.len];
    }
};

const BlockCipherMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) BlockCipherMultiImp {
        var self = BlockCipherMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetBlockCipherImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *BlockCipherMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const BlockCipherMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn msgBlockLen(self: *const BlockCipherMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestBlockCipherMsgBlockLen(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn chainBlockLen(self: *const BlockCipherMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestBlockCipherChainBlockLen(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn coreBlockLen(self: *const BlockCipherMultiImp) usize {
        var v: usize = std.math.maxInt(usize);
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const iv = scTestBlockCipherCoreBlockLen(imp);
            check(v == std.math.maxInt(usize) or v == iv, "?");
            v = iv;
        }
        return v;
    }

    fn setKey(self: *BlockCipherMultiImp, pbKey: [*]const u8, cbKey: usize) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestBlockCipherSetKey(imp, pbKey, cbKey) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn encrypt(
        self: *BlockCipherMultiImp,
        pbChain: ?[*]u8,
        cbChain: usize,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) void {
        var bufData: [512]u8 = undefined;
        var bufChain: [32]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        const resChain = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resChain);

        check(cbData <= bufData.len, "Buffer too small");
        check(cbChain <= bufChain.len, "Buf too small");

        for (self.m_comps[0..self.m_nComps]) |imp| {
            if (cbChain > 0) {
                @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
            }

            const pbSrcLocal: [*]const u8 = if (pbSrc == pbDst) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else blk: {
                @memset(bufData[0..cbData], 0);
                break :blk pbSrc;
            };

            scTestBlockCipherEncrypt(
                imp,
                if (cbChain == 0) null else &bufChain,
                cbChain,
                pbSrcLocal,
                &bufData,
                cbData,
            );
            scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
            scTestResultMergeAddAlgImp(resChain, imp, &bufChain, cbChain);
        }

        if (cbChain > 0) {
            result_merge.scTestResultMergeGetResult(resChain, pbChain.?, cbChain, 0);
        } else {
            result_merge.scTestResultMergeGetResult(resChain, &bufChain, 0, 0);
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
    }

    fn decrypt(
        self: *BlockCipherMultiImp,
        pbChain: ?[*]u8,
        cbChain: usize,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
    ) void {
        var bufData: [512]u8 = undefined;
        var bufChain: [32]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        const resChain = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resChain);

        check(cbData <= bufData.len, "Buffer too small");
        check(cbChain <= bufChain.len, "Buf too small");

        for (self.m_comps[0..self.m_nComps]) |imp| {
            if (cbChain > 0) {
                @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
            }

            const pbSrcLocal: [*]const u8 = if (pbSrc == pbDst) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else blk: {
                @memset(bufData[0..cbData], 0);
                break :blk pbSrc;
            };

            scTestBlockCipherDecrypt(
                imp,
                if (cbChain == 0) null else &bufChain,
                cbChain,
                pbSrcLocal,
                &bufData,
                cbData,
            );
            scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
            scTestResultMergeAddAlgImp(resChain, imp, &bufChain, cbChain);
        }

        if (cbChain > 0) {
            result_merge.scTestResultMergeGetResult(resChain, pbChain.?, cbChain, 0);
        } else {
            result_merge.scTestResultMergeGetResult(resChain, &bufChain, 0, 0);
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 1);
    }
};

fn katBlockCipherSingle(
    pImp: *BlockCipherMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    pbChain: ?[*]const u8,
    cbChain: usize,
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    line: u64,
) void {
    var bufData: [512]u8 = undefined;
    var bufChain: [32]u8 = undefined;
    const msgBlockLen = pImp.msgBlockLen();

    check3(cbPlaintext < bufData.len, "Buffer too small, need %lld bytes", cbPlaintext);
    check(cbChain <= bufChain.len, "?");
    check3(cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line);

    check(pImp.setKey(pbKey, cbKey) == 0, "Error in setting key");

    // Do single encryption
    @memset(&bufData, 0);
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }

    pImp.encrypt(&bufChain, cbChain, pbPlaintext, &bufData, cbPlaintext);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext mismatch in line %lld", line);

    // Do encryption piecewise
    @memset(&bufData, 0);
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }
    var offset: usize = 0;
    while (offset < cbPlaintext) {
        const nBytes = h.g_rng.sizetNonUniform((cbPlaintext - offset) / msgBlockLen + 1, 4, 1) * msgBlockLen;
        pImp.encrypt(&bufChain, cbChain, pbPlaintext + offset, bufData[offset..].ptr, nBytes);
        offset += nBytes;
    }
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext 2 mismatch in line %lld", line);

    // Do single decryption
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }
    pImp.decrypt(&bufChain, cbChain, pbCiphertext, &bufData, cbCiphertext);
    check3(std.mem.eql(u8, bufData[0..cbCiphertext], pbPlaintext[0..cbCiphertext]), "Plaintext mismatch in line %lld", line);

    // Do piecewise decryption
    @memset(&bufData, 0);
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }
    offset = 0;
    while (offset < cbPlaintext) {
        const nBytes = h.g_rng.sizetNonUniform((cbPlaintext - offset) / msgBlockLen + 1, 4, 1) * msgBlockLen;
        pImp.decrypt(&bufChain, cbChain, pbCiphertext + offset, bufData[offset..].ptr, nBytes);
        offset += nBytes;
    }
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbPlaintext[0..cbPlaintext]), "Plaintext 2 mismatch in line %lld", line);

    // Do in-place encryption
    @memcpy(bufData[0..cbPlaintext], pbPlaintext[0..cbPlaintext]);
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }
    pImp.encrypt(&bufChain, cbChain, &bufData, &bufData, cbPlaintext);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "In-place ciphertext mismatch in line %lld", line);

    // Do in-place decryption
    @memcpy(bufData[0..cbCiphertext], pbCiphertext[0..cbCiphertext]);
    if (cbChain > 0) {
        @memcpy(bufChain[0..cbChain], pbChain.?[0..cbChain]);
    }
    pImp.decrypt(&bufChain, cbChain, &bufData, &bufData, cbCiphertext);
    check3(std.mem.eql(u8, bufData[0..cbCiphertext], pbPlaintext[0..cbCiphertext]), "In-place plaintext mismatch in line %lld", line);
}

fn testBlockCipherRandom(
    pImp: *BlockCipherMultiImp,
    rrep: usize,
    keyLen: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: u64,
) void {
    const rng_mod = @import("rng.zig");
    var buf: [1024]u8 = undefined;
    var chainBuf: [64]u8 = undefined;
    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    const algNameSize = pImp.m_algorithmNameLen;
    check(algNameSize < buf.len - @sizeOf(u64), "Algorithm name too long");
    @memcpy(buf[0..algNameSize], pImp.m_algorithmName[0..algNameSize]);
    std.mem.writeInt(u64, buf[algNameSize..][0..8], @as(u64, keyLen), .little);
    rng_mod.scTestRngReset(&rng, &buf, algNameSize + @sizeOf(u64));

    const chainBlockLen = pImp.chainBlockLen();
    const msgBlockLen = pImp.msgBlockLen();
    const coreBlockLen = pImp.coreBlockLen();
    const bufSize = coreBlockLen * 32;
    check(bufSize <= buf.len, "Input block len too large");
    check(bufSize > keyLen, "?");
    check(bufSize > chainBlockLen, "?");
    check(bufSize > msgBlockLen, "?");

    @memset(&buf, 0);

    for (0..rrep) |_| {
        const keyIdx = rng.sizet(bufSize - keyLen);
        check3(pImp.setKey(buf[keyIdx..].ptr, keyLen) >= 0, "Key setting failure, line %lld", line);

        const chainIdx = rng.sizet(bufSize - chainBlockLen);

        var nPieces = @as(usize, rng.byte());
        const fEncrypt = ((nPieces & 1) != 0);
        nPieces = 1 + nPieces % 5;

        @memcpy(chainBuf[0..chainBlockLen], buf[chainIdx .. chainIdx + chainBlockLen]);
        for (0..nPieces) |_| {
            var pos: usize = 0;
            var len: usize = 0;
            rng.randomSubRange(bufSize, &pos, &len);
            len = msgBlockLen * (len / msgBlockLen);
            h.g_rc2EffectiveKeyLength = @intCast(9 + (pos % (1024 - 9)));
            if (fEncrypt) {
                pImp.encrypt(&chainBuf, chainBlockLen, buf[pos..].ptr, buf[pos..].ptr, len);
            } else {
                pImp.decrypt(&chainBuf, chainBlockLen, buf[pos..].ptr, buf[pos..].ptr, len);
            }
        }
        @memcpy(buf[chainIdx .. chainIdx + chainBlockLen], chainBuf[0..chainBlockLen]);
    }

    @memset(chainBuf[0..coreBlockLen], 0);
    for (0..bufSize) |i| {
        chainBuf[i % coreBlockLen] ^= buf[i];
    }

    check3(cbResult == coreBlockLen, "Result size is wrong in line %lld", line);
    if (!std.mem.eql(u8, chainBuf[0..coreBlockLen], pbResult[0..coreBlockLen])) {
        scTestKatReportWrongData(pImp.algNameZ(), "Random test outcome", pbResult, cbResult, &chainBuf, cbResult, @intCast(line));
        pImp.m_nErrorKatFailure += 1;
    }
    h.g_rc2EffectiveKeyLength = 0;
}

fn testBlockCipherKats() void {
    const pKatBlockCipher = getCustomResource("kat_blockcipher.dat", "KAT_BLOCK_CIPHER");
    if (pKatBlockCipher == null) return;
    defer scTestKatDestroy(pKatBlockCipher.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var line: u64 = 0;
    var optMultiImp: ?BlockCipherMultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var sep: [*:0]const u8 = "    ";
    var doneAnything: bool = false;

    while (true) {
        scTestKatGetNextItem(pKatBlockCipher.?, katItem);
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
            optMultiImp = BlockCipherMultiImp.init(catSlice);
            skipData = (optMultiImp.?.m_nImps == 0);
            if (!skipData) {
                iprint("%s%s", sep, optMultiImp.?.algNameZ());
                sep = ", ";
                doneAnything = true;
            }
        }

        if (itemType == KAT_TYPE_DATASET and !skipData) {
            const pImp = &optMultiImp.?;
            if (scTestKatIsFieldPresent(katItem, "effectivekeylength") != 0) {
                h.g_rc2EffectiveKeyLength = @intCast(scTestKatParseInteger(katItem, "effectivekeylength"));
            }

            if (scTestKatIsFieldPresent(katItem, "shift") != 0) {
                h.g_modeCfbShiftParam = @intCast(scTestKatParseInteger(katItem, "shift"));
            }

            if (scTestKatIsFieldPresent(katItem, "ciphertext") != 0) {
                const katKey = KatBuf.parse(katItem, "key");
                defer katKey.deinit();
                const katPlaintext = KatBuf.parse(katItem, "plaintext");
                defer katPlaintext.deinit();
                const katCiphertext = KatBuf.parse(katItem, "ciphertext");
                defer katCiphertext.deinit();

                if (scTestKatIsFieldPresent(katItem, "iv") != 0) {
                    const katChain = KatBuf.parse(katItem, "iv");
                    defer katChain.deinit();
                    var chainBuf: [32]u8 = undefined;
                    check(katChain.len <= chainBuf.len, "IV too long");
                    @memcpy(chainBuf[0..katChain.len], katChain.ptr[0..katChain.len]);

                    katBlockCipherSingle(
                        pImp,
                        katKey.ptr,
                        katKey.len,
                        &chainBuf,
                        katChain.len,
                        katPlaintext.ptr,
                        katPlaintext.len,
                        katCiphertext.ptr,
                        katCiphertext.len,
                        line,
                    );
                } else {
                    katBlockCipherSingle(
                        pImp,
                        katKey.ptr,
                        katKey.len,
                        null,
                        0,
                        katPlaintext.ptr,
                        katPlaintext.len,
                        katCiphertext.ptr,
                        katCiphertext.len,
                        line,
                    );
                }
            } else if (scTestKatIsFieldPresent(katItem, "rnd") != 0) {
                check3(scTestKatItemDataCount(katItem) <= 4, "Wrong # items in RND record ending at line %lld", line);
                const rrep: usize = @intCast(scTestKatParseInteger(katItem, "rrep"));
                const keyLen: usize = @intCast(scTestKatParseInteger(katItem, "keylen"));
                const katRnd = KatBuf.parse(katItem, "rnd");
                defer katRnd.deinit();
                testBlockCipherRandom(pImp, rrep, keyLen, katRnd.ptr, katRnd.len, line);
            } else {
                h.fatal("Unknown data record ending at line {d}", .{line});
            }

            h.g_rc2EffectiveKeyLength = 0;
            h.g_modeCfbShiftParam = 1;
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

pub export fn testBlockCipherAlgorithms() callconv(.c) void {
    testBlockCipherKats();
}

pub export fn testBlockCiphers() callconv(.c) void {
    testBlockCipherAlgorithms();
}
