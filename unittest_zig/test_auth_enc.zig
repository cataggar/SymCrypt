// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");
const sc_imp = @import("sc_implementations.zig");

const types = struct {
    pub const SYMCRYPT_CALL: std.builtin.CallingConvention = .c;
    pub const SYMCRYPT_GCM_BLOCK_SIZE: usize = 16;

    pub const SYMCRYPT_ERROR = enum(c_int) {
        SYMCRYPT_NO_ERROR = 0,
        SYMCRYPT_AUTHENTICATION_FAILURE = 0x8007,
        SYMCRYPT_INVALID_ARGUMENT = 0x800e,
        SYMCRYPT_SESSION_REPLAY_FAILURE = 0x8013,
        _,
    };

    pub const SYMCRYPT_BLOCKCIPHER_ID = enum(c_int) {
        SYMCRYPT_BLOCKCIPHER_ID_AES = 1,
        _,
    };

    pub const PCSYMCRYPT_BLOCKCIPHER = *const anyopaque;

    pub const SYMCRYPT_GCM_EXPANDED_KEY = extern struct {
        data: [4096]u8 align(64),
    };
    pub const PSYMCRYPT_GCM_EXPANDED_KEY = *SYMCRYPT_GCM_EXPANDED_KEY;
    pub const PCSYMCRYPT_GCM_EXPANDED_KEY = *const SYMCRYPT_GCM_EXPANDED_KEY;

    pub const SYMCRYPT_SESSION_REPLAY_STATE = extern struct {
        replayMask: u64 align(16),
        messageNumber: u64,
    };

    pub const SYMCRYPT_SESSION = extern struct {
        replayState: SYMCRYPT_SESSION_REPLAY_STATE align(16),
        senderId: u32,
        flags: u32,
        pMutex: ?*anyopaque,
    };
    pub const PSYMCRYPT_SESSION = *SYMCRYPT_SESSION;
};

const check = h.check;
const check3 = h.check3;
const check4 = h.check4;
const check5 = h.check5;
const iprint = h.iprint;
const print = h.print;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const AUTHENC_FLAG_PARTIAL: u32 = 1;

const KAT_TYPE_CATEGORY: c_int = 0;
const KAT_TYPE_DATASET: c_int = 1;
const KAT_TYPE_END: c_int = 2;

const MAX_IMPS = 32;
const MAX_SIZES = 512;
const MAX_AUTH_ENC_DATA_SIZE = 512;

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

extern fn scTestGetAuthEncImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestAuthEncGetNonceSizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestAuthEncGetTagSizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestAuthEncGetKeySizes(pImp: *anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize;
extern fn scTestAuthEncSetKey(pImp: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) i32;
extern fn scTestAuthEncSetTotalCbData(pImp: *anyopaque, cbData: usize) callconv(.c) void;
extern fn scTestAuthEncEncrypt(
    pImp: *anyopaque,
    pbNonce: [*]const u8,
    cbNonce: usize,
    pbAuthData: [*]const u8,
    cbAuthData: usize,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
    pbTag: ?[*]u8,
    cbTag: usize,
    flags: u32,
) callconv(.c) i32;
extern fn scTestAuthEncDecrypt(
    pImp: *anyopaque,
    pbNonce: [*]const u8,
    cbNonce: usize,
    pbAuthData: [*]const u8,
    cbAuthData: usize,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
    pbTag: ?[*]const u8,
    cbTag: usize,
    flags: u32,
) callconv(.c) i32;

extern fn SymCryptGetBlockCipher(id: types.SYMCRYPT_BLOCKCIPHER_ID) callconv(types.SYMCRYPT_CALL) ?types.PCSYMCRYPT_BLOCKCIPHER;
extern fn SymCryptGcmExpandKey(
    pExpandedKey: types.PSYMCRYPT_GCM_EXPANDED_KEY,
    pBlockCipher: types.PCSYMCRYPT_BLOCKCIPHER,
    pbKey: [*]const u8,
    cbKey: usize,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;
extern fn SymCryptGcmEncrypt(
    pExpandedKey: types.PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: [*]const u8,
    cbNonce: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    pbDst: ?[*]u8,
    cbData: usize,
    pbTag: [*]u8,
    cbTag: usize,
) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptSessionSenderInit(
    pSession: types.PSYMCRYPT_SESSION,
    senderId: u32,
    flags: u32,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;
extern fn SymCryptSessionReceiverInit(
    pSession: types.PSYMCRYPT_SESSION,
    senderId: u32,
    flags: u32,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;
extern fn SymCryptSessionDestroy(
    pSession: types.PSYMCRYPT_SESSION,
) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptSessionGcmEncrypt(
    pSession: types.PSYMCRYPT_SESSION,
    pExpandedKey: types.PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    pbDst: ?[*]u8,
    cbData: usize,
    pbTag: [*]u8,
    cbTag: usize,
    pu64MessageNumber: ?*u64,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;
extern fn SymCryptSessionGcmDecrypt(
    pSession: types.PSYMCRYPT_SESSION,
    messageNumber: u64,
    pExpandedKey: types.PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    pbDst: ?[*]u8,
    cbData: usize,
    pbTag: [*]const u8,
    cbTag: usize,
) callconv(types.SYMCRYPT_CALL) types.SYMCRYPT_ERROR;

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

const AuthEncMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_comps: [MAX_IMPS]*anyopaque = undefined,
    m_nComps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) AuthEncMultiImp {
        var self = AuthEncMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetAuthEncImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *AuthEncMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const AuthEncMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn getNonceSizes(self: *const AuthEncMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestAuthEncGetNonceSizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn getTagSizes(self: *const AuthEncMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestAuthEncGetTagSizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn getKeySizes(self: *const AuthEncMultiImp, outSizes: *[MAX_SIZES]usize) usize {
        var count: usize = 0;
        var tmp: [MAX_SIZES]usize = undefined;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            const n = scTestAuthEncGetKeySizes(imp, &tmp, MAX_SIZES);
            for (tmp[0..n]) |sz| {
                addUniqueSorted(outSizes, &count, sz);
            }
        }
        return count;
    }

    fn setKey(self: *AuthEncMultiImp, pbKey: [*]const u8, cbKey: usize) i32 {
        self.m_nComps = 0;
        for (self.m_imps[0..self.m_nImps]) |imp| {
            if (scTestAuthEncSetKey(imp, pbKey, cbKey) == 0) {
                self.m_comps[self.m_nComps] = imp;
                self.m_nComps += 1;
            }
        }
        return if (self.m_nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn setTotalCbData(self: *AuthEncMultiImp, cbData: usize) void {
        for (self.m_comps[0..self.m_nComps]) |imp| {
            scTestAuthEncSetTotalCbData(imp, cbData);
        }
    }

    fn encrypt(
        self: *AuthEncMultiImp,
        pbNonce: [*]const u8,
        cbNonce: usize,
        pbAuthData: [*]const u8,
        cbAuthData: usize,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
        pbTag: ?[*]u8,
        cbTag: usize,
        flags: u32,
    ) i32 {
        var bufData: [1 << 13]u8 = undefined;
        var bufTag: [32]u8 = undefined;

        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        const resTag = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resTag);

        check(cbData < bufData.len, "Buffer too small");
        check(cbTag < bufTag.len, "Buf too small");
        check(pbTag != null or (flags & AUTHENC_FLAG_PARTIAL) != 0, "?");

        var res: i32 = STATUS_UNSUCCESSFUL;
        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');
            @memset(bufTag[0 .. cbTag + 1], 't');

            const pbSrcLocal: [*]const u8 = if (pbSrc == pbDst) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;

            const status = scTestAuthEncEncrypt(
                imp,
                pbNonce,
                cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrcLocal,
                &bufData,
                cbData,
                if (pbTag == null) null else &bufTag,
                cbTag,
                flags,
            );
            check(bufData[cbData] == 'd', "?");
            check(bufTag[cbTag] == 't', "?");
            if (status >= 0) {
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
                if (pbTag != null) {
                    scTestResultMergeAddAlgImp(resTag, imp, &bufTag, cbTag);
                }
                res = STATUS_SUCCESS;
            }
        }

        if (pbTag) |tagOut| {
            result_merge.scTestResultMergeGetResult(resTag, tagOut, cbTag, 1);
        }
        result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 0);

        return res;
    }

    fn decrypt(
        self: *AuthEncMultiImp,
        pbNonce: [*]const u8,
        cbNonce: usize,
        pbAuthData: [*]const u8,
        cbAuthData: usize,
        pbSrc: [*]const u8,
        pbDst: [*]u8,
        cbData: usize,
        pbTag: ?[*]const u8,
        cbTag: usize,
        flags: u32,
    ) i32 {
        var bufData: [1 << 13]u8 = undefined;
        const resData = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resData);
        const resTagError = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(resTagError);

        var tagError: c_int = 0;

        check(cbData < bufData.len, "Buffer too small");

        for (self.m_comps[0..self.m_nComps]) |imp| {
            @memset(bufData[0 .. cbData + 1], 'd');

            const pbSrcLocal: [*]const u8 = if (pbSrc == pbDst) blk: {
                @memcpy(bufData[0..cbData], pbSrc[0..cbData]);
                break :blk &bufData;
            } else pbSrc;

            const status = scTestAuthEncDecrypt(
                imp,
                pbNonce,
                cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrcLocal,
                &bufData,
                cbData,
                pbTag,
                cbTag,
                flags,
            );
            check(bufData[cbData] == 'd', "?");
            if (status != STATUS_NOT_SUPPORTED) {
                if (pbTag != null) {
                    tagError = if (status < 0) 1 else 0;
                    scTestResultMergeAddAlgImp(resTagError, imp, @ptrCast(&tagError), @sizeOf(c_int));
                }
                scTestResultMergeAddAlgImp(resData, imp, &bufData, cbData);
            }
        }

        if (pbTag != null) {
            result_merge.scTestResultMergeGetResult(resTagError, @ptrCast(&tagError), @sizeOf(c_int), 1);
        }

        if (tagError == 0) {
            result_merge.scTestResultMergeGetResult(resData, pbDst, cbData, 0);
        }

        return if (tagError != 0) STATUS_UNSUCCESSFUL else STATUS_SUCCESS;
    }
};

fn katAuthEncSingle(
    pImp: *AuthEncMultiImp,
    pbKey: [*]const u8,
    cbKey: usize,
    pbNonce: [*]const u8,
    cbNonce: usize,
    pbAuthData: [*]const u8,
    cbAuthData: usize,
    pbPlaintext: [*]const u8,
    cbPlaintext: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pbTag: [*]const u8,
    cbTag: usize,
    line: u64,
) void {
    var bufData: [4096]u8 = undefined;
    var bufTag: [32]u8 = undefined;

    check3(cbPlaintext <= bufData.len, "Buffer too small, need %lld bytes", cbPlaintext);
    check(cbTag <= bufTag.len, "?");
    check3(cbPlaintext == cbCiphertext, "Plaintext/Ciphertext size mismatch in line %lld", line);

    // Do single encryption
    @memset(&bufData, 0);
    @memset(&bufTag, 0);

    check4(pImp.setKey(pbKey, cbKey) >= 0, "Failed to set key size %d in line %lld", cbKey, line);

    _ = pImp.encrypt(pbNonce, cbNonce, pbAuthData, cbAuthData, pbPlaintext, &bufData, cbPlaintext, &bufTag, cbTag, 0);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbCiphertext[0..cbPlaintext]), "Ciphertext mismatch in line %lld", line);
    check3(std.mem.eql(u8, bufTag[0..cbTag], pbTag[0..cbTag]), "Tag mismatch in line %lld", line);

    // Do single decryption
    @memset(&bufData, 0);

    const status = pImp.decrypt(pbNonce, cbNonce, pbAuthData, cbAuthData, pbCiphertext, &bufData, cbPlaintext, &bufTag, cbTag, 0);
    check4(status >= 0, "Decryption signaled error %08x in line %lld", status, line);
    check3(std.mem.eql(u8, bufData[0..cbPlaintext], pbPlaintext[0..cbPlaintext]), "Plaintext mismatch in line %lld", line);
}

fn testAuthEncRandom(
    pImp: *AuthEncMultiImp,
    rrep: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: u64,
    fSupportsPartialEncryption: bool,
) void {
    const rng_mod = @import("rng.zig");
    const bufSize: usize = 1 << 13;
    var buf: [bufSize]u8 = @splat(0);
    var tmp1: [bufSize]u8 = undefined;
    var tmp2: [bufSize]u8 = undefined;
    var tagBuf: [32]u8 = undefined;
    var tagTmp: [32]u8 = undefined;
    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    rng_mod.scTestRngReset(&rng, &pImp.m_algorithmName, pImp.m_algorithmNameLen);

    var keySizes: [MAX_SIZES]usize = undefined;
    const nKeySizes = pImp.getKeySizes(&keySizes);
    var nonceSizes: [MAX_SIZES]usize = undefined;
    const nNonceSizes = pImp.getNonceSizes(&nonceSizes);
    var tagSizes: [MAX_SIZES]usize = undefined;
    const nTagSizes = pImp.getTagSizes(&tagSizes);

    for (0..rrep) |_| {
        const cbKey = keySizes[rng.sizet(nKeySizes)];
        var cbNonce = nonceSizes[rng.sizet(nNonceSizes)];
        const cbTag = tagSizes[rng.sizet(nTagSizes)];

        if (std.mem.eql(u8, pImp.m_algorithmName[0..pImp.m_algorithmNameLen], "AesGcm") and (rng.byte() & 1) != 0) {
            cbNonce = 12;
        }

        check(cbKey <= bufSize and cbNonce <= bufSize and cbTag <= tagBuf.len, "??");

        const keyIdx = rng.sizet(bufSize - cbKey);
        const nonceIdx = rng.sizet(bufSize - cbNonce);
        const tagIdx = rng.sizet(bufSize - cbTag);

        var cbAuthData: usize = 0;
        var authDataIdx: usize = 0;
        rng.randomSubRange(bufSize, &authDataIdx, &cbAuthData);

        var cbData: usize = 0;
        var srcIdx: usize = 0;
        rng.randomSubRange(bufSize, &srcIdx, &cbData);
        const dstIdx = rng.sizet(bufSize - cbData);

        _ = pImp.setKey(buf[keyIdx..].ptr, cbKey);

        _ = pImp.encrypt(
            buf[nonceIdx..].ptr,
            cbNonce,
            buf[authDataIdx..].ptr,
            cbAuthData,
            buf[srcIdx..].ptr,
            &tmp1,
            cbData,
            &tagBuf,
            cbTag,
            0,
        );

        // Encrypt again in-place
        @memcpy(tmp2[0..cbData], buf[srcIdx .. srcIdx + cbData]);
        _ = pImp.encrypt(
            buf[nonceIdx..].ptr,
            cbNonce,
            buf[authDataIdx..].ptr,
            cbAuthData,
            &tmp2,
            &tmp2,
            cbData,
            &tagTmp,
            cbTag,
            0,
        );
        check(std.mem.eql(u8, tmp1[0..cbData], tmp2[0..cbData]), "In-place/Out-of-place encryption data mismatch");
        check(std.mem.eql(u8, tagBuf[0..cbTag], tagTmp[0..cbTag]), "In-place/Out-of-place encryption tag mismatch");

        if (fSupportsPartialEncryption) {
            pImp.setTotalCbData(cbData);
            var idx: usize = 0;
            while (true) {
                var todo = h.g_rng.sizet(cbData - idx + cbData / 10 + 10);
                todo = @min(todo, cbData - idx);
                const last = (todo == cbData - idx);

                _ = pImp.encrypt(
                    buf[nonceIdx..].ptr,
                    cbNonce,
                    buf[authDataIdx..].ptr,
                    cbAuthData,
                    buf[srcIdx + idx ..].ptr,
                    tmp2[idx..].ptr,
                    todo,
                    if (last) &tagTmp else null,
                    cbTag,
                    AUTHENC_FLAG_PARTIAL,
                );
                idx += todo;
                if (idx >= cbData) break;
            }
            check(std.mem.eql(u8, tmp1[0..cbData], tmp2[0..cbData]), "Partial/full encryption data mismatch");
            check(std.mem.eql(u8, tagBuf[0..cbTag], tagTmp[0..cbTag]), "Partial/full encryption tag mismatch");
        }

        @memcpy(tagTmp[0..cbTag], tagBuf[0..cbTag]);
        const errorIdx = rng.sizet(cbTag);
        tagTmp[errorIdx] ^= (@as(u8, 1) << @intCast(rng.byte() & 7));
        var status = pImp.decrypt(
            buf[nonceIdx..].ptr,
            cbNonce,
            buf[authDataIdx..].ptr,
            cbAuthData,
            &tmp1,
            &tmp2,
            cbData,
            &tagTmp,
            cbTag,
            0,
        );
        check3(status < 0, "No decryption error, line %lld", line);

        status = pImp.decrypt(
            buf[nonceIdx..].ptr,
            cbNonce,
            buf[authDataIdx..].ptr,
            cbAuthData,
            &tmp1,
            &tmp2,
            cbData,
            &tagBuf,
            cbTag,
            0,
        );
        check3(status >= 0, "Decryption error, line %lld", line);
        check3(std.mem.eql(u8, tmp2[0..cbData], buf[srcIdx .. srcIdx + cbData]), "Decryption mismatch, line %lld", line);

        // Decrypt again in-place
        @memcpy(tmp2[0..cbData], tmp1[0..cbData]);
        status = pImp.decrypt(
            buf[nonceIdx..].ptr,
            cbNonce,
            buf[authDataIdx..].ptr,
            cbAuthData,
            &tmp2,
            &tmp2,
            cbData,
            &tagBuf,
            cbTag,
            0,
        );
        check3(status >= 0, "In-place decryption error, line %lld", line);
        check3(std.mem.eql(u8, tmp2[0..cbData], buf[srcIdx .. srcIdx + cbData]), "In-place decryption mismatch, line %lld", line);

        if (fSupportsPartialEncryption) {
            pImp.setTotalCbData(cbData);
            var idx: usize = 0;
            while (true) {
                var todo = h.g_rng.sizet(cbData - idx + cbData / 10 + 10);
                todo = @min(todo, cbData - idx);
                const last = (todo == cbData - idx);
                if (last and (h.g_rng.byte() & 1) == 0) {
                    tagBuf[0] ^= 1;
                    status = pImp.decrypt(
                        buf[nonceIdx..].ptr,
                        cbNonce,
                        buf[authDataIdx..].ptr,
                        cbAuthData,
                        tmp1[idx..].ptr,
                        tmp2[idx..].ptr,
                        todo,
                        if (last) &tagBuf else null,
                        cbTag,
                        AUTHENC_FLAG_PARTIAL,
                    );
                    check(status < 0, "No partial decrypt error");
                    tagBuf[0] ^= 1;
                    if (idx > 0) {
                        status = pImp.decrypt(
                            buf[nonceIdx..].ptr,
                            cbNonce,
                            buf[authDataIdx..].ptr,
                            cbAuthData,
                            &tmp1,
                            &tmp2,
                            idx,
                            null,
                            cbTag,
                            AUTHENC_FLAG_PARTIAL,
                        );
                    }
                }
                status = pImp.decrypt(
                    buf[nonceIdx..].ptr,
                    cbNonce,
                    buf[authDataIdx..].ptr,
                    cbAuthData,
                    tmp1[idx..].ptr,
                    tmp2[idx..].ptr,
                    todo,
                    if (last) &tagBuf else null,
                    cbTag,
                    AUTHENC_FLAG_PARTIAL,
                );
                check(status >= 0, "Decrypt error");
                check(std.mem.eql(u8, tmp2[idx .. idx + todo], buf[srcIdx + idx .. srcIdx + idx + todo]), "Partial decryption mismatch");
                idx += todo;
                if (idx >= cbData) break;
            }
            check3(std.mem.eql(u8, tmp2[0..cbData], buf[srcIdx .. srcIdx + cbData]), "Decryption mismatch, line %lld", line);
        }
        @memcpy(buf[dstIdx .. dstIdx + cbData], tmp1[0..cbData]);
        @memcpy(buf[tagIdx .. tagIdx + cbTag], tagBuf[0..cbTag]);
    }

    @memset(&tagBuf, 0);
    const blockLen = tagSizes[nTagSizes - 1];

    for (0..bufSize) |i| {
        tagBuf[i % blockLen] ^= buf[i];
    }

    check3(cbResult == blockLen, "Result size is wrong in line %lld", line);
    if (!std.mem.eql(u8, tagBuf[0..blockLen], pbResult[0..blockLen])) {
        scTestKatReportWrongData(pImp.algNameZ(), "Random test outcome", pbResult, cbResult, &tagBuf, cbResult, @intCast(line));
        pImp.m_nErrorKatFailure += 1;
    }
}

fn testAuthEncKats() void {
    const pKatAuthEnc = getCustomResource("kat_authenc.dat", "KAT_AUTHENC");
    if (pKatAuthEnc == null) return;
    defer scTestKatDestroy(pKatAuthEnc.?);

    const katItem = scTestKatItemCreate().?;
    defer scTestKatItemDestroy(katItem);

    var line: u64 = 0;
    var optMultiImp: ?AuthEncMultiImp = null;
    defer if (optMultiImp) |*imp| imp.deinit();

    var skipData: bool = true;
    var sep: [*:0]const u8 = "    ";
    var doneAnything: bool = false;

    while (true) {
        scTestKatGetNextItem(pKatAuthEnc.?, katItem);
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
            optMultiImp = AuthEncMultiImp.init(catSlice);
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
                const katNonce = KatBuf.parse(katItem, "nonce");
                defer katNonce.deinit();
                const katAuthData = KatBuf.parse(katItem, "authdata");
                defer katAuthData.deinit();
                const katPlaintext = KatBuf.parse(katItem, "plaintext");
                defer katPlaintext.deinit();
                const katCiphertext = KatBuf.parse(katItem, "ciphertext");
                defer katCiphertext.deinit();
                const katTag = KatBuf.parse(katItem, "tag");
                defer katTag.deinit();

                katAuthEncSingle(
                    pImp,
                    katKey.ptr,
                    katKey.len,
                    katNonce.ptr,
                    katNonce.len,
                    katAuthData.ptr,
                    katAuthData.len,
                    katPlaintext.ptr,
                    katPlaintext.len,
                    katCiphertext.ptr,
                    katCiphertext.len,
                    katTag.ptr,
                    katTag.len,
                    line,
                );
            } else if (scTestKatIsFieldPresent(katItem, "rnd") != 0) {
                check3(scTestKatItemDataCount(katItem) == 3, "Wrong # items in RND record ending at line %lld", line);
                const rrep: usize = @intCast(scTestKatParseInteger(katItem, "rrep"));
                const katRnd = KatBuf.parse(katItem, "rnd");
                defer katRnd.deinit();
                const fSupportsPartialEncryption = scTestKatParseInteger(katItem, "partial") != 0;
                testAuthEncRandom(pImp, rrep, katRnd.ptr, katRnd.len, line, fSupportsPartialEncryption);
            } else {
                h.fatal("Unknown data record ending at line {d}", .{line});
            }
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

extern const SymCryptAesBlockCipher: types.PCSYMCRYPT_BLOCKCIPHER;

pub export fn testSessionRandom() callconv(.c) void {
    const rng_mod = @import("rng.zig");
    var rng: rng_mod.Rng = undefined;
    rng_mod.scTestRngInit(&rng);
    defer rng_mod.scTestRngDeinit(&rng);

    var scError: types.SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (h.g_useDynamicFunctionsInTestCall != 0) {
        if (sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptGcmExpandKey", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptSessionSenderInit", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptSessionReceiverInit", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptSessionGcmEncrypt", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptGcmEncrypt", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptSessionGcmDecrypt", .function_ptr) == null or
            sc_imp.lookupDynamicSymbol(*const anyopaque, "SymCryptSessionDestroy", .function_ptr) == null)
        {
            print("    skipped\n");
            return;
        }
    }

    var senderSession: types.SYMCRYPT_SESSION = undefined;
    var receiverSession: types.SYMCRYPT_SESSION = undefined;
    const seed: usize = h.g_rng.sizet(std.math.maxInt(usize));

    rng_mod.scTestRngReset(&rng, std.mem.asBytes(&seed).ptr, @sizeOf(usize));

    const senderId: u32 = rng.uint32();
    var key: [32]u8 = @splat(0);
    var nonce: [12]u8 = @splat(0);
    var authData: [16]u8 = @splat(0);
    var sessionPlainText: [128]u8 = @splat(0);
    var testPlainText: [128]u8 = @splat(0);
    var sessionCipherText: [128]u8 = @splat(0);
    var testCipherText: [128]u8 = @splat(0);
    var backupCipherText: [128]u8 = @splat(0);
    var sessionTag: [16]u8 = @splat(0);
    var testTag: [16]u8 = @splat(0);
    var backupTag: [16]u8 = @splat(0);
    var messageNumber: u64 = 0;
    var testMessageNumber: u64 = 0;
    var backupMessageNumber: u64 = 0;
    var gcmExpandedKey: types.SYMCRYPT_GCM_EXPANDED_KEY = undefined;

    for (&key) |*b| b.* = rng.byte();
    for (&authData) |*b| b.* = rng.byte();
    for (&sessionPlainText) |*b| b.* = rng.byte();

    const pAesBlockCipher: types.PCSYMCRYPT_BLOCKCIPHER = sc_imp.lookupSymCryptSymbol(
        types.PCSYMCRYPT_BLOCKCIPHER,
        "SymCryptAesBlockCipher",
        SymCryptAesBlockCipher,
        .data_ptr,
    ).?;

    scError = sc_imp.callSymCrypt(
        "SymCryptGcmExpandKey",
        @TypeOf(&SymCryptGcmExpandKey),
        &SymCryptGcmExpandKey,
        .{ &gcmExpandedKey, pAesBlockCipher, &key, key.len },
    );
    check(scError == .SYMCRYPT_NO_ERROR, "SymCryptGcmExpandKey failed");

    scError = sc_imp.callSymCrypt(
        "SymCryptSessionSenderInit",
        @TypeOf(&SymCryptSessionSenderInit),
        &SymCryptSessionSenderInit,
        .{ &senderSession, senderId, 0 },
    );
    check(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionSenderInit failed");

    scError = sc_imp.callSymCrypt(
        "SymCryptSessionReceiverInit",
        @TypeOf(&SymCryptSessionReceiverInit),
        &SymCryptSessionReceiverInit,
        .{ &receiverSession, senderId, 0 },
    );
    check(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionReceiverInit failed");

    std.mem.writeInt(u32, nonce[0..4], senderId, .big);
    std.mem.writeInt(u64, nonce[4..12], 1, .big);

    scError = sc_imp.callSymCrypt(
        "SymCryptSessionGcmEncrypt",
        @TypeOf(&SymCryptSessionGcmEncrypt),
        &SymCryptSessionGcmEncrypt,
        .{ &senderSession, &gcmExpandedKey, &authData, authData.len, &sessionPlainText, &sessionCipherText, sessionPlainText.len, &sessionTag, sessionTag.len, &messageNumber },
    );
    check3(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionGcmEncrypt failed with 0x%x", @as(u32, @intCast(@backingInt(scError))));

    sc_imp.callSymCrypt(
        "SymCryptGcmEncrypt",
        @TypeOf(&SymCryptGcmEncrypt),
        &SymCryptGcmEncrypt,
        .{ &gcmExpandedKey, &nonce, nonce.len, &authData, authData.len, &sessionPlainText, &testCipherText, sessionPlainText.len, &testTag, testTag.len },
    );
    check(std.mem.eql(u8, &sessionCipherText, &testCipherText), "Session/Non-Session encryption data mismatch");
    check(std.mem.eql(u8, &sessionTag, &testTag), "Session/Non-Session encryption tag mismatch");

    @memcpy(&backupCipherText, &sessionCipherText);
    @memcpy(&backupTag, &sessionTag);
    backupMessageNumber = messageNumber;

    for (0..1024) |i| {
        scError = sc_imp.callSymCrypt(
            "SymCryptSessionGcmEncrypt",
            @TypeOf(&SymCryptSessionGcmEncrypt),
            &SymCryptSessionGcmEncrypt,
            .{ &senderSession, &gcmExpandedKey, &authData, authData.len, &sessionPlainText, &sessionCipherText, sessionPlainText.len, &sessionTag, sessionTag.len, &messageNumber },
        );
        check3(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionGcmEncrypt failed with 0x%x", @as(u32, @intCast(@backingInt(scError))));
        check(messageNumber == @as(u64, i) + 2, "SymCryptSessionGcmEncrypt returned unexpected messageNumber");

        std.mem.writeInt(u64, nonce[4..12], messageNumber, .big);

        sc_imp.callSymCrypt(
            "SymCryptGcmEncrypt",
            @TypeOf(&SymCryptGcmEncrypt),
            &SymCryptGcmEncrypt,
            .{ &gcmExpandedKey, &nonce, nonce.len, &authData, authData.len, &sessionPlainText, &testCipherText, sessionPlainText.len, &testTag, testTag.len },
        );
        check(std.mem.eql(u8, &sessionCipherText, &testCipherText), "Session/Non-Session encryption data mismatch");
        check(std.mem.eql(u8, &sessionTag, &testTag), "Session/Non-Session encryption tag mismatch");

        switch (rng.byte() & 3) {
            0 => {
                scError = sc_imp.callSymCrypt(
                    "SymCryptSessionGcmDecrypt",
                    @TypeOf(&SymCryptSessionGcmDecrypt),
                    &SymCryptSessionGcmDecrypt,
                    .{ &receiverSession, messageNumber, &gcmExpandedKey, &authData, authData.len, &sessionCipherText, &testPlainText, sessionCipherText.len, &sessionTag, sessionTag.len },
                );
                check3(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionGcmDecrypt failed with 0x%x", @as(u32, @intCast(@backingInt(scError))));
                check(std.mem.eql(u8, &sessionPlainText, &testPlainText), "Plaintext mismatch in SymCryptSessionGcm");

                testMessageNumber = receiverSession.replayState.messageNumber;

                scError = sc_imp.callSymCrypt(
                    "SymCryptSessionGcmDecrypt",
                    @TypeOf(&SymCryptSessionGcmDecrypt),
                    &SymCryptSessionGcmDecrypt,
                    .{ &receiverSession, messageNumber + rng.sizetRange(1, 512), &gcmExpandedKey, &authData, authData.len, &sessionCipherText, &testPlainText, sessionCipherText.len, &sessionTag, sessionTag.len },
                );
                check3(
                    scError == .SYMCRYPT_AUTHENTICATION_FAILURE,
                    "SymCryptSessionGcmDecrypt did not return SYMCRYPT_AUTHENTICATION_FAILURE but 0x%x",
                    @as(u32, @intCast(@backingInt(scError))),
                );
                check4(
                    receiverSession.replayState.messageNumber == testMessageNumber,
                    "Unexpected value for receiverSession messageNumber after failed decryption. Expected %d but is %d",
                    testMessageNumber,
                    receiverSession.replayState.messageNumber,
                );
            },
            1 => {
                scError = sc_imp.callSymCrypt(
                    "SymCryptSessionGcmDecrypt",
                    @TypeOf(&SymCryptSessionGcmDecrypt),
                    &SymCryptSessionGcmDecrypt,
                    .{ &receiverSession, backupMessageNumber, &gcmExpandedKey, &authData, authData.len, &backupCipherText, &testPlainText, backupCipherText.len, &backupTag, backupTag.len },
                );
                if (backupMessageNumber > receiverSession.replayState.messageNumber -| 64) {
                    check3(scError == .SYMCRYPT_NO_ERROR, "SymCryptSessionGcmDecrypt failed with 0x%x", @as(u32, @intCast(@backingInt(scError))));
                    check(std.mem.eql(u8, &sessionPlainText, &testPlainText), "Plaintext mismatch in SymCryptSessionGcm");
                } else {
                    check3(
                        scError == .SYMCRYPT_SESSION_REPLAY_FAILURE,
                        "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x",
                        @as(u32, @intCast(@backingInt(scError))),
                    );
                }

                scError = sc_imp.callSymCrypt(
                    "SymCryptSessionGcmDecrypt",
                    @TypeOf(&SymCryptSessionGcmDecrypt),
                    &SymCryptSessionGcmDecrypt,
                    .{ &receiverSession, backupMessageNumber, &gcmExpandedKey, &authData, authData.len, &backupCipherText, &testPlainText, backupCipherText.len, &backupTag, backupTag.len },
                );
                check3(
                    scError == .SYMCRYPT_SESSION_REPLAY_FAILURE,
                    "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x",
                    @as(u32, @intCast(@backingInt(scError))),
                );
                // Intentional fallthrough to case 2
                @memcpy(&backupCipherText, &sessionCipherText);
                @memcpy(&backupTag, &sessionTag);
                backupMessageNumber = messageNumber;
            },
            2 => {
                @memcpy(&backupCipherText, &sessionCipherText);
                @memcpy(&backupTag, &sessionTag);
                backupMessageNumber = messageNumber;
            },
            3 => {
                if (receiverSession.replayState.messageNumber > 64) {
                    scError = sc_imp.callSymCrypt(
                        "SymCryptSessionGcmDecrypt",
                        @TypeOf(&SymCryptSessionGcmDecrypt),
                        &SymCryptSessionGcmDecrypt,
                        .{ &receiverSession, receiverSession.replayState.messageNumber - 64, &gcmExpandedKey, &authData, authData.len, &backupCipherText, &testPlainText, backupCipherText.len, &backupTag, backupTag.len },
                    );
                    check3(
                        scError == .SYMCRYPT_SESSION_REPLAY_FAILURE,
                        "SymCryptSessionGcmDecrypt did not return SYMCRYPT_SESSION_REPLAY_FAILURE but 0x%x",
                        @as(u32, @intCast(@backingInt(scError))),
                    );
                }
            },
            else => {},
        }
    }

    sc_imp.callSymCrypt(
        "SymCryptSessionDestroy",
        @TypeOf(&SymCryptSessionDestroy),
        &SymCryptSessionDestroy,
        .{&senderSession},
    );
    sc_imp.callSymCrypt(
        "SymCryptSessionDestroy",
        @TypeOf(&SymCryptSessionDestroy),
        &SymCryptSessionDestroy,
        .{&receiverSession},
    );
}

pub export fn testSession() callconv(.c) void {
    testSessionRandom();
}

pub export fn testAuthEncAlgorithms() callconv(.c) void {
    testAuthEncKats();

    print("    testSessionRandom static\n");
    testSessionRandom();

    if (h.g_dynamicSymCryptModuleHandle != null) {
        print("    testSessionRandom dynamic\n");
        h.g_useDynamicFunctionsInTestCall = 1;
        testSessionRandom();
        h.g_useDynamicFunctionsInTestCall = 0;
    }
}

pub export fn testAuthEnc() callconv(.c) void {
    testAuthEncAlgorithms();
}
