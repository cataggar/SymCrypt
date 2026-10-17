//
// pbkdf2.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement the PBKDF2 function
// and its HMAC-SHA1 and HMAC-SHA256 self-tests.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const selftest = @import("selftest.zig");
const hmac = @import("hmac.zig");
const hkdf = @import("hkdf.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const PSYMCRYPT_MAC_INIT = types.PSYMCRYPT_MAC_INIT;
const PSYMCRYPT_MAC_RESULT = types.PSYMCRYPT_MAC_RESULT;

const SYMCRYPT_MAC_MAX_RESULT_SIZE = hkdf.SYMCRYPT_MAC_MAX_RESULT_SIZE;
const SYMCRYPT_MAC_STATE = hkdf.SYMCRYPT_MAC_STATE;
const SYMCRYPT_MAC_EXPANDED_KEY = hkdf.SYMCRYPT_MAC_EXPANDED_KEY;
const MacExpandKeyFn = hkdf.MacExpandKeyFn;
const MacAppendFn = hkdf.MacAppendFn;

extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbBuf: PBYTE, cbBuf: SIZE_T) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// PBKDF2 Key Structure (matching inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_PBKDF2_EXPANDED_KEY = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_PBKDF2_EXPANDED_KEY = *SYMCRYPT_PBKDF2_EXPANDED_KEY;
pub const PCSYMCRYPT_PBKDF2_EXPANDED_KEY = *const SYMCRYPT_PBKDF2_EXPANDED_KEY;

// ==============================================================================================
// PBKDF2 Implementation (port of lib/pbkdf2.c)
// ==============================================================================================

pub export fn SymCryptPbkdf2Derive(
    pExpandedKey: PCSYMCRYPT_PBKDF2_EXPANDED_KEY,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    iterationCnt: UINT64,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var macState: SYMCRYPT_MAC_STATE = undefined;
    var iBlock: UINT32 = undefined;
    var bytes: SIZE_T = undefined;
    const blockSize: SIZE_T = pExpandedKey.macAlg.resultSize;
    var iterations: UINT64 = undefined;
    var rbBlockResult: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var rbWorkBuffer: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.ASSERT(blockSize <= SYMCRYPT_MAC_MAX_RESULT_SIZE and cbResult > 0);

    if (iterationCnt == 0) {
        return .SYMCRYPT_WRONG_ITERATION_COUNT;
    }

    const initFunc: PSYMCRYPT_MAC_INIT = pExpandedKey.macAlg.initFunc.?;
    const appendFunc: MacAppendFn = @ptrCast(pExpandedKey.macAlg.appendFunc.?);
    const resultFunc: PSYMCRYPT_MAC_RESULT = pExpandedKey.macAlg.resultFunc.?;

    var pbCurr: PBYTE = pbResult;
    var cbRem: SIZE_T = cbResult;

    iBlock = 0;
    while (cbRem > 0) {
        iBlock += 1;
        macros.STORE_MSBFIRST32(&rbBlockResult, iBlock); // use result buf as temp

        initFunc(&macState, &pExpandedKey.macKey);
        appendFunc(&macState, pbSalt, cbSalt);
        appendFunc(&macState, &rbBlockResult, 4); // block count encoded in 4 bytes
        resultFunc(&macState, &rbWorkBuffer);

        @memcpy(rbBlockResult[0..blockSize], rbWorkBuffer[0..blockSize]);
        iterations = 1;
        while (iterations < iterationCnt) : (iterations += 1) {
            initFunc(&macState, &pExpandedKey.macKey);
            appendFunc(&macState, &rbWorkBuffer, blockSize);
            resultFunc(&macState, &rbWorkBuffer);
            SymCryptXorBytes(&rbWorkBuffer, &rbBlockResult, &rbBlockResult, blockSize);
        }

        bytes = @min(cbRem, blockSize);
        @memcpy(pbCurr[0..bytes], rbBlockResult[0..bytes]);
        pbCurr += bytes;
        cbRem -= bytes;
    }

    hmac.SymCryptWipeKnownSize(&rbWorkBuffer, @sizeOf(@TypeOf(rbWorkBuffer)));
    hmac.SymCryptWipeKnownSize(&rbBlockResult, @sizeOf(@TypeOf(rbBlockResult)));
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptPbkdf2ExpandKey(
    pExpandedKey: PSYMCRYPT_PBKDF2_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(@TypeOf(pExpandedKey.macKey)));

    pExpandedKey.macAlg = macAlgorithm;
    const expandKeyFunc: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
    return expandKeyFunc(&pExpandedKey.macKey, pbKey, cbKey);
}

pub export fn SymCryptPbkdf2(
    macAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    iterationCnt: UINT64,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var key: SYMCRYPT_PBKDF2_EXPANDED_KEY = undefined;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(SYMCRYPT_PBKDF2_EXPANDED_KEY));

    scError = SymCryptPbkdf2ExpandKey(&key, macAlgorithm, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptPbkdf2Derive(&key, pbSalt, cbSalt, iterationCnt, pbResult, cbResult);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

// ==============================================================================================
// PBKDF2 Self-Tests (port of lib/pbkdf2_hmacsha1.c and lib/pbkdf2_hmacsha256.c)
// ==============================================================================================

const pbkdf2_IterationCnt: UINT64 = 5;

const pbkdf2_sha1Answer: [8]BYTE = .{
    0xef, 0xa9, 0xbf, 0xea, 0xa3, 0x4d, 0x70, 0x64,
};

pub export fn SymCryptPbkdf2_HmacSha1SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [pbkdf2_sha1Answer.len]BYTE = undefined;

    _ = SymCryptPbkdf2(
        hmac.SymCryptHmacSha1Algorithm,
        &selftest.SymCryptTestKey32,
        8,
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16,
        pbkdf2_IterationCnt,
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &pbkdf2_sha1Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("Pbk2"));
    }
}

const pbkdf2_sha256Answer: [8]BYTE = .{
    0x05, 0x98, 0x1e, 0x89, 0x48, 0xd2, 0x84, 0x61,
};

pub export fn SymCryptPbkdf2_HmacSha256SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [pbkdf2_sha256Answer.len]BYTE = undefined;

    _ = SymCryptPbkdf2(
        hmac.SymCryptHmacSha256Algorithm,
        &selftest.SymCryptTestKey32,
        8,
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16,
        pbkdf2_IterationCnt,
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &pbkdf2_sha256Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("Pbk2"));
    }
}

comptime {
    std.debug.assert(@alignOf(SYMCRYPT_PBKDF2_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
}
