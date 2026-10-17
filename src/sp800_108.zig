//
// sp800_108.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement the SP800-108 CTR KDF function
// and its HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 self-tests.
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

extern fn SymCryptInjectError(pbBuf: PBYTE, cbBuf: SIZE_T) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// SP800-108 Key Structure (matching inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_SP800_108_EXPANDED_KEY = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_SP800_108_EXPANDED_KEY = *SYMCRYPT_SP800_108_EXPANDED_KEY;
pub const PCSYMCRYPT_SP800_108_EXPANDED_KEY = *const SYMCRYPT_SP800_108_EXPANDED_KEY;

// ==============================================================================================
// SP800-108 Implementation (port of lib/sp800_108.c)
// ==============================================================================================

pub export fn SymCryptSp800_108Derive(
    pExpandedKey: PCSYMCRYPT_SP800_108_EXPANDED_KEY,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var macState: SYMCRYPT_MAC_STATE = undefined;
    var iBlock: UINT32 = undefined;
    var bytes: SIZE_T = undefined;
    const blockSize: SIZE_T = pExpandedKey.macAlg.resultSize;
    var bytesRemaining: SIZE_T = cbResult;
    var buf: [4]BYTE = undefined;
    var rbBlockResult: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.ASSERT(blockSize <= SYMCRYPT_MAC_MAX_RESULT_SIZE and bytesRemaining > 0);

    if (cbResult > types.UINT32_MAX / 8) {
        // SP800-108 requires the output size in bits to be encoded in a 32-bit value.
        // cbResults that are too large are impossible.
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const initFunc: PSYMCRYPT_MAC_INIT = pExpandedKey.macAlg.initFunc.?;
    const appendFunc: MacAppendFn = @ptrCast(pExpandedKey.macAlg.appendFunc.?);
    const resultFunc: PSYMCRYPT_MAC_RESULT = pExpandedKey.macAlg.resultFunc.?;

    var pbCurr: PBYTE = pbResult;

    iBlock = 0;
    while (bytesRemaining > 0) {
        iBlock += 1;
        initFunc(&macState, &pExpandedKey.macKey);

        macros.STORE_MSBFIRST32(&buf, iBlock);
        appendFunc(&macState, &buf, 4); // block count encoded in 4 bytes

        if (cbLabel != types.SIZE_T_MAX) {
            //
            // cbLabel == -1 signals a generic input in the Context field.
            //
            appendFunc(&macState, pbLabel, cbLabel); // label

            buf[0] = 0;
            appendFunc(&macState, &buf, 1); // zero byte
        }

        appendFunc(&macState, pbContext, cbContext); // Context

        macros.STORE_MSBFIRST32(&buf, 8 * @as(UINT32, @intCast(cbResult)));
        appendFunc(&macState, &buf, 4); // output length, in bits

        resultFunc(&macState, &rbBlockResult);

        bytes = @min(bytesRemaining, blockSize);
        @memcpy(pbCurr[0..bytes], rbBlockResult[0..bytes]);
        pbCurr += bytes;
        bytesRemaining -= bytes;
    }

    hmac.SymCryptWipeKnownSize(&rbBlockResult, @sizeOf(@TypeOf(rbBlockResult)));
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSp800_108ExpandKey(
    pExpandedKey: PSYMCRYPT_SP800_108_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(@TypeOf(pExpandedKey.macKey)));

    pExpandedKey.macAlg = macAlgorithm;
    const expandKeyFunc: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
    return expandKeyFunc(&pExpandedKey.macKey, pbKey, cbKey);
}

pub export fn SymCryptSp800_108(
    macAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var key: SYMCRYPT_SP800_108_EXPANDED_KEY = undefined;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(SYMCRYPT_SP800_108_EXPANDED_KEY));

    scError = SymCryptSp800_108ExpandKey(&key, macAlgorithm, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptSp800_108Derive(&key, pbLabel, cbLabel, pbContext, cbContext, pbResult, cbResult);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

// ==============================================================================================
// SP800-108 Self-Tests (port of lib/sp800_108_hmacsha1.c, lib/sp800_108_hmacsha256.c,
// and lib/sp800_108_hmacsha512.c)
// ==============================================================================================

const sp800_108_sha1Answer: [8]BYTE = .{
    0xcf, 0x4b, 0xfe, 0x4f, 0x85, 0xa1, 0x0b, 0xad,
};

pub export fn SymCryptSp800_108_HmacSha1SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [sp800_108_sha1Answer.len]BYTE = undefined;

    _ = SymCryptSp800_108(
        hmac.SymCryptHmacSha1Algorithm,
        &selftest.SymCryptTestKey32,
        8, // key
        "Label",
        5, // label
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16, // context
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &sp800_108_sha1Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("8108"));
    }
}

const sp800_108_sha256Answer: [8]BYTE = .{
    0x00, 0x26, 0x4b, 0xbb, 0x14, 0x97, 0x40, 0x54,
};

pub export fn SymCryptSp800_108_HmacSha256SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [sp800_108_sha256Answer.len]BYTE = undefined;

    _ = SymCryptSp800_108(
        hmac.SymCryptHmacSha256Algorithm,
        &selftest.SymCryptTestKey32,
        8, // key
        "Label",
        5, // label
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16, // context
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &sp800_108_sha256Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("8108"));
    }
}

const sp800_108_sha384Answer: [8]BYTE = .{
    0xc7, 0x10, 0x27, 0x87, 0xd8, 0x96, 0xbc, 0x89,
};

pub export fn SymCryptSp800_108_HmacSha384SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [sp800_108_sha384Answer.len]BYTE = undefined;

    _ = SymCryptSp800_108(
        hmac.SymCryptHmacSha384Algorithm,
        &selftest.SymCryptTestKey32,
        8, // key
        "Label",
        5, // label
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16, // context
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &sp800_108_sha384Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("8108"));
    }
}

const sp800_108_sha512Answer: [8]BYTE = .{
    0xdb, 0x3a, 0x18, 0xd9, 0x6c, 0x4a, 0xd4, 0x1e,
};

pub export fn SymCryptSp800_108_HmacSha512SelfTest() callconv(SYMCRYPT_CALL) void {
    var res: [sp800_108_sha512Answer.len]BYTE = undefined;

    _ = SymCryptSp800_108(
        hmac.SymCryptHmacSha512Algorithm,
        &selftest.SymCryptTestKey32,
        8, // key
        "Label",
        5, // label
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16, // context
        &res,
        res.len,
    );

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &sp800_108_sha512Answer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("8108"));
    }
}

comptime {
    std.debug.assert(@alignOf(SYMCRYPT_SP800_108_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
}
