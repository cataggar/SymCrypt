//
// hkdf.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement the HKDF
// function for the TLS protocol 1.3. It is used in
// the protocol's key derivation function.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const selftest = @import("selftest.zig");
const hmac = @import("hmac.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const PSYMCRYPT_MAC_INIT = types.PSYMCRYPT_MAC_INIT;
const PSYMCRYPT_MAC_RESULT = types.PSYMCRYPT_MAC_RESULT;

pub const MacExpandKeyFn = *const fn (pExpandedKey: PVOID, pbKey: ?PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub const MacAppendFn = *const fn (pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptInjectError(pbBuf: PBYTE, cbBuf: SIZE_T) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// MAC Union & HKDF Key Structures (matching inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_MAC_MAX_RESULT_SIZE: usize = hmac.SYMCRYPT_HMAC_SHA512_RESULT_SIZE;

pub const SYMCRYPT_AES_EXPANDED_KEY = extern struct {
    RoundKey: [29][4][4]BYTE align(SYMCRYPT_ALIGN_VALUE),
    lastEncRoundKey: ?*[4][4]BYTE,
    lastDecRoundKey: ?*[4][4]BYTE,
    magic: SIZE_T,
};

pub const SYMCRYPT_AES_CMAC_EXPANDED_KEY = extern struct {
    aesKey: SYMCRYPT_AES_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
    K1: [16]BYTE,
    K2: [16]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_AES_CMAC_EXPANDED_KEY = *SYMCRYPT_AES_CMAC_EXPANDED_KEY;
pub const PCSYMCRYPT_AES_CMAC_EXPANDED_KEY = *const SYMCRYPT_AES_CMAC_EXPANDED_KEY;

pub const SYMCRYPT_AES_CMAC_STATE = extern struct {
    chain: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    buf: [16]BYTE,
    bytesInBuf: SIZE_T,
    pKey: ?PCSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    magic: SIZE_T,
};
pub const PSYMCRYPT_AES_CMAC_STATE = *SYMCRYPT_AES_CMAC_STATE;
pub const PCSYMCRYPT_AES_CMAC_STATE = *const SYMCRYPT_AES_CMAC_STATE;

pub const SYMCRYPT_KMAC128_EXPANDED_KEY = extern struct {
    ks: hmac.SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_KMAC128_STATE = extern struct {
    ks: hmac.SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_KMAC256_EXPANDED_KEY = extern struct {
    ks: hmac.SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_KMAC256_STATE = extern struct {
    ks: hmac.SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_MAC_STATE = extern union {
    md5State: hmac.SYMCRYPT_HMAC_MD5_STATE,
    sha1State: hmac.SYMCRYPT_HMAC_SHA1_STATE,
    sha224State: hmac.SYMCRYPT_HMAC_SHA224_STATE,
    sha256State: hmac.SYMCRYPT_HMAC_SHA256_STATE,
    sha384State: hmac.SYMCRYPT_HMAC_SHA384_STATE,
    sha512State: hmac.SYMCRYPT_HMAC_SHA512_STATE,
    sha512_224State: hmac.SYMCRYPT_HMAC_SHA512_224_STATE,
    sha512_256State: hmac.SYMCRYPT_HMAC_SHA512_256_STATE,
    sha3_224State: hmac.SYMCRYPT_HMAC_SHA3_224_STATE,
    sha3_256State: hmac.SYMCRYPT_HMAC_SHA3_256_STATE,
    sha3_384State: hmac.SYMCRYPT_HMAC_SHA3_384_STATE,
    sha3_512State: hmac.SYMCRYPT_HMAC_SHA3_512_STATE,
    aescmacState: SYMCRYPT_AES_CMAC_STATE,
    kmac128State: SYMCRYPT_KMAC128_STATE,
    kmac256State: SYMCRYPT_KMAC256_STATE,
};
pub const PSYMCRYPT_MAC_STATE = *SYMCRYPT_MAC_STATE;
pub const PCSYMCRYPT_MAC_STATE = *const SYMCRYPT_MAC_STATE;

pub const SYMCRYPT_MAC_EXPANDED_KEY = extern union {
    md5Key: hmac.SYMCRYPT_HMAC_MD5_EXPANDED_KEY,
    sha1Key: hmac.SYMCRYPT_HMAC_SHA1_EXPANDED_KEY,
    sha224Key: hmac.SYMCRYPT_HMAC_SHA224_EXPANDED_KEY,
    sha256Key: hmac.SYMCRYPT_HMAC_SHA256_EXPANDED_KEY,
    sha384Key: hmac.SYMCRYPT_HMAC_SHA384_EXPANDED_KEY,
    sha512Key: hmac.SYMCRYPT_HMAC_SHA512_EXPANDED_KEY,
    sha512_224Key: hmac.SYMCRYPT_HMAC_SHA512_224_EXPANDED_KEY,
    sha512_256Key: hmac.SYMCRYPT_HMAC_SHA512_256_EXPANDED_KEY,
    sha3_224Key: hmac.SYMCRYPT_HMAC_SHA3_224_EXPANDED_KEY,
    sha3_256Key: hmac.SYMCRYPT_HMAC_SHA3_256_EXPANDED_KEY,
    sha3_384Key: hmac.SYMCRYPT_HMAC_SHA3_384_EXPANDED_KEY,
    sha3_512Key: hmac.SYMCRYPT_HMAC_SHA3_512_EXPANDED_KEY,
    aescmacKey: SYMCRYPT_AES_CMAC_EXPANDED_KEY,
    kmac128Key: SYMCRYPT_KMAC128_EXPANDED_KEY,
    kmac256Key: SYMCRYPT_KMAC256_EXPANDED_KEY,
};
pub const PSYMCRYPT_MAC_EXPANDED_KEY = *SYMCRYPT_MAC_EXPANDED_KEY;
pub const PCSYMCRYPT_MAC_EXPANDED_KEY = *const SYMCRYPT_MAC_EXPANDED_KEY;

pub const SYMCRYPT_HKDF_EXPANDED_KEY = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_HKDF_EXPANDED_KEY = *SYMCRYPT_HKDF_EXPANDED_KEY;
pub const PCSYMCRYPT_HKDF_EXPANDED_KEY = *const SYMCRYPT_HKDF_EXPANDED_KEY;

// ==============================================================================================
// HKDF Implementation (port of lib/hkdf.c)
// ==============================================================================================

pub export fn SymCryptHkdfExpandKey(
    pExpandedKey: PSYMCRYPT_HKDF_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var rbPrk: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = @splat(0);
    defer hmac.SymCryptWipeKnownSize(&rbPrk, @sizeOf(@TypeOf(rbPrk)));

    macros.ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(@TypeOf(pExpandedKey.macKey)));

    scError = SymCryptHkdfExtractPrk(macAlgorithm, pbIkm, cbIkm, pbSalt, cbSalt, &rbPrk, macAlgorithm.resultSize);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptHkdfPrkExpandKey(pExpandedKey, macAlgorithm, &rbPrk, macAlgorithm.resultSize);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptHkdfExtractPrk(
    macAlgorithm: PCSYMCRYPT_MAC,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    pbPrk: PBYTE,
    cbPrk: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var state: SYMCRYPT_MAC_STATE = undefined;
    var key: SYMCRYPT_MAC_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(SYMCRYPT_MAC_EXPANDED_KEY));

    // Ensure that pbPrk is the correct size
    if (cbPrk != macAlgorithm.resultSize) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    const expandKeyFunc: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
    const initFunc: PSYMCRYPT_MAC_INIT = macAlgorithm.initFunc.?;
    const appendFunc: MacAppendFn = @ptrCast(macAlgorithm.appendFunc.?);
    const resultFunc: PSYMCRYPT_MAC_RESULT = macAlgorithm.resultFunc.?;

    // Calculation of PRK = HMAC-Hash(salt, IKM)
    scError = expandKeyFunc(&key, pbSalt, cbSalt);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    initFunc(&state, &key);
    appendFunc(&state, pbIkm, cbIkm);
    resultFunc(&state, pbPrk);

    return scError;
}

pub export fn SymCryptHkdfPrkExpandKey(
    pExpandedKey: PSYMCRYPT_HKDF_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbPrk: ?PCBYTE,
    cbPrk: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(@TypeOf(pExpandedKey.macKey)));

    pExpandedKey.macAlg = macAlgorithm;
    const expandKeyFunc: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
    return expandKeyFunc(&pExpandedKey.macKey, pbPrk, cbPrk);
}

pub export fn SymCryptHkdfDerive(
    pExpandedKey: PCSYMCRYPT_HKDF_EXPANDED_KEY,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var state: SYMCRYPT_MAC_STATE = undefined;
    const pMacAlgorithm: PCSYMCRYPT_MAC = pExpandedKey.macAlg;
    var rbPartialResult: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    defer hmac.SymCryptWipeKnownSize(&rbPartialResult, @sizeOf(@TypeOf(rbPartialResult)));

    const cbMacResultSize: SIZE_T = pMacAlgorithm.resultSize;
    var cntr: BYTE = 0x01;

    // Check that cbResult <= 255*HashLen
    if (cbResult > 0xff * cbMacResultSize) {
        scError = .SYMCRYPT_WRONG_DATA_SIZE;
        return scError;
    }

    const initFunc: PSYMCRYPT_MAC_INIT = pMacAlgorithm.initFunc.?;
    const appendFunc: MacAppendFn = @ptrCast(pMacAlgorithm.appendFunc.?);
    const resultFunc: PSYMCRYPT_MAC_RESULT = pMacAlgorithm.resultFunc.?;

    // In the first iteration T(0) is the empty string
    // Calculate T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
    initFunc(&state, pExpandedKey);
    appendFunc(&state, pbInfo, cbInfo);
    appendFunc(&state, @ptrCast(&cntr), @sizeOf(BYTE));
    resultFunc(&state, &rbPartialResult);

    // Store the result in the output buffer
    const firstCopy = @min(cbResult, cbMacResultSize);
    if (firstCopy > 0) {
        @memcpy(pbResult.?[0..firstCopy], rbPartialResult[0..firstCopy]);
    }
    if (cbResult <= cbMacResultSize) {
        return scError;
    }

    // Update counters
    cntr += 1;
    var pbCurr: PBYTE = pbResult.? + cbMacResultSize;
    var cbRem: SIZE_T = cbResult - cbMacResultSize;

    while (cbRem > 0) {
        // Calculate T(i) = HMAC-Hash(PRK, T(i-1) | info | 0xi)
        initFunc(&state, pExpandedKey);
        appendFunc(&state, &rbPartialResult, cbMacResultSize);
        appendFunc(&state, pbInfo, cbInfo);
        appendFunc(&state, @ptrCast(&cntr), @sizeOf(BYTE));
        resultFunc(&state, &rbPartialResult);

        // Store the result in the output buffer
        const toCopy = @min(cbRem, cbMacResultSize);
        @memcpy(pbCurr[0..toCopy], rbPartialResult[0..toCopy]);
        if (cbRem <= cbMacResultSize) {
            return scError;
        }

        // Update counters
        cntr += 1;
        pbCurr += cbMacResultSize;
        cbRem -= cbMacResultSize;
    }

    return scError;
}

pub export fn SymCryptHkdf(
    macAlgorithm: PCSYMCRYPT_MAC,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var key: SYMCRYPT_HKDF_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(SYMCRYPT_HKDF_EXPANDED_KEY));

    // Create the expanded key
    scError = SymCryptHkdfExpandKey(
        &key,
        macAlgorithm,
        pbIkm,
        cbIkm,
        pbSalt,
        cbSalt,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Derive the key
    scError = SymCryptHkdfDerive(
        &key,
        pbInfo,
        cbInfo,
        pbResult,
        cbResult,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

// ==============================================================================================
// HKDF Self-Test (port of lib/hkdf_selftest.c)
// ==============================================================================================

const pbResultHkdfSha512: [13]BYTE = .{
    0xdf, 0xcd, 0x33, 0xf4, 0x16, 0x4b, 0x5a, 0x66, 0x61, 0x66, 0x85, 0xff, 0xd3,
};

pub export fn SymCryptHkdfSelfTest() callconv(SYMCRYPT_CALL) void {
    var rbResult: [pbResultHkdfSha512.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptHkdf(
        hmac.SymCryptHmacSha512Algorithm,
        &selftest.SymCryptTestKey32,
        15,
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        16,
        &selftest.SymCryptTestMsg3,
        3,
        &rbResult,
        pbResultHkdfSha512.len,
    );

    SymCryptInjectError(&rbResult, pbResultHkdfSha512.len);

    if (!std.mem.eql(u8, &rbResult, &pbResultHkdfSha512)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("hkdf"));
    }
}

comptime {
    std.debug.assert(@alignOf(SYMCRYPT_HKDF_EXPANDED_KEY) == SYMCRYPT_ALIGN_VALUE);
}
