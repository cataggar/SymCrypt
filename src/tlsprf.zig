//
// tlsprf.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Routines implementing the TLS 1.0/1.1 and TLS 1.2 PRF key derivation functions
// and their self-tests, ported from lib/tlsprf.c and lib/tlsprf_selftest.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hmac = @import("hmac.zig");
const aescmac = @import("aescmac.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;

pub const SYMCRYPT_TLS_MAX_LABEL_SIZE: usize = 256;
pub const SYMCRYPT_TLS_MAX_SEED_SIZE: usize = 256;
pub const SYMCRYPT_TLS_MAX_LABEL_AND_SEED_SIZE: usize = SYMCRYPT_TLS_MAX_LABEL_SIZE + SYMCRYPT_TLS_MAX_SEED_SIZE;
pub const SYMCRYPT_TLS_1_1_CHUNK_SIZE: usize = 80;
pub const SYMCRYPT_MAC_MAX_RESULT_SIZE: usize = hmac.SYMCRYPT_HMAC_SHA512_RESULT_SIZE;

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
    aescmacState: aescmac.SYMCRYPT_AES_CMAC_STATE,
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
    aescmacKey: aescmac.SYMCRYPT_AES_CMAC_EXPANDED_KEY,
    kmac128Key: SYMCRYPT_KMAC128_EXPANDED_KEY,
    kmac256Key: SYMCRYPT_KMAC256_EXPANDED_KEY,
};
pub const PSYMCRYPT_MAC_EXPANDED_KEY = *SYMCRYPT_MAC_EXPANDED_KEY;
pub const PCSYMCRYPT_MAC_EXPANDED_KEY = *const SYMCRYPT_MAC_EXPANDED_KEY;

pub const SYMCRYPT_TLSPRF1_1_EXPANDED_KEY = extern struct {
    macMd5Key: hmac.SYMCRYPT_HMAC_MD5_EXPANDED_KEY,
    macSha1Key: hmac.SYMCRYPT_HMAC_SHA1_EXPANDED_KEY,
};
pub const PSYMCRYPT_TLSPRF1_1_EXPANDED_KEY = *SYMCRYPT_TLSPRF1_1_EXPANDED_KEY;
pub const PCSYMCRYPT_TLSPRF1_1_EXPANDED_KEY = *const SYMCRYPT_TLSPRF1_1_EXPANDED_KEY;

pub const SYMCRYPT_TLSPRF1_2_EXPANDED_KEY = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_TLSPRF1_2_EXPANDED_KEY = *SYMCRYPT_TLSPRF1_2_EXPANDED_KEY;
pub const PCSYMCRYPT_TLSPRF1_2_EXPANDED_KEY = *const SYMCRYPT_TLSPRF1_2_EXPANDED_KEY;

const MacExpandKeyFn = *const fn (pExpandedKey: PVOID, pbKey: ?PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
const MacAppendFn = *const fn (pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg3: [3]BYTE;

pub export fn SymCryptTlsPrf1_1ExpandKey(
    pExpandedKey: PSYMCRYPT_TLSPRF1_1_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHalfSecret: SIZE_T = cbKey / 2;
    const cbOdd: SIZE_T = cbKey % 2;
    const cbKeySize: SIZE_T = cbHalfSecret + cbOdd;

    var scError = hmac.SymCryptHmacMd5ExpandKey(&pExpandedKey.macMd5Key, pbKey, cbKeySize);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const pbSecondHalf: ?PCBYTE = if (pbKey) |p| p + cbHalfSecret else null;
    scError = hmac.SymCryptHmacSha1ExpandKey(&pExpandedKey.macSha1Key, pbSecondHalf, cbKeySize);
    if (scError != .SYMCRYPT_NO_ERROR) {
        hmac.SymCryptWipeKnownSize(&pExpandedKey.macMd5Key, @sizeOf(hmac.SYMCRYPT_HMAC_MD5_EXPANDED_KEY));
        return scError;
    }

    return scError;
}

pub export fn SymCryptTlsPrf1_2ExpandKey(
    pExpandedKey: PSYMCRYPT_TLSPRF1_2_EXPANDED_KEY,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.SYMCRYPT_ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(SYMCRYPT_MAC_EXPANDED_KEY));

    pExpandedKey.macAlg = macAlgorithm;
    const expandKeyFn: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
    return expandKeyFn(&pExpandedKey.macKey, pbKey, cbKey);
}

pub export fn SymCryptTlsPrfMac(
    pMacAlgorithm: PCSYMCRYPT_MAC,
    pMacExpandedKey: PCSYMCRYPT_MAC_EXPANDED_KEY,
    pbAi: ?PCBYTE,
    cbAi: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var macState: SYMCRYPT_MAC_STATE = undefined;
    const appendFn: MacAppendFn = @ptrCast(pMacAlgorithm.appendFunc.?);

    pMacAlgorithm.initFunc.?(&macState, pMacExpandedKey);
    appendFn(&macState, pbAi, cbAi);

    if (cbSeed > 0) {
        appendFn(&macState, pbSeed, cbSeed);
    }

    pMacAlgorithm.resultFunc.?(&macState, pbResult);
}

pub export fn SymCryptTlsPrfPHash(
    pMacAlgorithm: PCSYMCRYPT_MAC,
    pMacExpandedKey: PCSYMCRYPT_MAC_EXPANDED_KEY,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbAiIn: ?PCBYTE,
    cbAiIn: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
    pbAiOut: ?PBYTE,
    cbAiOut: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var rbAi: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var rbPartialResult: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var pbTmp: ?PBYTE = pbResult;

    const cbMacResultSize: SIZE_T = pMacAlgorithm.resultSize;
    var cbBytesToWrite: SIZE_T = cbResult;

    if (cbAiIn == 0) {
        // Build A(1)
        SymCryptTlsPrfMac(
            pMacAlgorithm,
            pMacExpandedKey,
            pbSeed,
            cbSeed,
            null,
            0,
            &rbAi,
        );
    } else {
        // Get the previous Ai
        const copyLen = @min(SYMCRYPT_MAC_MAX_RESULT_SIZE, cbAiIn);
        @memcpy(rbAi[0..copyLen], pbAiIn.?[0..copyLen]);
    }

    while (cbBytesToWrite > 0) {
        // Build HMAC( secret, A(i) + seed )
        SymCryptTlsPrfMac(
            pMacAlgorithm,
            pMacExpandedKey,
            &rbAi,
            cbMacResultSize,
            pbSeed,
            cbSeed,
            &rbPartialResult,
        );

        // Store it in the output buffer
        const copyLen = @min(cbBytesToWrite, cbMacResultSize);
        @memcpy(pbTmp.?[0..copyLen], rbPartialResult[0..copyLen]);

        // Build A(i+1)
        SymCryptTlsPrfMac(
            pMacAlgorithm,
            pMacExpandedKey,
            &rbAi,
            cbMacResultSize,
            null,
            0,
            &rbAi,
        );

        if (cbBytesToWrite <= cbMacResultSize) {
            break;
        }

        pbTmp = pbTmp.? + cbMacResultSize;
        cbBytesToWrite -= cbMacResultSize;
    }

    // Store the next A(i) if needed
    if (cbAiOut > 0) {
        const copyLen = @min(cbAiOut, cbMacResultSize);
        @memcpy(pbAiOut.?[0..copyLen], rbAi[0..copyLen]);
    }

    hmac.SymCryptWipeKnownSize(&rbAi, @sizeOf(@TypeOf(rbAi)));
    hmac.SymCryptWipeKnownSize(&rbPartialResult, @sizeOf(@TypeOf(rbPartialResult)));
}

pub export fn SymCryptTlsPrf1_1Derive(
    pExpandedKey: PCSYMCRYPT_TLSPRF1_1_EXPANDED_KEY,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    var rbLabelAndSeed: [SYMCRYPT_TLS_MAX_LABEL_AND_SEED_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var cbLabelAndSeed: SIZE_T = 0;

    var rbAiMd5: [hmac.SYMCRYPT_HMAC_MD5_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var rbPartialResultMd5: [SYMCRYPT_TLS_1_1_CHUNK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    var rbAiSha1: [hmac.SYMCRYPT_HMAC_SHA1_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var rbPartialResultSha1: [SYMCRYPT_TLS_1_1_CHUNK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    var pbTmp: ?PBYTE = pbResult;
    var cbBytesToWrite: SIZE_T = cbResult;

    defer {
        hmac.SymCryptWipeKnownSize(&rbLabelAndSeed, @sizeOf(@TypeOf(rbLabelAndSeed)));
        hmac.SymCryptWipeKnownSize(&rbAiMd5, @sizeOf(@TypeOf(rbAiMd5)));
        hmac.SymCryptWipeKnownSize(&rbPartialResultMd5, @sizeOf(@TypeOf(rbPartialResultMd5)));
        hmac.SymCryptWipeKnownSize(&rbAiSha1, @sizeOf(@TypeOf(rbAiSha1)));
        hmac.SymCryptWipeKnownSize(&rbPartialResultSha1, @sizeOf(@TypeOf(rbPartialResultSha1)));
    }

    // Size checks
    if ((cbLabel > SYMCRYPT_TLS_MAX_LABEL_SIZE) or (cbSeed > SYMCRYPT_TLS_MAX_SEED_SIZE)) {
        scError = .SYMCRYPT_WRONG_DATA_SIZE;
        return scError;
    }

    // Concatenating the label and the seed
    if (cbLabel > 0) {
        @memcpy(rbLabelAndSeed[0..cbLabel], pbLabel.?[0..cbLabel]);
    }
    if (cbSeed > 0) {
        @memcpy(rbLabelAndSeed[cbLabel .. cbLabel + cbSeed], pbSeed.?[0..cbSeed]);
    }
    cbLabelAndSeed = cbLabel + cbSeed;

    const pMd5Key: PCSYMCRYPT_MAC_EXPANDED_KEY = @ptrCast(&pExpandedKey.macMd5Key);
    const pSha1Key: PCSYMCRYPT_MAC_EXPANDED_KEY = @ptrCast(&pExpandedKey.macSha1Key);

    // Build A(1)'s
    SymCryptTlsPrfMac(
        hmac.SymCryptHmacMd5Algorithm,
        pMd5Key,
        &rbLabelAndSeed,
        cbLabelAndSeed,
        null,
        0,
        &rbAiMd5,
    );

    SymCryptTlsPrfMac(
        hmac.SymCryptHmacSha1Algorithm,
        pSha1Key,
        &rbLabelAndSeed,
        cbLabelAndSeed,
        null,
        0,
        &rbAiSha1,
    );

    // Calculate the output
    pbTmp = pbResult;
    while (cbBytesToWrite > 0) {
        const chunkBytes = @min(cbBytesToWrite, SYMCRYPT_TLS_1_1_CHUNK_SIZE);

        // P_MD5
        SymCryptTlsPrfPHash(
            hmac.SymCryptHmacMd5Algorithm,
            pMd5Key,
            &rbLabelAndSeed,
            cbLabelAndSeed,
            &rbAiMd5,
            hmac.SYMCRYPT_HMAC_MD5_RESULT_SIZE,
            &rbPartialResultMd5,
            chunkBytes,
            &rbAiMd5,
            hmac.SYMCRYPT_HMAC_MD5_RESULT_SIZE,
        );

        // P_SHA1
        SymCryptTlsPrfPHash(
            hmac.SymCryptHmacSha1Algorithm,
            pSha1Key,
            &rbLabelAndSeed,
            cbLabelAndSeed,
            &rbAiSha1,
            hmac.SYMCRYPT_HMAC_SHA1_RESULT_SIZE,
            &rbPartialResultSha1,
            chunkBytes,
            &rbAiSha1,
            hmac.SYMCRYPT_HMAC_SHA1_RESULT_SIZE,
        );

        // XOR the two into the output
        SymCryptXorBytes(
            &rbPartialResultMd5,
            &rbPartialResultSha1,
            pbTmp.?,
            chunkBytes,
        );

        if (cbBytesToWrite <= SYMCRYPT_TLS_1_1_CHUNK_SIZE) {
            break;
        }

        cbBytesToWrite -= SYMCRYPT_TLS_1_1_CHUNK_SIZE;
        pbTmp = pbTmp.? + SYMCRYPT_TLS_1_1_CHUNK_SIZE;
    }

    return scError;
}

pub export fn SymCryptTlsPrf1_2Derive(
    pExpandedKey: PCSYMCRYPT_TLSPRF1_2_EXPANDED_KEY,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var rbLabelAndSeed: [SYMCRYPT_TLS_MAX_LABEL_AND_SEED_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    defer hmac.SymCryptWipeKnownSize(&rbLabelAndSeed, @sizeOf(@TypeOf(rbLabelAndSeed)));

    // Size checks
    if ((cbLabel > SYMCRYPT_TLS_MAX_LABEL_SIZE) or (cbSeed > SYMCRYPT_TLS_MAX_SEED_SIZE)) {
        scError = .SYMCRYPT_WRONG_DATA_SIZE;
        return scError;
    }

    // Concatenating the label and the seed
    if (cbLabel > 0) {
        @memcpy(rbLabelAndSeed[0..cbLabel], pbLabel.?[0..cbLabel]);
    }
    if (cbSeed > 0) {
        @memcpy(rbLabelAndSeed[cbLabel .. cbLabel + cbSeed], pbSeed.?[0..cbSeed]);
    }

    SymCryptTlsPrfPHash(
        pExpandedKey.macAlg,
        &pExpandedKey.macKey,
        &rbLabelAndSeed,
        cbLabel + cbSeed,
        null,
        0,
        pbResult,
        cbResult,
        null,
        0,
    );

    return scError;
}

pub export fn SymCryptTlsPrf1_1(
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var key: SYMCRYPT_TLSPRF1_1_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(@TypeOf(key)));

    const scError = SymCryptTlsPrf1_1ExpandKey(&key, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptTlsPrf1_1Derive(
        &key,
        pbLabel,
        cbLabel,
        pbSeed,
        cbSeed,
        pbResult,
        cbResult,
    );
}

pub export fn SymCryptTlsPrf1_2(
    pMacAlgorithm: PCSYMCRYPT_MAC,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var key: SYMCRYPT_TLSPRF1_2_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&key, @sizeOf(@TypeOf(key)));

    const scError = SymCryptTlsPrf1_2ExpandKey(&key, pMacAlgorithm, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptTlsPrf1_2Derive(
        &key,
        pbLabel,
        cbLabel,
        pbSeed,
        cbSeed,
        pbResult,
        cbResult,
    );
}

// ==============================================================================================
// Self-tests (ported from lib/tlsprf_selftest.c)
// ==============================================================================================

const pbResult1_1 = [_]BYTE{
    0x8e, 0x7e, 0x7b, 0x2f, 0x7d, 0x00, 0x77, 0x09, 0x78, 0x22, 0x51, 0xf2, 0xcf,
};

const pbResult1_2Sha512 = [_]BYTE{
    0xf9, 0x9f, 0x44, 0x4d, 0x26, 0xde, 0x8b, 0x4f, 0xc2, 0x81, 0x5b, 0x23, 0x70,
};

pub export fn SymCryptTlsPrf1_1SelfTest() callconv(SYMCRYPT_CALL) void {
    var rbResult: [pbResult1_1.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptTlsPrf1_1(
        &SymCryptTestKey32,
        15,
        SymCryptTestKey32[16..].ptr,
        16,
        &SymCryptTestMsg3,
        3,
        &rbResult,
        pbResult1_1.len,
    );

    SymCryptInjectError(&rbResult, pbResult1_1.len);

    if (!std.mem.eql(u8, &rbResult, &pbResult1_1)) {
        macros.SymCryptFatal(macros.multiCharConstant("tl11"));
    }
}

pub export fn SymCryptTlsPrf1_2SelfTest() callconv(SYMCRYPT_CALL) void {
    var rbResult: [pbResult1_2Sha512.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptTlsPrf1_2(
        hmac.SymCryptHmacSha512Algorithm,
        &SymCryptTestKey32,
        15,
        SymCryptTestKey32[16..].ptr,
        16,
        &SymCryptTestMsg3,
        3,
        &rbResult,
        pbResult1_2Sha512.len,
    );

    SymCryptInjectError(&rbResult, pbResult1_2Sha512.len);

    if (!std.mem.eql(u8, &rbResult, &pbResult1_2Sha512)) {
        macros.SymCryptFatal(macros.multiCharConstant("tl12"));
    }
}
