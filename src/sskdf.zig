//
// sskdf.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Single-Step KDF implementation as specified in SP800-56C section 4 and self-test,
// ported from lib/sskdf.c and lib/sskdf_selftest.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hmac = @import("hmac.zig");
const tlsprf = @import("tlsprf.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_MAC_STATE = tlsprf.SYMCRYPT_MAC_STATE;
const SYMCRYPT_MAC_EXPANDED_KEY = tlsprf.SYMCRYPT_MAC_EXPANDED_KEY;
const SYMCRYPT_KMAC128_EXPANDED_KEY = tlsprf.SYMCRYPT_KMAC128_EXPANDED_KEY;
const SYMCRYPT_KMAC256_EXPANDED_KEY = tlsprf.SYMCRYPT_KMAC256_EXPANDED_KEY;
const SYMCRYPT_KMAC128_STATE = tlsprf.SYMCRYPT_KMAC128_STATE;
const SYMCRYPT_KMAC256_STATE = tlsprf.SYMCRYPT_KMAC256_STATE;
const SYMCRYPT_MAC_MAX_RESULT_SIZE = tlsprf.SYMCRYPT_MAC_MAX_RESULT_SIZE;

pub const SYMCRYPT_SSKDF_KMAC_128_DEFAULT_SALT_SIZE: usize = 164;
pub const SYMCRYPT_SSKDF_KMAC_256_DEFAULT_SALT_SIZE: usize = 132;
pub const SYMCRYPT_SSKDF_DEFAULT_SALT_MAX: usize = SYMCRYPT_SSKDF_KMAC_128_DEFAULT_SALT_SIZE;

pub const SYMCRYPT_SSKDF_MAC_EXPANDED_SALT = extern struct {
    macKey: SYMCRYPT_MAC_EXPANDED_KEY,
    macAlg: PCSYMCRYPT_MAC,
};
pub const PSYMCRYPT_SSKDF_MAC_EXPANDED_SALT = *SYMCRYPT_SSKDF_MAC_EXPANDED_SALT;
pub const PCSYMCRYPT_SSKDF_MAC_EXPANDED_SALT = *const SYMCRYPT_SSKDF_MAC_EXPANDED_SALT;

const MacExpandKeyFn = *const fn (pExpandedKey: PVOID, pbKey: ?PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
const MacAppendFn = *const fn (pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
const MacResultExFn = *const fn (pState: PVOID, pbResult: ?PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptKmac128Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptKmac256Algorithm: PCSYMCRYPT_MAC;

extern fn SymCryptKmac128ExpandKeyEx(
    pExpandedKey: *SYMCRYPT_KMAC128_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbCustomizationString: PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptKmac256ExpandKeyEx(
    pExpandedKey: *SYMCRYPT_KMAC256_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbCustomizationString: PCBYTE,
    cbCustomizationString: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptKmac128ResultEx(
    pState: *SYMCRYPT_KMAC128_STATE,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptKmac256ResultEx(
    pState: *SYMCRYPT_KMAC256_STATE,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptHashInit(pHash: PCSYMCRYPT_HASH, pState: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashAppend(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashResult(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashInputBlockSize(pHash: PCSYMCRYPT_HASH) callconv(SYMCRYPT_CALL) SIZE_T;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;

const pbKmacCustomizationString = [3]BYTE{ 'K', 'D', 'F' };

pub export fn SymCryptSskdfMacExpandSalt(
    pExpandedSalt: PSYMCRYPT_SSKDF_MAC_EXPANDED_SALT,
    macAlgorithm: PCSYMCRYPT_MAC,
    pbSaltIn: ?PCBYTE,
    cbSaltIn: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pbSaltDefault: [SYMCRYPT_SSKDF_DEFAULT_SALT_MAX]BYTE = @splat(0);
    var pbSalt: ?PCBYTE = pbSaltIn;
    var cbSalt: SIZE_T = cbSaltIn;

    macros.SYMCRYPT_ASSERT(macAlgorithm.expandedKeySize <= @sizeOf(SYMCRYPT_MAC_EXPANDED_KEY));

    pExpandedSalt.macAlg = macAlgorithm;

    if (pbSalt == null) {
        if (macAlgorithm == SymCryptKmac128Algorithm) {
            cbSalt = SYMCRYPT_SSKDF_KMAC_128_DEFAULT_SALT_SIZE;
        } else if (macAlgorithm == SymCryptKmac256Algorithm) {
            cbSalt = SYMCRYPT_SSKDF_KMAC_256_DEFAULT_SALT_SIZE;
        } else {
            cbSalt = SymCryptHashInputBlockSize(macAlgorithm.ppHashAlgorithm.?.*.?);
        }

        pbSalt = &pbSaltDefault;
    }

    if (macAlgorithm == SymCryptKmac128Algorithm) {
        return SymCryptKmac128ExpandKeyEx(
            &pExpandedSalt.macKey.kmac128Key,
            pbSalt,
            cbSalt,
            &pbKmacCustomizationString,
            pbKmacCustomizationString.len,
        );
    } else if (macAlgorithm == SymCryptKmac256Algorithm) {
        return SymCryptKmac256ExpandKeyEx(
            &pExpandedSalt.macKey.kmac256Key,
            pbSalt,
            cbSalt,
            &pbKmacCustomizationString,
            pbKmacCustomizationString.len,
        );
    } else {
        const expandKeyFn: MacExpandKeyFn = @ptrCast(macAlgorithm.expandKeyFunc.?);
        return expandKeyFn(&pExpandedSalt.macKey, pbSalt, cbSalt);
    }
}

pub export fn SymCryptSskdfMacDerive(
    pExpandedSalt: PCSYMCRYPT_SSKDF_MAC_EXPANDED_SALT,
    cbMacOutputSize: SIZE_T,
    pbSecret: ?PCBYTE,
    cbSecret: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: ?PBYTE,
    cbResultIn: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var state: SYMCRYPT_MAC_STATE = undefined;
    const pMacAlgorithm: PCSYMCRYPT_MAC = pExpandedSalt.macAlg;
    var resultFuncEx: ?MacResultExFn = null;

    var rbPartialResult: [SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    defer hmac.SymCryptWipeKnownSize(&rbPartialResult, @sizeOf(@TypeOf(rbPartialResult)));

    var pbCurr: ?PBYTE = pbResult;
    var cbResult: SIZE_T = cbResultIn;

    var cbMacResultSize: SIZE_T = pMacAlgorithm.resultSize;
    var cntr: UINT32 = 1;
    var ctrBuf: [4]BYTE = undefined;

    if (cbMacOutputSize > 64) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pMacAlgorithm == SymCryptKmac128Algorithm) {
        cbMacResultSize = cbMacOutputSize;
        resultFuncEx = @ptrCast(&SymCryptKmac128ResultEx);
    } else if (pMacAlgorithm == SymCryptKmac256Algorithm) {
        cbMacResultSize = cbMacOutputSize;
        resultFuncEx = @ptrCast(&SymCryptKmac256ResultEx);
    } else if (cbMacOutputSize > 0 and cbMacOutputSize != pMacAlgorithm.resultSize) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const appendFn: MacAppendFn = @ptrCast(pMacAlgorithm.appendFunc.?);

    while (cbResult > 0) {
        macros.SYMCRYPT_STORE_MSBFIRST32(&ctrBuf, cntr);

        // Calculate K(i) = H(counter || Z || FixedInfo)
        pMacAlgorithm.initFunc.?(&state, &pExpandedSalt.macKey);
        appendFn(&state, &ctrBuf, ctrBuf.len);
        appendFn(&state, pbSecret, cbSecret);
        appendFn(&state, pbInfo, cbInfo);

        const cbBlock: SIZE_T = @min(cbResult, cbMacResultSize);

        if (resultFuncEx) |resEx| {
            if (cbMacOutputSize > 0) {
                resEx(&state, &rbPartialResult, cbMacOutputSize);
            } else {
                // If the output size is not specified, calculate the full result
                resEx(&state, pbResult, cbResult);
                break;
            }
        } else {
            pMacAlgorithm.resultFunc.?(&state, &rbPartialResult);
        }

        // Store the result in the output buffer
        @memcpy(pbCurr.?[0..cbBlock], rbPartialResult[0..cbBlock]);

        // Update counters
        cntr += 1;
        pbCurr = pbCurr.? + cbBlock;
        cbResult -= cbBlock;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSskdfMac(
    macAlgorithm: PCSYMCRYPT_MAC,
    cbMacOutputSize: SIZE_T,
    pbSecret: ?PCBYTE,
    cbSecret: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: ?PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var expandedSalt: SYMCRYPT_SSKDF_MAC_EXPANDED_SALT = undefined;
    defer hmac.SymCryptWipeKnownSize(&expandedSalt, @sizeOf(@TypeOf(expandedSalt)));

    const scError = SymCryptSskdfMacExpandSalt(&expandedSalt, macAlgorithm, pbSalt, cbSalt);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptSskdfMacDerive(
        &expandedSalt,
        cbMacOutputSize,
        pbSecret,
        cbSecret,
        pbInfo,
        cbInfo,
        pbResult,
        cbResult,
    );
}

pub export fn SymCryptSskdfHash(
    hashAlgorithm: PCSYMCRYPT_HASH,
    cbHashOutputSize: SIZE_T,
    pbSecret: ?PCBYTE,
    cbSecret: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: ?PBYTE,
    cbResultIn: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var state: hmac.SYMCRYPT_HASH_STATE = undefined;

    var pbCurr: ?PBYTE = pbResult;
    var cbResult: SIZE_T = cbResultIn;

    const cbHashResultSize: SIZE_T = hashAlgorithm.resultSize;
    var cntr: UINT32 = 1;
    var ctrBuf: [4]BYTE = undefined;

    if (cbHashOutputSize > 64 or
        (cbHashOutputSize > 0 and cbHashOutputSize != hashAlgorithm.resultSize))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    while (cbResult > 0) {
        macros.SYMCRYPT_STORE_MSBFIRST32(&ctrBuf, cntr);

        const cbPartialResult: SIZE_T = @min(cbResult, cbHashResultSize);

        // Calculate K(i) = H(counter || Z || FixedInfo)
        SymCryptHashInit(hashAlgorithm, &state);
        SymCryptHashAppend(hashAlgorithm, &state, &ctrBuf, ctrBuf.len);
        SymCryptHashAppend(hashAlgorithm, &state, pbSecret, cbSecret);
        SymCryptHashAppend(hashAlgorithm, &state, pbInfo, cbInfo);
        SymCryptHashResult(hashAlgorithm, &state, pbCurr.?, cbPartialResult);

        // Update counters
        cntr += 1;
        pbCurr = pbCurr.? + cbPartialResult;
        cbResult -= cbPartialResult;
    }

    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Self-test (ported from lib/sskdf_selftest.c)
// ==============================================================================================

const selftest_pbResult = [_]BYTE{
    0x30, 0xe5, 0x3e, 0x4c, 0xf6, 0xb1, 0xa5, 0x42, 0x5d, 0xc6, 0x4c, 0xe6, 0x15, 0x7f, 0x5f, 0xa6,
};

pub export fn SymCryptSskdfSelfTest() callconv(SYMCRYPT_CALL) void {
    var rbResult: [selftest_pbResult.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptSskdfMac(
        hmac.SymCryptHmacSha512Algorithm,
        0,
        &SymCryptTestKey32,
        16,
        SymCryptTestKey32[16..].ptr,
        16,
        &SymCryptTestMsg16,
        16,
        &rbResult,
        selftest_pbResult.len,
    );

    SymCryptInjectError(&rbResult, selftest_pbResult.len);

    if (!std.mem.eql(u8, &rbResult, &selftest_pbResult)) {
        macros.SymCryptFatal(macros.multiCharConstant("sskd"));
    }
}
