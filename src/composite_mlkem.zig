//
// composite_mlkem.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Composite ML-KEM implementation according to draft-ietf-lamps-pq-composite-kem-12
// and draft-irtf-cfrg-concrete-hybrid-kems-03, ported from lib/composite_mlkem.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha3 = @import("sha3.zig");
const shake = @import("shake.zig");
const prim = @import("mlkem_primitives.zig");
const mlkem = @import("mlkem.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ASYM_ALIGN_VALUE = types.SYMCRYPT_ASYM_ALIGN_VALUE;

const SYMCRYPT_MLKEM_PARAMS = prim.SYMCRYPT_MLKEM_PARAMS;
const SYMCRYPT_MLKEMKEY_FORMAT = prim.SYMCRYPT_MLKEMKEY_FORMAT;
const PSYMCRYPT_MLKEMKEY = prim.PSYMCRYPT_MLKEMKEY;
const SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE = prim.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE;
const SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET = prim.SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET;
const SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM = prim.SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM;

// ==============================================================================================
// Composite ML-KEM Constants & Types (from inc/symcrypt.h and lib/sc_lib.h)
// ==============================================================================================

pub const SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE: usize = 32;

pub const SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_P256: usize = 115;
pub const SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_X25519: usize = 96;
pub const SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM1024_P384: usize = 128;

pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256: usize = 1249;
pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519: usize = 1216;
pub const SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384: usize = 1665;

pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_P256: usize = 1153;
pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_X25519: usize = 1120;
pub const SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM1024_P384: usize = 1665;

pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256: usize = 65;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384: usize = 97;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_CURVE_25519: usize = 32;
pub const SYMCRYPT_COMPOSITE_SIZEOF_MAX_ENCODED_EC_PUBLIC_KEY: usize = SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384;

pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256: usize = 51;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384: usize = 64;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_CURVE_25519: usize = 32;

const MAX_ECDH_KEM_SHARED_SECRET_SIZE: usize = 48;
const COMPOSITE_MLKEM_SHARED_SECRET_SIZE: usize = 32;

const IRTF_MLKEM_768_X25519_EXPANDED_SEED_SIZE: usize = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + 32;
const IRTF_MLKEM_768_P256_EXPANDED_SEED_SIZE: usize = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + 32 * 4;
const IRTF_MLKEM_1024_P384_EXPANDED_SEED_SIZE: usize = SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + 48;
const MAX_IRTF_COMPOSITE_MLKEM_EXPANDED_SEED_SIZE: usize = IRTF_MLKEM_768_P256_EXPANDED_SEED_SIZE;
const MAX_IRTF_EC_SCALAR_SIZE: usize = 48;

pub const SYMCRYPT_FLAG_KEY_NO_FIPS: UINT32 = 0x100;
pub const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: UINT32 = 0x200;
pub const SYMCRYPT_FLAG_ECKEY_ECDH: UINT32 = 0x2000;

pub const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT = enum(c_uint) {
    NULL = 0,
    IRTF_PRIVATE_SEED = 1,
    LAMPS_PRIVATE_KEY = 2,
    PUBLIC_KEY = 3,
    _,
};

pub const SYMCRYPT_COMPOSITE_MLKEM_PARAMS = enum(c_uint) {
    NULL = 0,
    MLKEM768_P256 = 1,
    MLKEM768_X25519 = 2,
    MLKEM1024_P384 = 3,
    _,
};

pub const SYMCRYPT_CACHED_ECURVE_ID = enum(c_uint) {
    NIST_P256 = 0,
    NIST_P384 = 1,
    CURVE_25519 = 2,
    COUNT = 3,
    _,
};

pub const SYMCRYPT_NUMBER_FORMAT = enum(c_uint) {
    LSB_FIRST = 1,
    MSB_FIRST = 2,
    _,
};

pub const SYMCRYPT_ECPOINT_FORMAT = enum(c_uint) {
    X = 1,
    XY = 2,
    _,
};

pub const SYMCRYPT_ECURVE = opaque {};
pub const PCSYMCRYPT_ECURVE = *const SYMCRYPT_ECURVE;

pub const SYMCRYPT_MODULUS = opaque {};
pub const PSYMCRYPT_MODULUS = *SYMCRYPT_MODULUS;
pub const PCSYMCRYPT_MODULUS = *const SYMCRYPT_MODULUS;

pub const SYMCRYPT_INT = opaque {};
pub const PSYMCRYPT_INT = *SYMCRYPT_INT;
pub const PCSYMCRYPT_INT = *const SYMCRYPT_INT;

pub const SYMCRYPT_ECPOINT = opaque {};
pub const PSYMCRYPT_ECPOINT = *SYMCRYPT_ECPOINT;

pub const SYMCRYPT_ECKEY = extern struct {
    fAlgorithmInfo: UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
    hasPrivateKey: BOOLEAN,
    pCurve: PCSYMCRYPT_ECURVE,
    poPublicKey: PSYMCRYPT_ECPOINT,
    piPrivateKey: PSYMCRYPT_INT,
    magic: SIZE_T,
};
pub const PSYMCRYPT_ECKEY = *SYMCRYPT_ECKEY;
pub const PCSYMCRYPT_ECKEY = *const SYMCRYPT_ECKEY;

pub const SYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS = extern struct {
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
    ecurveId: SYMCRYPT_CACHED_ECURVE_ID,
    mlKemParams: SYMCRYPT_MLKEM_PARAMS,
    pbLabel: PCBYTE,
    cbLabel: SIZE_T,
    cbCiphertext: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    cbExpandedSeed: SIZE_T,
    cbEncodedPrivateKey: SIZE_T,
    cbEncodedPublicKey: SIZE_T,
};
pub const PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS = *const SYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS;

pub const SYMCRYPT_COMPOSITE_MLKEMKEY = extern struct {
    pParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS align(SYMCRYPT_ASYM_ALIGN_VALUE),
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
    pkEcKey: PSYMCRYPT_ECKEY,
    hasPrivateSeed: BOOLEAN,
    privateSeed: [SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_COMPOSITE_MLKEMKEY = *SYMCRYPT_COMPOSITE_MLKEMKEY;
pub const PCSYMCRYPT_COMPOSITE_MLKEMKEY = *const SYMCRYPT_COMPOSITE_MLKEMKEY;

// ==============================================================================================
// External C Functions (EC, FDEF/Int, Composite Encoding)
// ==============================================================================================

pub extern fn SymCryptGetCachedEcurve(curveId: SYMCRYPT_CACHED_ECURVE_ID) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_ECURVE;
pub extern fn SymCryptEckeyAllocate(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECKEY;
pub extern fn SymCryptEckeyFree(pkObj: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptEckeyWipePrivateState(pkEckey: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptEckeySizeofPrivateKey(pkEckey: PCSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEckeySetValue(
    pbPrivateKey: ?PCBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PCBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
    pkEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEckeySetRandom(flags: UINT32, pkEckey: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEcDhSecretAgreement(
    pkPrivate: PCSYMCRYPT_ECKEY,
    pkPublic: PCSYMCRYPT_ECKEY,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub extern fn SymCryptEcurveSizeofFieldElement(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEcurveSizeofScalarMultiplier(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEcurveDigitsofScalarMultiplier(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEcurveGroupOrder(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) PCSYMCRYPT_MODULUS;

pub extern fn SymCryptSizeofIntFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptIntCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT;
pub extern fn SymCryptIntFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT;
pub extern fn SymCryptIntSetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptIntGetValue(
    piSrc: PCSYMCRYPT_INT,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptIntIsEqualUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptIntIsLessThan(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32;

pub extern fn SymCryptCompositeGetSizeOfEncodedEcPk(curveId: SYMCRYPT_CACHED_ECURVE_ID) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEckeyGetValueCompositeEncodingSk(
    pEckey: PCSYMCRYPT_ECKEY,
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEckeyGetValueCompositeEncodingPk(
    pEckey: PCSYMCRYPT_ECKEY,
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEckeySetValueCompositeEncodingPk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEckeySetValueCompositeEncodingSk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

// ==============================================================================================
// Parameter Tables
// ==============================================================================================

const rgbMlKem768P256Label = [_]BYTE{
    'M', 'L', 'K', 'E', 'M', '7', '6', '8', '-', 'P', '2', '5', '6',
};

const rgbMlKem768X25519Label = [_]BYTE{
    0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c,
};

const rgbMlKem1024P384Label = [_]BYTE{
    'M', 'L', 'K', 'E', 'M', '1', '0', '2', '4', '-', 'P', '3', '8', '4',
};

const SymCryptCompositeMlKemInternalParamsMlKem768P256 = SYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS{
    .params = .MLKEM768_P256,
    .ecurveId = .NIST_P256,
    .mlKemParams = .MLKEM768,
    .pbLabel = &rgbMlKem768P256Label,
    .cbLabel = rgbMlKem768P256Label.len,
    .cbCiphertext = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_P256,
    .numFormat = .MSB_FIRST,
    .ecPointFormat = .XY,
    .cbExpandedSeed = IRTF_MLKEM_768_P256_EXPANDED_SEED_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_P256,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256,
};

const SymCryptCompositeMlKemInternalParamsMlKem768X25519 = SYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS{
    .params = .MLKEM768_X25519,
    .ecurveId = .CURVE_25519,
    .mlKemParams = .MLKEM768,
    .pbLabel = &rgbMlKem768X25519Label,
    .cbLabel = rgbMlKem768X25519Label.len,
    .cbCiphertext = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_X25519,
    .numFormat = .LSB_FIRST,
    .ecPointFormat = .X,
    .cbExpandedSeed = IRTF_MLKEM_768_X25519_EXPANDED_SEED_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_X25519,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519,
};

const SymCryptCompositeMlKemInternalParamsMlKem1024P384 = SYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS{
    .params = .MLKEM1024_P384,
    .ecurveId = .NIST_P384,
    .mlKemParams = .MLKEM1024,
    .pbLabel = &rgbMlKem1024P384Label,
    .cbLabel = rgbMlKem1024P384Label.len,
    .cbCiphertext = SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM1024_P384,
    .numFormat = .MSB_FIRST,
    .ecPointFormat = .XY,
    .cbExpandedSeed = IRTF_MLKEM_1024_P384_EXPANDED_SEED_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM1024_P384,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384,
};

comptime {
    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256 ==
        (prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_P256 ==
        (SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256));

    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519 ==
        (prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_CURVE_25519));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM768_X25519 ==
        (SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_CURVE_25519));

    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384 ==
        (prim.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLKEM_LAMPS_PRIVATE_KEY_SIZE_MLKEM1024_P384 ==
        (SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384));
}

fn SymCryptCompositeMlKemGetInternalParamsFromParams(
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
    ppInternalParams: *PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS,
) SYMCRYPT_ERROR {
    switch (params) {
        .MLKEM768_P256 => ppInternalParams.* = &SymCryptCompositeMlKemInternalParamsMlKem768P256,
        .MLKEM768_X25519 => ppInternalParams.* = &SymCryptCompositeMlKemInternalParamsMlKem768X25519,
        .MLKEM1024_P384 => ppInternalParams.* = &SymCryptCompositeMlKemInternalParamsMlKem1024P384,
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Public & Internal Composite ML-KEM Functions
// ==============================================================================================

pub export fn SymCryptCompositeMlKemkeyAllocate(
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_COMPOSITE_MLKEMKEY {
    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptCompositeMlKemGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const pCurve = SymCryptGetCachedEcurve(pInternalParams.ecurveId) orelse return null;

    const pkMlKemkey = mlkem.SymCryptMlKemkeyAllocate(pInternalParams.mlKemParams) orelse return null;

    const pkEckey = SymCryptEckeyAllocate(pCurve) orelse {
        mlkem.SymCryptMlKemkeyFree(pkMlKemkey);
        return null;
    };

    const pbKey = mlkem.SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_COMPOSITE_MLKEMKEY)) orelse {
        SymCryptEckeyFree(pkEckey);
        mlkem.SymCryptMlKemkeyFree(pkMlKemkey);
        return null;
    };

    const alignedKey: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbKey);
    const pKey: PSYMCRYPT_COMPOSITE_MLKEMKEY = @ptrCast(alignedKey);

    hash.SymCryptWipeKnownSize(@ptrCast(pKey), @sizeOf(SYMCRYPT_COMPOSITE_MLKEMKEY));

    pKey.pParams = pInternalParams;
    pKey.pkEcKey = pkEckey;
    pKey.pkMlKemkey = pkMlKemkey;
    pKey.hasPrivateSeed = 0;

    macros.SET_MAGIC(pKey);

    return pKey;
}

pub export fn SymCryptCompositeMlKemkeyFree(
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pkCompositeMlKemkey);

    SymCryptEckeyFree(pkCompositeMlKemkey.pkEcKey);
    mlkem.SymCryptMlKemkeyFree(pkCompositeMlKemkey.pkMlKemkey);

    hash.SymCryptWipe(@ptrCast(pkCompositeMlKemkey), @sizeOf(SYMCRYPT_COMPOSITE_MLKEMKEY));

    mlkem.SymCryptCallbackFree(@ptrCast(pkCompositeMlKemkey));
}

pub export fn SymCryptCompositeMlKemSizeofKeyFormatFromParams(
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
    compositeMlKemKeyformat: SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT,
    pcbKeyFormat: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (compositeMlKemKeyformat == .NULL) {
        return .SYMCRYPT_INCOMPATIBLE_FORMAT;
    }

    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptCompositeMlKemGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    switch (compositeMlKemKeyformat) {
        .IRTF_PRIVATE_SEED => pcbKeyFormat.* = SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
        .LAMPS_PRIVATE_KEY => pcbKeyFormat.* = pInternalParams.cbEncodedPrivateKey,
        .PUBLIC_KEY => pcbKeyFormat.* = pInternalParams.cbEncodedPublicKey,
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlKemSizeofCiphertextFromParams(
    params: SYMCRYPT_COMPOSITE_MLKEM_PARAMS,
    pcbCiphertext: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS = undefined;
    const scError = SymCryptCompositeMlKemGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pcbCiphertext.* = pInternalParams.cbCiphertext;
    return .SYMCRYPT_NO_ERROR;
}

fn SymCryptCompositeMlKemkeyWipePrivateState(
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
) void {
    prim.SymCryptMlKemkeyWipePrivateState(pkCompositeMlKemkey.pkMlKemkey);
    SymCryptEckeyWipePrivateState(pkCompositeMlKemkey.pkEcKey);

    hash.SymCryptWipeKnownSize(&pkCompositeMlKemkey.privateSeed, pkCompositeMlKemkey.privateSeed.len);
    pkCompositeMlKemkey.hasPrivateSeed = 0;
}

pub export fn SymCryptCompositeMlKemkeyGenerate(
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var rgbPrivateSeed: [SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE]BYTE = undefined;
    defer hash.SymCryptWipeKnownSize(&rgbPrivateSeed, rgbPrivateSeed.len);

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((flags & ~allowedFlags) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const scError = mlkem.SymCryptCallbackRandom(&rgbPrivateSeed, rgbPrivateSeed.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptCompositeMlKemkeySetValue(
        &rgbPrivateSeed,
        rgbPrivateSeed.len,
        .IRTF_PRIVATE_SEED,
        flags,
        pkCompositeMlKemkey,
    );
}

fn SymCryptCompositeMlKemExpandPrivateSeed(
    pbSeed: PCBYTE,
    cbSeed: SIZE_T,
    pbExpandedSeed: PBYTE,
    cbExpandedSeed: SIZE_T,
) void {
    var shakeState: shake.SYMCRYPT_SHAKE256_STATE = undefined;

    macros.ASSERT(cbSeed == SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE);

    shake.SymCryptShake256Init(&shakeState);
    shake.SymCryptShake256Append(&shakeState, pbSeed, cbSeed);
    shake.SymCryptShake256Extract(&shakeState, pbExpandedSeed, cbExpandedSeed, 1);
}

fn SymCryptCompositeMlKemGetRandomScalarForEcKey(
    pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS,
    pbSeed: PCBYTE,
    cbSeed: SIZE_T,
    pbScalar: PBYTE,
    cbScalar: SIZE_T,
) SYMCRYPT_ERROR {
    return SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
        pInternalParams.ecurveId,
        pInternalParams.numFormat,
        pbSeed,
        cbSeed,
        pbScalar,
        cbScalar,
    );
}

pub export fn SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
    ecurveId: SYMCRYPT_CACHED_ECURVE_ID,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    pbSeed: PCBYTE,
    cbSeed: SIZE_T,
    pbScalar: PBYTE,
    cbScalar: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pCurve = SymCryptGetCachedEcurve(ecurveId) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;

    const cbScalarSize: UINT32 = SymCryptEcurveSizeofScalarMultiplier(pCurve);
    const nDigits: UINT32 = SymCryptEcurveDigitsofScalarMultiplier(pCurve);
    const cbIntScalarSize: UINT32 = SymCryptSizeofIntFromDigits(nDigits);

    macros.ASSERT(cbScalar == @as(SIZE_T, cbScalarSize));
    macros.ASSERT(cbSeed >= @as(SIZE_T, cbScalarSize));

    if (ecurveId == .CURVE_25519) {
        @memcpy(pbScalar[0..cbScalar], pbSeed[0..cbScalar]);

        pbScalar[0] &= 0xF8;
        pbScalar[31] &= 0x7F;
        pbScalar[31] |= 0x40;

        return .SYMCRYPT_NO_ERROR;
    }

    const pbScratch = mlkem.SymCryptCallbackAlloc(cbIntScalarSize) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer {
        hash.SymCryptWipe(pbScratch, cbIntScalarSize);
        mlkem.SymCryptCallbackFree(pbScratch);
    }

    const piScalarCandidate = SymCryptIntCreate(pbScratch, cbIntScalarSize, nDigits).?;
    const pmOrder = SymCryptEcurveGroupOrder(pCurve);
    const piOrder = SymCryptIntFromModulus(@constCast(pmOrder)).?;

    var seedOffset: SIZE_T = 0;
    var fFoundValidScalar: bool = false;

    while (seedOffset + cbScalarSize <= cbSeed) {
        var scError = SymCryptIntSetValue(
            pbSeed + seedOffset,
            cbScalarSize,
            numFormat,
            piScalarCandidate,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        if ((SymCryptIntIsEqualUint32(piScalarCandidate, 0) == 0) and
            (SymCryptIntIsLessThan(piScalarCandidate, piOrder) != 0))
        {
            scError = SymCryptIntGetValue(
                piScalarCandidate,
                pbScalar,
                cbScalar,
                numFormat,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            fFoundValidScalar = true;
            break;
        }

        seedOffset += cbScalarSize;
    }

    if (!fFoundValidScalar) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlKemkeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    compositeMlKemkeyFormat: SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT,
    flags: UINT32,
    pkCompositeMlKemkey: PSYMCRYPT_COMPOSITE_MLKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pInternalParams = pkCompositeMlKemkey.pParams;
    const eckeyFlags: UINT32 = flags | SYMCRYPT_FLAG_ECKEY_ECDH;

    var rgbExpandedSeed: [MAX_IRTF_COMPOSITE_MLKEM_EXPANDED_SEED_SIZE]BYTE = undefined;
    var rgbRandomScalar: [MAX_IRTF_EC_SCALAR_SIZE]BYTE = undefined;
    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCryptCompositeMlKemkeyWipePrivateState(pkCompositeMlKemkey);
        }
        hash.SymCryptWipeKnownSize(&rgbExpandedSeed, rgbExpandedSeed.len);
        hash.SymCryptWipeKnownSize(&rgbRandomScalar, rgbRandomScalar.len);
    }

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS | SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
    var cbExpectedFormatSize: SIZE_T = 0;

    if ((flags & ~allowedFlags) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    if (((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) and
        ((flags & SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION) != 0))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    if (compositeMlKemkeyFormat == .NULL) {
        scError = .SYMCRYPT_INCOMPATIBLE_FORMAT;
        return scError;
    }

    scError = SymCryptCompositeMlKemSizeofKeyFormatFromParams(
        pInternalParams.params,
        compositeMlKemkeyFormat,
        &cbExpectedFormatSize,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (cbSrc != cbExpectedFormatSize) {
        scError = .SYMCRYPT_WRONG_KEY_SIZE;
        return scError;
    }

    if (compositeMlKemkeyFormat == .IRTF_PRIVATE_SEED) {
        macros.ASSERT(pInternalParams.cbExpandedSeed <= rgbExpandedSeed.len);

        SymCryptCompositeMlKemExpandPrivateSeed(
            pbSrc,
            cbSrc,
            &rgbExpandedSeed,
            pInternalParams.cbExpandedSeed,
        );

        scError = mlkem.SymCryptMlKemkeySetValue(
            &rgbExpandedSeed,
            SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            .PRIVATE_SEED,
            flags,
            pkCompositeMlKemkey.pkMlKemkey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        const cbRandomScalar: SIZE_T = SymCryptEckeySizeofPrivateKey(pkCompositeMlKemkey.pkEcKey);
        macros.ASSERT(cbRandomScalar <= rgbRandomScalar.len);

        scError = SymCryptCompositeMlKemGetRandomScalarForEcKey(
            pInternalParams,
            rgbExpandedSeed[SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE..].ptr,
            pInternalParams.cbExpandedSeed - SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            &rgbRandomScalar,
            cbRandomScalar,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptEckeySetValue(
            &rgbRandomScalar,
            cbRandomScalar,
            null,
            0,
            pInternalParams.numFormat,
            pInternalParams.ecPointFormat,
            eckeyFlags,
            pkCompositeMlKemkey.pkEcKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        @memcpy(&pkCompositeMlKemkey.privateSeed, pbSrc[0..cbSrc]);
        pkCompositeMlKemkey.hasPrivateSeed = 1;
    } else if (compositeMlKemkeyFormat == .LAMPS_PRIVATE_KEY) {
        scError = mlkem.SymCryptMlKemkeySetValue(
            pbSrc,
            SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            .PRIVATE_SEED,
            flags,
            pkCompositeMlKemkey.pkMlKemkey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptEckeySetValueCompositeEncodingSk(
            pInternalParams.ecurveId,
            pbSrc + SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            cbSrc - SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            eckeyFlags,
            pkCompositeMlKemkey.pkEcKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        pkCompositeMlKemkey.hasPrivateSeed = 0;
    } else if (compositeMlKemkeyFormat == .PUBLIC_KEY) {
        const cbMlkemPubKey: SIZE_T = cbSrc - SymCryptCompositeGetSizeOfEncodedEcPk(pInternalParams.ecurveId);
        scError = mlkem.SymCryptMlKemkeySetValue(
            pbSrc,
            cbMlkemPubKey,
            .ENCAPSULATION_KEY,
            flags,
            pkCompositeMlKemkey.pkMlKemkey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptEckeySetValueCompositeEncodingPk(
            pInternalParams.ecurveId,
            pbSrc + cbMlkemPubKey,
            cbSrc - cbMlkemPubKey,
            eckeyFlags,
            pkCompositeMlKemkey.pkEcKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        pkCompositeMlKemkey.hasPrivateSeed = 0;
    } else {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlKemkeyGetValue(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    compositeMlKemkeyFormat: SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const allowedFlags: UINT32 = 0;
    var cbExpectedFormatSize: SIZE_T = 0;
    const pInternalParams = pkCompositeMlKemkey.pParams;

    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            hash.SymCryptWipe(pbDst, cbDst);
        }
    }

    if ((flags & ~allowedFlags) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    if (compositeMlKemkeyFormat == .NULL) {
        scError = .SYMCRYPT_INCOMPATIBLE_FORMAT;
        return scError;
    }

    scError = SymCryptCompositeMlKemSizeofKeyFormatFromParams(
        pInternalParams.params,
        compositeMlKemkeyFormat,
        &cbExpectedFormatSize,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (cbDst != cbExpectedFormatSize) {
        scError = .SYMCRYPT_WRONG_KEY_SIZE;
        return scError;
    }

    if (compositeMlKemkeyFormat == .IRTF_PRIVATE_SEED) {
        if (pkCompositeMlKemkey.hasPrivateSeed == 0) {
            scError = .SYMCRYPT_INCOMPATIBLE_FORMAT;
            return scError;
        }

        @memcpy(pbDst[0..pkCompositeMlKemkey.privateSeed.len], &pkCompositeMlKemkey.privateSeed);
    } else if (compositeMlKemkeyFormat == .LAMPS_PRIVATE_KEY) {
        scError = mlkem.SymCryptMlKemkeyGetValue(
            pkCompositeMlKemkey.pkMlKemkey,
            pbDst,
            SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            .PRIVATE_SEED,
            0,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptEckeyGetValueCompositeEncodingSk(
            pkCompositeMlKemkey.pkEcKey,
            pInternalParams.ecurveId,
            pbDst + SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
            cbDst - SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else if (compositeMlKemkeyFormat == .PUBLIC_KEY) {
        const cbMlKemPubKey: SIZE_T = cbDst - SymCryptCompositeGetSizeOfEncodedEcPk(pInternalParams.ecurveId);

        scError = mlkem.SymCryptMlKemkeyGetValue(
            pkCompositeMlKemkey.pkMlKemkey,
            pbDst,
            cbMlKemPubKey,
            .ENCAPSULATION_KEY,
            0,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        scError = SymCryptEckeyGetValueCompositeEncodingPk(
            pkCompositeMlKemkey.pkEcKey,
            pInternalParams.ecurveId,
            pbDst + cbMlKemPubKey,
            cbDst - cbMlKemPubKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}

fn SymCryptCompositeEcdhKemEncapsulateEx(
    pkEcKey: PSYMCRYPT_ECKEY,
    pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS,
    pbRandom: ?PCBYTE,
    cbRandom: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: SIZE_T,
) SYMCRYPT_ERROR {
    var eckeyFlags: UINT32 = SYMCRYPT_FLAG_ECKEY_ECDH;

    if (pInternalParams.ecurveId == .CURVE_25519) {
        eckeyFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }

    const pkEphemeralEcKey = SymCryptEckeyAllocate(pkEcKey.pCurve) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer SymCryptEckeyFree(pkEphemeralEcKey);

    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    if (pbRandom) |rand_ptr| {
        scError = SymCryptEckeySetValue(
            rand_ptr,
            cbRandom,
            null,
            0,
            pInternalParams.numFormat,
            pInternalParams.ecPointFormat,
            eckeyFlags,
            pkEphemeralEcKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else {
        scError = SymCryptEckeySetRandom(eckeyFlags, pkEphemeralEcKey);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    scError = SymCryptEcDhSecretAgreement(
        pkEphemeralEcKey,
        pkEcKey,
        pInternalParams.numFormat,
        0,
        pbSharedSecret,
        cbSharedSecret,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptEckeyGetValueCompositeEncodingPk(
        pkEphemeralEcKey,
        pInternalParams.ecurveId,
        pbCiphertext,
        cbCiphertext,
    );
}

pub export fn SymCryptCompositeMlKemEncapsulateEx(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbMlKemRandom: ?PCBYTE,
    cbMlKemRandom: SIZE_T,
    pbTradRandom: ?PCBYTE,
    cbTradRandom: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pInternalParams = pkCompositeMlKemkey.pParams;

    const pbMlKemCiphertext: PBYTE = pbCiphertext;
    var cbMlKemCiphertext: SIZE_T = 0;

    var rgbSharedSecretEcdh: [MAX_ECDH_KEM_SHARED_SECRET_SIZE]BYTE = undefined;
    const cbSharedSecretEcdh: SIZE_T = SymCryptEcurveSizeofFieldElement(pkCompositeMlKemkey.pkEcKey.pCurve);
    var rgbSharedSecretMlKem: [SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET]BYTE = undefined;
    defer {
        hash.SymCryptWipeKnownSize(&rgbSharedSecretEcdh, rgbSharedSecretEcdh.len);
        hash.SymCryptWipeKnownSize(&rgbSharedSecretMlKem, rgbSharedSecretMlKem.len);
    }

    var rgbEncodedEcPk: [SYMCRYPT_COMPOSITE_SIZEOF_MAX_ENCODED_EC_PUBLIC_KEY]BYTE = undefined;
    var sha3State: sha3.SYMCRYPT_SHA3_256_STATE = undefined;

    macros.ASSERT(cbSharedSecretEcdh <= rgbSharedSecretEcdh.len);

    if (pbMlKemRandom != null and cbMlKemRandom != SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pbTradRandom != null and cbTradRandom != SymCryptEckeySizeofPrivateKey(pkCompositeMlKemkey.pkEcKey)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbCiphertext != pInternalParams.cbCiphertext or
        cbAgreedSecret != COMPOSITE_MLKEM_SHARED_SECRET_SIZE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = mlkem.SymCryptMlKemSizeofCiphertextFromParams(
        pInternalParams.mlKemParams,
        &cbMlKemCiphertext,
    );
    macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);

    if (pbMlKemRandom) |rand_ptr| {
        scError = mlkem.SymCryptMlKemEncapsulateEx(
            pkCompositeMlKemkey.pkMlKemkey,
            rand_ptr,
            cbMlKemRandom,
            &rgbSharedSecretMlKem,
            rgbSharedSecretMlKem.len,
            pbMlKemCiphertext,
            cbMlKemCiphertext,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else {
        scError = mlkem.SymCryptMlKemEncapsulate(
            pkCompositeMlKemkey.pkMlKemkey,
            &rgbSharedSecretMlKem,
            rgbSharedSecretMlKem.len,
            pbMlKemCiphertext,
            cbMlKemCiphertext,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    const pbEcKeyCiphertext: PBYTE = pbCiphertext + cbMlKemCiphertext;
    const cbEcKeyCiphertext: SIZE_T = cbCiphertext - cbMlKemCiphertext;

    scError = SymCryptCompositeEcdhKemEncapsulateEx(
        pkCompositeMlKemkey.pkEcKey,
        pInternalParams,
        pbTradRandom,
        cbTradRandom,
        pbEcKeyCiphertext,
        cbEcKeyCiphertext,
        &rgbSharedSecretEcdh,
        cbSharedSecretEcdh,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const cbEncodedEcPk: SIZE_T = SymCryptCompositeGetSizeOfEncodedEcPk(pInternalParams.ecurveId);
    macros.ASSERT(cbEncodedEcPk <= rgbEncodedEcPk.len);

    scError = SymCryptEckeyGetValueCompositeEncodingPk(
        pkCompositeMlKemkey.pkEcKey,
        pInternalParams.ecurveId,
        &rgbEncodedEcPk,
        cbEncodedEcPk,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    sha3.SymCryptSha3_256Init(&sha3State);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbSharedSecretMlKem, rgbSharedSecretMlKem.len);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbSharedSecretEcdh, cbSharedSecretEcdh);
    sha3.SymCryptSha3_256Append(&sha3State, pbEcKeyCiphertext, cbEcKeyCiphertext);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbEncodedEcPk, cbEncodedEcPk);
    sha3.SymCryptSha3_256Append(&sha3State, pInternalParams.pbLabel, pInternalParams.cbLabel);
    sha3.SymCryptSha3_256Result(&sha3State, pbAgreedSecret);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlKemEncapsulate(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
    pbCiphertext: PBYTE,
    cbCiphertext: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptCompositeMlKemEncapsulateEx(
        pkCompositeMlKemkey,
        null,
        0,
        null,
        0,
        pbAgreedSecret,
        cbAgreedSecret,
        pbCiphertext,
        cbCiphertext,
    );
}

fn SymCryptCompositeEcdhKemDecapsulate(
    pkEcKey: PSYMCRYPT_ECKEY,
    pInternalParams: PCSYMCRYPT_COMPOSITE_MLKEM_INTERNAL_PARAMS,
    pbCiphertext: PCBYTE,
    cbCiphertext: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: SIZE_T,
) SYMCRYPT_ERROR {
    var eckeyFlags: UINT32 = SYMCRYPT_FLAG_ECKEY_ECDH;

    if (pInternalParams.ecurveId == .CURVE_25519) {
        eckeyFlags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }

    const pkEphemeralEcKey = SymCryptEckeyAllocate(pkEcKey.pCurve) orelse return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    defer SymCryptEckeyFree(pkEphemeralEcKey);

    const scError = SymCryptEckeySetValueCompositeEncodingPk(
        pInternalParams.ecurveId,
        pbCiphertext,
        cbCiphertext,
        eckeyFlags,
        pkEphemeralEcKey,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptEcDhSecretAgreement(
        pkEcKey,
        pkEphemeralEcKey,
        pInternalParams.numFormat,
        0,
        pbSharedSecret,
        cbSharedSecret,
    );
}

pub export fn SymCryptCompositeMlKemDecapsulate(
    pkCompositeMlKemkey: PCSYMCRYPT_COMPOSITE_MLKEMKEY,
    pbCiphertext: PCBYTE,
    cbCiphertext: SIZE_T,
    pbAgreedSecret: PBYTE,
    cbAgreedSecret: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pInternalParams = pkCompositeMlKemkey.pParams;

    const pbMlKemCiphertext: PCBYTE = pbCiphertext;
    var cbMlKemCiphertext: SIZE_T = 0;

    var rgbSharedSecretEcdh: [MAX_ECDH_KEM_SHARED_SECRET_SIZE]BYTE = undefined;
    const cbSharedSecretEcdh: SIZE_T = SymCryptEcurveSizeofFieldElement(pkCompositeMlKemkey.pkEcKey.pCurve);
    var rgbSharedSecretMlKem: [SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET]BYTE = undefined;
    defer {
        hash.SymCryptWipeKnownSize(&rgbSharedSecretEcdh, rgbSharedSecretEcdh.len);
        hash.SymCryptWipeKnownSize(&rgbSharedSecretMlKem, rgbSharedSecretMlKem.len);
    }

    var rgbEncodedEcPk: [SYMCRYPT_COMPOSITE_SIZEOF_MAX_ENCODED_EC_PUBLIC_KEY]BYTE = undefined;
    var sha3State: sha3.SYMCRYPT_SHA3_256_STATE = undefined;

    macros.ASSERT(cbSharedSecretEcdh <= rgbSharedSecretEcdh.len);

    if (cbCiphertext != pInternalParams.cbCiphertext or
        cbAgreedSecret != COMPOSITE_MLKEM_SHARED_SECRET_SIZE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = mlkem.SymCryptMlKemSizeofCiphertextFromParams(
        pInternalParams.mlKemParams,
        &cbMlKemCiphertext,
    );
    macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);

    scError = mlkem.SymCryptMlKemDecapsulate(
        pkCompositeMlKemkey.pkMlKemkey,
        pbMlKemCiphertext,
        cbMlKemCiphertext,
        &rgbSharedSecretMlKem,
        rgbSharedSecretMlKem.len,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const pbEcCiphertext: PCBYTE = pbCiphertext + cbMlKemCiphertext;
    const cbEcCiphertext: SIZE_T = cbCiphertext - cbMlKemCiphertext;

    scError = SymCryptCompositeEcdhKemDecapsulate(
        pkCompositeMlKemkey.pkEcKey,
        pInternalParams,
        pbEcCiphertext,
        cbEcCiphertext,
        &rgbSharedSecretEcdh,
        cbSharedSecretEcdh,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const cbEncodedEcPk: SIZE_T = SymCryptCompositeGetSizeOfEncodedEcPk(pInternalParams.ecurveId);
    macros.ASSERT(cbEncodedEcPk <= rgbEncodedEcPk.len);

    scError = SymCryptEckeyGetValueCompositeEncodingPk(
        pkCompositeMlKemkey.pkEcKey,
        pInternalParams.ecurveId,
        &rgbEncodedEcPk,
        cbEncodedEcPk,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    sha3.SymCryptSha3_256Init(&sha3State);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbSharedSecretMlKem, rgbSharedSecretMlKem.len);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbSharedSecretEcdh, cbSharedSecretEcdh);
    sha3.SymCryptSha3_256Append(&sha3State, pbEcCiphertext, cbEcCiphertext);
    sha3.SymCryptSha3_256Append(&sha3State, &rgbEncodedEcPk, cbEncodedEcPk);
    sha3.SymCryptSha3_256Append(&sha3State, pInternalParams.pbLabel, pInternalParams.cbLabel);
    sha3.SymCryptSha3_256Result(&sha3State, pbAgreedSecret);

    return .SYMCRYPT_NO_ERROR;
}
