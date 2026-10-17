//
// composite_mldsa.zig   ML-DSA related functionality
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const mldsa_primitives = @import("mldsa_primitives.zig");
const mldsa = @import("mldsa.zig");
const composite_encoding = @import("composite_encoding.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_HASH_ID = types.SYMCRYPT_HASH_ID;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_CACHED_ECURVE_ID = types.SYMCRYPT_CACHED_ECURVE_ID;
const SYMCRYPT_MLDSA_PARAMS = types.SYMCRYPT_MLDSA_PARAMS;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS = types.SYMCRYPT_COMPOSITE_MLDSA_PARAMS;
const SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT = types.SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT;

const PSYMCRYPT_MLDSAKEY = mldsa_primitives.PSYMCRYPT_MLDSAKEY;
const PCSYMCRYPT_ECURVE = composite_encoding.PCSYMCRYPT_ECURVE;
const PSYMCRYPT_ECKEY = composite_encoding.PSYMCRYPT_ECKEY;
const PCSYMCRYPT_ECKEY = composite_encoding.PCSYMCRYPT_ECKEY;

extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) ?*anyopaque;
extern fn SymCryptCallbackFree(pMem: *anyopaque) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptEckeyAllocate(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_ECKEY;
extern fn SymCryptEckeyFree(pkObj: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptEckeySetRandom(flags: UINT32, pkEckey: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptEckeyWipePrivateState(pkEckey: PSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptEcurveSizeofFieldElement(pCurve: PCSYMCRYPT_ECURVE) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptEcDsaSign(
    pkEckey: PCSYMCRYPT_ECKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptEcDsaVerify(
    pkEckey: PCSYMCRYPT_ECKEY,
    pbHashValue: PCBYTE,
    cbHashValue: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptSha256(pbData: ?PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha384(pbData: ?PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSha512(pbData: ?PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_SHA256_RESULT_SIZE: SIZE_T = 32;
pub const SYMCRYPT_SHA384_RESULT_SIZE: SIZE_T = 48;
pub const SYMCRYPT_SHA512_RESULT_SIZE: SIZE_T = 64;

pub const SYMCRYPT_FLAG_KEY_NO_FIPS: UINT32 = 0x00000100;
pub const SYMCRYPT_FLAG_ECKEY_ECDSA: UINT32 = 0x00001000;
pub const SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED: UINT32 = 0x00000001;
pub const SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH: SIZE_T = 255;

pub const SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256: SIZE_T = 83;
pub const SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512: SIZE_T = 83;
pub const SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512: SIZE_T = 96;
pub const SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512: SIZE_T = 96;

pub const SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256: SIZE_T = 1377;
pub const SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512: SIZE_T = 2017;
pub const SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512: SIZE_T = 2049;
pub const SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512: SIZE_T = 2689;

pub const SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA44_ECDSA_P256_SHA256: SIZE_T = 2492;
pub const SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P256_SHA512: SIZE_T = 3381;
pub const SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P384_SHA512: SIZE_T = 3413;
pub const SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA87_ECDSA_P384_SHA512: SIZE_T = 4731;

// 436F6D706F73697465416C676F726974686D5369676E61747572657332303235
const c_pszPrefix = "CompositeAlgorithmSignatures2025";
const c_cbPrefix: SIZE_T = c_pszPrefix.len;

const SYMCRYPT_COMPOSITE_MLDSA_44_ECDSA_P256_SHA256_LABEL = "COMPSIG-MLDSA44-ECDSA-P256-SHA256";
const SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P256_SHA512_LABEL = "COMPSIG-MLDSA65-ECDSA-P256-SHA512";
const SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P384_SHA512_LABEL = "COMPSIG-MLDSA65-ECDSA-P384-SHA512";
const SYMCRYPT_COMPOSITE_MLDSA_87_ECDSA_P384_SHA512_LABEL = "COMPSIG-MLDSA87-ECDSA-P384-SHA512";

const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P256_MAX: SIZE_T = 72;
const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P384_MAX: SIZE_T = 104;

//
// M' :=  Prefix || Label || len(ctx) || ctx || PH( M )
//        32     +  33    +  1        +  255  + 64      ==  385 bytes
//
const SYMCRYPT_COMPOSITE_MLDSA_SIZEOF_MU_MAX: usize =
    c_pszPrefix.len +
    SYMCRYPT_COMPOSITE_MLDSA_87_ECDSA_P384_SHA512_LABEL.len +
    @sizeOf(BYTE) +
    SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH +
    SYMCRYPT_SHA512_RESULT_SIZE;

//
// Mu + Mu Hash + ECDSA-P384 signature == 529 bytes
//
const SYMCRYPT_COMPOSITE_MLDSA_SIZEOF_SCRATCH_MAX: usize =
    SYMCRYPT_COMPOSITE_MLDSA_SIZEOF_MU_MAX +
    SYMCRYPT_SHA384_RESULT_SIZE +
    96;

pub const SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = extern struct {
    pcszLabel: [*:0]const u8,
    cbLabel: SIZE_T,

    mldsaParams: SYMCRYPT_MLDSA_PARAMS,
    eCurveId: SYMCRYPT_CACHED_ECURVE_ID,

    messagePreHashId: SYMCRYPT_HASH_ID,
    cbMessagePreHash: SIZE_T,

    messageRepresentativeHashId: SYMCRYPT_HASH_ID,
    cbMessageRepresentativeHash: SIZE_T,

    cbEncodedPrivateKey: SIZE_T,
    cbEncodedPublicKey: SIZE_T,
    cbEncodedSignatureMax: SIZE_T,
};
pub const PSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = *SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS;
pub const PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = *const SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS;

pub const SYMCRYPT_COMPOSITE_MLDSAKEY = extern struct {
    pParams: PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS,
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
    pkEckey: PSYMCRYPT_ECKEY,

    magic: SIZE_T,
};
pub const PSYMCRYPT_COMPOSITE_MLDSAKEY = *SYMCRYPT_COMPOSITE_MLDSAKEY;
pub const PCSYMCRYPT_COMPOSITE_MLDSAKEY = *const SYMCRYPT_COMPOSITE_MLDSAKEY;

const SymCryptCompositeMlDsaInternalParams_MLDSA44_ECDSA_P256_SHA256 = SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS{
    .pcszLabel = SYMCRYPT_COMPOSITE_MLDSA_44_ECDSA_P256_SHA256_LABEL.ptr,
    .cbLabel = SYMCRYPT_COMPOSITE_MLDSA_44_ECDSA_P256_SHA256_LABEL.len,
    .mldsaParams = .SYMCRYPT_MLDSA_PARAMS_MLDSA44,
    .eCurveId = .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
    .messagePreHashId = .SYMCRYPT_HASH_ID_SHA256,
    .cbMessagePreHash = SYMCRYPT_SHA256_RESULT_SIZE,
    .messageRepresentativeHashId = .SYMCRYPT_HASH_ID_SHA256,
    .cbMessageRepresentativeHash = SYMCRYPT_SHA256_RESULT_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256,
    .cbEncodedSignatureMax = SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA44_ECDSA_P256_SHA256,
};

const SymCryptCompositeMlDsaInternalParams_MLDSA65_ECDSA_P256_SHA512 = SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS{
    .pcszLabel = SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P256_SHA512_LABEL.ptr,
    .cbLabel = SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P256_SHA512_LABEL.len,
    .mldsaParams = .SYMCRYPT_MLDSA_PARAMS_MLDSA65,
    .eCurveId = .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
    .messagePreHashId = .SYMCRYPT_HASH_ID_SHA512,
    .cbMessagePreHash = SYMCRYPT_SHA512_RESULT_SIZE,
    .messageRepresentativeHashId = .SYMCRYPT_HASH_ID_SHA256,
    .cbMessageRepresentativeHash = SYMCRYPT_SHA256_RESULT_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512,
    .cbEncodedSignatureMax = SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P256_SHA512,
};

const SymCryptCompositeMlDsaInternalParams_MLDSA65_ECDSA_P384_SHA512 = SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS{
    .pcszLabel = SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P384_SHA512_LABEL.ptr,
    .cbLabel = SYMCRYPT_COMPOSITE_MLDSA_65_ECDSA_P384_SHA512_LABEL.len,
    .mldsaParams = .SYMCRYPT_MLDSA_PARAMS_MLDSA65,
    .eCurveId = .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
    .messagePreHashId = .SYMCRYPT_HASH_ID_SHA512,
    .cbMessagePreHash = SYMCRYPT_SHA512_RESULT_SIZE,
    .messageRepresentativeHashId = .SYMCRYPT_HASH_ID_SHA384,
    .cbMessageRepresentativeHash = SYMCRYPT_SHA384_RESULT_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512,
    .cbEncodedSignatureMax = SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P384_SHA512,
};

const SymCryptCompositeMlDsaInternalParams_MLDSA87_ECDSA_P384_SHA512 = SYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS{
    .pcszLabel = SYMCRYPT_COMPOSITE_MLDSA_87_ECDSA_P384_SHA512_LABEL.ptr,
    .cbLabel = SYMCRYPT_COMPOSITE_MLDSA_87_ECDSA_P384_SHA512_LABEL.len,
    .mldsaParams = .SYMCRYPT_MLDSA_PARAMS_MLDSA87,
    .eCurveId = .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
    .messagePreHashId = .SYMCRYPT_HASH_ID_SHA512,
    .cbMessagePreHash = SYMCRYPT_SHA512_RESULT_SIZE,
    .messageRepresentativeHashId = .SYMCRYPT_HASH_ID_SHA384,
    .cbMessageRepresentativeHash = SYMCRYPT_SHA384_RESULT_SIZE,
    .cbEncodedPrivateKey = SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512,
    .cbEncodedPublicKey = SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512,
    .cbEncodedSignatureMax = SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA87_ECDSA_P384_SHA512,
};

comptime {
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA44_ECDSA_P256_SHA256 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44 + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA44_ECDSA_P256_SHA256 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA44 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P256_MAX));

    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P256_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65 + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P256_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P256_MAX));

    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA65_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65 + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA65_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P384_MAX));

    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87 + composite_encoding.SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384));
    std.debug.assert(SYMCRYPT_COMPOSITE_MLDSA_SIGNATURE_SIZE_MLDSA87_ECDSA_P384_SHA512 ==
        (mldsa_primitives.SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA87 + SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_SIGNATURE_P384_MAX));
}

fn SymCryptCompositeMlDsaHash(
    hashId: SYMCRYPT_HASH_ID,
    pbData: ?PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) void {
    switch (hashId) {
        .SYMCRYPT_HASH_ID_SHA256 => {
            SymCryptSha256(pbData, cbData, pbResult);
        },
        .SYMCRYPT_HASH_ID_SHA384 => {
            SymCryptSha384(pbData, cbData, pbResult);
        },
        .SYMCRYPT_HASH_ID_SHA512 => {
            SymCryptSha512(pbData, cbData, pbResult);
        },
        else => {
            macros.ASSERT(false);
        },
    }
}

fn SymCryptCompositeMlDsaWipePrivateState(
    pkCompositeMlDsakey: PSYMCRYPT_COMPOSITE_MLDSAKEY,
) void {
    mldsa_primitives.SymCryptMlDsakeyWipePrivateState(pkCompositeMlDsakey.pkMlDsakey);
    SymCryptEckeyWipePrivateState(pkCompositeMlDsakey.pkEckey);
}

fn SymCryptCompositeMlDsaGetInternalParamsFromParams(
    params: SYMCRYPT_COMPOSITE_MLDSA_PARAMS,
    ppInternalParams: *PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS,
) SYMCRYPT_ERROR {
    switch (params) {
        .SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256 => {
            ppInternalParams.* = &SymCryptCompositeMlDsaInternalParams_MLDSA44_ECDSA_P256_SHA256;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512 => {
            ppInternalParams.* = &SymCryptCompositeMlDsaInternalParams_MLDSA65_ECDSA_P256_SHA512;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512 => {
            ppInternalParams.* = &SymCryptCompositeMlDsaInternalParams_MLDSA65_ECDSA_P384_SHA512;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512 => {
            ppInternalParams.* = &SymCryptCompositeMlDsaInternalParams_MLDSA87_ECDSA_P384_SHA512;
            return .SYMCRYPT_NO_ERROR;
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

pub export fn SymCryptCompositeMlDsaSizeofKeyFormatFromParams(
    params: SYMCRYPT_COMPOSITE_MLDSA_PARAMS,
    compositeMlDsakeyFormat: SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT,
    pcbKeyFormat: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = undefined;

    const scError = SymCryptCompositeMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    switch (compositeMlDsakeyFormat) {
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            pcbKeyFormat.* = pInternalParams.cbEncodedPrivateKey;
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            pcbKeyFormat.* = pInternalParams.cbEncodedPublicKey;
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL => {
            return .SYMCRYPT_INCOMPATIBLE_FORMAT;
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlDsaSizeofSignatureFromParams(
    params: SYMCRYPT_COMPOSITE_MLDSA_PARAMS,
    pcbSignature: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = undefined;

    const scError = SymCryptCompositeMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pcbSignature.* = pInternalParams.cbEncodedSignatureMax;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCompositeMlDsakeyAllocate(
    params: SYMCRYPT_COMPOSITE_MLDSA_PARAMS,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_COMPOSITE_MLDSAKEY {
    var pInternalParams: PCSYMCRYPT_COMPOSITE_MLDSA_INTERNAL_PARAMS = undefined;
    const scError = SymCryptCompositeMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const pCurve = composite_encoding.SymCryptGetCachedEcurve(pInternalParams.eCurveId) orelse return null;

    const pkMlDsakey = mldsa.SymCryptMlDsakeyAllocate(pInternalParams.mldsaParams) orelse return null;

    const pkEckey = SymCryptEckeyAllocate(pCurve) orelse {
        mldsa.SymCryptMlDsakeyFree(pkMlDsakey);
        return null;
    };

    const pMem = SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_COMPOSITE_MLDSAKEY)) orelse {
        mldsa.SymCryptMlDsakeyFree(pkMlDsakey);
        SymCryptEckeyFree(pkEckey);
        return null;
    };
    const pkCompositeKey: PSYMCRYPT_COMPOSITE_MLDSAKEY = @ptrCast(@alignCast(pMem));

    libmain.SymCryptWipeKnownSize(@ptrCast(pkCompositeKey), @sizeOf(SYMCRYPT_COMPOSITE_MLDSAKEY));

    pkCompositeKey.pParams = pInternalParams;
    pkCompositeKey.pkMlDsakey = pkMlDsakey;
    pkCompositeKey.pkEckey = pkEckey;

    macros.SET_MAGIC(pkCompositeKey);

    return pkCompositeKey;
}

pub export fn SymCryptCompositeMlDsakeyFree(
    pkCompositeMlDsakey: PSYMCRYPT_COMPOSITE_MLDSAKEY,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    mldsa.SymCryptMlDsakeyFree(pkCompositeMlDsakey.pkMlDsakey);
    SymCryptEckeyFree(pkCompositeMlDsakey.pkEckey);

    libmain.SymCryptWipeKnownSize(@ptrCast(pkCompositeMlDsakey), @sizeOf(SYMCRYPT_COMPOSITE_MLDSAKEY));
    SymCryptCallbackFree(@ptrCast(pkCompositeMlDsakey));
}

pub export fn SymCryptCompositeMlDsakeyGenerate(
    pkCompositeMlDsakey: PSYMCRYPT_COMPOSITE_MLDSAKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;

    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCryptCompositeMlDsaWipePrivateState(pkCompositeMlDsakey);
        }
    }

    if ((flags & ~allowedFlags) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    scError = mldsa.SymCryptMlDsakeyGenerate(pkCompositeMlDsakey.pkMlDsakey, flags);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptEckeySetRandom(flags | SYMCRYPT_FLAG_ECKEY_ECDSA, pkCompositeMlDsakey.pkEckey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}

pub export fn SymCryptCompositeMlDsakeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    compositeMlDsakeyFormat: SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT,
    flags: UINT32,
    pkCompositeMlDsakey: PSYMCRYPT_COMPOSITE_MLDSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbEncodedMlDsaKey: SIZE_T = 0;
    var cbEncodedEcKey: SIZE_T = 0;
    const allowedFlags: UINT32 = SYMCRYPT_FLAG_KEY_NO_FIPS;

    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCryptCompositeMlDsaWipePrivateState(pkCompositeMlDsakey);
        }
    }

    if ((flags & ~allowedFlags) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    switch (compositeMlDsakeyFormat) {
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            if (cbSrc != pkCompositeMlDsakey.pParams.cbEncodedPrivateKey) {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }

            cbEncodedMlDsaKey = mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE;
            cbEncodedEcKey = composite_encoding.SymCryptCompositeGetSizeOfEncodedEcSk(pkCompositeMlDsakey.pParams.eCurveId);
            macros.ASSERT((cbEncodedMlDsaKey + cbEncodedEcKey) == cbSrc);

            scError = mldsa.SymCryptMlDsakeySetValue(
                pbSrc,
                cbEncodedMlDsaKey,
                .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                flags,
                pkCompositeMlDsakey.pkMlDsakey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            scError = composite_encoding.SymCryptEckeySetValueCompositeEncodingSk(
                pkCompositeMlDsakey.pParams.eCurveId,
                pbSrc + cbEncodedMlDsaKey,
                cbEncodedEcKey,
                flags | SYMCRYPT_FLAG_ECKEY_ECDSA,
                pkCompositeMlDsakey.pkEckey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            SymCryptCompositeMlDsaWipePrivateState(pkCompositeMlDsakey);

            if (cbSrc != pkCompositeMlDsakey.pParams.cbEncodedPublicKey) {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }

            scError = mldsa_primitives.SymCryptMlDsaSizeofKeyFormatFromParams(
                pkCompositeMlDsakey.pParams.mldsaParams,
                .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                &cbEncodedMlDsaKey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            cbEncodedEcKey = composite_encoding.SymCryptCompositeGetSizeOfEncodedEcPk(pkCompositeMlDsakey.pParams.eCurveId);
            macros.ASSERT((cbEncodedMlDsaKey + cbEncodedEcKey) == cbSrc);

            scError = mldsa.SymCryptMlDsakeySetValue(
                pbSrc,
                cbEncodedMlDsaKey,
                .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                flags,
                pkCompositeMlDsakey.pkMlDsakey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            scError = composite_encoding.SymCryptEckeySetValueCompositeEncodingPk(
                pkCompositeMlDsakey.pParams.eCurveId,
                pbSrc + cbEncodedMlDsaKey,
                cbEncodedEcKey,
                flags | SYMCRYPT_FLAG_ECKEY_ECDSA,
                pkCompositeMlDsakey.pkEckey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL => {
            scError = .SYMCRYPT_INCOMPATIBLE_FORMAT;
            return scError;
        },
        else => {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        },
    }

    return scError;
}

pub export fn SymCryptCompositeMlDsakeyGetValue(
    pkCompositeMlDsakey: PCSYMCRYPT_COMPOSITE_MLDSAKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    compositeMlDsakeyFormat: SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var cbEncodedMlDsaKey: SIZE_T = 0;
    var cbEncodedEcKey: SIZE_T = 0;

    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            libmain.SymCryptWipe(@ptrCast(pbDst), cbDst);
        }
    }

    if (flags != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    switch (compositeMlDsakeyFormat) {
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            if (cbDst != pkCompositeMlDsakey.pParams.cbEncodedPrivateKey) {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }

            cbEncodedMlDsaKey = mldsa_primitives.SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE;
            cbEncodedEcKey = composite_encoding.SymCryptCompositeGetSizeOfEncodedEcSk(pkCompositeMlDsakey.pParams.eCurveId);
            macros.ASSERT((cbEncodedMlDsaKey + cbEncodedEcKey) == cbDst);

            scError = mldsa.SymCryptMlDsakeyGetValue(
                pkCompositeMlDsakey.pkMlDsakey,
                pbDst,
                cbEncodedMlDsaKey,
                .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            scError = composite_encoding.SymCryptEckeyGetValueCompositeEncodingSk(
                pkCompositeMlDsakey.pkEckey,
                pkCompositeMlDsakey.pParams.eCurveId,
                pbDst + cbEncodedMlDsaKey,
                cbEncodedEcKey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            if (cbDst != pkCompositeMlDsakey.pParams.cbEncodedPublicKey) {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            }

            scError = mldsa_primitives.SymCryptMlDsaSizeofKeyFormatFromParams(
                pkCompositeMlDsakey.pParams.mldsaParams,
                .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                &cbEncodedMlDsaKey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            cbEncodedEcKey = composite_encoding.SymCryptCompositeGetSizeOfEncodedEcPk(pkCompositeMlDsakey.pParams.eCurveId);
            macros.ASSERT((cbEncodedMlDsaKey + cbEncodedEcKey) == cbDst);

            scError = mldsa.SymCryptMlDsakeyGetValue(
                pkCompositeMlDsakey.pkMlDsakey,
                pbDst,
                cbEncodedMlDsaKey,
                .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }

            scError = composite_encoding.SymCryptEckeyGetValueCompositeEncodingPk(
                pkCompositeMlDsakey.pkEckey,
                pkCompositeMlDsakey.pParams.eCurveId,
                pbDst + cbEncodedMlDsaKey,
                cbEncodedEcKey,
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        },
        .SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL => {
            scError = .SYMCRYPT_INCOMPATIBLE_FORMAT;
            return scError;
        },
        else => {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        },
    }

    return scError;
}

pub export fn SymCryptCompositeMlDsaSign(
    pkCompositeMlDsakey: PCSYMCRYPT_COMPOSITE_MLDSAKEY,
    pbMessage: ?PCBYTE,
    cbMessage: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    flags: UINT32,
    pbSignature: PBYTE,
    cbSignature: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pbMlDsaSignature: PBYTE = pbSignature;
    var cbMlDsaSignature: SIZE_T = 0;
    var rgbScratch: [SYMCRYPT_COMPOSITE_MLDSA_SIZEOF_SCRATCH_MAX]BYTE = @splat(0);
    var cbResult: SIZE_T = 0;

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED;
    const bMessageIsPreHashed: bool = (flags & SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED) != 0;

    pcbResult.* = 0;

    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    defer {
        libmain.SymCryptWipeKnownSize(@ptrCast(&rgbScratch), @sizeOf(@TypeOf(rgbScratch)));

        if (scError != .SYMCRYPT_NO_ERROR) {
            libmain.SymCryptWipe(@ptrCast(pbSignature), cbSignature);
        }
    }

    if (((flags & ~allowedFlags) != 0) or
        (cbContext > SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH) or
        (cbSignature != pkCompositeMlDsakey.pParams.cbEncodedSignatureMax) or
        (bMessageIsPreHashed and (cbMessage != pkCompositeMlDsakey.pParams.cbMessagePreHash)))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    const cbContextU8: UINT8 = @intCast(cbContext);
    const cbMessageRepresentativeHash: SIZE_T = pkCompositeMlDsakey.pParams.cbMessageRepresentativeHash;
    const cbRawEcDsaSignature: SIZE_T = 2 * @as(SIZE_T, SymCryptEcurveSizeofFieldElement(pkCompositeMlDsakey.pkEckey.pCurve));

    scError = mldsa_primitives.SymCryptMlDsaSizeofSignatureFromParams(
        pkCompositeMlDsakey.pParams.mldsaParams,
        &cbMlDsaSignature,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var cbMessageRepresentative: SIZE_T = 0;
    cbMessageRepresentative += c_cbPrefix;
    cbMessageRepresentative += pkCompositeMlDsakey.pParams.cbLabel;
    cbMessageRepresentative += @sizeOf(UINT8);
    cbMessageRepresentative += cbContext;
    cbMessageRepresentative += pkCompositeMlDsakey.pParams.cbMessagePreHash;

    macros.ASSERT((cbMessageRepresentative + cbMessageRepresentativeHash + cbRawEcDsaSignature) <= @sizeOf(@TypeOf(rgbScratch)));

    var pbMessageRepresentative: PBYTE = &rgbScratch;

    @memcpy(pbMessageRepresentative[0..c_cbPrefix], c_pszPrefix[0..c_cbPrefix]);
    pbMessageRepresentative += c_cbPrefix;

    const cbLabel = pkCompositeMlDsakey.pParams.cbLabel;
    @memcpy(pbMessageRepresentative[0..cbLabel], pkCompositeMlDsakey.pParams.pcszLabel[0..cbLabel]);
    pbMessageRepresentative += cbLabel;

    pbMessageRepresentative[0] = cbContextU8;
    pbMessageRepresentative += 1;

    if (cbContext > 0) {
        @memcpy(pbMessageRepresentative[0..cbContext], pbContext.?[0..cbContext]);
        pbMessageRepresentative += cbContext;
    }

    if (bMessageIsPreHashed) {
        if (cbMessage > 0) {
            @memcpy(pbMessageRepresentative[0..cbMessage], pbMessage.?[0..cbMessage]);
        }
    } else {
        SymCryptCompositeMlDsaHash(
            pkCompositeMlDsakey.pParams.messagePreHashId,
            pbMessage,
            cbMessage,
            pbMessageRepresentative,
        );
    }

    pbMessageRepresentative = &rgbScratch;
    const pbMessageRepresentativeHash: PBYTE = pbMessageRepresentative + cbMessageRepresentative;
    const pbRawEcDsaSignature: PBYTE = pbMessageRepresentative + cbMessageRepresentative + cbMessageRepresentativeHash;

    SymCryptCompositeMlDsaHash(
        pkCompositeMlDsakey.pParams.messageRepresentativeHashId,
        pbMessageRepresentative,
        cbMessageRepresentative,
        pbMessageRepresentativeHash,
    );

    scError = mldsa.SymCryptMlDsaSign(
        pkCompositeMlDsakey.pkMlDsakey,
        pbMessageRepresentative,
        cbMessageRepresentative,
        pkCompositeMlDsakey.pParams.pcszLabel,
        pkCompositeMlDsakey.pParams.cbLabel,
        0,
        pbMlDsaSignature,
        cbMlDsaSignature,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptEcDsaSign(
        pkCompositeMlDsakey.pkEckey,
        pbMessageRepresentativeHash,
        cbMessageRepresentativeHash,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        pbRawEcDsaSignature,
        cbRawEcDsaSignature,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    const pbEncodedEcDsaSignature: PBYTE = pbSignature + cbMlDsaSignature;
    const cbEncodedEcDsaSignature: SIZE_T = cbSignature - cbMlDsaSignature;

    scError = composite_encoding.SymCryptEcdsaSigValueCompositeEncode(
        pbRawEcDsaSignature,
        cbRawEcDsaSignature,
        pbEncodedEcDsaSignature,
        cbEncodedEcDsaSignature,
        &cbResult,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pcbResult.* = cbMlDsaSignature + cbResult;

    return scError;
}

pub export fn SymCryptCompositeMlDsaVerify(
    pkCompositeMlDsakey: PCSYMCRYPT_COMPOSITE_MLDSAKEY,
    pbMessage: ?PCBYTE,
    cbMessage: SIZE_T,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbSignature: PCBYTE,
    cbSignature: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pbMlDsaSignature: PCBYTE = pbSignature;
    var cbMlDsaSignature: SIZE_T = 0;
    var rgbScratch: [SYMCRYPT_COMPOSITE_MLDSA_SIZEOF_SCRATCH_MAX]BYTE = @splat(0);

    const allowedFlags: UINT32 = SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED;
    const bMessageIsPreHashed: bool = (flags & SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED) != 0;

    macros.CHECK_MAGIC(pkCompositeMlDsakey);

    defer libmain.SymCryptWipeKnownSize(@ptrCast(&rgbScratch), @sizeOf(@TypeOf(rgbScratch)));

    scError = mldsa_primitives.SymCryptMlDsaSizeofSignatureFromParams(
        pkCompositeMlDsakey.pParams.mldsaParams,
        &cbMlDsaSignature,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (((flags & ~allowedFlags) != 0) or
        (cbContext > SYMCRYPT_COMPOSITE_MLDSA_CONTEXT_MAX_LENGTH) or
        (bMessageIsPreHashed and (cbMessage != pkCompositeMlDsakey.pParams.cbMessagePreHash)) or
        (cbSignature <= cbMlDsaSignature) or
        (cbSignature > pkCompositeMlDsakey.pParams.cbEncodedSignatureMax))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    const cbContextU8: UINT8 = @intCast(cbContext);
    const cbMessageRepresentativeHash: SIZE_T = pkCompositeMlDsakey.pParams.cbMessageRepresentativeHash;
    const cbRawEcDsaSignature: SIZE_T = 2 * @as(SIZE_T, SymCryptEcurveSizeofFieldElement(pkCompositeMlDsakey.pkEckey.pCurve));

    var cbMessageRepresentative: SIZE_T = 0;
    cbMessageRepresentative += c_cbPrefix;
    cbMessageRepresentative += pkCompositeMlDsakey.pParams.cbLabel;
    cbMessageRepresentative += @sizeOf(UINT8);
    cbMessageRepresentative += cbContext;
    cbMessageRepresentative += pkCompositeMlDsakey.pParams.cbMessagePreHash;

    macros.ASSERT((cbMessageRepresentative + cbMessageRepresentativeHash + cbRawEcDsaSignature) <= @sizeOf(@TypeOf(rgbScratch)));

    var pbMessageRepresentative: PBYTE = &rgbScratch;

    @memcpy(pbMessageRepresentative[0..c_cbPrefix], c_pszPrefix[0..c_cbPrefix]);
    pbMessageRepresentative += c_cbPrefix;

    const cbLabel = pkCompositeMlDsakey.pParams.cbLabel;
    @memcpy(pbMessageRepresentative[0..cbLabel], pkCompositeMlDsakey.pParams.pcszLabel[0..cbLabel]);
    pbMessageRepresentative += cbLabel;

    pbMessageRepresentative[0] = cbContextU8;
    pbMessageRepresentative += 1;

    if (cbContext > 0) {
        @memcpy(pbMessageRepresentative[0..cbContext], pbContext.?[0..cbContext]);
        pbMessageRepresentative += cbContext;
    }

    if (bMessageIsPreHashed) {
        if (cbMessage > 0) {
            @memcpy(pbMessageRepresentative[0..cbMessage], pbMessage.?[0..cbMessage]);
        }
    } else {
        SymCryptCompositeMlDsaHash(
            pkCompositeMlDsakey.pParams.messagePreHashId,
            pbMessage,
            cbMessage,
            pbMessageRepresentative,
        );
    }

    pbMessageRepresentative = &rgbScratch;
    const pbMessageRepresentativeHash: PBYTE = pbMessageRepresentative + cbMessageRepresentative;
    const pbRawEcDsaSignature: PBYTE = pbMessageRepresentative + cbMessageRepresentative + cbMessageRepresentativeHash;

    const pbEncodedEcDsaSignature: PCBYTE = pbSignature + cbMlDsaSignature;
    const cbEncodedEcDsaSignature: SIZE_T = cbSignature - cbMlDsaSignature;

    SymCryptCompositeMlDsaHash(
        pkCompositeMlDsakey.pParams.messageRepresentativeHashId,
        pbMessageRepresentative,
        cbMessageRepresentative,
        pbMessageRepresentativeHash,
    );

    scError = composite_encoding.SymCryptEcdsaSigValueCompositeDecode(
        pbEncodedEcDsaSignature,
        cbEncodedEcDsaSignature,
        pbRawEcDsaSignature,
        cbRawEcDsaSignature,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        scError = .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
        return scError;
    }

    scError = mldsa.SymCryptMlDsaVerify(
        pkCompositeMlDsakey.pkMlDsakey,
        pbMessageRepresentative,
        cbMessageRepresentative,
        pkCompositeMlDsakey.pParams.pcszLabel,
        pkCompositeMlDsakey.pParams.cbLabel,
        pbMlDsaSignature,
        cbMlDsaSignature,
        0,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptEcDsaVerify(
        pkCompositeMlDsakey.pkEckey,
        pbMessageRepresentativeHash,
        cbMessageRepresentativeHash,
        pbRawEcDsaSignature,
        cbRawEcDsaSignature,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return scError;
}
