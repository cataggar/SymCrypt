//
// data_accessors.zig
// Helper functions for accessing built-in constant structures.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");

const SIZE_T = types.SIZE_T;
const SYMCRYPT_BLOCKCIPHER_ID = types.SYMCRYPT_BLOCKCIPHER_ID;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const SYMCRYPT_ECURVE_ID = types.SYMCRYPT_ECURVE_ID;
const SYMCRYPT_HASH_ID = types.SYMCRYPT_HASH_ID;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_MAC_ID = types.SYMCRYPT_MAC_ID;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_OID_LIST_ID = types.SYMCRYPT_OID_LIST_ID;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const PCSYMCRYPT_OID = types.PCSYMCRYPT_OID;

pub const SYMCRYPT_ECURVE_PARAMS = types.SYMCRYPT_ECURVE_PARAMS;
pub const PCSYMCRYPT_ECURVE_PARAMS = types.PCSYMCRYPT_ECURVE_PARAMS;

pub const SYMCRYPT_MARVIN32_EXPANDED_SEED = opaque {};
pub const PCSYMCRYPT_MARVIN32_EXPANDED_SEED = *const SYMCRYPT_MARVIN32_EXPANDED_SEED;

// Block cipher algorithm pointers
extern const SymCryptAesBlockCipher: PCSYMCRYPT_BLOCKCIPHER;
extern const SymCryptDesBlockCipher: PCSYMCRYPT_BLOCKCIPHER;
extern const SymCrypt3DesBlockCipher: PCSYMCRYPT_BLOCKCIPHER;
extern const SymCryptDesxBlockCipher: PCSYMCRYPT_BLOCKCIPHER;
extern const SymCryptRc2BlockCipher: PCSYMCRYPT_BLOCKCIPHER;

// Elliptic curve parameter pointers
extern const SymCryptEcurveParamsNistP192: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNistP224: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNistP256: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNistP384: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNistP521: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNumsP256t1: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNumsP384t1: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsNumsP512t1: PCSYMCRYPT_ECURVE_PARAMS;
extern const SymCryptEcurveParamsCurve25519: PCSYMCRYPT_ECURVE_PARAMS;

// Hash algorithm pointers
extern const SymCryptMd2Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptMd4Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptMd5Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha1Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha224Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha256Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha384Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha512Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha512_224Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha512_256Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_224Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_256Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_384Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha3_512Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptShake128HashAlgorithm: PCSYMCRYPT_HASH;
extern const SymCryptShake256HashAlgorithm: PCSYMCRYPT_HASH;

// MAC algorithm pointers
extern const SymCryptHmacMd5Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha1Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha224Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha256Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha384Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha512Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha512_224Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha512_256Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha3_224Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha3_256Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha3_384Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptHmacSha3_512Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptAesCmacAlgorithm: PCSYMCRYPT_MAC;
extern const SymCryptKmac128Algorithm: PCSYMCRYPT_MAC;
extern const SymCryptKmac256Algorithm: PCSYMCRYPT_MAC;

// Marvin32 default seed pointer
extern const SymCryptMarvin32DefaultSeed: PCSYMCRYPT_MARVIN32_EXPANDED_SEED;

// OID lists and counts
pub const SYMCRYPT_MD5_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA1_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA224_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA256_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA384_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA512_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA512_224_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA512_256_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA3_224_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA3_256_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA3_384_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHA3_512_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHAKE128_OID_COUNT: usize = 2;
pub const SYMCRYPT_SHAKE256_OID_COUNT: usize = 2;

pub extern const SymCryptMd5OidList: [SYMCRYPT_MD5_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha1OidList: [SYMCRYPT_SHA1_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha224OidList: [SYMCRYPT_SHA224_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha256OidList: [SYMCRYPT_SHA256_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha384OidList: [SYMCRYPT_SHA384_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha512OidList: [SYMCRYPT_SHA512_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha512_224OidList: [SYMCRYPT_SHA512_224_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha512_256OidList: [SYMCRYPT_SHA512_256_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha3_224OidList: [SYMCRYPT_SHA3_224_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha3_256OidList: [SYMCRYPT_SHA3_256_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha3_384OidList: [SYMCRYPT_SHA3_384_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptSha3_512OidList: [SYMCRYPT_SHA3_512_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptShake128OidList: [SYMCRYPT_SHAKE128_OID_COUNT]SYMCRYPT_OID;
pub extern const SymCryptShake256OidList: [SYMCRYPT_SHAKE256_OID_COUNT]SYMCRYPT_OID;

pub export fn SymCryptGetBlockCipher(
    blockCipherId: SYMCRYPT_BLOCKCIPHER_ID,
) callconv(types.SYMCRYPT_CALL) ?PCSYMCRYPT_BLOCKCIPHER {
    return switch (blockCipherId) {
        .SYMCRYPT_BLOCKCIPHER_ID_AES => SymCryptAesBlockCipher,
        .SYMCRYPT_BLOCKCIPHER_ID_DES => SymCryptDesBlockCipher,
        .SYMCRYPT_BLOCKCIPHER_ID_3DES => SymCrypt3DesBlockCipher,
        .SYMCRYPT_BLOCKCIPHER_ID_DESX => SymCryptDesxBlockCipher,
        .SYMCRYPT_BLOCKCIPHER_ID_RC2 => SymCryptRc2BlockCipher,
        else => null,
    };
}

pub export fn SymCryptGetEcurveParams(
    ecurveId: SYMCRYPT_ECURVE_ID,
) callconv(types.SYMCRYPT_CALL) ?PCSYMCRYPT_ECURVE_PARAMS {
    return switch (ecurveId) {
        .SYMCRYPT_ECURVE_ID_NIST_P192 => SymCryptEcurveParamsNistP192,
        .SYMCRYPT_ECURVE_ID_NIST_P224 => SymCryptEcurveParamsNistP224,
        .SYMCRYPT_ECURVE_ID_NIST_P256 => SymCryptEcurveParamsNistP256,
        .SYMCRYPT_ECURVE_ID_NIST_P384 => SymCryptEcurveParamsNistP384,
        .SYMCRYPT_ECURVE_ID_NIST_P521 => SymCryptEcurveParamsNistP521,
        .SYMCRYPT_ECURVE_ID_NUMS_P256T1 => SymCryptEcurveParamsNumsP256t1,
        .SYMCRYPT_ECURVE_ID_NUMS_P384T1 => SymCryptEcurveParamsNumsP384t1,
        .SYMCRYPT_ECURVE_ID_NUMS_P512T1 => SymCryptEcurveParamsNumsP512t1,
        .SYMCRYPT_ECURVE_ID_CURVE25519 => SymCryptEcurveParamsCurve25519,
        else => null,
    };
}

pub export fn SymCryptGetHashAlgorithm(
    hashId: SYMCRYPT_HASH_ID,
) callconv(types.SYMCRYPT_CALL) ?PCSYMCRYPT_HASH {
    return switch (hashId) {
        .SYMCRYPT_HASH_ID_MD2 => SymCryptMd2Algorithm,
        .SYMCRYPT_HASH_ID_MD4 => SymCryptMd4Algorithm,
        .SYMCRYPT_HASH_ID_MD5 => SymCryptMd5Algorithm,
        .SYMCRYPT_HASH_ID_SHA1 => SymCryptSha1Algorithm,
        .SYMCRYPT_HASH_ID_SHA224 => SymCryptSha224Algorithm,
        .SYMCRYPT_HASH_ID_SHA256 => SymCryptSha256Algorithm,
        .SYMCRYPT_HASH_ID_SHA384 => SymCryptSha384Algorithm,
        .SYMCRYPT_HASH_ID_SHA512 => SymCryptSha512Algorithm,
        .SYMCRYPT_HASH_ID_SHA512_224 => SymCryptSha512_224Algorithm,
        .SYMCRYPT_HASH_ID_SHA512_256 => SymCryptSha512_256Algorithm,
        .SYMCRYPT_HASH_ID_SHA3_224 => SymCryptSha3_224Algorithm,
        .SYMCRYPT_HASH_ID_SHA3_256 => SymCryptSha3_256Algorithm,
        .SYMCRYPT_HASH_ID_SHA3_384 => SymCryptSha3_384Algorithm,
        .SYMCRYPT_HASH_ID_SHA3_512 => SymCryptSha3_512Algorithm,
        .SYMCRYPT_HASH_ID_SHAKE128 => SymCryptShake128HashAlgorithm,
        .SYMCRYPT_HASH_ID_SHAKE256 => SymCryptShake256HashAlgorithm,
        else => null,
    };
}

pub export fn SymCryptGetMacAlgorithm(
    macId: SYMCRYPT_MAC_ID,
) callconv(types.SYMCRYPT_CALL) ?PCSYMCRYPT_MAC {
    return switch (macId) {
        .SYMCRYPT_MAC_ID_HMAC_MD5 => SymCryptHmacMd5Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA1 => SymCryptHmacSha1Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA224 => SymCryptHmacSha224Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA256 => SymCryptHmacSha256Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA384 => SymCryptHmacSha384Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA512 => SymCryptHmacSha512Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA512_224 => SymCryptHmacSha512_224Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA512_256 => SymCryptHmacSha512_256Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA3_224 => SymCryptHmacSha3_224Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA3_256 => SymCryptHmacSha3_256Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA3_384 => SymCryptHmacSha3_384Algorithm,
        .SYMCRYPT_MAC_ID_HMAC_SHA3_512 => SymCryptHmacSha3_512Algorithm,
        .SYMCRYPT_MAC_ID_AES_CMAC => SymCryptAesCmacAlgorithm,
        .SYMCRYPT_MAC_ID_KMAC_128 => SymCryptKmac128Algorithm,
        .SYMCRYPT_MAC_ID_KMAC_256 => SymCryptKmac256Algorithm,
        else => null,
    };
}

pub export fn SymCryptGetMarvin32DefaultSeed() callconv(types.SYMCRYPT_CALL) PCSYMCRYPT_MARVIN32_EXPANDED_SEED {
    return SymCryptMarvin32DefaultSeed;
}

pub export fn SymCryptGetOidList(
    oidId: SYMCRYPT_OID_LIST_ID,
    pCount: ?*SIZE_T,
) callconv(types.SYMCRYPT_CALL) ?PCSYMCRYPT_OID {
    var oidCount: SIZE_T = 0;
    var pOidList: ?PCSYMCRYPT_OID = null;

    switch (oidId) {
        .SYMCRYPT_OID_LIST_ID_MD5 => {
            pOidList = &SymCryptMd5OidList[0];
            oidCount = SYMCRYPT_MD5_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA1 => {
            pOidList = &SymCryptSha1OidList[0];
            oidCount = SYMCRYPT_SHA1_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA224 => {
            pOidList = &SymCryptSha224OidList[0];
            oidCount = SYMCRYPT_SHA224_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA256 => {
            pOidList = &SymCryptSha256OidList[0];
            oidCount = SYMCRYPT_SHA256_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA384 => {
            pOidList = &SymCryptSha384OidList[0];
            oidCount = SYMCRYPT_SHA384_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA512 => {
            pOidList = &SymCryptSha512OidList[0];
            oidCount = SYMCRYPT_SHA512_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA512_224 => {
            pOidList = &SymCryptSha512_224OidList[0];
            oidCount = SYMCRYPT_SHA512_224_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA512_256 => {
            pOidList = &SymCryptSha512_256OidList[0];
            oidCount = SYMCRYPT_SHA512_256_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA3_224 => {
            pOidList = &SymCryptSha3_224OidList[0];
            oidCount = SYMCRYPT_SHA3_224_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA3_256 => {
            pOidList = &SymCryptSha3_256OidList[0];
            oidCount = SYMCRYPT_SHA3_256_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA3_384 => {
            pOidList = &SymCryptSha3_384OidList[0];
            oidCount = SYMCRYPT_SHA3_384_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHA3_512 => {
            pOidList = &SymCryptSha3_512OidList[0];
            oidCount = SYMCRYPT_SHA3_512_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHAKE128 => {
            pOidList = &SymCryptShake128OidList[0];
            oidCount = SYMCRYPT_SHAKE128_OID_COUNT;
        },
        .SYMCRYPT_OID_LIST_ID_SHAKE256 => {
            pOidList = &SymCryptShake256OidList[0];
            oidCount = SYMCRYPT_SHAKE256_OID_COUNT;
        },
        else => return null,
    }

    if (pCount) |cnt| {
        cnt.* = oidCount;
    }

    return pOidList;
}
