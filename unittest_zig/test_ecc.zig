// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const kat = @import("kat.zig");
const cb = @import("callback.zig");
const mont = @import("test_montgomery.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800c;
const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8007;
const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE: u32 = 0x8010;
const SYMCRYPT_FIPS_FAILURE: u32 = 0x8009;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

const SYMCRYPT_ECPOINT_FORMAT_X: i32 = 1;
const SYMCRYPT_ECPOINT_FORMAT_XY: i32 = 2;

const SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS: i32 = 1;
const SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS: i32 = 2;
const SYMCRYPT_ECURVE_TYPE_MONTGOMERY: i32 = 3;

const SYMCRYPT_ECURVE_GEN_ALG_ID_NULL: i32 = 0;
const SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL: u32 = 1;

const SYMCRYPT_FLAG_DATA_PUBLIC: u32 = 0x01;
const SYMCRYPT_FLAG_ECPOINT_EQUAL: u32 = 0x01;
const SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL: u32 = 0x02;
const SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL: u32 = 0x20;
const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x0100;
const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: u32 = 0x0200;
const SYMCRYPT_FLAG_ECKEY_ECDSA: u32 = 0x1000;
const SYMCRYPT_FLAG_ECKEY_ECDH: u32 = 0x2000;
const SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION: u32 = 0x08;

const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;
const SYMCRYPT_SHA512_RESULT_SIZE: usize = 64;
const SYMCRYPT_BITSIZE_P521: usize = 521;
const ECKEY_MAXPUBKEYSIZE: usize = 2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8);
const ECKEY_SEEDED_KEYGEN_MIN_SEED_SIZE: usize = 48;
const ECKEY_SEEDED_KEYGEN_MAX_SEED_SIZE: usize = 256;
const NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS: u32 = 100;

pub const SymCryptEcurveParams = extern struct {
    version: u32,
    curveType: i32,
    algId: i32,
    cbFieldLength: u32,
    cbSubgroupOrder: u32,
    cbCofactor: u32,
    cbSeed: u32,
};

extern const SymCryptEcurveParamsNistP192: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNistP224: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNistP256: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNistP384: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNistP521: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNumsP256t1: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNumsP384t1: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsNumsP512t1: *const SymCryptEcurveParams;
extern const SymCryptEcurveParamsCurve25519: *const SymCryptEcurveParams;

const rgbW25519 align(8) = [_]u8{
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00,
    0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // p
    0x7F, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xED,
    // A
    0x2A, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x98, 0x49, 0x14, 0xA1, 0x44,
    // B
    0x7B, 0x42, 0x5E, 0xD0,
    0x97, 0xB4, 0x25, 0xED, 0x09, 0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED, 0x09, 0x7B, 0x42,
    0x5E, 0xD0, 0x97, 0xB4, 0x26, 0x0B, 0x5E, 0x9C, 0x77, 0x10, 0xC8, 0x64,
    // x
    0x2A, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAD, 0x24, 0x5A,
    // y
    0x5F, 0x51, 0xE6, 0x5E,
    0x47, 0x5F, 0x79, 0x4B, 0x1F, 0xE1, 0x22, 0xD3, 0x88, 0xB7, 0x2E, 0xB3, 0x6D, 0xC2, 0xB2, 0x81,
    0x92, 0x83, 0x9E, 0x4D, 0xD6, 0x16, 0x3A, 0x5D, 0x81, 0x31, 0x2C, 0x14,
    // q
    0x10, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0xDE, 0xF9, 0xDE,
    0xA2, 0xF7, 0x9C, 0xD6, 0x58, 0x12, 0x63, 0x1A, 0x5C, 0xF5, 0xD3, 0xED,
    // h
    0x08,
};
const SymCryptEcurveParamsW25519: *const SymCryptEcurveParams = @ptrCast(@alignCast(&rgbW25519));

const rgbW448 align(8) = [_]u8{
    0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x38, 0x00, 0x00, 0x00,
    0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // p
    0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF,
    // A
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xA9,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0x1A, 0x76, 0xD4, 0x1F,
    // B
    0x5E, 0xD0, 0x97, 0xB4,
    0x25, 0xED, 0x09, 0x7B, 0x42, 0x5E, 0xD0, 0x97, 0xB4, 0x25, 0xED, 0x09, 0x7B, 0x42, 0x5E, 0xD0,
    0x97, 0xB4, 0x25, 0xED, 0x09, 0x7B, 0x42, 0x5E, 0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7,
    0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x71, 0xC7, 0x1C, 0x72, 0xC8, 0x7B,
    0x7C, 0xC6, 0x9F, 0x70,
    // x
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xCB, 0x91,
    // y
    0x7D, 0x23, 0x5D, 0x12,
    0x95, 0xF5, 0xB1, 0xF6, 0x6C, 0x98, 0xAB, 0x6E, 0x58, 0x32, 0x6F, 0xCE, 0xCB, 0xAE, 0x5D, 0x34,
    0xF5, 0x55, 0x45, 0xD0, 0x60, 0xF7, 0x5D, 0xC2, 0x8D, 0xF3, 0xF6, 0xED, 0xB8, 0x02, 0x7E, 0x23,
    0x46, 0x43, 0x0D, 0x21, 0x13, 0x12, 0xC4, 0xB1, 0x50, 0x67, 0x7A, 0xF7, 0x6F, 0xD7, 0x22, 0x3D,
    0x45, 0x7B, 0x5B, 0x1A,
    // q
    0x3F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7C, 0xCA, 0x23, 0xE9, 0xC4, 0x4E, 0xDB, 0x49, 0xAE, 0xD6, 0x36, 0x90, 0x21, 0x6C, 0xC2, 0x72,
    0x8D, 0xC5, 0x8F, 0x55, 0x23, 0x78, 0xC2, 0x92, 0xAB, 0x58, 0x44, 0xF3,
    // h
    0x04,
};
const SymCryptEcurveParamsW448: *const SymCryptEcurveParams = @ptrCast(@alignCast(&rgbW448));

extern const SymCryptSha1Algorithm: *const anyopaque;
extern const SymCryptSha256Algorithm: *const anyopaque;
extern const SymCryptSha384Algorithm: *const anyopaque;
extern const SymCryptSha512Algorithm: *const anyopaque;

extern fn SymCryptEcurveAllocate(pParams: *const anyopaque, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptEcurveFree(pCurve: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEcurveSizeofFieldElement(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveSizeofScalarMultiplier(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveDigitsofScalarMultiplier(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveBitsizeofFieldModulus(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveBitsizeofGroupOrder(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveGroupOrder(pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEcurvePrivateKeyDefaultFormat(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveHighBitRestrictionNumOfBits(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveHighBitRestrictionPosition(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEcurveHighBitRestrictionValue(pCurve: ?*const anyopaque) callconv(.c) u32;

extern fn SymCryptSizeofEcpointFromCurve(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptSizeofEckeyFromCurve(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptSizeofIntFromDigits(nDigits: u32) callconv(.c) u32;

extern fn SymCryptEcpointCreate(pbBuffer: [*]u8, cbBuffer: usize, pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEckeyCreate(pbBuffer: [*]u8, cbBuffer: usize, pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptIntCreate(pbBuffer: [*]u8, cbBuffer: usize, nDigits: u32) callconv(.c) ?*anyopaque;

extern fn SymCryptEcpointSetZero(
    pCurve: ?*const anyopaque,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointSetDistinguishedPoint(
    pCurve: ?*const anyopaque,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointSetRandom(
    pCurve: ?*const anyopaque,
    piScalar: ?*anyopaque,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointSetValue(
    pCurve: ?*const anyopaque,
    pbSrc: [*]const u8,
    cbSrc: usize,
    numFormat: i32,
    ecPointFormat: i32,
    poDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointGetValue(
    pCurve: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    numFormat: i32,
    ecPointFormat: i32,
    pbDst: [*]u8,
    cbDst: usize,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointOnCurve(
    pCurve: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointIsEqual(
    pCurve: ?*const anyopaque,
    poSrc1: ?*const anyopaque,
    poSrc2: ?*const anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointIsZero(
    pCurve: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointAdd(
    pCurve: ?*const anyopaque,
    poSrc1: ?*const anyopaque,
    poSrc2: ?*const anyopaque,
    poDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointAddDiffNonZero(
    pCurve: ?*const anyopaque,
    poSrc1: ?*const anyopaque,
    poSrc2: ?*const anyopaque,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointDouble(
    pCurve: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    poDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptEcpointScalarMul(
    pCurve: ?*const anyopaque,
    piScalar: ?*const anyopaque,
    poSrc: ?*const anyopaque,
    flags: u32,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptEcpointMultiScalarMul(
    pCurve: ?*const anyopaque,
    piTable: [*]const ?*const anyopaque,
    poTable: [*]const ?*const anyopaque,
    nPoints: u32,
    flags: u32,
    poDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptEckeyAllocate(pCurve: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptEckeyFree(pkObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptEckeySizeofPublicKey(pkEckey: ?*const anyopaque, ecPointFormat: i32) callconv(.c) u32;
extern fn SymCryptEckeySizeofPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptEckeySetValue(
    pbPrivateKey: ?[*]const u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]const u8,
    cbPublicKey: usize,
    numFormat: i32,
    ecPointFormat: i32,
    flags: u32,
    pkDst: ?*anyopaque,
) callconv(.c) u32;
extern fn SymCryptEckeyGetValue(
    pkEckey: ?*const anyopaque,
    pbPrivateKey: ?[*]u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]u8,
    cbPublicKey: usize,
    numFormat: i32,
    ecPointFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptEckeySetRandom(flags: u32, pkDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptEckeyDerive(
    pkEckey: ?*anyopaque,
    pbSeed: [*]const u8,
    cbSeed: usize,
    flags: u32,
) callconv(.c) u32;

extern fn SymCryptEcDsaSign(
    pkEckey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    numFormat: i32,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;
extern fn SymCryptEcDsaSignEx(
    pkEckey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    piK: ?*const anyopaque,
    numFormat: i32,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;
extern fn SymCryptEcDsaVerify(
    pkEckey: ?*const anyopaque,
    pbHashValue: [*]const u8,
    cbHashValue: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
    numFormat: i32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptEcDhSecretAgreement(
    pkPrivate: ?*const anyopaque,
    pkPublic: ?*const anyopaque,
    numFormat: i32,
    flags: u32,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) u32;

extern fn SymCryptIntAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptIntFree(piObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntSetValue(pbSrc: [*]const u8, cbSrc: usize, format: i32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntSetValueUint32(u32Src: u32, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntCopy(piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntAddMixedSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntSubUint32(piSrc1: ?*const anyopaque, u32Src2: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntDivMod(
    piSrc: ?*const anyopaque,
    pdDivisor: ?*const anyopaque,
    piQuotient: ?*anyopaque,
    piRemainder: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntIsEqual(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntFromModulus(pmSrc: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptDivisorFromModulus(pmSrc: ?*anyopaque) callconv(.c) ?*anyopaque;

extern fn SymCryptHashResultSize(pHashAlgorithm: ?*const anyopaque) callconv(.c) usize;
extern fn SymCryptHash(
    pHashAlgorithm: ?*const anyopaque,
    pbData: [*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void;
extern fn SymCryptSha512(pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

extern fn scTestEcurveScratchCommon(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn scTestEcurveScratchScalar(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn scTestEcurveScratchMultiScalar(pCurve: ?*const anyopaque, nPoints: u32) callconv(.c) u32;
extern fn scTestEcurveScratchGetSetValue(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn scTestEcurveGOrdDigits(pCurve: ?*const anyopaque) callconv(.c) u32;
extern fn scTestScratchBytesForIntDivMod(nSrcDigits: u32, nDivisorDigits: u32) callconv(.c) u32;
extern fn scTestEckeyGetPublicKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn scTestEckeyGetPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn scTestSha256Init(pState: [*]u8) callconv(.c) void;
extern fn scTestSha256Append(pState: [*]u8, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestSha256Result(pState: [*]u8, pbResult: [*]u8) callconv(.c) void;

const EccCurveEntry = struct {
    pszCurveName: []const u8,
    ppParams: *const *const SymCryptEcurveParams,
    pCurve: ?*anyopaque = null,
};

var rgbInternalCurves = [_]EccCurveEntry{
    .{ .pszCurveName = "nistP192", .ppParams = &SymCryptEcurveParamsNistP192 },
    .{ .pszCurveName = "nistP224", .ppParams = &SymCryptEcurveParamsNistP224 },
    .{ .pszCurveName = "nistP256", .ppParams = &SymCryptEcurveParamsNistP256 },
    .{ .pszCurveName = "nistP384", .ppParams = &SymCryptEcurveParamsNistP384 },
    .{ .pszCurveName = "nistP521", .ppParams = &SymCryptEcurveParamsNistP521 },
    .{ .pszCurveName = "numsP256t1", .ppParams = &SymCryptEcurveParamsNumsP256t1 },
    .{ .pszCurveName = "numsP384t1", .ppParams = &SymCryptEcurveParamsNumsP384t1 },
    .{ .pszCurveName = "numsP512t1", .ppParams = &SymCryptEcurveParamsNumsP512t1 },
    .{ .pszCurveName = "curve25519", .ppParams = &SymCryptEcurveParamsCurve25519 },
    .{ .pszCurveName = "W25519", .ppParams = &SymCryptEcurveParamsW25519 },
    .{ .pszCurveName = "W448", .ppParams = &SymCryptEcurveParamsW448 },
};

const rgbPrivateKeyFormatNames = [_][]const u8{
    "Null",
    "Canonical",
    "DivH",
    "DivHTimesH",
    "TimesH",
};

fn getHashAlgorithm(pszHashName: []const u8, line: i64, ppHash: *?*const anyopaque) bool {
    if (std.mem.eql(u8, pszHashName, "SHA1")) {
        ppHash.* = SymCryptSha1Algorithm;
    } else if (std.mem.eql(u8, pszHashName, "SHA224")) {
        h.zdprint("Ecdsa record at line {d} is skipped due to unsupported hash function ({s}).\n", .{ line, pszHashName });
        return false;
    } else if (std.mem.eql(u8, pszHashName, "SHA256")) {
        ppHash.* = SymCryptSha256Algorithm;
    } else if (std.mem.eql(u8, pszHashName, "SHA384")) {
        ppHash.* = SymCryptSha384Algorithm;
    } else if (std.mem.eql(u8, pszHashName, "SHA512")) {
        ppHash.* = SymCryptSha512Algorithm;
    } else {
        h.zdprint("Assuming no hash function at line {d} for unknown hash function ({s}).\n", .{ line, pszHashName });
        ppHash.* = null;
    }
    return true;
}

fn testEccArithmetic(pCurve: ?*const anyopaque) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const pmGOrd = SymCryptEcurveGroupOrder(pCurve);

    const MULTIMUL_POINTS: u32 = 2;
    var poTable: [2]?*const anyopaque = .{ null, null };
    var piTable: [2]?*const anyopaque = .{ null, null };

    var pbHashValue: [2 * SYMCRYPT_SHA512_RESULT_SIZE]u8 = std.mem.zeroes([2 * SYMCRYPT_SHA512_RESULT_SIZE]u8);
    const pbMessage = [_]u8{ 'h', 'e', 'l', 'l', 'o' };

    const cbEcpointSize: usize = SymCryptSizeofEcpointFromCurve(pCurve);
    const nScalarDigits: u32 = SymCryptEcurveDigitsofScalarMultiplier(pCurve);
    const cbIntScalarSize: usize = SymCryptSizeofIntFromDigits(nScalarDigits);
    const cbIntLargeSize: usize = SymCryptSizeofIntFromDigits(nScalarDigits + 1);
    const cbEckeySize: usize = SymCryptSizeofEckeyFromCurve(pCurve);

    const cbScratch: usize = @max(
        scTestEcurveScratchCommon(pCurve),
        scTestScratchBytesForIntDivMod(nScalarDigits + 1, scTestEcurveGOrdDigits(pCurve)),
    );
    const cbScratchMul: usize = scTestEcurveScratchScalar(pCurve);
    const cbScratchMultiMul: usize = scTestEcurveScratchMultiScalar(pCurve, MULTIMUL_POINTS);
    const cbScratchGetSet: usize = scTestEcurveScratchGetSetValue(pCurve);
    const cbSignature: usize = 2 * @as(usize, SymCryptEcurveSizeofFieldElement(pCurve));
    const cbAgreedSecret: usize = SymCryptEcurveSizeofFieldElement(pCurve);
    const cbBuffer: usize = cbSignature;

    const cbWorkSpace: usize = 3 * cbEcpointSize + 2 * cbIntScalarSize + cbIntLargeSize + 2 * cbEckeySize +
        cbScratch + cbScratchMul + cbScratchMultiMul + cbScratchGetSet + cbSignature + cbBuffer;

    const pbWorkSpaceRaw = SymCryptCallbackAlloc(cbWorkSpace);
    h.check(pbWorkSpaceRaw != null, "Memory allocation failed");
    const pbWorkSpace: [*]u8 = @ptrCast(pbWorkSpaceRaw.?);

    var pCurr: [*]u8 = pbWorkSpace;

    const poP1 = SymCryptEcpointCreate(pCurr, cbEcpointSize, pCurve);
    h.check(poP1 != null, "P1 creation failed");
    pCurr += cbEcpointSize;

    const poP2 = SymCryptEcpointCreate(pCurr, cbEcpointSize, pCurve);
    h.check(poP2 != null, "P2 creation failed");
    pCurr += cbEcpointSize;

    const poP3 = SymCryptEcpointCreate(pCurr, cbEcpointSize, pCurve);
    h.check(poP3 != null, "P3 creation failed");
    pCurr += cbEcpointSize;

    const piSc1 = SymCryptIntCreate(pCurr, cbIntScalarSize, nScalarDigits);
    h.check(piSc1 != null, "S1 allocation failed");
    pCurr += cbIntScalarSize;

    const piSc2 = SymCryptIntCreate(pCurr, cbIntScalarSize, nScalarDigits);
    h.check(piSc2 != null, "S2 allocation failed");
    pCurr += cbIntScalarSize;

    const piLarge = SymCryptIntCreate(pCurr, cbIntLargeSize, nScalarDigits + 1);
    h.check(piLarge != null, "Large int allocation failed");
    pCurr += cbIntLargeSize;

    const pkKey1 = SymCryptEckeyCreate(pCurr, cbEckeySize, pCurve);
    h.check(pkKey1 != null, "Eckey 1 allocation failed");
    pCurr += cbEckeySize;

    const pkKey2 = SymCryptEckeyCreate(pCurr, cbEckeySize, pCurve);
    h.check(pkKey2 != null, "Eckey 2 allocation failed");
    pCurr += cbEckeySize;

    const pbScratch: [*]u8 = pCurr;
    const pbScratchMul: [*]u8 = pbScratch + cbScratch;
    const pbScratchMultiMul: [*]u8 = pbScratchMul + cbScratchMul;
    const pbScratchGetSet: [*]u8 = pbScratchMultiMul + cbScratchMultiMul;
    const pbSignature: [*]u8 = pbScratchGetSet + cbScratchGetSet;
    const pbAgreedSecret1: [*]u8 = pbSignature;
    const pbAgreedSecret2: [*]u8 = pbSignature + cbAgreedSecret;
    const pbBuffer: [*]u8 = pbSignature + cbSignature;

    poTable[0] = poP1;
    poTable[1] = poP2;
    piTable[0] = piSc1;
    piTable[1] = piSc2;

    SymCryptEcpointSetZero(pCurve, poP1, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP1, pbScratch, cbScratch) != 0, "Zero point is not on curve!");
    h.check(SymCryptEcpointIsZero(pCurve, poP1, pbScratch, cbScratch) != 0, "Zero point is not zero!");

    SymCryptEcpointSetDistinguishedPoint(pCurve, poP1, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP1, pbScratch, cbScratch) != 0, "Distinguished point is not on curve!");
    h.check(SymCryptEcpointIsZero(pCurve, poP1, pbScratch, cbScratch) == 0, "Distinguished point is zero!");

    SymCryptEcpointDouble(pCurve, poP1, poP2, 0, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Doubled point not on curve!");

    SymCryptEcpointAddDiffNonZero(pCurve, poP1, poP2, poP2, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Tripled point not on curve!");

    SymCryptIntSetValueUint32(3, piSc1);
    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptIntSetValueUint32(5, piSc2);
    scError = SymCryptEcpointScalarMul(pCurve, piSc2, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");

    SymCryptEcpointAdd(pCurve, poP2, poP3, poP2, 0, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "P2 not on curve!");

    SymCryptIntSetValueUint32(8, piSc1);
    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptIntSetValueUint32(8, piSc1);
    SymCryptIntSetValueUint32(0, piSc2);
    scError = SymCryptEcpointMultiScalarMul(pCurve, &piTable, &poTable, MULTIMUL_POINTS, SYMCRYPT_FLAG_DATA_PUBLIC, poP3, pbScratchMultiMul, cbScratchMultiMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Multi Scalar Multiplying failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptIntSetValueUint32(6, piSc1);
    SymCryptIntSetValueUint32(17, piSc2);
    scError = SymCryptEcpointMultiScalarMul(pCurve, &piTable, &poTable, MULTIMUL_POINTS, SYMCRYPT_FLAG_DATA_PUBLIC, poP3, pbScratchMultiMul, cbScratchMultiMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Multi Scalar Multiplying failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");

    SymCryptIntSetValueUint32(142, piSc1);
    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP1, 0, poP2, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptEcpointSetRandom(pCurve, piSc1, poP2, pbScratchMul, cbScratchMul);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Random not on curve!");

    SymCryptEcpointSetRandom(pCurve, piSc2, poP3, pbScratchMul, cbScratchMul);
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Random not on curve!");

    SymCryptEcpointAdd(pCurve, poP2, poP3, poP2, 0, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Random not on curve!");

    const carry = SymCryptIntAddMixedSize(piSc1, piSc2, piLarge);
    h.check(carry == 0, "Adding the two scalars cannot fit the larger integer");

    SymCryptIntDivMod(piLarge, SymCryptDivisorFromModulus(pmGOrd), null, piSc2, pbScratch, cbScratch);
    scError = SymCryptEcpointScalarMul(pCurve, piSc2, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P1 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptIntCopy(SymCryptIntFromModulus(pmGOrd), piSc1);
    _ = SymCryptIntSubUint32(piSc1, 1, piSc1);

    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP2, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P2 failed");
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "Multiplied point not on curve!");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, SYMCRYPT_FLAG_ECPOINT_NEG_EQUAL, pbScratch, cbScratch) != 0, " P2 != -P3 ");

    scError = SymCryptEcpointGetValue(pCurve, poP2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, pbSignature, cbSignature, rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointGetValue failed");

    scError = SymCryptEcpointSetValue(pCurve, pbSignature, cbSignature, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, poP3, rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointSetValue failed");
    h.check(SymCryptEcpointIsEqual(pCurve, poP2, poP3, SYMCRYPT_FLAG_ECPOINT_EQUAL, pbScratch, cbScratch) != 0, " P2 != P3 ");

    SymCryptEcpointSetRandom(pCurve, piSc2, poP2, pbScratchMul, cbScratchMul);
    h.check(SymCryptEcpointOnCurve(pCurve, poP2, pbScratch, cbScratch) != 0, "Random point not on curve!");

    SymCryptEcpointAdd(pCurve, poP2, poP3, poP3, 0, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "P2 + P3 not on curve!");

    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP2, 0, poP2, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying P2 failed");

    SymCryptEcpointAdd(pCurve, poP2, poP3, poP3, 0, pbScratch, cbScratch);
    h.check(SymCryptEcpointOnCurve(pCurve, poP3, pbScratch, cbScratch) != 0, "P2 + P3 not on curve!");

    scError = SymCryptEcpointGetValue(pCurve, poP3, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, pbBuffer, cbBuffer, rng.scTestRngUint32(&rng.g_rng) & SYMCRYPT_FLAG_DATA_PUBLIC, pbScratchGetSet, cbScratchGetSet);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointGetValue failed");
    h.check(std.mem.eql(u8, pbSignature[0..cbSignature], pbBuffer[0..cbSignature]), "Mismatch on get / set value ops");

    SymCryptIntSetValueUint32(0, piSc1);
    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointScalarMul failed");
    h.check(SymCryptEcpointIsZero(pCurve, poP3, pbScratch, cbScratch) != 0, "Result is not zero!");

    SymCryptIntSetValueUint32(35, piSc1);
    SymCryptEcpointSetZero(pCurve, poP1, pbScratch, cbScratch);
    scError = SymCryptEcpointScalarMul(pCurve, piSc1, poP1, 0, poP3, pbScratchMul, cbScratchMul);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcpointScalarMul failed");
    h.check(SymCryptEcpointIsZero(pCurve, poP3, pbScratch, cbScratch) != 0, "Result is not zero!");

    const msbNumOfBits = SymCryptEcurveHighBitRestrictionNumOfBits(pCurve);
    h.check(msbNumOfBits < 33, "Invalid high bit restriction num of bits");

    var msbMask: u32 = 0;
    var msbValue: u32 = 0;
    if (msbNumOfBits != 0) {
        const shift: u5 = @intCast(32 - msbNumOfBits);
        msbMask = @as(u32, 0xffffffff) << shift;
        msbValue = SymCryptEcurveHighBitRestrictionValue(pCurve) << shift;
    }

    var msbCounter: u32 = NUM_OF_HIGH_BIT_RESTRICTION_ITERATIONS;
    while (true) {
        scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH, pkKey1);
        h.check(scError == SYMCRYPT_NO_ERROR, "Set random key failed");

        const poPub1 = scTestEckeyGetPublicKey(pkKey1);
        const piPriv1 = scTestEckeyGetPrivateKey(pkKey1);

        h.check(SymCryptEcpointOnCurve(pCurve, poPub1, pbScratch, cbScratch) != 0, "Public key not on curve");
        scError = SymCryptEcpointScalarMul(pCurve, piPriv1, null, SYMCRYPT_FLAG_ECC_LL_COFACTOR_MUL, poP3, pbScratchMul, cbScratchMul);
        h.check(scError == SYMCRYPT_NO_ERROR, "Scalar Multiplying private key failed");
        h.check(SymCryptEcpointIsEqual(pCurve, poPub1, poP3, 0, pbScratch, cbScratch) != 0, " P2 != P3 ");

        const cbPriv = SymCryptEckeySizeofPrivateKey(pkKey1);
        scError = SymCryptEckeyGetValue(pkKey1, pbSignature, cbPriv, null, 0, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_ECPOINT_FORMAT_XY, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue private key failed");

        const msbActual: u32 = (@as(u32, pbSignature[0]) << 24) | (@as(u32, pbSignature[1]) << 16) |
            (@as(u32, pbSignature[2]) << 8) | @as(u32, pbSignature[3]);
        h.check((msbActual & msbMask) == msbValue, "High bit restriction failed");

        scError = SymCryptEckeySetValue(
            pbSignature,
            cbPriv,
            null,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            SYMCRYPT_ECPOINT_FORMAT_XY,
            SYMCRYPT_FLAG_ECKEY_ECDSA | SYMCRYPT_FLAG_ECKEY_ECDH,
            pkKey2,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeySetValue private key failed");

        h.check(SymCryptIntIsEqual(piPriv1, scTestEckeyGetPrivateKey(pkKey2)) != 0, " pkKey1->piPrivateKey != pkKey2->piPrivateKey ");
        h.check(SymCryptEcpointIsEqual(pCurve, poPub1, scTestEckeyGetPublicKey(pkKey2), 0, pbScratch, cbScratch) != 0, " pkKey1->poPublicKey != pkKey2->poPublicKey ");

        msbCounter -= 1;
        if (!(msbCounter > 0 and msbNumOfBits > 0)) break;
    }

    SymCryptSha512(&pbMessage, pbMessage.len, &pbHashValue);
    @memcpy(pbHashValue[SYMCRYPT_SHA512_RESULT_SIZE..], pbHashValue[0..SYMCRYPT_SHA512_RESULT_SIZE]);

    scError = SymCryptEcDsaSign(pkKey1, &pbHashValue, pbHashValue.len, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, pbSignature, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed");

    scError = SymCryptEcDsaVerify(pkKey1, &pbHashValue, pbHashValue.len, pbSignature, cbSignature, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed");

    scError = SymCryptEcDsaSign(pkKey1, &pbHashValue, pbHashValue.len, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION, pbSignature, cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaSign failed");

    scError = SymCryptEcDsaVerify(pkKey1, &pbHashValue, pbHashValue.len, pbSignature, cbSignature, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, SYMCRYPT_FLAG_ECDSA_NO_TRUNCATION);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify failed");

    scError = SymCryptEckeySetRandom(SYMCRYPT_FLAG_ECKEY_ECDH, pkKey2);
    h.check(scError == SYMCRYPT_NO_ERROR, "Set random key failed");

    scError = SymCryptEcDhSecretAgreement(pkKey1, pkKey2, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, pbAgreedSecret1, cbAgreedSecret);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed");

    scError = SymCryptEcDhSecretAgreement(pkKey2, pkKey1, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0, pbAgreedSecret2, cbAgreedSecret);
    h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed");

    h.check(std.mem.eql(u8, pbAgreedSecret1[0..cbAgreedSecret], pbAgreedSecret2[0..cbAgreedSecret]), "SymCryptEcDhSecretAgreement is inconsistent between two parties");

    SymCryptEcpointSetZero(pCurve, scTestEckeyGetPublicKey(pkKey1), pbScratchMul, cbScratchMul);
    scError = SymCryptEcDsaVerify(pkKey1, &pbHashValue, pbHashValue.len, pbSignature, cbSignature, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, 0);
    h.check(scError != SYMCRYPT_NO_ERROR, "SymCryptEcDsaVerify should have failed but succeeded");

    SymCryptWipe(pbWorkSpace, cbWorkSpace);
    SymCryptCallbackFree(pbWorkSpace);
}

fn testCurveParamsValid(pParams: *SymCryptEcurveParams, pbBuf: [*]u8, cbData: usize) bool {
    var i: u32 = 0;
    const hdrSize = @sizeOf(SymCryptEcurveParams);
    while (i < 1000) : (i += 1) {
        SymCryptCallbackRandom(pbBuf + hdrSize, cbData - hdrSize);
        const offset: usize = 5 * @as(usize, pParams.cbFieldLength) + @as(usize, pParams.cbSubgroupOrder);
        (pbBuf + hdrSize)[offset] = 1;

        const eCurve = SymCryptEcurveAllocate(pParams, 0);
        if (eCurve != null) {
            SymCryptEcurveFree(eCurve);
            return true;
        }
    }
    return false;
}

fn testBadCurveParams() void {
    const cbBuf: usize = 1 << 20;
    const pbBuf = std.c.malloc(cbBuf) orelse h.fatal("Out of memory", .{});
    defer std.c.free(pbBuf);

    const pbBytes: [*]u8 = @ptrCast(pbBuf);
    const pParams: *SymCryptEcurveParams = @ptrCast(@alignCast(pbBuf));

    SymCryptCallbackRandom(pbBytes, cbBuf);

    pParams.version = 1;
    pParams.curveType = SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS;
    pParams.algId = SYMCRYPT_ECURVE_GEN_ALG_ID_NULL;
    pParams.cbFieldLength = 32;
    pParams.cbSubgroupOrder = 32;
    pParams.cbCofactor = 1;
    pParams.cbSeed = 0;

    h.check(testCurveParamsValid(pParams, pbBytes, cbBuf), "Params invalid");

    pParams.cbFieldLength = 128;
    h.check(testCurveParamsValid(pParams, pbBytes, cbBuf), "Params invalid");

    pParams.cbFieldLength = 129;
    h.check(!testCurveParamsValid(pParams, pbBytes, cbBuf), "Params valid");

    pParams.cbFieldLength = 32;

    pParams.cbSubgroupOrder = 130;
    h.check(!testCurveParamsValid(pParams, pbBytes, cbBuf), "Params valid");

    pParams.cbSubgroupOrder = 32;

    pParams.cbCofactor = 3;
    h.check(!testCurveParamsValid(pParams, pbBytes, cbBuf), "Params valid");
    pParams.cbCofactor = 1;

    pParams.cbSeed = 256;
    h.check(testCurveParamsValid(pParams, pbBytes, cbBuf), "Params invalid");
    pParams.cbSeed = 257;
    h.check(!testCurveParamsValid(pParams, pbBytes, cbBuf), "Params valid");
    pParams.cbSeed = 0;

    h.check(testCurveParamsValid(pParams, pbBytes, cbBuf), "Params invalid");
}

fn testEcdsaVerifyKat(
    pCurve: ?*anyopaque,
    pHash: ?*const anyopaque,
    pbMsg: [*]const u8,
    cbMsg: usize,
    pbQx: [*]const u8,
    cbQx: usize,
    pbQy: [*]const u8,
    cbQy: usize,
    pbR: [*]const u8,
    cbR: usize,
    pbS: [*]const u8,
    cbS: usize,
    pbResult: [*]const u8,
    cbResult: usize,
    line: i64,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var pbHashValue: [SYMCRYPT_SHA512_RESULT_SIZE]u8 = std.mem.zeroes([SYMCRYPT_SHA512_RESULT_SIZE]u8);
    var pbSignature: [2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8 = std.mem.zeroes([2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8);
    var pbPublicKey: [2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8 = std.mem.zeroes([2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8);

    const pkPublic = SymCryptEckeyAllocate(pCurve);
    h.check3(pkPublic != null, "Failure to allocate public key for ECDSA record at line %lld", line);
    defer SymCryptEckeyFree(pkPublic);

    var pbDigest: [*]const u8 = pbMsg;
    var cbDigest: usize = cbMsg;
    if (pHash != null) {
        cbDigest = SymCryptHashResultSize(pHash);
        h.check3(SYMCRYPT_SHA512_RESULT_SIZE >= cbDigest, "Hash result too big for ECDSA record at line %lld", line);
        SymCryptHash(pHash, pbMsg, cbMsg, &pbHashValue, cbDigest);
        pbDigest = &pbHashValue;
    }

    @memcpy(pbPublicKey[0..cbQx], pbQx[0..cbQx]);
    @memcpy(pbPublicKey[cbQx .. cbQx + cbQy], pbQy[0..cbQy]);

    scError = SymCryptEckeySetValue(
        null,
        0,
        &pbPublicKey,
        cbQx + cbQy,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDSA,
        pkPublic,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "Public key set value failed for ECDSA record at line %lld", line);

    @memcpy(pbSignature[0..cbR], pbR[0..cbR]);
    @memcpy(pbSignature[cbR .. cbR + cbS], pbS[0..cbS]);

    scError = SymCryptEcDsaVerify(
        pkPublic,
        pbDigest,
        cbDigest,
        &pbSignature,
        cbR + cbS,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    );
    h.check3(
        scError == SYMCRYPT_NO_ERROR or scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE,
        "EcDsaVerify failed for ECDSA record at line %lld",
        line,
    );

    h.check3(cbResult > 0, "Wrong format result for ECDSA record at line %lld", line);
    h.check3(pbResult[0] == 'F' or pbResult[0] == 'P', "Unknown result value for ECDSA record at line %lld", line);
    if (pbResult[0] == 'F') {
        h.check3(scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "Wrong EcDsaVerify result for ECDSA record at line %lld", line);
    } else {
        h.check3(scError == SYMCRYPT_NO_ERROR, "Wrong EcDsaVerify result for ECDSA record at line %lld", line);
    }
}

fn testEcdsaSignKat(
    pCurve: ?*anyopaque,
    pHash: ?*const anyopaque,
    pbMsg: [*]const u8,
    cbMsg: usize,
    pbD: [*]const u8,
    cbD: usize,
    pbQx: [*]const u8,
    cbQx: usize,
    pbQy: [*]const u8,
    cbQy: usize,
    pbK: [*]const u8,
    cbK: usize,
    pbR: [*]const u8,
    cbR: usize,
    pbS: [*]const u8,
    cbS: usize,
    line: i64,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var pbHashValue: [SYMCRYPT_SHA512_RESULT_SIZE]u8 = std.mem.zeroes([SYMCRYPT_SHA512_RESULT_SIZE]u8);
    var pbSignature: [2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8 = std.mem.zeroes([2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8);

    const pkPrivate = SymCryptEckeyAllocate(pCurve);
    h.check3(pkPrivate != null, "Failure to allocate private key for ECDSA record at line %lld", line);
    defer SymCryptEckeyFree(pkPrivate);

    const piK = SymCryptIntAllocate(SymCryptEcurveDigitsofScalarMultiplier(pCurve));
    h.check3(piK != null, "Failure to allocate random exponent K for ECDSA record at line %lld", line);
    defer SymCryptIntFree(piK);

    h.check(pHash != null, "Unsupported test case for ECDSA sign");
    const cbDigest = SymCryptHashResultSize(pHash);
    h.check3(SYMCRYPT_SHA512_RESULT_SIZE >= cbDigest, "Hash result too big for ECDSA record at line %lld", line);
    SymCryptHash(pHash, pbMsg, cbMsg, &pbHashValue, cbDigest);

    scError = SymCryptEckeySetValue(
        pbD,
        cbD,
        null,
        0,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        SYMCRYPT_FLAG_ECKEY_ECDSA,
        pkPrivate,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "Private key set value failed for ECDSA record at line %lld", line);

    scError = SymCryptEckeyGetValue(
        pkPrivate,
        null,
        0,
        &pbSignature,
        SymCryptEckeySizeofPublicKey(pkPrivate, SYMCRYPT_ECPOINT_FORMAT_XY),
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue failed for ECDSA record at line %lld", line);
    h.check3(std.mem.eql(u8, pbQx[0..cbQx], pbSignature[0..cbQx]), "Qx doesn't match for ECDSA record at line %lld", line);
    h.check3(std.mem.eql(u8, pbQy[0..cbQy], pbSignature[cbQx .. cbQx + cbQy]), "Qy doesn't match for ECDSA record at line %lld", line);

    scError = SymCryptIntSetValue(pbK, cbK, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piK);
    h.check3(scError == SYMCRYPT_NO_ERROR, "Modelement K failed to set value for ECDSA record at line %lld", line);

    scError = SymCryptEcDsaSignEx(
        pkPrivate,
        &pbHashValue,
        cbDigest,
        piK,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        &pbSignature,
        2 * @as(usize, SymCryptEcurveSizeofScalarMultiplier(pCurve)),
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "EcDsaSignEx failed for ECDSA record at line %lld", line);

    h.check3(std.mem.eql(u8, pbR[0..cbR], pbSignature[0..cbR]), "Test vector R doesn't match for ECDSA record at line %lld", line);
    h.check3(std.mem.eql(u8, pbS[0..cbS], pbSignature[cbR .. cbR + cbS]), "Test vector S doesn't match for ECDSA record at line %lld", line);
}

fn testEcdhKat(
    pCurve: ?*anyopaque,
    pbSa: [*]const u8,
    cbSa: usize,
    pbQxa: [*]const u8,
    cbQxa: usize,
    pbQya: [*]const u8,
    cbQya: usize,
    pbQxb: [*]const u8,
    cbQxb: usize,
    pbQyb: [*]const u8,
    cbQyb: usize,
    pbSs: [*]const u8,
    cbSs: usize,
    secretAgreementFlags: u32,
    line: i64,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var pbSharedSecret: [(SYMCRYPT_BITSIZE_P521 + 7) / 8]u8 = std.mem.zeroes([(SYMCRYPT_BITSIZE_P521 + 7) / 8]u8);
    var pbPublicKey: [2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8 = std.mem.zeroes([2 * ((SYMCRYPT_BITSIZE_P521 + 7) / 8)]u8);
    var pbOptPublicKey: ?[*]const u8 = null;
    var cbOptPublicKey: usize = 0;

    const randByte: u8 = @intCast(rng.scTestRngUint32(&rng.g_rng) & 0xff);
    var flags: u32 = SYMCRYPT_FLAG_ECKEY_ECDH;

    const pkPrivate = SymCryptEckeyAllocate(pCurve);
    h.check3(pkPrivate != null, "Failure to allocate private key for ECDH record at line %lld", line);
    defer SymCryptEckeyFree(pkPrivate);

    const pkPublic = SymCryptEckeyAllocate(pCurve);
    h.check3(pkPublic != null, "Failure to allocate public key for ECDH record at line %lld", line);
    defer SymCryptEckeyFree(pkPublic);

    if ((randByte & 0x1) != 0) flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((randByte & 0x2) != 0) flags |= SYMCRYPT_FLAG_ECKEY_ECDSA;
    if ((randByte & 0x4) != 0) {
        @memcpy(pbPublicKey[0..cbQxa], pbQxa[0..cbQxa]);
        @memcpy(pbPublicKey[cbQxa .. cbQxa + cbQya], pbQya[0..cbQya]);
        pbOptPublicKey = &pbPublicKey;
        cbOptPublicKey = cbQxa + cbQya;
    }

    scError = SymCryptEckeySetValue(
        pbSa,
        cbSa,
        pbOptPublicKey,
        cbOptPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        flags,
        pkPrivate,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "Private key set value failed for ECDH record at line %lld", line);

    scError = SymCryptEckeyGetValue(
        pkPrivate,
        null,
        0,
        &pbPublicKey,
        SymCryptEckeySizeofPublicKey(pkPrivate, SYMCRYPT_ECPOINT_FORMAT_XY),
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEckeyGetValue failed for ECDH record at line %lld", line);
    h.check3(std.mem.eql(u8, pbQxa[0..cbQxa], pbPublicKey[0..cbQxa]), "Qx doesn't match for ECDH record at line %lld", line);
    h.check3(std.mem.eql(u8, pbQya[0..cbQya], pbPublicKey[cbQxa .. cbQxa + cbQya]), "Qy doesn't match for ECDH record at line %lld", line);

    flags = SYMCRYPT_FLAG_ECKEY_ECDH;
    if ((randByte & 0x10) != 0) flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    if ((randByte & 0x20) != 0 and (flags & SYMCRYPT_FLAG_KEY_NO_FIPS) != 0) flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
    if ((randByte & 0x40) != 0) flags |= SYMCRYPT_FLAG_ECKEY_ECDSA;

    @memcpy(pbPublicKey[0..cbQxb], pbQxb[0..cbQxb]);
    @memcpy(pbPublicKey[cbQxb .. cbQxb + cbQyb], pbQyb[0..cbQyb]);

    scError = SymCryptEckeySetValue(
        null,
        0,
        &pbPublicKey,
        cbQxb + cbQyb,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        flags,
        pkPublic,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "Public key set value failed for ECDH record at line %lld", line);

    scError = SymCryptEcDhSecretAgreement(
        pkPrivate,
        pkPublic,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        secretAgreementFlags,
        &pbSharedSecret,
        SymCryptEcurveSizeofFieldElement(pCurve),
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptEcDhSecretAgreement failed for ECDH record at line %lld", line);
    h.check3(std.mem.eql(u8, pbSs[0..cbSs], pbSharedSecret[0..cbSs]), "Shared secret doesn't match for ECDH record at line %lld", line);
}

fn eccSeededKeygenDerivePublicKey(
    pCurve: ?*const anyopaque,
    pbSeed: [*]const u8,
    cbSeed: usize,
    pbPublicKey: [*]u8,
) usize {
    const pKey = SymCryptEckeyAllocate(pCurve);
    h.check(pKey != null, "Seeded ECC keygen allocation failed");
    defer SymCryptEckeyFree(pKey);

    var scError = SymCryptEckeyDerive(pKey, pbSeed, cbSeed, SYMCRYPT_FLAG_ECKEY_ECDH);
    h.check(scError == SYMCRYPT_NO_ERROR, "Seeded ECC keygen derivation failed");

    const cbPublicKey: usize = SymCryptEckeySizeofPublicKey(pKey, SYMCRYPT_ECPOINT_FORMAT_XY);
    h.check(cbPublicKey <= ECKEY_MAXPUBKEYSIZE, "Seeded ECC keygen public key too large");

    scError = SymCryptEckeyGetValue(
        pKey,
        null,
        0,
        pbPublicKey,
        cbPublicKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_ECPOINT_FORMAT_XY,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Seeded ECC keygen public key export failed");

    return cbPublicKey;
}

fn eccSeededKeygenAggregateDigest(
    pbSeed: [*]const u8,
    cbSeed: usize,
    nIterations: usize,
    pbDigest: [*]u8,
) void {
    var localRng: rng.Rng = undefined;
    var sha256State: [256]u8 align(16) = undefined;
    var seed: [ECKEY_SEEDED_KEYGEN_MAX_SEED_SIZE]u8 = undefined;
    var publicKey: [ECKEY_MAXPUBKEYSIZE]u8 = undefined;

    var supportedCurves: [rgbInternalCurves.len]usize = undefined;
    var nSupportedCurves: usize = 0;
    for (rgbInternalCurves, 0..) |entry, idx| {
        if (SymCryptEcurvePrivateKeyDefaultFormat(entry.pCurve) == SYMCRYPT_ECKEY_PRIVATE_FORMAT_CANONICAL) {
            supportedCurves[nSupportedCurves] = idx;
            nSupportedCurves += 1;
        }
    }
    h.check(nSupportedCurves > 0, "No curve supports seeded ECC keygen");

    rng.scTestRngReset(&localRng, pbSeed, cbSeed);
    scTestSha256Init(&sha256State);

    var i: usize = 0;
    while (i < nIterations) : (i += 1) {
        const curveIndex = supportedCurves[rng.scTestRngSizet(&localRng, nSupportedCurves)];
        const pCurve = rgbInternalCurves[curveIndex].pCurve;

        const cbIterSeed = ECKEY_SEEDED_KEYGEN_MIN_SEED_SIZE +
            rng.scTestRngSizet(&localRng, ECKEY_SEEDED_KEYGEN_MAX_SEED_SIZE - ECKEY_SEEDED_KEYGEN_MIN_SEED_SIZE + 1);

        for (0..cbIterSeed) |j| {
            seed[j] = rng.scTestRngByte(&localRng);
        }

        const cbPublicKey = eccSeededKeygenDerivePublicKey(pCurve, &seed, cbIterSeed, &publicKey);
        scTestSha256Append(&sha256State, &publicKey, cbPublicKey);
    }

    scTestSha256Result(&sha256State, pbDigest);
}

fn testEccSeededKeygenFixedKat(katItem: *const kat.KatItem) void {
    const pKatCurve = kat.findDataItem(katItem, "curve") orelse h.fatal("No curve at line {d}", .{katItem.line});
    const rawCurve = pKatCurve.dataPtr[0..pKatCurve.dataLen];
    const curveName = rawCurve[1 .. rawCurve.len - 1];

    var foundIndex: ?usize = null;
    for (rgbInternalCurves, 0..) |entry, i| {
        if (std.mem.eql(u8, curveName, entry.pszCurveName)) {
            foundIndex = i;
            break;
        }
    }
    h.check3(foundIndex != null, "Unknown curve in EcSeededKeygen record at line %lld", katItem.line);

    const bSeed = kat.katParseData(katItem, "seed");
    const bExpectedPub = kat.katParseData(katItem, "pub");
    var publicKey: [ECKEY_MAXPUBKEYSIZE]u8 = undefined;
    const cbPublicKey = eccSeededKeygenDerivePublicKey(
        rgbInternalCurves[foundIndex.?].pCurve,
        bSeed.pbData,
        bSeed.cbData,
        &publicKey,
    );
    h.check3(
        cbPublicKey == bExpectedPub.cbData and std.mem.eql(u8, publicKey[0..cbPublicKey], bExpectedPub.pbData[0..cbPublicKey]),
        "Seeded ECC KAT public key mismatch at line %lld",
        katItem.line,
    );
}

fn testEccSeededKeygenAggregateKat(katItem: *const kat.KatItem) void {
    const bSeed = kat.katParseData(katItem, "seed");
    const bExpectedDigest = kat.katParseData(katItem, "md");
    const nIterations = kat.katParseInteger(katItem, "iter");
    var digest: [SYMCRYPT_SHA256_RESULT_SIZE]u8 = undefined;

    h.check3(bExpectedDigest.cbData == digest.len, "Seeded ECC aggregate KAT digest size mismatch at line %lld", katItem.line);

    eccSeededKeygenAggregateDigest(bSeed.pbData, bSeed.cbData, @intCast(nIterations), &digest);

    h.check3(
        std.mem.eql(u8, &digest, bExpectedDigest.pbData[0..digest.len]),
        "Seeded ECC aggregate KAT digest mismatch at line %lld",
        katItem.line,
    );
}

fn testEccEcdsaKats() void {
    const pResource = h.findDataItem("kat_ecdsa.dat") orelse h.fatal("kat_ecdsa.dat not found", .{});
    var katEcc = kat.KatData.init(pResource.name, pResource.pbData, pResource.cbData);
    var katItem: kat.KatItem = .{};

    var sep: []const u8 = "";
    var pHash: ?*const anyopaque = null;

    var cEcdsaSignSamples: u32 = 0;
    var cEcdsaVrfySamples: u32 = 0;
    var cEcdhSamples: u32 = 0;

    var currentCategoryBuf: [64]u8 = undefined;
    var currentCategoryLen: usize = 0;

    while (true) {
        katEcc.getKatItem(&katItem);
        const line: i64 = katItem.line;

        if (katItem.itemType == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.itemType == kat.KAT_TYPE_CATEGORY) {
            const cat = katItem.categoryName();
            const len = @min(cat.len, currentCategoryBuf.len);
            @memcpy(currentCategoryBuf[0..len], cat[0..len]);
            currentCategoryLen = len;
            h.ziprint("{s}{s}", .{ sep, cat });
            sep = ", ";
        }

        if (katItem.itemType == kat.KAT_TYPE_DATASET) {
            const catName = currentCategoryBuf[0..currentCategoryLen];
            if (std.mem.eql(u8, catName, "EcSeededKeygen")) {
                testEccSeededKeygenFixedKat(&katItem);
                continue;
            }
            if (std.mem.eql(u8, catName, "EcSeededKeygenHash")) {
                testEccSeededKeygenAggregateKat(&katItem);
                continue;
            }

            const pKatCurve = kat.findDataItem(&katItem, "curve") orelse h.fatal("No curve data item at line {d}", .{line});
            const rawCurve = pKatCurve.dataPtr[0..pKatCurve.dataLen];
            const curveName = rawCurve[1 .. rawCurve.len - 1];

            var foundIndex: ?usize = null;
            for (rgbInternalCurves, 0..) |entry, i| {
                if (std.mem.eql(u8, curveName, entry.pszCurveName)) {
                    foundIndex = i;
                    break;
                }
            }
            if (foundIndex == null) {
                h.zdprint("Ecdsa record at line {d} is skipped due to unknown curve.\n", .{line});
                continue;
            }

            const pCurve = rgbInternalCurves[foundIndex.?].pCurve;
            h.check3(pCurve != null, "Curve not allocated for ECDSA record at line %lld", line);

            if (kat.katIsFieldPresent(&katItem, "result")) {
                h.check3(katItem.nDataItems == 8, "Wrong number of items in ECDSA Verify record at line %lld", line);

                const pKatHash = kat.findDataItem(&katItem, "hash") orelse h.fatal("No hash data item at line {d}", .{line});
                const rawHash = pKatHash.dataPtr[0..pKatHash.dataLen];
                if (!getHashAlgorithm(rawHash[1 .. rawHash.len - 1], line, &pHash)) {
                    continue;
                }

                const katMsg = kat.katParseData(&katItem, "msg");
                const katQx = kat.katParseData(&katItem, "qx");
                const katQy = kat.katParseData(&katItem, "qy");
                const katR = kat.katParseData(&katItem, "r");
                const katS = kat.katParseData(&katItem, "s");
                const katResult = kat.katParseData(&katItem, "result");

                testEcdsaVerifyKat(
                    pCurve,
                    pHash,
                    katMsg.pbData,
                    katMsg.cbData,
                    katQx.pbData,
                    katQx.cbData,
                    katQy.pbData,
                    katQy.cbData,
                    katR.pbData,
                    katR.cbData,
                    katS.pbData,
                    katS.cbData,
                    katResult.pbData,
                    katResult.cbData,
                    katEcc.m_line,
                );
                cEcdsaVrfySamples += 1;
                continue;
            } else if (kat.katIsFieldPresent(&katItem, "ziut")) {
                h.check3(katItem.nDataItems == 9, "Wrong number of items in ECDH record at line %lld", line);

                const katDiut = kat.katParseData(&katItem, "diut");
                const katQiutX = kat.katParseData(&katItem, "qiutx");
                const katQiutY = kat.katParseData(&katItem, "qiuty");
                const katQcavsX = kat.katParseData(&katItem, "qcavsx");
                const katQcavsY = kat.katParseData(&katItem, "qcavsy");
                const katZiut = kat.katParseData(&katItem, "ziut");
                const katDivH = kat.katParseData(&katItem, "flags");

                testEcdhKat(
                    pCurve,
                    katDiut.pbData,
                    katDiut.cbData,
                    katQiutX.pbData,
                    katQiutX.cbData,
                    katQiutY.pbData,
                    katQiutY.cbData,
                    katQcavsX.pbData,
                    katQcavsX.cbData,
                    katQcavsY.pbData,
                    katQcavsY.cbData,
                    katZiut.pbData,
                    katZiut.cbData,
                    katDivH.pbData[0],
                    katEcc.m_line,
                );
                cEcdhSamples += 1;
                continue;
            } else {
                h.check3(katItem.nDataItems == 9, "Wrong number of items in ECDSA Verify record at line %lld", line);

                const pKatHash = kat.findDataItem(&katItem, "hash") orelse h.fatal("No hash data item at line {d}", .{line});
                const rawHash = pKatHash.dataPtr[0..pKatHash.dataLen];
                if (!getHashAlgorithm(rawHash[1 .. rawHash.len - 1], line, &pHash)) {
                    continue;
                }

                const katMsg = kat.katParseData(&katItem, "msg");
                const katD = kat.katParseData(&katItem, "d");
                const katQx = kat.katParseData(&katItem, "qx");
                const katQy = kat.katParseData(&katItem, "qy");
                const katK = kat.katParseData(&katItem, "k");
                const katR = kat.katParseData(&katItem, "r");
                const katS = kat.katParseData(&katItem, "s");

                testEcdsaSignKat(
                    pCurve,
                    pHash,
                    katMsg.pbData,
                    katMsg.cbData,
                    katD.pbData,
                    katD.cbData,
                    katQx.pbData,
                    katQx.cbData,
                    katQy.pbData,
                    katQy.cbData,
                    katK.pbData,
                    katK.cbData,
                    katR.pbData,
                    katR.cbData,
                    katS.pbData,
                    katS.cbData,
                    katEcc.m_line,
                );
                cEcdsaSignSamples += 1;
                continue;
            }
        }
    }

    h.ziprint("\n        Total samples: {d} EcdsaSign, {d} EcdsaVerify, {d} Ecdh\n", .{
        cEcdsaSignSamples,
        cEcdsaVrfySamples,
        cEcdhSamples,
    });
}

var hasRun: bool = false;

pub export fn testEcc() callconv(.c) void {
    if (hasRun) {
        return;
    }
    hasRun = true;

    if (!h.isAlgorithmPresent("Ec", 1)) {
        return;
    }

    h.ziprint("    Elliptic Curve Crypto\n", .{});

    var nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs);

    h.ziprint("    > Functional testing", .{});
    h.vprint(h.g_verbose == 0, ": ", .{});
    h.vprint(h.g_verbose != 0, "\n", .{});

    for (&rgbInternalCurves, 0..) |*entry, i| {
        h.vprint(h.g_verbose != 0, "    > Curve ", .{});
        h.ziprint("{s}", .{entry.pszCurveName});
        if (i + 1 < rgbInternalCurves.len) {
            h.vprint(h.g_verbose == 0, ", ", .{});
        }
        h.vprint(h.g_verbose != 0, "\n", .{});

        const nAllocs = @atomicLoad(i64, &cb.g_nAllocs, .seq_cst);
        const pParams = entry.ppParams.*;
        const pCurve = SymCryptEcurveAllocate(pParams, 0);
        h.check(pCurve != null, "Curve allocation failed");
        h.check(@atomicLoad(i64, &cb.g_nAllocs, .seq_cst) == nAllocs + 2, "Undesired allocation");

        entry.pCurve = pCurve;

        h.vprint(h.g_verbose != 0, "    Field Modulus bitsize   : {d}\n", .{SymCryptEcurveBitsizeofFieldModulus(pCurve)});
        h.vprint(h.g_verbose != 0, "    Group Order bitsize     : {d}\n", .{SymCryptEcurveBitsizeofGroupOrder(pCurve)});
        h.vprint(h.g_verbose != 0, "    Ecpoint size in bytes   : {d}\n", .{SymCryptSizeofEcpointFromCurve(pCurve)});
        h.vprint(h.g_verbose != 0, "    F. element size in bytes: {d}\n", .{SymCryptEcurveSizeofFieldElement(pCurve)});
        h.vprint(h.g_verbose != 0, "    Private key default form: {s}\n", .{rgbPrivateKeyFormatNames[SymCryptEcurvePrivateKeyDefaultFormat(pCurve)]});
        h.vprint(h.g_verbose != 0, "    High bit restriction #Bs: {d}\n", .{SymCryptEcurveHighBitRestrictionNumOfBits(pCurve)});
        h.vprint(h.g_verbose != 0, "    High bit restriction Pos: {d}\n", .{SymCryptEcurveHighBitRestrictionPosition(pCurve)});
        h.vprint(h.g_verbose != 0, "    High bit restriction Val: 0x{X}\n", .{SymCryptEcurveHighBitRestrictionValue(pCurve)});

        if (pParams.curveType == SYMCRYPT_ECURVE_TYPE_SHORT_WEIERSTRASS or
            pParams.curveType == SYMCRYPT_ECURVE_TYPE_TWISTED_EDWARDS)
        {
            testEccArithmetic(pCurve);
        } else if (pParams.curveType == SYMCRYPT_ECURVE_TYPE_MONTGOMERY) {
            mont.testMontgomery(pCurve);
        }

        h.vprint(h.g_verbose != 0, "\n", .{});
    }

    h.ziprint("\n    > KAT testing       : ", .{});
    testEccEcdsaKats();
    h.zprint("    0 skipped KATS\n", .{});

    for (&rgbInternalCurves) |*entry| {
        SymCryptEcurveFree(entry.pCurve);
        entry.pCurve = null;
    }

    nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs);

    testBadCurveParams();

    h.ziprint("\n", .{});
}
