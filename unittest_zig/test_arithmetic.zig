// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const cb = @import("callback.zig");
const ref = @import("ref_implementations.zig");
const rnd = @import("rnd_driver.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_VALUE_TOO_LARGE: u32 = 0x8012;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: i32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: i32 = 2;

const SYMCRYPT_FLAG_DATA_PUBLIC: u32 = 0x01;
const SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC: u32 = 0x02;
const SYMCRYPT_FLAG_MODULUS_INV_TOTIENT: u32 = 0x04;
const SYMCRYPT_FLAG_MODULUS_PRIME: u32 = 0x08;
const SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO: u32 = 0x01;
const SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE: u32 = 0x02;
const SYMCRYPT_FLAG_MODRANDOM_ALLOW_MINUSONE: u32 = 0x04;

const SYMCRYPT_INT_MAX_BITS: usize = 1 << 20;

extern fn SymCryptDigitsFromBits(nBits: u32) callconv(.c) u32;
extern fn SymCryptSizeofIntFromDigits(nDigits: u32) callconv(.c) u32;
extern fn SymCryptIntAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptIntCreate(pbBuffer: [*]u8, cbBuffer: usize, nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptIntFree(piObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntCopy(piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntCopyMixedSize(piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntMaskedCopy(piSrc: ?*const anyopaque, piDst: ?*anyopaque, mask: u32) callconv(.c) void;
extern fn SymCryptIntConditionalCopy(piSrc: ?*const anyopaque, piDst: ?*anyopaque, cond: u32) callconv(.c) void;
extern fn SymCryptIntConditionalSwap(piSrcDst1: ?*anyopaque, piSrcDst2: ?*anyopaque, cond: u32) callconv(.c) void;
extern fn SymCryptIntBitsizeOfObject(piObj: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntDigitsizeOfObject(piObj: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntBytesizeOfObject(piObj: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntBitsizeOfValue(piSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntSetValueUint32(u32Src: u32, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntSetValueUint64(u64Src: u64, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntGetValueLsbits32(piSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntGetValueLsbits64(piSrc: ?*const anyopaque) callconv(.c) u64;
extern fn SymCryptIntSetValue(pbSrc: [*]const u8, cbSrc: usize, format: i32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntGetValue(piSrc: ?*const anyopaque, pbDst: [*]u8, cbDst: usize, format: i32) callconv(.c) u32;
extern fn SymCryptIntGetBit(piSrc: ?*const anyopaque, iBit: u32) callconv(.c) u32;
extern fn SymCryptIntGetBits(piSrc: ?*const anyopaque, iBit: u32, nBits: u32) callconv(.c) u32;
extern fn SymCryptIntSetBits(piDst: ?*anyopaque, val: u32, iBit: u32, nBits: u32) callconv(.c) void;
extern fn SymCryptIntIsEqualUint32(piSrc1: ?*const anyopaque, u32Src2: u32) callconv(.c) u32;
extern fn SymCryptIntIsEqual(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntIsLessThan(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntAddUint32(piSrc1: ?*const anyopaque, u32Src2: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntAddSameSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntAddMixedSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntSubUint32(piSrc1: ?*const anyopaque, u32Src2: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntSubSameSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntSubMixedSize(piSrc1: ?*const anyopaque, piSrc2: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntNeg(piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntMulPow2(piSrc: ?*const anyopaque, exp: usize, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntDivPow2(piSrc: ?*const anyopaque, exp: usize, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntShr1(highBit: u32, piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntModPow2(piSrc: ?*const anyopaque, exp: usize, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntMulUint32(piSrc1: ?*const anyopaque, u32Src2: u32, piDst: ?*anyopaque) callconv(.c) u32;
extern fn SymCryptIntMulSameSize(
    piSrc1: ?*const anyopaque,
    piSrc2: ?*const anyopaque,
    piDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntSquare(
    piSrc: ?*const anyopaque,
    piDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntMulMixedSize(
    piSrc1: ?*const anyopaque,
    piSrc2: ?*const anyopaque,
    piDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;

extern fn SymCryptSizeofDivisorFromDigits(nDigits: u32) callconv(.c) u32;
extern fn SymCryptDivisorAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptDivisorCreate(pbBuffer: [*]u8, cbBuffer: usize, nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptDivisorFree(pdObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptDivisorCopy(pdSrc: ?*const anyopaque, pdDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptDivisorDigitsizeOfObject(pdObj: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntFromDivisor(pdSrc: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptIntToDivisor(
    piSrc: ?*const anyopaque,
    pdDst: ?*anyopaque,
    totalOperations: u32,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntDivMod(
    piSrc: ?*const anyopaque,
    pdDivisor: ?*const anyopaque,
    piQuotient: ?*anyopaque,
    piRemainder: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntExtendedGcd(
    piSrc1: ?*const anyopaque,
    piSrc2: ?*const anyopaque,
    flags: u32,
    piGcd: ?*anyopaque,
    piLcm: ?*anyopaque,
    piInvSrc1ModSrc2: ?*anyopaque,
    piInvSrc2ModSrc1: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptIntSqrt(piSrc: ?*const anyopaque, piDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptIntMillerRabinPrimalityTest(
    pmPrime: ?*const anyopaque,
    nBitsSrc: u32,
    nIterations: u32,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptIntGenerateRandomPrime(
    piLow: ?*const anyopaque,
    piHigh: ?*const anyopaque,
    pu64PubExp: ?[*]const u64,
    nPubExp: u32,
    nTries: u32,
    flags: u32,
    piDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptSizeofModulusFromDigits(nDigits: u32) callconv(.c) u32;
extern fn SymCryptModulusAllocate(nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptModulusCreate(pbBuffer: [*]u8, cbBuffer: usize, nDigits: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptModulusFree(pmObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModulusCopy(pmSrc: ?*const anyopaque, pmDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModulusDigitsizeOfObject(pmObj: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntFromModulus(pmSrc: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptDivisorFromModulus(pmSrc: ?*anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptIntToModulus(
    piSrc: ?*const anyopaque,
    pmDst: ?*anyopaque,
    averageOperations: u32,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;

extern fn SymCryptSizeofModElementFromModulus(pmMod: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptModElementAllocate(pmMod: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptModElementCreate(pbBuffer: [*]u8, cbBuffer: usize, pmMod: ?*const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptModElementFree(pmMod: ?*const anyopaque, peObj: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModElementCopy(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque, peDst: ?*anyopaque) callconv(.c) void;
extern fn SymCryptModElementMaskedCopy(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque, peDst: ?*anyopaque, mask: u32) callconv(.c) void;
extern fn SymCryptModElementConditionalSwap(pmMod: ?*const anyopaque, peData1: ?*anyopaque, peData2: ?*anyopaque, cond: u32) callconv(.c) void;
extern fn SymCryptModElementSetValueUint32(
    value: u32,
    pmMod: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModElementSetValueNegUint32(
    value: u32,
    pmMod: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModElementSetValue(
    pbSrc: [*]const u8,
    cbSrc: usize,
    format: i32,
    pmMod: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptModElementGetValue(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    pbDst: [*]u8,
    cbDst: usize,
    format: i32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptModElementIsEqual(pmMod: ?*const anyopaque, peSrc1: ?*const anyopaque, peSrc2: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptModElementIsZero(pmMod: ?*const anyopaque, peSrc: ?*const anyopaque) callconv(.c) u32;
extern fn SymCryptIntToModElement(
    piSrc: ?*const anyopaque,
    pmMod: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModElementToInt(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    piDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModSetRandom(
    pmMod: ?*const anyopaque,
    peDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModAdd(
    pmMod: ?*const anyopaque,
    peSrc1: ?*const anyopaque,
    peSrc2: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModSub(
    pmMod: ?*const anyopaque,
    peSrc1: ?*const anyopaque,
    peSrc2: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModNeg(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModMul(
    pmMod: ?*const anyopaque,
    peSrc1: ?*const anyopaque,
    peSrc2: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModSquare(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModDivPow2(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    exp: u32,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModInv(
    pmMod: ?*const anyopaque,
    peSrc: ?*const anyopaque,
    peDst: ?*anyopaque,
    flags: u32,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;
extern fn SymCryptModExp(
    pmMod: ?*const anyopaque,
    peBase: ?*const anyopaque,
    piExp: ?*const anyopaque,
    nBitsExp: u32,
    flags: u32,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) void;
extern fn SymCryptModMultiExp(
    pmMod: ?*const anyopaque,
    peBaseArray: [*]const ?*const anyopaque,
    piExpArray: [*]const ?*const anyopaque,
    nBases: u32,
    nBitsExp: u32,
    flags: u32,
    peDst: ?*anyopaque,
    pbScratch: [*]u8,
    cbScratch: usize,
) callconv(.c) u32;

extern fn SymCryptCreateTrialDivisionContext(nDigits: u32) callconv(.c) ?*const anyopaque;
extern fn SymCryptFreeTrialDivisionContext(pContext: ?*const anyopaque) callconv(.c) void;
extern fn SymCryptIntFindSmallDivisor(
    pContext: ?*const anyopaque,
    piSrc: ?*const anyopaque,
    piContinue: ?*const anyopaque,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptTestTrialdivisionMaxSmallPrime(pContext: ?*const anyopaque) callconv(.c) u32;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void;
extern fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) void;

const PERF_KEY_SECRET: u32 = 0x01000000;
const PERF_KEY_PUB_ODD: u32 = 0x02000000;
const PERF_KEY_PUBLIC: u32 = 0x03000000;
const PERF_KEY_PUB_PM: u32 = 0x04000000;
const PERF_KEY_PUB_NIST: u32 = 0x05000000;
const PERF_KEY_PRIME: u32 = 0x80000000;

const PrimeBrainPoolP160 = [_]u8{
    0xE9, 0x5E, 0x4A, 0x5F, 0x73, 0x70, 0x59, 0xDC,
    0x60, 0xDF, 0xC7, 0xAD, 0x95, 0xB3, 0xD8, 0x13,
    0x95, 0x15, 0x62, 0x0F,
};

const PrimeBrainPoolP192 = [_]u8{
    0xC3, 0x02, 0xF4, 0x1D, 0x93, 0x2A, 0x36, 0xCD,
    0xA7, 0xA3, 0x46, 0x30, 0x93, 0xD1, 0x8D, 0xB7,
    0x8F, 0xCE, 0x47, 0x6D, 0xE1, 0xA8, 0x62, 0x97,
};

const PrimeBrainPoolP224 = [_]u8{
    0xD7, 0xC1, 0x34, 0xAA, 0x26, 0x43, 0x66, 0x86,
    0x2A, 0x18, 0x30, 0x25, 0x75, 0xD1, 0xD7, 0x87,
    0xB0, 0x9F, 0x07, 0x57, 0x97, 0xDA, 0x89, 0xF5,
    0x7E, 0xC8, 0xC0, 0xFF,
};

const PrimeBrainPoolP256 = [_]u8{
    0xA9, 0xFB, 0x57, 0xDB, 0xA1, 0xEE, 0xA9, 0xBC,
    0x3E, 0x66, 0x0A, 0x90, 0x9D, 0x83, 0x8D, 0x72,
    0x6E, 0x3B, 0xF6, 0x23, 0xD5, 0x26, 0x20, 0x28,
    0x20, 0x13, 0x48, 0x1D, 0x1F, 0x6E, 0x53, 0x77,
};

const PrimeBrainPoolP320 = [_]u8{
    0xD3, 0x5E, 0x47, 0x20, 0x36, 0xBC, 0x4F, 0xB7,
    0xE1, 0x3C, 0x78, 0x5E, 0xD2, 0x01, 0xE0, 0x65,
    0xF9, 0x8F, 0xCF, 0xA6, 0xF6, 0xF4, 0x0D, 0xEF,
    0x4F, 0x92, 0xB9, 0xEC, 0x78, 0x93, 0xEC, 0x28,
    0xFC, 0xD4, 0x12, 0xB1, 0xF1, 0xB3, 0x2E, 0x27,
};

const PrimeBrainPoolP384 = [_]u8{
    0x8C, 0xB9, 0x1E, 0x82, 0xA3, 0x38, 0x6D, 0x28,
    0x0F, 0x5D, 0x6F, 0x7E, 0x50, 0xE6, 0x41, 0xDF,
    0x15, 0x2F, 0x71, 0x09, 0xED, 0x54, 0x56, 0xB4,
    0x12, 0xB1, 0xDA, 0x19, 0x7F, 0xB7, 0x11, 0x23,
    0xAC, 0xD3, 0xA7, 0x29, 0x90, 0x1D, 0x1A, 0x71,
    0x87, 0x47, 0x00, 0x13, 0x31, 0x07, 0xEC, 0x53,
};

const PrimeBrainPoolP512 = [_]u8{
    0xAA, 0xDD, 0x9D, 0xB8, 0xDB, 0xE9, 0xC4, 0x8B,
    0x3F, 0xD4, 0xE6, 0xAE, 0x33, 0xC9, 0xFC, 0x07,
    0xCB, 0x30, 0x8D, 0xB3, 0xB3, 0xC9, 0xD2, 0x0E,
    0xD6, 0x63, 0x9C, 0xCA, 0x70, 0x33, 0x08, 0x71,
    0x7D, 0x4D, 0x9B, 0x00, 0x9B, 0xC6, 0x68, 0x42,
    0xAE, 0xCD, 0xA1, 0x2A, 0xE6, 0xA3, 0x80, 0xE6,
    0x28, 0x81, 0xFF, 0x2F, 0x2D, 0x82, 0xC6, 0x85,
    0x28, 0xAA, 0x60, 0x56, 0x58, 0x3A, 0x48, 0xF3,
};

const PrimeWapiP192 = [_]u8{
    0xBD, 0xB6, 0xF4, 0xFE, 0x3E, 0x8B, 0x1D, 0x9E,
    0x0D, 0xA8, 0xC0, 0xD4, 0x6F, 0x4C, 0x31, 0x8C,
    0xEF, 0xE4, 0xAF, 0xE3, 0xB6, 0xB8, 0x55, 0x1F,
};

const PrimeNistP192 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const PrimeNistP224 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01,
};

const PrimeNistP256 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const PrimeNistP384 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
};

const PrimeNistP521 = [_]u8{
    0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF,
};

const PrimeSecP160k = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xAC, 0x73,
};

const PrimeSecP160r = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x7F, 0xFF, 0xFF, 0xFF,
};

const PrimeSecP192k = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xEE, 0x37,
};

const PrimeSecP224r = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xFF, 0xFF, 0xE5, 0x6D,
};

const PrimeSecP256 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
};

const PrimeWtlsP160 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFC, 0x80, 0x8F,
};

const PrimeX962P239 = [_]u8{
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x7F, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const PrimeNumsP256 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x43,
};

const PrimeNumsP384 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xC3,
};

const PrimeNumsP512 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD, 0xC7,
};

const Prime1024Rfc5114 = [_]u8{
    0xB1, 0x0B, 0x8F, 0x96, 0xA0, 0x80, 0xE0, 0x1D, 0xDE, 0x92, 0xDE, 0x5E, 0xAE, 0x5D, 0x54, 0xEC,
    0x52, 0xC9, 0x9F, 0xBC, 0xFB, 0x06, 0xA3, 0xC6, 0x9A, 0x6A, 0x9D, 0xCA, 0x52, 0xD2, 0x3B, 0x61,
    0x60, 0x73, 0xE2, 0x86, 0x75, 0xA2, 0x3D, 0x18, 0x98, 0x38, 0xEF, 0x1E, 0x2E, 0xE6, 0x52, 0xC0,
    0x13, 0xEC, 0xB4, 0xAE, 0xA9, 0x06, 0x11, 0x23, 0x24, 0x97, 0x5C, 0x3C, 0xD4, 0x9B, 0x83, 0xBF,
    0xAC, 0xCB, 0xDD, 0x7D, 0x90, 0xC4, 0xBD, 0x70, 0x98, 0x48, 0x8E, 0x9C, 0x21, 0x9A, 0x73, 0x72,
    0x4E, 0xFF, 0xD6, 0xFA, 0xE5, 0x64, 0x47, 0x38, 0xFA, 0xA3, 0x1A, 0x4F, 0xF5, 0x5B, 0xCC, 0xC0,
    0xA1, 0x51, 0xAF, 0x5F, 0x0D, 0xC8, 0xB4, 0xBD, 0x45, 0xBF, 0x37, 0xDF, 0x36, 0x5C, 0x1A, 0x65,
    0xE6, 0x8C, 0xFD, 0xA7, 0x6D, 0x4D, 0xA7, 0x08, 0xDF, 0x1F, 0xB2, 0xBC, 0x2E, 0x4A, 0x43, 0x71,
};

const Prime2048Rfc5114 = [_]u8{
    0xAD, 0x10, 0x7E, 0x1E, 0x91, 0x23, 0xA9, 0xD0, 0xD6, 0x60, 0xFA, 0xA7, 0x95, 0x59, 0xC5, 0x1F,
    0xA2, 0x0D, 0x64, 0xE5, 0x68, 0x3B, 0x9F, 0xD1, 0xB5, 0x4B, 0x15, 0x97, 0xB6, 0x1D, 0x0A, 0x75,
    0xE6, 0xFA, 0x14, 0x1D, 0xF9, 0x5A, 0x56, 0xDB, 0xAF, 0x9A, 0x3C, 0x40, 0x7B, 0xA1, 0xDF, 0x15,
    0xEB, 0x3D, 0x68, 0x8A, 0x30, 0x9C, 0x18, 0x0E, 0x1D, 0xE6, 0xB8, 0x5A, 0x12, 0x74, 0xA0, 0xA6,
    0x6D, 0x3F, 0x81, 0x52, 0xAD, 0x6A, 0xC2, 0x12, 0x90, 0x37, 0xC9, 0xED, 0xEF, 0xDA, 0x4D, 0xF8,
    0xD9, 0x1E, 0x8F, 0xEF, 0x55, 0xB7, 0x39, 0x4B, 0x7A, 0xD5, 0xB7, 0xD0, 0xB6, 0xC1, 0x22, 0x07,
    0xC9, 0xF9, 0x8D, 0x11, 0xED, 0x34, 0xDB, 0xF6, 0xC6, 0xBA, 0x0B, 0x2C, 0x8B, 0xBC, 0x27, 0xBE,
    0x6A, 0x00, 0xE0, 0xA0, 0xB9, 0xC4, 0x97, 0x08, 0xB3, 0xBF, 0x8A, 0x31, 0x70, 0x91, 0x88, 0x36,
    0x81, 0x28, 0x61, 0x30, 0xBC, 0x89, 0x85, 0xDB, 0x16, 0x02, 0xE7, 0x14, 0x41, 0x5D, 0x93, 0x30,
    0x27, 0x82, 0x73, 0xC7, 0xDE, 0x31, 0xEF, 0xDC, 0x73, 0x10, 0xF7, 0x12, 0x1F, 0xD5, 0xA0, 0x74,
    0x15, 0x98, 0x7D, 0x9A, 0xDC, 0x0A, 0x48, 0x6D, 0xCD, 0xF9, 0x3A, 0xCC, 0x44, 0x32, 0x83, 0x87,
    0x31, 0x5D, 0x75, 0xE1, 0x98, 0xC6, 0x41, 0xA4, 0x80, 0xCD, 0x86, 0xA1, 0xB9, 0xE5, 0x87, 0xE8,
    0xBE, 0x60, 0xE6, 0x9C, 0xC9, 0x28, 0xB2, 0xB9, 0xC5, 0x21, 0x72, 0xE4, 0x13, 0x04, 0x2E, 0x9B,
    0x23, 0xF1, 0x0B, 0x0E, 0x16, 0xE7, 0x97, 0x63, 0xC9, 0xB5, 0x3D, 0xCF, 0x4B, 0xA8, 0x0A, 0x29,
    0xE3, 0xFB, 0x73, 0xC1, 0x6B, 0x8E, 0x75, 0xB9, 0x7E, 0xF3, 0x63, 0xE2, 0xFF, 0xA3, 0x1F, 0x71,
    0xCF, 0x9D, 0xE5, 0x38, 0x4E, 0x71, 0xB8, 0x1C, 0x0A, 0xC4, 0xDF, 0xFE, 0x0C, 0x10, 0xE6, 0x4F,
};

const Prime3072Rfc3526 = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68, 0xC2, 0x34,
    0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74,
    0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37,
    0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6,
    0xF4, 0x4C, 0x42, 0xE9, 0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
    0x49, 0x28, 0x66, 0x51, 0xEC, 0xE4, 0x5B, 0x3D, 0xC2, 0x00, 0x7C, 0xB8, 0xA1, 0x63, 0xBF, 0x05,
    0x98, 0xDA, 0x48, 0x36, 0x1C, 0x55, 0xD3, 0x9A, 0x69, 0x16, 0x3F, 0xA8, 0xFD, 0x24, 0xCF, 0x5F,
    0x83, 0x65, 0x5D, 0x23, 0xDC, 0xA3, 0xAD, 0x96, 0x1C, 0x62, 0xF3, 0x56, 0x20, 0x85, 0x52, 0xBB,
    0x9E, 0xD5, 0x29, 0x07, 0x70, 0x96, 0x96, 0x6D, 0x67, 0x0C, 0x35, 0x4E, 0x4A, 0xBC, 0x98, 0x04,
    0xF1, 0x74, 0x6C, 0x08, 0xCA, 0x18, 0x21, 0x7C, 0x32, 0x90, 0x5E, 0x46, 0x2E, 0x36, 0xCE, 0x3B,
    0xE3, 0x9E, 0x77, 0x2C, 0x18, 0x0E, 0x86, 0x03, 0x9B, 0x27, 0x83, 0xA2, 0xEC, 0x07, 0xA2, 0x8F,
    0xB5, 0xC5, 0x5D, 0xF0, 0x6F, 0x4C, 0x52, 0xC9, 0xDE, 0x2B, 0xCB, 0xF6, 0x95, 0x58, 0x17, 0x18,
    0x39, 0x95, 0x49, 0x7C, 0xEA, 0x95, 0x6A, 0xE5, 0x15, 0xD2, 0x26, 0x18, 0x98, 0xFA, 0x05, 0x10,
    0x15, 0x72, 0x8E, 0x5A, 0x8A, 0xAA, 0xC4, 0x2D, 0xAD, 0x33, 0x17, 0x0D, 0x04, 0x50, 0x7A, 0x33,
    0xA8, 0x55, 0x21, 0xAB, 0xDF, 0x1C, 0xBA, 0x64, 0xEC, 0xFB, 0x85, 0x04, 0x58, 0xDB, 0xEF, 0x0A,
    0x8A, 0xEA, 0x71, 0x57, 0x5D, 0x06, 0x0C, 0x7D, 0xB3, 0x97, 0x0F, 0x85, 0xA6, 0xE1, 0xE4, 0xC7,
    0xAB, 0xF5, 0xAE, 0x8C, 0xDB, 0x09, 0x33, 0xD7, 0x1E, 0x8C, 0x94, 0xE0, 0x4A, 0x25, 0x61, 0x9D,
    0xCE, 0xE3, 0xD2, 0x26, 0x1A, 0xD2, 0xEE, 0x6B, 0xF1, 0x2F, 0xFA, 0x06, 0xD9, 0x8A, 0x08, 0x64,
    0xD8, 0x76, 0x02, 0x73, 0x3E, 0xC8, 0x6A, 0x64, 0x52, 0x1F, 0x2B, 0x18, 0x17, 0x7B, 0x20, 0x0C,
    0xBB, 0xE1, 0x17, 0x57, 0x7A, 0x61, 0x5D, 0x6C, 0x77, 0x09, 0x88, 0xC0, 0xBA, 0xD9, 0x46, 0xE2,
    0x08, 0xE2, 0x4F, 0xA0, 0x74, 0xE5, 0xAB, 0x31, 0x43, 0xDB, 0x5B, 0xFC, 0xE0, 0xFD, 0x10, 0x8E,
    0x4B, 0x82, 0xD1, 0x20, 0xA9, 0x3A, 0xD2, 0xCA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

const TEST_PRIMES = struct {
    perfCategory: u32,
    prime: []const u8,
};

const g_testPrimes = [_]TEST_PRIMES{
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP160 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP192 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP224 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP256 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP320 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP384 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeBrainPoolP512 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &Prime1024Rfc5114 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &Prime2048Rfc5114 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &Prime3072Rfc3526 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeWapiP192 },
    .{ .perfCategory = PERF_KEY_PUB_NIST, .prime = &PrimeNistP192 },
    .{ .perfCategory = PERF_KEY_PUB_NIST, .prime = &PrimeNistP224 },
    .{ .perfCategory = PERF_KEY_PUB_NIST, .prime = &PrimeNistP256 },
    .{ .perfCategory = PERF_KEY_PUB_NIST, .prime = &PrimeNistP384 },
    .{ .perfCategory = PERF_KEY_PUB_NIST, .prime = &PrimeNistP521 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeSecP160k },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeSecP160r },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeSecP192k },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeSecP224r },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeSecP256 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeWtlsP160 },
    .{ .perfCategory = PERF_KEY_PUB_ODD, .prime = &PrimeX962P239 },
    .{ .perfCategory = PERF_KEY_PUB_PM, .prime = &PrimeNumsP256 },
    .{ .perfCategory = PERF_KEY_PUB_PM, .prime = &PrimeNumsP384 },
    .{ .perfCategory = PERF_KEY_PUB_PM, .prime = &PrimeNumsP512 },
};

pub export fn getPerfTestModulus(exKeySize: u32) callconv(.c) ?[*]const u8 {
    const keyBytes: u32 = exKeySize & 0x00ffffff;
    var keyFlags: u32 = exKeySize & 0xff000000;

    keyFlags &= ~PERF_KEY_PRIME;
    if (keyFlags == PERF_KEY_SECRET or keyFlags == PERF_KEY_PUBLIC) {
        keyFlags = PERF_KEY_PUB_ODD;
    }

    for (g_testPrimes) |entry| {
        if (entry.perfCategory == keyFlags and entry.prime.len == keyBytes) {
            return entry.prime.ptr;
        }
    }
    h.check3(false, "Did not find suitable test modulus %08x", exKeySize);
    return null;
}

const MAX_TEST_DIGITS: u32 = 8;
const SCRATCH_BUF_SIZE: usize = 1 << 18;

var g_pbScratch: [*]u8 = undefined;
var g_piPool: [16]?*anyopaque = @splat(null);
var g_pdPool: [4]?*anyopaque = @splat(null);
var g_pmPool: [4]?*anyopaque = @splat(null);
var g_pePool: [8]?*anyopaque = @splat(null);

fn randomInt(piDst: ?*anyopaque) void {
    const cbVal: usize = (SymCryptIntBitsizeOfObject(piDst) + 7) / 8;
    var buf: [1024]u8 = undefined;
    h.check(cbVal <= buf.len, "Int too large");
    SymCryptCallbackRandom(&buf, cbVal);
    const mode = rng.scTestRngUint32(&rng.g_rng) % 4;
    if (mode == 0) {
        SymCryptIntSetValueUint32(rng.scTestRngUint32(&rng.g_rng) % 16, piDst);
    } else if (mode == 1) {
        const zeroBytes = rng.scTestRngUint32(&rng.g_rng) % cbVal;
        @memset(buf[0..zeroBytes], 0);
        _ = SymCryptIntSetValue(&buf, cbVal, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piDst);
    } else {
        _ = SymCryptIntSetValue(&buf, cbVal, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, piDst);
    }
}

fn arithInit() callconv(.c) void {
    const raw = SymCryptCallbackAlloc(SCRATCH_BUF_SIZE);
    h.check(raw != null, "Scratch allocation failed");
    g_pbScratch = @ptrCast(raw.?);

    const nDigits: u32 = 4;
    const nDigitsDouble: u32 = 8;
    for (0..12) |i| {
        g_piPool[i] = SymCryptIntAllocate(nDigits);
        h.check(g_piPool[i] != null, "Int allocation failed");
        randomInt(g_piPool[i]);
    }
    for (12..16) |i| {
        g_piPool[i] = SymCryptIntAllocate(nDigitsDouble);
        h.check(g_piPool[i] != null, "Double Int allocation failed");
        randomInt(g_piPool[i]);
    }

    for (0..4) |i| {
        g_pdPool[i] = SymCryptDivisorAllocate(nDigits);
        h.check(g_pdPool[i] != null, "Divisor allocation failed");
        randomInt(g_piPool[0]);
        _ = SymCryptIntAddUint32(g_piPool[0], 1, g_piPool[0]);
        if (SymCryptIntIsEqualUint32(g_piPool[0], 0) != 0) {
            SymCryptIntSetValueUint32(1, g_piPool[0]);
        }
        SymCryptIntToDivisor(g_piPool[0], g_pdPool[i], 100, 0, g_pbScratch, SCRATCH_BUF_SIZE);
    }

    for (0..4) |i| {
        g_pmPool[i] = SymCryptModulusAllocate(nDigits);
        h.check(g_pmPool[i] != null, "Modulus allocation failed");
        randomInt(g_piPool[0]);
        SymCryptIntSetBits(g_piPool[0], 1, 0, 1); // Make odd for Montgomery
        if (SymCryptIntBitsizeOfValue(g_piPool[0]) < 2) {
            SymCryptIntSetValueUint32(3 + @as(u32, @intCast(i * 2)), g_piPool[0]);
        }
        const flags: u32 = if ((i & 1) != 0) (SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PARITY_PUBLIC) else 0;
        SymCryptIntToModulus(g_piPool[0], g_pmPool[i], 100, flags, g_pbScratch, SCRATCH_BUF_SIZE);
    }

    for (0..8) |i| {
        g_pePool[i] = SymCryptModElementAllocate(g_pmPool[0]);
        h.check(g_pePool[i] != null, "ModElement allocation failed");
        SymCryptModSetRandom(g_pmPool[0], g_pePool[i], SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO | SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    }
}

fn arithCleanup() callconv(.c) void {
    for (&g_pePool) |*pe| {
        if (pe.*) |p| {
            SymCryptModElementFree(g_pmPool[0], p);
            pe.* = null;
        }
    }
    for (&g_pmPool) |*pm| {
        if (pm.*) |p| {
            SymCryptModulusFree(p);
            pm.* = null;
        }
    }
    for (&g_pdPool) |*pd| {
        if (pd.*) |p| {
            SymCryptDivisorFree(p);
            pd.* = null;
        }
    }
    for (&g_piPool) |*pi| {
        if (pi.*) |p| {
            SymCryptIntFree(p);
            pi.* = null;
        }
    }
    SymCryptWipe(g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptCallbackFree(g_pbScratch);
}

fn arithInvariant() callconv(.c) void {}

fn testIntAddSub() callconv(.c) void {
    const a = g_piPool[0];
    const b = g_piPool[1];
    const c = g_piPool[2];
    const d = g_piPool[3];
    randomInt(a);
    randomInt(b);

    const carry = SymCryptIntAddSameSize(a, b, c);
    const borrow = SymCryptIntSubSameSize(c, b, d);
    h.check(carry == borrow, "IntAddSameSize / IntSubSameSize carry!=borrow");
    h.check(SymCryptIntIsEqual(a, d) != 0, "IntAddSameSize / IntSubSameSize a != d");

    const u = rng.scTestRngUint32(&rng.g_rng);
    const c2 = SymCryptIntAddUint32(a, u, c);
    const b2 = SymCryptIntSubUint32(c, u, d);
    h.check(c2 == b2 and SymCryptIntIsEqual(a, d) != 0, "IntAddUint32 / IntSubUint32 mismatch");
}

fn testIntMulDiv() callconv(.c) void {
    const a = g_piPool[0];
    const b = g_piPool[1];
    const prod = g_piPool[12];
    const sq = g_piPool[13];
    const q = g_piPool[14];
    const r = g_piPool[2];

    randomInt(a);
    randomInt(b);

    SymCryptIntMulSameSize(a, a, prod, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptIntSquare(a, sq, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptIntIsEqual(prod, sq) != 0, "IntMulSameSize(a,a) != IntSquare(a)");

    SymCryptIntMulSameSize(a, b, prod, g_pbScratch, SCRATCH_BUF_SIZE);

    if (SymCryptIntIsEqualUint32(b, 0) == 0) {
        SymCryptIntToDivisor(b, g_pdPool[0], 10, 0, g_pbScratch, SCRATCH_BUF_SIZE);
        SymCryptIntDivMod(prod, g_pdPool[0], q, r, g_pbScratch, SCRATCH_BUF_SIZE);
        h.check(SymCryptIntIsEqualUint32(r, 0) != 0, "(a*b) mod b != 0");
        const status = SymCryptIntCopyMixedSize(q, g_piPool[3]);
        h.check(status == SYMCRYPT_NO_ERROR and SymCryptIntIsEqual(a, g_piPool[3]) != 0, "(a*b) / b != a");
    }
}

fn testIntShiftsAndBits() callconv(.c) void {
    const a = g_piPool[0];
    const b = g_piPool[1];
    const c = g_piPool[2];
    randomInt(a);

    const nBits = SymCryptIntBitsizeOfObject(a);
    const iBit = rng.scTestRngUint32(&rng.g_rng) % nBits;
    const width = 1 + (rng.scTestRngUint32(&rng.g_rng) % @min(@as(u32, 32), nBits - iBit));
    const val = rng.scTestRngUint32(&rng.g_rng) & (if (width == 32) 0xffffffff else ((@as(u32, 1) << @intCast(width)) - 1));

    SymCryptIntCopy(a, b);
    SymCryptIntSetBits(b, val, iBit, width);
    const readBack = SymCryptIntGetBits(b, iBit, width);
    h.check(readBack == val, "SymCryptIntSetBits / GetBits mismatch");

    const shift: usize = rng.scTestRngUint32(&rng.g_rng) % nBits;
    SymCryptIntCopy(a, b);
    SymCryptIntModPow2(b, shift, b);
    SymCryptIntCopy(a, c);
    SymCryptIntDivPow2(c, shift, c);
    SymCryptIntMulPow2(c, shift, c);
    _ = SymCryptIntAddSameSize(b, c, c);
    h.check(SymCryptIntIsEqual(a, c) != 0, "DivPow2 * 2^k + ModPow2 != a");
}

fn testIntGcdAndSqrt() callconv(.c) void {
    const a = g_piPool[0];
    const b = g_piPool[1];
    const gcd = g_piPool[2];
    const lcm = g_piPool[12];
    const prod = g_piPool[13];
    const prod2 = g_piPool[14];

    randomInt(a);
    randomInt(b);
    SymCryptIntSetBits(b, 1, 0, 1); // Ensure b is odd as required by SymCryptIntExtendedGcd
    if (SymCryptIntIsEqualUint32(a, 0) != 0) {
        SymCryptIntSetValueUint32(2, a);
    }

    SymCryptIntExtendedGcd(a, b, SYMCRYPT_FLAG_DATA_PUBLIC, gcd, lcm, null, null, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptIntMulSameSize(a, b, prod, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptIntToDivisor(gcd, g_pdPool[0], 1, SYMCRYPT_FLAG_DATA_PUBLIC, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptIntDivMod(prod, g_pdPool[0], prod2, g_piPool[3], g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptIntIsEqualUint32(g_piPool[3], 0) != 0, "(a*b) mod gcd(a,b) != 0");
    h.check(SymCryptIntIsEqual(prod2, lcm) != 0, "(a*b) / gcd(a,b) != lcm(a,b)");
}

fn testModArithmetic() callconv(.c) void {
    const pm = g_pmPool[0];
    const peA = g_pePool[0];
    const peB = g_pePool[1];
    const peC = g_pePool[2];
    const peD = g_pePool[3];
    const peE = g_pePool[4];

    SymCryptModSetRandom(pm, peA, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO | SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModSetRandom(pm, peB, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO | SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModSetRandom(pm, peC, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ZERO | SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);

    // (A + B) - B == A
    SymCryptModAdd(pm, peA, peB, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModSub(pm, peD, peB, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptModElementIsEqual(pm, peA, peD) != 0, "(A + B) - B != A");

    // A + (-A) == 0
    SymCryptModNeg(pm, peA, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModAdd(pm, peA, peD, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptModElementIsZero(pm, peD) != 0, "A + (-A) != 0");

    // A * A == Square(A)
    SymCryptModMul(pm, peA, peA, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModSquare(pm, peA, peE, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptModElementIsEqual(pm, peD, peE) != 0, "A * A != Square(A)");

    // Distributivity: A * (B + C) == A*B + A*C
    SymCryptModAdd(pm, peB, peC, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModMul(pm, peA, peD, peD, g_pbScratch, SCRATCH_BUF_SIZE);

    SymCryptModMul(pm, peA, peB, peE, g_pbScratch, SCRATCH_BUF_SIZE);
    const peF = g_pePool[5];
    SymCryptModMul(pm, peA, peC, peF, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModAdd(pm, peE, peF, peE, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptModElementIsEqual(pm, peD, peE) != 0, "A*(B+C) != A*B + A*C");
}

fn testModExpAndMultiExp() callconv(.c) void {
    const pm = g_pmPool[0];
    const peA = g_pePool[0];
    const peB = g_pePool[1];
    const peC = g_pePool[2];
    const peD = g_pePool[3];
    const piE1 = g_piPool[0];
    const piE2 = g_piPool[1];

    SymCryptModSetRandom(pm, peA, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModSetRandom(pm, peB, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    randomInt(piE1);
    randomInt(piE2);

    const nBitsExp = SymCryptIntBitsizeOfObject(piE1);
    SymCryptModExp(pm, peA, piE1, nBitsExp, SYMCRYPT_FLAG_DATA_PUBLIC, peC, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModExp(pm, peB, piE2, nBitsExp, SYMCRYPT_FLAG_DATA_PUBLIC, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModMul(pm, peC, peD, peC, g_pbScratch, SCRATCH_BUF_SIZE);

    var bases = [2]?*const anyopaque{ peA, peB };
    var exps = [2]?*const anyopaque{ piE1, piE2 };
    const scErr = SymCryptModMultiExp(pm, &bases, &exps, 2, nBitsExp, SYMCRYPT_FLAG_DATA_PUBLIC, peD, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(scErr == SYMCRYPT_NO_ERROR, "SymCryptModMultiExp failed");
    h.check(SymCryptModElementIsEqual(pm, peC, peD) != 0, "ModMultiExp != A^e1 * B^e2");
}

fn testPrimeGenAndIsPrime() callconv(.c) void {
    const nDigits = SymCryptDigitsFromBits(128);
    const piLow = SymCryptIntAllocate(nDigits);
    const piHigh = SymCryptIntAllocate(nDigits);
    const piPrime = SymCryptIntAllocate(nDigits);
    const pmPrime = SymCryptModulusAllocate(nDigits);
    h.check(piLow != null and piHigh != null and piPrime != null and pmPrime != null, "Allocation failed");
    defer {
        SymCryptModulusFree(pmPrime);
        SymCryptIntFree(piPrime);
        SymCryptIntFree(piHigh);
        SymCryptIntFree(piLow);
    }

    SymCryptIntSetValueUint32(1000, piLow);
    SymCryptIntSetValueUint32(100000, piHigh);

    const scErr = SymCryptIntGenerateRandomPrime(piLow, piHigh, null, 0, 1000, 0, piPrime, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(scErr == SYMCRYPT_NO_ERROR, "SymCryptIntGenerateRandomPrime failed");
    h.check(ref.RefIsPrime(piPrime, g_pbScratch, SCRATCH_BUF_SIZE) != 0, "Generated prime failed RefIsPrime");

    SymCryptIntToModulus(piPrime, pmPrime, 100, SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME, g_pbScratch, SCRATCH_BUF_SIZE);
    const isPrime = SymCryptIntMillerRabinPrimalityTest(piPrime, SymCryptIntBitsizeOfValue(piPrime), 10, SYMCRYPT_FLAG_DATA_PUBLIC, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(isPrime != 0, "Generated prime failed Miller-Rabin");

    // Check mod inverse modulo prime: A * A^-1 == 1
    const peA = SymCryptModElementAllocate(pmPrime);
    const peInv = SymCryptModElementAllocate(pmPrime);
    const peOne = SymCryptModElementAllocate(pmPrime);
    h.check(peA != null and peInv != null and peOne != null, "ModElement alloc failed");
    defer {
        SymCryptModElementFree(pmPrime, peOne);
        SymCryptModElementFree(pmPrime, peInv);
        SymCryptModElementFree(pmPrime, peA);
    }

    SymCryptModSetRandom(pmPrime, peA, SYMCRYPT_FLAG_MODRANDOM_ALLOW_ONE, g_pbScratch, SCRATCH_BUF_SIZE);
    const invErr = SymCryptModInv(pmPrime, peA, peInv, SYMCRYPT_FLAG_DATA_PUBLIC, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(invErr == SYMCRYPT_NO_ERROR, "SymCryptModInv failed");
    SymCryptModMul(pmPrime, peA, peInv, peInv, g_pbScratch, SCRATCH_BUF_SIZE);
    SymCryptModElementSetValueUint32(1, pmPrime, peOne, g_pbScratch, SCRATCH_BUF_SIZE);
    h.check(SymCryptModElementIsEqual(pmPrime, peInv, peOne) != 0, "A * A^-1 != 1 mod p");
}

fn gcdUint32(a_in: u32, b_in: u32) u32 {
    var a = a_in;
    var b = b_in;
    while (a != 0) {
        const t = b % a;
        b = a;
        a = t;
    }
    return b;
}

fn testCompositeModInv() void {
    const pMod = SymCryptModulusAllocate(1);
    const pEl = SymCryptModElementAllocate(pMod);
    const pInv = SymCryptModElementAllocate(pMod);
    const cbScratch: usize = 1 << 20;
    const raw = SymCryptCallbackAlloc(cbScratch);
    h.check(pMod != null and pEl != null and pInv != null and raw != null, "Out of memory");
    const pbScratch: [*]u8 = @ptrCast(raw.?);
    defer {
        SymCryptWipe(pbScratch, cbScratch);
        SymCryptCallbackFree(pbScratch);
        SymCryptModElementFree(pMod, pEl);
        SymCryptModElementFree(pMod, pInv);
        SymCryptModulusFree(pMod);
    }

    for (0..1000) |_| {
        var mod: u32 = @intCast(rng.scTestRngSizetRange(&rng.g_rng, 2, 1 << 16));
        if (mod != 2) {
            mod |= 1;
        }

        const x: u32 = @intCast(rng.scTestRngSizet(&rng.g_rng, mod));
        h.check(x < mod, "?");
        SymCryptIntSetValueUint32(mod, SymCryptIntFromModulus(pMod));

        var b: u8 = rng.scTestRngByte(&rng.g_rng);
        const modFlags: u32 = SYMCRYPT_FLAG_DATA_PUBLIC | SYMCRYPT_FLAG_MODULUS_PRIME;

        SymCryptIntToModulus(SymCryptIntFromModulus(pMod), pMod, rng.scTestRngByte(&rng.g_rng), modFlags, pbScratch, cbScratch);
        SymCryptModElementSetValueUint32(x, pMod, pEl, pbScratch, cbScratch);

        const opFlags: u32 = SYMCRYPT_FLAG_DATA_PUBLIC;
        const scError = SymCryptModInv(pMod, pEl, pInv, opFlags, pbScratch, cbScratch);

        if (scError == SYMCRYPT_NO_ERROR) {
            SymCryptModMul(pMod, pEl, pInv, pInv, pbScratch, cbScratch);
            const scError2 = SymCryptModElementGetValue(pMod, pInv, @ptrCast(&b), 1, SYMCRYPT_NUMBER_FORMAT_LSB_FIRST, pbScratch, cbScratch);
            h.check(scError2 == SYMCRYPT_NO_ERROR and b == 1, "ModInv * input is not 1");
        }

        const coPrime = gcdUint32(x, mod) == 1;
        h.check(coPrime or scError != SYMCRYPT_NO_ERROR, "No error for modinv that does not exist");
        h.check((modFlags & SYMCRYPT_FLAG_DATA_PUBLIC) == 0 or
            (modFlags & SYMCRYPT_FLAG_MODULUS_PRIME) == 0 or
            !coPrime or
            scError == SYMCRYPT_NO_ERROR, "Unexpected error for modinverse");
    }
}

fn testTrialDivisionOne() callconv(.c) void {
    const nD: u32 = 4;
    const pCtx = SymCryptCreateTrialDivisionContext(nD);
    const pCtxNext = SymCryptCreateTrialDivisionContext(nD + 1);
    h.check(pCtx != null and pCtxNext != null, "Out of memory");
    defer {
        SymCryptFreeTrialDivisionContext(pCtx);
        SymCryptFreeTrialDivisionContext(pCtxNext);
    }

    const piSrc = g_piPool[0];
    randomInt(piSrc);
    if (SymCryptIntBitsizeOfValue(piSrc) < 2) {
        SymCryptIntSetValueUint32(15, piSrc);
    }

    var div = SymCryptIntFindSmallDivisor(pCtx, piSrc, g_pbScratch, SCRATCH_BUF_SIZE);
    if (div == 0) {
        div = SymCryptIntFindSmallDivisor(pCtxNext, piSrc, g_pbScratch, SCRATCH_BUF_SIZE);
        h.check(div == 0 or div > SymCryptTestTrialdivisionMaxSmallPrime(pCtx), "Divisor inconsistent");
    }

    if (div != 0) {
        const pdDiv = SymCryptDivisorAllocate(1);
        const piRem = SymCryptIntAllocate(1);
        h.check(pdDiv != null and piRem != null, "Out of memory");
        defer {
            SymCryptIntFree(piRem);
            SymCryptDivisorFree(pdDiv);
        }
        SymCryptIntSetValueUint32(div, SymCryptIntFromDivisor(pdDiv));
        SymCryptIntToDivisor(SymCryptIntFromDivisor(pdDiv), pdDiv, 1, 0, g_pbScratch, SCRATCH_BUF_SIZE);
        SymCryptIntDivMod(piSrc, pdDiv, null, piRem, g_pbScratch, SCRATCH_BUF_SIZE);
        h.check(SymCryptIntIsEqualUint32(piRem, 0) != 0, "Trial division divisor doesn't divide number");
    }
}

fn testArithAll() void {
    rnd.registerInitFunction(&arithInit);
    rnd.registerCleanupFunction(&arithCleanup);
    rnd.registerInvariantFunction(&arithInvariant);

    rnd.registerTestFunction(&testIntAddSub, "IntAddSub", 10);
    rnd.registerTestFunction(&testIntMulDiv, "IntMulDiv", 10);
    rnd.registerTestFunction(&testIntShiftsAndBits, "IntShiftsAndBits", 10);
    rnd.registerTestFunction(&testIntGcdAndSqrt, "IntGcdAndSqrt", 5);
    rnd.registerTestFunction(&testModArithmetic, "ModArithmetic", 10);
    rnd.registerTestFunction(&testModExpAndMultiExp, "ModExpAndMultiExp", 5);
    rnd.registerTestFunction(&testPrimeGenAndIsPrime, "PrimeGenAndIsPrime", 2);
    rnd.registerTestFunction(&testTrialDivisionOne, "TrialDivision", 5);

    rnd.runTest(5, 1);
}

var hasRun: bool = false;

pub export fn testArithmetic() callconv(.c) void {
    if (hasRun) {
        return;
    }
    hasRun = true;

    if (!h.isAlgorithmPresent("Int", 1) and
        !h.isAlgorithmPresent("Mod", 1))
    {
        return;
    }

    h.ziprint("    Arithmetic", .{});

    var nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak %d", nOutstandingAllocs);

    testArithAll();

    nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak, %d outstanding", nOutstandingAllocs);

    testCompositeModInv();

    h.ziprint("\n", .{});
}
