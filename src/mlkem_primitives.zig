//
// mlkem_primitives.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// ML-KEM polynomial ring element, vector, and matrix primitives ported from lib/mlkem_primitives.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const shake = @import("shake.zig");
const sha3 = @import("sha3.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT16 = types.UINT16;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ASYM_ALIGN_VALUE = types.SYMCRYPT_ASYM_ALIGN_VALUE;

// ==============================================================================================
// ML-KEM Constants & Internal Types (from inc/symcrypt_internal.h and lib/sc_lib_mlkem.h)
// ==============================================================================================

pub const SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS: usize = 256;
pub const SYMCRYPT_MLKEM_Q: UINT32 = 3329;
pub const SYMCRYPT_MLKEM_MATRIX_MAX_NROWS: usize = 4;
pub const SYMCRYPT_MLKEMKEY_MAX_SIZEOF_ENCODED_T: usize = 1536;

pub const SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE: usize = 2 * 32;
pub const SYMCRYPT_MLKEM_AGREED_SECRET_SIZE: usize = 32;
pub const SYMCRYPT_MLKEM_SIZEOF_MAX_CIPHERTEXT: usize = 1568;
pub const SYMCRYPT_MLKEM_SIZEOF_AGREED_SECRET: usize = SYMCRYPT_MLKEM_AGREED_SECRET_SIZE;
pub const SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM: usize = 32;

pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM512: usize = 800;
pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768: usize = 1184;
pub const SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024: usize = 1568;

pub const SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM512: usize = 1632;
pub const SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM768: usize = 2400;
pub const SYMCRYPT_MLKEM_DECAPSULATION_KEY_SIZE_MLKEM1024: usize = 3168;

pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM512: usize = 768;
pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM768: usize = 1088;
pub const SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM1024: usize = 1568;

pub const SYMCRYPT_MLKEMKEY_FORMAT = enum(c_uint) {
    NULL = 0,
    PRIVATE_SEED = 1,
    DECAPSULATION_KEY = 2,
    ENCAPSULATION_KEY = 3,
    _,
};

pub const SYMCRYPT_MLKEM_PARAMS = enum(c_uint) {
    NULL = 0,
    MLKEM512 = 1,
    MLKEM768 = 2,
    MLKEM1024 = 3,
    _,
};

pub const SYMCRYPT_MLKEM_POLYELEMENT = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]UINT16 align(SYMCRYPT_ASYM_ALIGN_VALUE),
};
pub const PSYMCRYPT_MLKEM_POLYELEMENT = *SYMCRYPT_MLKEM_POLYELEMENT;
pub const PCSYMCRYPT_MLKEM_POLYELEMENT = *const SYMCRYPT_MLKEM_POLYELEMENT;

pub const SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
};
pub const PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR = *SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR;

pub const SYMCRYPT_MLKEM_VECTOR = extern struct {
    nRows: UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
    cbTotalSize: UINT32,
};
pub const PSYMCRYPT_MLKEM_VECTOR = *SYMCRYPT_MLKEM_VECTOR;
pub const PCSYMCRYPT_MLKEM_VECTOR = *const SYMCRYPT_MLKEM_VECTOR;

pub const SYMCRYPT_MLKEM_MATRIX = extern struct {
    nRows: UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
    cbTotalSize: UINT32,
    apPolyElements: [SYMCRYPT_MLKEM_MATRIX_MAX_NROWS * SYMCRYPT_MLKEM_MATRIX_MAX_NROWS]PSYMCRYPT_MLKEM_POLYELEMENT,
};
pub const PSYMCRYPT_MLKEM_MATRIX = *SYMCRYPT_MLKEM_MATRIX;
pub const PCSYMCRYPT_MLKEM_MATRIX = *const SYMCRYPT_MLKEM_MATRIX;

pub const SYMCRYPT_MLKEM_INTERNAL_PARAMS = extern struct {
    params: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    cbPolyElement: UINT32,
    cbVector: UINT32,
    cbMatrix: UINT32,
    nRows: UINT8,
    nEta1: UINT8,
    nEta2: UINT8,
    nBitsOfU: UINT8,
    nBitsOfV: UINT8,
};
pub const PSYMCRYPT_MLKEM_INTERNAL_PARAMS = *SYMCRYPT_MLKEM_INTERNAL_PARAMS;
pub const PCSYMCRYPT_MLKEM_INTERNAL_PARAMS = *const SYMCRYPT_MLKEM_INTERNAL_PARAMS;

pub const SYMCRYPT_MLKEMKEY = extern struct {
    fAlgorithmInfo: UINT32 align(SYMCRYPT_ASYM_ALIGN_VALUE),
    params: SYMCRYPT_MLKEM_INTERNAL_PARAMS,
    cbTotalSize: UINT32,
    hasPrivateSeed: BOOLEAN,
    hasPrivateKey: BOOLEAN,
    privateSeed: [32]BYTE,
    privateRandom: [32]BYTE,
    publicSeed: [32]BYTE,
    pmAtranspose: PSYMCRYPT_MLKEM_MATRIX,
    pvt: PSYMCRYPT_MLKEM_VECTOR,
    pvs: PSYMCRYPT_MLKEM_VECTOR,
    encodedT: [SYMCRYPT_MLKEMKEY_MAX_SIZEOF_ENCODED_T]BYTE,
    encapsKeyHash: [32]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_MLKEMKEY = *SYMCRYPT_MLKEMKEY;
pub const PCSYMCRYPT_MLKEMKEY = *const SYMCRYPT_MLKEMKEY;

pub const SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT: usize = @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT);
pub const SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT_ACCUMULATOR: usize = @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR);
pub const SYMCRYPT_INTERNAL_MLKEM_MAXIMUM_VECTOR_SIZE: usize =
    @sizeOf(SYMCRYPT_MLKEM_VECTOR) + (SYMCRYPT_MLKEM_MATRIX_MAX_NROWS * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT);

pub inline fn vectorElementOffset(row: usize) usize {
    return @sizeOf(SYMCRYPT_MLKEM_VECTOR) + (row * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT);
}

pub inline fn vectorElement(pVector: PSYMCRYPT_MLKEM_VECTOR, row: usize) PSYMCRYPT_MLKEM_POLYELEMENT {
    const base: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @ptrCast(pVector);
    const elem_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(base + vectorElementOffset(row));
    return @ptrCast(elem_ptr);
}

pub inline fn vectorElementConst(pVector: PCSYMCRYPT_MLKEM_VECTOR, row: usize) PCSYMCRYPT_MLKEM_POLYELEMENT {
    const base: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) const BYTE = @ptrCast(pVector);
    const elem_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) const BYTE = @alignCast(base + vectorElementOffset(row));
    return @ptrCast(elem_ptr);
}

pub const HashStateUnion = extern union {
    shake128State: shake.SYMCRYPT_SHAKE128_STATE,
    shake256State: shake.SYMCRYPT_SHAKE256_STATE,
    sha3_256State: sha3.SYMCRYPT_SHA3_256_STATE,
    sha3_512State: sha3.SYMCRYPT_SHA3_512_STATE,
};

pub const SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = extern struct {
    abVectorBuffer0: [SYMCRYPT_INTERNAL_MLKEM_MAXIMUM_VECTOR_SIZE]BYTE align(SYMCRYPT_ASYM_ALIGN_VALUE),
    abVectorBuffer1: [SYMCRYPT_INTERNAL_MLKEM_MAXIMUM_VECTOR_SIZE]BYTE align(SYMCRYPT_ASYM_ALIGN_VALUE),
    abPolyElementBuffer0: [SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT]BYTE align(SYMCRYPT_ASYM_ALIGN_VALUE),
    abPolyElementBuffer1: [SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT]BYTE align(SYMCRYPT_ASYM_ALIGN_VALUE),
    abPolyElementAccumulatorBuffer: [SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT_ACCUMULATOR]BYTE align(SYMCRYPT_ASYM_ALIGN_VALUE),
    hashState0: HashStateUnion,
    hashState1: HashStateUnion,
};
pub const PSYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES = *SYMCRYPT_MLKEM_INTERNAL_COMPUTATION_TEMPORARIES;

// ==============================================================================================
// Arithmetic Constants & Zeta Tables
// ==============================================================================================

pub export const SYMCRYPT_MLKEM_Rlog2: UINT32 = 16;
pub export const SYMCRYPT_MLKEM_Rmask: UINT32 = 0xffff;
pub export const SYMCRYPT_MLKEM_NegQInvModR: UINT32 = 3327;
pub export const SYMCRYPT_MLKEM_Rsqr: UINT32 = 1353;
pub export const SYMCRYPT_MLKEM_RsqrTimesNegQInvModR: UINT32 = 44983;
pub export const SYMCRYPT_MLKEM_INTTFixupTimesRsqr: UINT32 = 1441;
pub export const SYMCRYPT_MLKEM_INTTFixupTimesRsqrTimesNegQInvModR: UINT32 = 10079;
pub export const SYMCRYPT_MLKEM_COMPRESS_MULCONSTANT: UINT32 = 0x275f6f;
pub export const SYMCRYPT_MLKEM_COMPRESS_SHIFTCONSTANT: UINT32 = 33;

const SYMCRYPT_MLKEM_MaxCoeff: UINT32 = SYMCRYPT_MLKEM_Q - 1;
const SYMCRYPT_MLKEM_MaxCoeffProduct: UINT32 = SYMCRYPT_MLKEM_MaxCoeff * SYMCRYPT_MLKEM_MaxCoeff;
const SYMCRYPT_MLKEM_MaxFirstStepReduction: UINT32 = 3494;
const SYMCRYPT_MLKEM_MaxZetaTwoTimesPlus1TimesR: UINT32 = 3254;
const SYMCRYPT_MLKEM_MaxA1B1ZetaPow: UINT32 =
    SYMCRYPT_MLKEM_MaxFirstStepReduction * SYMCRYPT_MLKEM_MaxZetaTwoTimesPlus1TimesR;

pub export const MlKemZetaBitRevTimesR: [128]UINT16 = .{
    2285, 2571, 2970, 1812, 1493, 1422, 287,  202,
    3158, 622,  1577, 182,  962,  2127, 1855, 1468,
    573,  2004, 264,  383,  2500, 1458, 1727, 3199,
    2648, 1017, 732,  608,  1787, 411,  3124, 1758,
    1223, 652,  2777, 1015, 2036, 1491, 3047, 1785,
    516,  3321, 3009, 2663, 1711, 2167, 126,  1469,
    2476, 3239, 3058, 830,  107,  1908, 3082, 2378,
    2931, 961,  1821, 2604, 448,  2264, 677,  2054,
    2226, 430,  555,  843,  2078, 871,  1550, 105,
    422,  587,  177,  3094, 3038, 2869, 1574, 1653,
    3083, 778,  1159, 3182, 2552, 1483, 2727, 1119,
    1739, 644,  2457, 349,  418,  329,  3173, 3254,
    817,  1097, 603,  610,  1322, 2044, 1864, 384,
    2114, 3193, 1218, 1994, 2455, 220,  2142, 1670,
    2144, 1799, 2051, 794,  1819, 2475, 2459, 478,
    3221, 3021, 996,  991,  958,  1869, 1522, 1628,
};

pub export const MlKemZetaBitRevTimesRTimesNegQInvModR: [128]UINT16 = .{
    19,    34037, 50790, 64748, 52011, 12402, 37345, 16694,
    20906, 37778, 3799,  15690, 54846, 64177, 11201, 34372,
    5827,  48172, 26360, 29057, 59964, 1102,  44097, 26241,
    28072, 41223, 10532, 56736, 47109, 56677, 38860, 16162,
    5689,  6516,  64039, 34569, 23564, 45357, 44825, 40455,
    12796, 38919, 49471, 12441, 56401, 649,   25986, 37699,
    45652, 28249, 15886, 8898,  28309, 56460, 30198, 47286,
    52109, 51519, 29155, 12756, 48704, 61224, 24155, 17914,
    334,   54354, 11477, 52149, 32226, 14233, 45042, 21655,
    27738, 52405, 64591, 4586,  14882, 42443, 59354, 60043,
    33525, 32502, 54905, 35218, 36360, 18741, 28761, 52897,
    18485, 45436, 47975, 47011, 14430, 46007, 5275,  12618,
    31183, 45239, 40101, 63390, 7382,  50180, 41144, 32384,
    20926, 6279,  54590, 14902, 41321, 11044, 48546, 51066,
    55200, 21497, 7933,  20198, 22501, 42325, 54629, 17442,
    33899, 23859, 36892, 20257, 41538, 57779, 17422, 42404,
};

pub export const zetaTwoTimesBitRevPlus1TimesR: [128]UINT16 = .{
    2226, 1103, 430,  2899, 555,  2774, 843,  2486,
    2078, 1251, 871,  2458, 1550, 1779, 105,  3224,
    422,  2907, 587,  2742, 177,  3152, 3094, 235,
    3038, 291,  2869, 460,  1574, 1755, 1653, 1676,
    3083, 246,  778,  2551, 1159, 2170, 3182, 147,
    2552, 777,  1483, 1846, 2727, 602,  1119, 2210,
    1739, 1590, 644,  2685, 2457, 872,  349,  2980,
    418,  2911, 329,  3000, 3173, 156,  3254, 75,
    817,  2512, 1097, 2232, 603,  2726, 610,  2719,
    1322, 2007, 2044, 1285, 1864, 1465, 384,  2945,
    2114, 1215, 3193, 136,  1218, 2111, 1994, 1335,
    2455, 874,  220,  3109, 2142, 1187, 1670, 1659,
    2144, 1185, 1799, 1530, 2051, 1278, 794,  2535,
    1819, 1510, 2475, 854,  2459, 870,  478,  2851,
    3221, 108,  3021, 308,  996,  2333, 991,  2338,
    958,  2371, 1869, 1460, 1522, 1807, 1628, 1701,
};

// ==============================================================================================
// Object Creation Helpers
// ==============================================================================================

inline fn assertAsymAligned(ptr: anytype) void {
    macros.ASSERT((@intFromPtr(ptr) & (SYMCRYPT_ASYM_ALIGN_VALUE - 1)) == 0);
}

pub export fn SymCryptMlKemPolyElementCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEM_POLYELEMENT {
    assertAsymAligned(pbBuffer);
    macros.ASSERT(cbBuffer == SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbBuffer);
    return @ptrCast(aligned_ptr);
}

pub export fn SymCryptMlKemPolyElementAccumulatorCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR {
    assertAsymAligned(pbBuffer);
    macros.ASSERT(cbBuffer == SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT_ACCUMULATOR);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbBuffer);
    return @ptrCast(aligned_ptr);
}

pub export fn SymCryptMlKemVectorCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
    nRows: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEM_VECTOR {
    assertAsymAligned(pbBuffer);
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbBuffer);
    const pVector: PSYMCRYPT_MLKEM_VECTOR = @ptrCast(aligned_ptr);
    pVector.nRows = nRows;
    pVector.cbTotalSize = cbBuffer;

    var pbTmp: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_MLKEM_VECTOR);
    var i: UINT32 = 0;
    while (i < nRows) : (i += 1) {
        const peTmp = SymCryptMlKemPolyElementCreate(pbTmp, @intCast(SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT));
        if (peTmp == null) {
            return null;
        }
        pbTmp += SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT;
    }

    macros.ASSERT(pbTmp == (pbBuffer + cbBuffer));
    return pVector;
}

pub export fn SymCryptMlKemMatrixCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
    nRows: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLKEM_MATRIX {
    assertAsymAligned(pbBuffer);
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    const aligned_ptr: [*]align(SYMCRYPT_ASYM_ALIGN_VALUE) BYTE = @alignCast(pbBuffer);
    const pMatrix: PSYMCRYPT_MLKEM_MATRIX = @ptrCast(aligned_ptr);
    pMatrix.nRows = nRows;
    pMatrix.cbTotalSize = cbBuffer;

    var pbTmp: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_MLKEM_MATRIX);
    var i: UINT32 = 0;
    while (i < (nRows * nRows)) : (i += 1) {
        const peTmp = SymCryptMlKemPolyElementCreate(pbTmp, @intCast(SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT));
        if (peTmp == null) {
            return null;
        }
        pMatrix.apPolyElements[i] = peTmp.?;
        pbTmp += SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT;
    }

    macros.ASSERT(pbTmp == (pbBuffer + cbBuffer));
    return pMatrix;
}

// ==============================================================================================
// Constant-Time Modular Arithmetic & NTT Primitives
// ==============================================================================================

inline fn SymCryptMlKemModAdd(a: UINT32, b: UINT32) UINT32 {
    macros.ASSERT(a < SYMCRYPT_MLKEM_Q);
    macros.ASSERT(b < SYMCRYPT_MLKEM_Q);

    var res: UINT32 = (a + b) -% SYMCRYPT_MLKEM_Q;
    macros.ASSERT(((res >> 16) == 0) or ((res >> 16) == 0xffff));
    res +%= SYMCRYPT_MLKEM_Q & (res >> 16);
    macros.ASSERT(res < SYMCRYPT_MLKEM_Q);

    return res;
}

inline fn SymCryptMlKemModSub(a: UINT32, b: UINT32) UINT32 {
    macros.ASSERT(a < 2 * SYMCRYPT_MLKEM_Q);
    macros.ASSERT(b <= SYMCRYPT_MLKEM_Q);

    var res: UINT32 = a -% b;
    macros.ASSERT(((res >> 16) == 0) or ((res >> 16) == 0xffff));
    res +%= SYMCRYPT_MLKEM_Q & (res >> 16);
    macros.ASSERT(res < SYMCRYPT_MLKEM_Q);

    return res;
}

inline fn SymCryptMlKemMontMul(a: UINT32, b: UINT32, bMont: UINT32) UINT32 {
    macros.ASSERT(a < SYMCRYPT_MLKEM_Q);
    macros.ASSERT(b < SYMCRYPT_MLKEM_Q);
    macros.ASSERT(bMont <= SYMCRYPT_MLKEM_Rmask);
    macros.ASSERT(bMont == ((b * SYMCRYPT_MLKEM_NegQInvModR) & SYMCRYPT_MLKEM_Rmask));

    var res: UINT32 = a * b;
    const inv: UINT32 = (a * bMont) & SYMCRYPT_MLKEM_Rmask;
    res += inv * SYMCRYPT_MLKEM_Q;
    macros.ASSERT((res & SYMCRYPT_MLKEM_Rmask) == 0);
    res >>= @intCast(SYMCRYPT_MLKEM_Rlog2);

    return SymCryptMlKemModSub(res, SYMCRYPT_MLKEM_Q);
}

inline fn nttLayerComptime(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
    comptime k_in: usize,
    comptime ulen: usize,
) void {
    var k: usize = k_in;
    var start: usize = 0;

    while (start < 256) : (start += 2 * ulen) {
        const twiddleFactor: UINT32 = MlKemZetaBitRevTimesR[k];
        const twiddleFactorMont: UINT32 = MlKemZetaBitRevTimesRTimesNegQInvModR[k];
        k += 1;

        for (0..ulen) |j| {
            var c0: UINT32 = peSrc.coeffs[start + j];
            macros.ASSERT(c0 < SYMCRYPT_MLKEM_Q);
            var c1: UINT32 = peSrc.coeffs[start + j + ulen];
            macros.ASSERT(c1 < SYMCRYPT_MLKEM_Q);

            const c1TimesTwiddle = SymCryptMlKemMontMul(c1, twiddleFactor, twiddleFactorMont);
            c1 = SymCryptMlKemModSub(c0, c1TimesTwiddle);
            c0 = SymCryptMlKemModAdd(c0, c1TimesTwiddle);

            peSrc.coeffs[start + j] = @truncate(c0);
            peSrc.coeffs[start + j + ulen] = @truncate(c1);
        }
    }
}

inline fn inttLayerComptime(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
    comptime k_in: usize,
    comptime ulen: usize,
) void {
    var k: usize = k_in;
    var start: usize = 0;

    while (start < 256) : (start += 2 * ulen) {
        const twiddleFactor: UINT32 = MlKemZetaBitRevTimesR[k];
        const twiddleFactorMont: UINT32 = MlKemZetaBitRevTimesRTimesNegQInvModR[k];
        k -= 1;

        for (0..ulen) |j| {
            const c0: UINT32 = peSrc.coeffs[start + j];
            macros.ASSERT(c0 < SYMCRYPT_MLKEM_Q);
            var c1: UINT32 = peSrc.coeffs[start + j + ulen];
            macros.ASSERT(c1 < SYMCRYPT_MLKEM_Q);

            const tmp = SymCryptMlKemModAdd(c0, c1);
            c1 = SymCryptMlKemModSub(c1, c0);
            c1 = SymCryptMlKemMontMul(c1, twiddleFactor, twiddleFactorMont);

            peSrc.coeffs[start + j] = @truncate(tmp);
            peSrc.coeffs[start + j + ulen] = @truncate(c1);
        }
    }
}

pub export fn SymCryptMlKemPolyElementNTTLayerC(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
    k_in: UINT32,
    len: UINT32,
) callconv(SYMCRYPT_CALL) void {
    var k: usize = k_in;
    const ulen: usize = len;
    var start: usize = 0;

    while (start < 256) : (start += 2 * ulen) {
        const twiddleFactor: UINT32 = MlKemZetaBitRevTimesR[k];
        const twiddleFactorMont: UINT32 = MlKemZetaBitRevTimesRTimesNegQInvModR[k];
        k += 1;

        var j: usize = 0;
        while (j < ulen) : (j += 1) {
            var c0: UINT32 = peSrc.coeffs[start + j];
            macros.ASSERT(c0 < SYMCRYPT_MLKEM_Q);
            var c1: UINT32 = peSrc.coeffs[start + j + ulen];
            macros.ASSERT(c1 < SYMCRYPT_MLKEM_Q);

            const c1TimesTwiddle = SymCryptMlKemMontMul(c1, twiddleFactor, twiddleFactorMont);
            c1 = SymCryptMlKemModSub(c0, c1TimesTwiddle);
            c0 = SymCryptMlKemModAdd(c0, c1TimesTwiddle);

            peSrc.coeffs[start + j] = @truncate(c0);
            peSrc.coeffs[start + j + ulen] = @truncate(c1);
        }
    }
}

pub export fn SymCryptMlKemPolyElementINTTLayerC(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
    k_in: UINT32,
    len: UINT32,
) callconv(SYMCRYPT_CALL) void {
    var k: usize = k_in;
    const ulen: usize = len;
    var start: usize = 0;

    while (start < 256) : (start += 2 * ulen) {
        const twiddleFactor: UINT32 = MlKemZetaBitRevTimesR[k];
        const twiddleFactorMont: UINT32 = MlKemZetaBitRevTimesRTimesNegQInvModR[k];
        k -= 1;

        var j: usize = 0;
        while (j < ulen) : (j += 1) {
            const c0: UINT32 = peSrc.coeffs[start + j];
            macros.ASSERT(c0 < SYMCRYPT_MLKEM_Q);
            var c1: UINT32 = peSrc.coeffs[start + j + ulen];
            macros.ASSERT(c1 < SYMCRYPT_MLKEM_Q);

            const tmp = SymCryptMlKemModAdd(c0, c1);
            c1 = SymCryptMlKemModSub(c1, c0);
            c1 = SymCryptMlKemMontMul(c1, twiddleFactor, twiddleFactorMont);

            peSrc.coeffs[start + j] = @truncate(tmp);
            peSrc.coeffs[start + j + ulen] = @truncate(c1);
        }
    }
}

pub export fn SymCryptMlKemPolyElementMulAndAccumulate(
    peSrc1: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLKEM_POLYELEMENT,
    paDst: PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    while (i < (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 2)) : (i += 1) {
        const a0: UINT32 = peSrc1.coeffs[2 * i];
        macros.ASSERT(a0 < SYMCRYPT_MLKEM_Q);
        const a1: UINT32 = peSrc1.coeffs[(2 * i) + 1];
        macros.ASSERT(a1 < SYMCRYPT_MLKEM_Q);

        const b0: UINT32 = peSrc2.coeffs[2 * i];
        macros.ASSERT(b0 < SYMCRYPT_MLKEM_Q);
        const b1: UINT32 = peSrc2.coeffs[(2 * i) + 1];
        macros.ASSERT(b1 < SYMCRYPT_MLKEM_Q);

        var c0: UINT32 = paDst.coeffs[2 * i];
        macros.ASSERT(c0 <= 3 * (SYMCRYPT_MLKEM_MaxCoeffProduct + SYMCRYPT_MLKEM_MaxA1B1ZetaPow));
        var c1: UINT32 = paDst.coeffs[(2 * i) + 1];
        macros.ASSERT(c1 <= 3 * (SYMCRYPT_MLKEM_MaxCoeffProduct + SYMCRYPT_MLKEM_MaxA1B1ZetaPow));

        var a0b0: UINT32 = a0 * b0;
        var a1b1: UINT32 = a1 * b1;
        var a0b1: UINT32 = a0 * b1;
        const a1b0: UINT32 = a1 * b0;

        const inv: UINT32 = (a1b1 *% SYMCRYPT_MLKEM_NegQInvModR) & SYMCRYPT_MLKEM_Rmask;
        a1b1 = (a1b1 + (inv * SYMCRYPT_MLKEM_Q)) >> @intCast(SYMCRYPT_MLKEM_Rlog2);
        macros.ASSERT(a1b1 <= SYMCRYPT_MLKEM_MaxFirstStepReduction);

        const a1b1zetapow: UINT32 = a1b1 * @as(UINT32, zetaTwoTimesBitRevPlus1TimesR[i]);
        macros.ASSERT(a1b1zetapow <= SYMCRYPT_MLKEM_MaxA1B1ZetaPow);

        a0b0 += a1b1zetapow;
        macros.ASSERT(a0b0 <= SYMCRYPT_MLKEM_MaxCoeffProduct + SYMCRYPT_MLKEM_MaxA1B1ZetaPow);
        a0b1 += a1b0;
        macros.ASSERT(a0b1 <= 2 * SYMCRYPT_MLKEM_MaxCoeffProduct);

        c0 += a0b0;
        macros.ASSERT(c0 < (4 * SYMCRYPT_MLKEM_MaxCoeffProduct) + (4 * SYMCRYPT_MLKEM_MaxA1B1ZetaPow));
        c1 += a0b1;
        macros.ASSERT(c1 < (5 * SYMCRYPT_MLKEM_MaxCoeffProduct) + (3 * SYMCRYPT_MLKEM_MaxA1B1ZetaPow));

        paDst.coeffs[2 * i] = c0;
        paDst.coeffs[(2 * i) + 1] = c1;
    }
}

pub export fn SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(
    paSrc: PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        var a: UINT32 = paSrc.coeffs[i];
        macros.ASSERT(a <= 4 * (SYMCRYPT_MLKEM_MaxCoeffProduct + SYMCRYPT_MLKEM_MaxA1B1ZetaPow));
        paSrc.coeffs[i] = 0;

        var c: UINT32 = peDst.coeffs[i];
        macros.ASSERT(c < SYMCRYPT_MLKEM_Q);

        const inv: UINT32 = (a *% SYMCRYPT_MLKEM_NegQInvModR) & SYMCRYPT_MLKEM_Rmask;
        a = (a + (inv * SYMCRYPT_MLKEM_Q)) >> @intCast(SYMCRYPT_MLKEM_Rlog2);
        macros.ASSERT(a <= 4698);

        c += a;
        macros.ASSERT(c <= 8026);

        c -%= 2 * SYMCRYPT_MLKEM_Q;
        c +%= SYMCRYPT_MLKEM_Q & (c >> 16);
        c +%= SYMCRYPT_MLKEM_Q & (c >> 16);
        macros.ASSERT(c < SYMCRYPT_MLKEM_Q);

        peDst.coeffs[i] = @truncate(c);
    }
}

pub export fn SymCryptMlKemPolyElementMulR(
    peSrc: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        peDst.coeffs[i] = @truncate(SymCryptMlKemMontMul(
            peSrc.coeffs[i],
            SYMCRYPT_MLKEM_Rsqr,
            SYMCRYPT_MLKEM_RsqrTimesNegQInvModR,
        ));
    }
}

pub export fn SymCryptMlKemPolyElementAdd(
    peSrc1: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        peDst.coeffs[i] = @truncate(SymCryptMlKemModAdd(peSrc1.coeffs[i], peSrc2.coeffs[i]));
    }
}

pub export fn SymCryptMlKemPolyElementSub(
    peSrc1: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLKEM_POLYELEMENT,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        peDst.coeffs[i] = @truncate(SymCryptMlKemModSub(peSrc1.coeffs[i], peSrc2.coeffs[i]));
    }
}

pub export fn SymCryptMlKemPolyElementNTT(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    nttLayerComptime(peSrc, 1, 128);
    nttLayerComptime(peSrc, 2, 64);
    nttLayerComptime(peSrc, 4, 32);
    nttLayerComptime(peSrc, 8, 16);
    nttLayerComptime(peSrc, 16, 8);
    nttLayerComptime(peSrc, 32, 4);
    nttLayerComptime(peSrc, 64, 2);
}

pub export fn SymCryptMlKemPolyElementINTTAndMulR(
    peSrc: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    inttLayerComptime(peSrc, 127, 2);
    inttLayerComptime(peSrc, 63, 4);
    inttLayerComptime(peSrc, 31, 8);
    inttLayerComptime(peSrc, 15, 16);
    inttLayerComptime(peSrc, 7, 32);
    inttLayerComptime(peSrc, 3, 64);
    inttLayerComptime(peSrc, 1, 128);

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peSrc.coeffs[i] = @truncate(SymCryptMlKemMontMul(
            peSrc.coeffs[i],
            SYMCRYPT_MLKEM_INTTFixupTimesRsqr,
            SYMCRYPT_MLKEM_INTTFixupTimesRsqrTimesNegQInvModR,
        ));
    }
}

pub export fn SymCryptMlKemPolyElementCompressAndEncode(
    peSrc: PCSYMCRYPT_MLKEM_POLYELEMENT,
    nBitsPerCoefficient: UINT32,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var cbDstWritten: usize = 0;
    var accumulator: UINT32 = 0;
    var nBitsInAccumulator: UINT32 = 0;

    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 12);

    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        var nBitsInCoefficient: UINT32 = nBitsPerCoefficient;
        var coefficient: UINT32 = peSrc.coeffs[i];
        macros.ASSERT(coefficient < SYMCRYPT_MLKEM_Q);

        if (nBitsPerCoefficient < 12) {
            const multiplication: UINT64 = @as(UINT64, coefficient) * @as(UINT64, SYMCRYPT_MLKEM_COMPRESS_MULCONSTANT);
            const shift_amt: u6 = @intCast(SYMCRYPT_MLKEM_COMPRESS_SHIFTCONSTANT - (nBitsPerCoefficient + 1));
            coefficient = @truncate(multiplication >> shift_amt);

            coefficient += 1;
            coefficient >>= 1;
            macros.ASSERT(coefficient <= (@as(UINT32, 1) << @intCast(nBitsPerCoefficient)));

            coefficient &= (@as(UINT32, 1) << @intCast(nBitsPerCoefficient)) - 1;
            macros.ASSERT(coefficient < (@as(UINT32, 1) << @intCast(nBitsPerCoefficient)));
        }

        while (true) {
            const nBitsToEncode: UINT32 = @min(nBitsInCoefficient, 32 - nBitsInAccumulator);

            const bitsToEncode: UINT32 = coefficient & ((@as(UINT32, 1) << @intCast(nBitsToEncode)) - 1);
            coefficient >>= @intCast(nBitsToEncode);
            nBitsInCoefficient -= nBitsToEncode;

            accumulator |= bitsToEncode << @intCast(nBitsInAccumulator);
            nBitsInAccumulator += nBitsToEncode;
            if (nBitsInAccumulator == 32) {
                macros.STORE_LSBFIRST32(pbDst + cbDstWritten, accumulator);
                cbDstWritten += 4;
                accumulator = 0;
                nBitsInAccumulator = 0;
            }

            if (nBitsInCoefficient == 0) break;
        }
    }

    macros.ASSERT(nBitsInAccumulator == 0);
    macros.ASSERT(cbDstWritten == (@as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8)));
}

pub export fn SymCryptMlKemPolyElementDecodeAndDecompress(
    pbSrc: PCBYTE,
    nBitsPerCoefficient: UINT32,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var cbSrcRead: usize = 0;
    var accumulator: UINT32 = 0;
    var nBitsInAccumulator: UINT32 = 0;

    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 12);

    var i: usize = 0;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        var coefficient: UINT32 = 0;
        var nBitsInCoefficient: UINT32 = 0;

        while (true) {
            if (nBitsInAccumulator == 0) {
                accumulator = macros.LOAD_LSBFIRST32(pbSrc + cbSrcRead);
                cbSrcRead += 4;
                nBitsInAccumulator = 32;
            }

            const nBitsToDecode: UINT32 = @min(nBitsPerCoefficient - nBitsInCoefficient, nBitsInAccumulator);
            macros.ASSERT(nBitsToDecode <= nBitsInAccumulator);

            const bitsToDecode: UINT32 = accumulator & ((@as(UINT32, 1) << @intCast(nBitsToDecode)) - 1);
            accumulator >>= @intCast(nBitsToDecode);
            nBitsInAccumulator -= nBitsToDecode;

            coefficient |= bitsToDecode << @intCast(nBitsInCoefficient);
            nBitsInCoefficient += nBitsToDecode;

            if (nBitsPerCoefficient <= nBitsInCoefficient) break;
        }
        macros.ASSERT(nBitsInCoefficient == nBitsPerCoefficient);

        if (nBitsPerCoefficient < 12) {
            coefficient *= SYMCRYPT_MLKEM_Q;
            coefficient >>= @intCast(nBitsPerCoefficient - 1);
            coefficient += 1;
            coefficient >>= 1;

            coefficient = SymCryptMlKemModSub(coefficient, SYMCRYPT_MLKEM_Q);
            macros.ASSERT(coefficient < SYMCRYPT_MLKEM_Q);
        } else if (coefficient >= SYMCRYPT_MLKEM_Q) {
            return .SYMCRYPT_INVALID_BLOB;
        }

        peDst.coeffs[i] = @truncate(coefficient);
    }

    macros.ASSERT(nBitsInAccumulator == 0);
    macros.ASSERT(cbSrcRead == (@as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8)));

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemPolyElementSampleNTTFromShake128(
    pState: shake.PSYMCRYPT_SHAKE128_STATE,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var i: usize = 0;
    var shakeOutputBuf: [3 * 8]BYTE = undefined;
    var currBufIndex: usize = shakeOutputBuf.len;

    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) {
        macros.ASSERT(currBufIndex <= shakeOutputBuf.len);
        if (currBufIndex == shakeOutputBuf.len) {
            shake.SymCryptShake128Extract(pState, &shakeOutputBuf, shakeOutputBuf.len, 0);
            currBufIndex = 0;
        }

        const sample0: UINT16 = macros.LOAD_LSBFIRST16(shakeOutputBuf[currBufIndex..].ptr) & 0xfff;
        const sample1: UINT16 = macros.LOAD_LSBFIRST16(shakeOutputBuf[currBufIndex + 1 ..].ptr) >> 4;
        currBufIndex += 3;

        peDst.coeffs[i] = sample0;
        i += @intFromBool(sample0 < SYMCRYPT_MLKEM_Q);

        if (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) {
            peDst.coeffs[i] = sample1;
            i += @intFromBool(sample1 < SYMCRYPT_MLKEM_Q);
        }
    }
}

pub export fn SymCryptMlKemPolyElementSampleCBDFromBytes(
    pbSrc_in: PCBYTE,
    eta: UINT32,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    macros.ASSERT((eta == 2) or (eta == 3));

    if (eta == 3) {
        var i: usize = 0;
        while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 4) {
            var sampleBits: UINT32 = macros.LOAD_LSBFIRST32(pbSrc);
            pbSrc += 3;

            sampleBits = (sampleBits & 0x249249) + ((sampleBits >> 1) & 0x249249) + ((sampleBits >> 2) & 0x249249);

            var j: usize = 0;
            while (j < 4) : (j += 1) {
                var coefficient: UINT32 = sampleBits & 0x3f;
                sampleBits >>= 6;
                coefficient = (coefficient & 3) -% (coefficient >> 3);
                macros.ASSERT((coefficient >= @as(UINT32, @bitCast(@as(i32, -3)))) or (coefficient <= 3));

                coefficient +%= SYMCRYPT_MLKEM_Q & (coefficient >> 16);
                macros.ASSERT(coefficient < SYMCRYPT_MLKEM_Q);

                peDst.coeffs[i + j] = @truncate(coefficient);
            }
        }
    } else {
        var i: usize = 0;
        while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 8) {
            var sampleBits: UINT32 = macros.LOAD_LSBFIRST32(pbSrc);
            pbSrc += 4;

            sampleBits = (sampleBits & 0x55555555) + ((sampleBits >> 1) & 0x55555555);

            var j: usize = 0;
            while (j < 8) : (j += 1) {
                var coefficient: UINT32 = sampleBits & 0xf;
                sampleBits >>= 4;
                coefficient = (coefficient & 3) -% (coefficient >> 2);
                macros.ASSERT((coefficient >= @as(UINT32, @bitCast(@as(i32, -2)))) or (coefficient <= 2));

                coefficient +%= SYMCRYPT_MLKEM_Q & (coefficient >> 16);
                macros.ASSERT(coefficient < SYMCRYPT_MLKEM_Q);

                peDst.coeffs[i + j] = @truncate(coefficient);
            }
        }
    }
}

pub export fn SymCryptMlKemMatrixTranspose(
    pmSrc: PSYMCRYPT_MLKEM_MATRIX,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pmSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        var j: usize = i + 1;
        while (j < nRows) : (j += 1) {
            const swap = pmSrc.apPolyElements[(i * nRows) + j];
            pmSrc.apPolyElements[(i * nRows) + j] = pmSrc.apPolyElements[(j * nRows) + i];
            pmSrc.apPolyElements[(j * nRows) + i] = swap;
        }
    }
}

pub export fn SymCryptMlKemMatrixVectorMontMulAndAdd(
    pmSrc1: PCSYMCRYPT_MLKEM_MATRIX,
    pvSrc2: PCSYMCRYPT_MLKEM_VECTOR,
    pvDst: PSYMCRYPT_MLKEM_VECTOR,
    paTmp: PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pmSrc1.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);
    macros.ASSERT(pvSrc2.nRows == nRows);
    macros.ASSERT(pvDst.nRows == nRows);

    hash.SymCryptWipeKnownSize(@ptrCast(paTmp), SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT_ACCUMULATOR);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        var j: usize = 0;
        while (j < nRows) : (j += 1) {
            const peSrc1 = pmSrc1.apPolyElements[(i * nRows) + j];
            const peSrc2 = vectorElementConst(pvSrc2, j);
            SymCryptMlKemPolyElementMulAndAccumulate(peSrc1, peSrc2, paTmp);
        }

        const peDst = vectorElement(pvDst, i);
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peDst);
    }
}

pub export fn SymCryptMlKemVectorMontDotProduct(
    pvSrc1: PCSYMCRYPT_MLKEM_VECTOR,
    pvSrc2: PCSYMCRYPT_MLKEM_VECTOR,
    peDst: PSYMCRYPT_MLKEM_POLYELEMENT,
    paTmp: PSYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pvSrc1.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);
    macros.ASSERT(pvSrc2.nRows == nRows);

    hash.SymCryptWipeKnownSize(@ptrCast(paTmp), SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT_ACCUMULATOR);
    hash.SymCryptWipeKnownSize(@ptrCast(peDst), SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        const peSrc1 = vectorElementConst(pvSrc1, i);
        const peSrc2 = vectorElementConst(pvSrc2, i);
        SymCryptMlKemPolyElementMulAndAccumulate(peSrc1, peSrc2, paTmp);
    }

    SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peDst);
}

pub export fn SymCryptMlKemVectorSetZero(
    pvSrc: PSYMCRYPT_MLKEM_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pvSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    hash.SymCryptWipe(@ptrCast(vectorElement(pvSrc, 0)), nRows * SYMCRYPT_INTERNAL_MLKEM_SIZEOF_POLYRINGELEMENT);
}

pub export fn SymCryptMlKemVectorMulR(
    pvSrc: PCSYMCRYPT_MLKEM_VECTOR,
    pvDst: PSYMCRYPT_MLKEM_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pvSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);
    macros.ASSERT(pvDst.nRows == nRows);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        SymCryptMlKemPolyElementMulR(vectorElementConst(pvSrc, i), vectorElement(pvDst, i));
    }
}

pub export fn SymCryptMlKemVectorNTT(
    pvSrc: PSYMCRYPT_MLKEM_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pvSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        SymCryptMlKemPolyElementNTT(vectorElement(pvSrc, i));
    }
}

pub export fn SymCryptMlKemVectorINTTAndMulR(
    pvSrc: PSYMCRYPT_MLKEM_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    const nRows: usize = pvSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        SymCryptMlKemPolyElementINTTAndMulR(vectorElement(pvSrc, i));
    }
}

pub export fn SymCryptMlKemVectorCompressAndEncode(
    pvSrc: PCSYMCRYPT_MLKEM_VECTOR,
    nBitsPerCoefficient: UINT32,
    pbDst_in: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbDst = pbDst_in;
    const nRows: usize = pvSrc.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);
    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 12);
    macros.ASSERT(cbDst == nRows * @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8));

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        const peSrc = vectorElementConst(pvSrc, i);
        SymCryptMlKemPolyElementCompressAndEncode(peSrc, nBitsPerCoefficient, pbDst);
        pbDst += @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    }
}

pub export fn SymCryptMlKemVectorDecodeAndDecompress(
    pbSrc_in: PCBYTE,
    cbSrc: SIZE_T,
    nBitsPerCoefficient: UINT32,
    pvDst: PSYMCRYPT_MLKEM_VECTOR,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbSrc = pbSrc_in;
    const nRows: usize = pvDst.nRows;
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLKEM_MATRIX_MAX_NROWS);
    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 12);
    macros.ASSERT(cbSrc == nRows * @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8));

    var i: usize = 0;
    while (i < nRows) : (i += 1) {
        const peDst = vectorElement(pvDst, i);
        const scError = SymCryptMlKemPolyElementDecodeAndDecompress(pbSrc, nBitsPerCoefficient, peDst);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pbSrc += @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlKemkeyWipePrivateState(
    pkMlKemkey: PSYMCRYPT_MLKEMKEY,
) callconv(SYMCRYPT_CALL) void {
    SymCryptMlKemVectorSetZero(pkMlKemkey.pvs);
    hash.SymCryptWipeKnownSize(&pkMlKemkey.privateRandom, pkMlKemkey.privateRandom.len);
    hash.SymCryptWipeKnownSize(&pkMlKemkey.privateSeed, pkMlKemkey.privateSeed.len);
    pkMlKemkey.hasPrivateKey = 0;
    pkMlKemkey.hasPrivateSeed = 0;
}
