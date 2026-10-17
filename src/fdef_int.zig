//
// fdef_int.zig   INT functions for default number format
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const fdef_general = @import("fdef_general.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const PCUINT32 = types.PCUINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const NATIVE_UINT = types.NATIVE_UINT;
const NATIVE_BITS = types.NATIVE_BITS;
const NATIVE_BYTES = types.NATIVE_BYTES;
const SYMCRYPT_INT = types.SYMCRYPT_INT;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const SYMCRYPT_DIVISOR = types.SYMCRYPT_DIVISOR;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PCSYMCRYPT_DIVISOR = types.PCSYMCRYPT_DIVISOR;
const SYMCRYPT_FDEF_DIGIT_SIZE = types.SYMCRYPT_FDEF_DIGIT_SIZE;
const SYMCRYPT_FDEF_DIGIT_BITS = types.SYMCRYPT_FDEF_DIGIT_BITS;
const SYMCRYPT_FDEF_DIGIT_NUINT32 = types.SYMCRYPT_FDEF_DIGIT_NUINT32;
const SYMCRYPT_FDEF_INT_PUINT32 = types.SYMCRYPT_FDEF_INT_PUINT32;
const SYMCRYPT_FDEF_INT_PCUINT32 = types.SYMCRYPT_FDEF_INT_PCUINT32;

const SYMCRYPT_CPU_FEATURES_FOR_MULX: types.SYMCRYPT_CPU_FEATURES =
    types.SYMCRYPT_CPU_FEATURE_BMI2 | types.SYMCRYPT_CPU_FEATURE_ADX;

extern var g_SymCryptCpuFeaturesNotPresent: types.SYMCRYPT_CPU_FEATURES;
extern fn SymCryptCpuFeaturesNeverPresent() callconv(SYMCRYPT_CALL) types.SYMCRYPT_CPU_FEATURES;
const c_wipe = struct {
    extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
};

inline fn SYMCRYPT_CPU_FEATURES_PRESENT(x: types.SYMCRYPT_CPU_FEATURES) bool {
    return ((x & SymCryptCpuFeaturesNeverPresent()) == 0) and ((x & g_SymCryptCpuFeaturesNotPresent) == 0);
}

inline fn SymCryptWipe(pbData: anytype, cbData: SIZE_T) void {
    c_wipe.SymCryptWipe(@ptrCast(pbData), cbData);
}

inline fn SYMCRYPT_ASSERT_ASYM_ALIGNED(p: anytype) void {
    macros.SYMCRYPT_ASSERT((@intFromPtr(p) & (types.SYMCRYPT_ASYM_ALIGN_VALUE - 1)) == 0);
}

inline fn SYMCRYPT_OBJ_NDIGITS(p: anytype) UINT32 {
    return p.nDigits;
}

inline fn SYMCRYPT_OBJ_NUINT32(p: anytype) UINT32 {
    return p.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
}

inline fn SYMCRYPT_MUL32x32TO64(a: UINT32, b: UINT32) UINT64 {
    return @as(UINT64, a) *% @as(UINT64, b);
}

const SYMCRYPT_FDEF_DIGIT_NNATIVE_UINT: NATIVE_UINT = SYMCRYPT_FDEF_DIGIT_SIZE / NATIVE_BYTES;

inline fn SYMCRYPT_FDEF_INT_PNATIVE_UINT(p: anytype) [*]NATIVE_UINT {
    return @ptrCast(@alignCast(SYMCRYPT_FDEF_INT_PUINT32(p)));
}

inline fn SYMCRYPT_FDEF_INT_PCNATIVE_UINT(p: anytype) [*]const NATIVE_UINT {
    return @ptrCast(@alignCast(SYMCRYPT_FDEF_INT_PCUINT32(p)));
}

pub export fn SymCryptFdefRawAddC(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var t: UINT64 = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        t = t +% pSrc1[i] +% pSrc2[i];
        pDst[i] = @truncate(t);
        t >>= 32;
    }

    return @truncate(t);
}

extern fn SymCryptFdefRawAddAsm(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32;

pub export fn SymCryptFdefRawAdd(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    if (comptime (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM64 or types.CPU_ARM)) {
        return SymCryptFdefRawAddAsm(pSrc1, pSrc2, pDst, nDigits);
    } else {
        return SymCryptFdefRawAddC(pSrc1, pSrc2, pDst, nDigits);
    }
}

pub export fn SymCryptFdefRawAddUint32(
    Src1: PCUINT32,
    Src2: UINT32,
    Dst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var t: UINT64 = Src2;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        t = t +% Src1[i];
        Dst[i] = @truncate(t);
        t >>= 32;
    }

    return @truncate(t);
}

pub export fn SymCryptFdefIntAddUint32(
    piSrc1: PCSYMCRYPT_INT,
    u32Src2: UINT32,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc1);
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piDst.nDigits);

    return SymCryptFdefRawAddUint32(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
        u32Src2,
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
        piDst.nDigits,
    );
}

pub export fn SymCryptFdefIntAddSameSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piSrc2.nDigits and piSrc2.nDigits == piDst.nDigits);

    return SymCryptFdefRawAdd(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
        piDst.nDigits,
    );
}

pub export fn SymCryptFdefIntAddMixedSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nS1: UINT32 = piSrc1.nDigits;
    const nS2: UINT32 = piSrc2.nDigits;
    const nD: UINT32 = piDst.nDigits;
    var c: UINT32 = 0;
    var nW: UINT32 = 0;

    macros.SYMCRYPT_ASSERT(nD >= nS1 and nD >= nS2);

    if (nS1 < nS2) {
        c = SymCryptFdefRawAdd(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            SYMCRYPT_FDEF_INT_PUINT32(piDst),
            nS1,
        );
        c = SymCryptFdefRawAddUint32(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2) + nS1 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            c,
            SYMCRYPT_FDEF_INT_PUINT32(piDst) + nS1 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nS2 - nS1,
        );
        nW = nS2;
    } else {
        c = SymCryptFdefRawAdd(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            SYMCRYPT_FDEF_INT_PUINT32(piDst),
            nS2,
        );
        c = SymCryptFdefRawAddUint32(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1) + nS2 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            c,
            SYMCRYPT_FDEF_INT_PUINT32(piDst) + nS2 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nS1 - nS2,
        );
        nW = nS1;
    }

    if (nW < nD) {
        SymCryptWipe(
            &SYMCRYPT_FDEF_INT_PUINT32(piDst)[nW * SYMCRYPT_FDEF_DIGIT_NUINT32],
            @as(SIZE_T, nD - nW) * SYMCRYPT_FDEF_DIGIT_SIZE,
        );
        SYMCRYPT_FDEF_INT_PUINT32(piDst)[nW * SYMCRYPT_FDEF_DIGIT_NUINT32] = c;
        c = 0;
    }

    return c;
}

pub export fn SymCryptFdefRawSubC(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        const t: UINT64 = @as(UINT64, pSrc1[i]) -% pSrc2[i] -% c;
        pDst[i] = @truncate(t);
        c = @as(UINT32, @truncate(t >> 32)) & 1;
    }

    return c;
}

extern fn SymCryptFdefRawSubAsm(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32;

pub export fn SymCryptFdefRawSub(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    if (comptime (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM64 or types.CPU_ARM)) {
        return SymCryptFdefRawSubAsm(pSrc1, pSrc2, pDst, nDigits);
    } else {
        return SymCryptFdefRawSubC(pSrc1, pSrc2, pDst, nDigits);
    }
}

pub export fn SymCryptFdefRawSubUint32(
    pSrc1: PCUINT32,
    Src2: UINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = Src2;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        const t: UINT64 = @as(UINT64, pSrc1[i]) -% c;
        pDst[i] = @truncate(t);
        c = @as(UINT32, @truncate(t >> 32)) & 1;
    }

    return c;
}

pub export fn SymCryptFdefRawNeg(
    pSrc1: PCUINT32,
    carryIn: UINT32,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = carryIn;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        const t: UINT64 = @as(UINT64, 0) -% pSrc1[i] -% c;
        pDst[i] = @truncate(t);
        c = @as(UINT32, @truncate(t >> 32)) & 1;
    }

    return c;
}

pub export fn SymCryptFdefIntSubUint32(
    piSrc1: PCSYMCRYPT_INT,
    u32Src2: UINT32,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piDst.nDigits);

    return SymCryptFdefRawSubUint32(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
        u32Src2,
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
        piDst.nDigits,
    );
}

pub export fn SymCryptFdefIntSubSameSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piSrc2.nDigits and piSrc1.nDigits == piDst.nDigits);

    return SymCryptFdefRawSub(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
        piDst.nDigits,
    );
}

pub export fn SymCryptFdefIntSubMixedSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nS1: UINT32 = piSrc1.nDigits;
    const nS2: UINT32 = piSrc2.nDigits;
    const nD: UINT32 = piDst.nDigits;
    var c: UINT32 = 0;
    var n: UINT32 = 0;

    macros.SYMCRYPT_ASSERT(nD >= nS1 and nD >= nS2);

    if (nS1 < nS2) {
        c = SymCryptFdefRawSub(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            SYMCRYPT_FDEF_INT_PUINT32(piDst),
            nS1,
        );
        c = SymCryptFdefRawNeg(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2) + nS1 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            c,
            SYMCRYPT_FDEF_INT_PUINT32(piDst) + nS1 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nS2 - nS1,
        );
        n = nS2 * SYMCRYPT_FDEF_DIGIT_NUINT32;
    } else {
        c = SymCryptFdefRawSub(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            SYMCRYPT_FDEF_INT_PUINT32(piDst),
            nS2,
        );
        c = SymCryptFdefRawSubUint32(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1) + nS2 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            c,
            SYMCRYPT_FDEF_INT_PUINT32(piDst) + nS2 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nS1 - nS2,
        );
        n = nS1 * SYMCRYPT_FDEF_DIGIT_NUINT32;
    }

    const pDst = SYMCRYPT_FDEF_INT_PUINT32(piDst);
    while (n < nD * SYMCRYPT_FDEF_DIGIT_NUINT32) : (n += 1) {
        pDst[n] = 0 -% c;
    }

    return c;
}

pub export fn SymCryptFdefRawIsLessThanC(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        const t: UINT64 = @as(UINT64, pSrc1[i]) -% pSrc2[i] -% c;
        c = @as(UINT32, @truncate(t >> 32)) & 1;
    }

    return 0 -% c;
}

pub export fn SymCryptFdefRawIsLessThan(
    pSrc1: PCUINT32,
    pSrc2: PCUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefRawIsLessThanC(pSrc1, pSrc2, nDigits);
}

pub export fn SymCryptFdefRawIsZeroC(
    pSrc1: PCUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        c |= pSrc1[i];
    }

    return macros.SYMCRYPT_MASK32_ZERO(c);
}

pub export fn SymCryptFdefRawIsZero(
    pSrc1: PCUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefRawIsZeroC(pSrc1, nDigits);
}

pub export fn SymCryptFdefIntIsLessThan(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nD1: UINT32 = piSrc1.nDigits;
    const nD2: UINT32 = piSrc2.nDigits;

    var res: UINT32 = undefined;

    if (nD1 == nD2) {
        res = SymCryptFdefRawIsLessThan(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            nD1,
        );
    } else if (nD1 < nD2) {
        res = SymCryptFdefRawIsLessThan(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            nD1,
        );
        res |= ~SymCryptFdefRawIsZero(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2) + nD1 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nD2 - nD1,
        );
    } else {
        res = SymCryptFdefRawIsLessThan(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
            nD2,
        );
        res &= SymCryptFdefRawIsZero(
            SYMCRYPT_FDEF_INT_PCUINT32(piSrc1) + nD2 * SYMCRYPT_FDEF_DIGIT_NUINT32,
            nD1 - nD2,
        );
    }

    return res;
}

pub export fn SymCryptFdefIntNeg(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    const nDigits: UINT32 = piDst.nDigits;
    macros.SYMCRYPT_ASSERT(piSrc.nDigits == nDigits);

    _ = SymCryptFdefRawNeg(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc),
        0,
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
        nDigits,
    );
}

pub export fn SymCryptFdefIntMulPow2(
    piSrc: PCSYMCRYPT_INT,
    Exp: SIZE_T,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    const shiftWords: SIZE_T = Exp / (8 * @sizeOf(UINT32));
    const shiftBits: u6 = @truncate(Exp % (8 * @sizeOf(UINT32)));

    const nWords: UINT32 = piDst.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    if (shiftWords >= nWords) {
        SymCryptWipe(SYMCRYPT_FDEF_INT_PUINT32(piDst), @as(SIZE_T, nWords) * @sizeOf(UINT32));
        return;
    }

    const pSrc = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    const pDst = SYMCRYPT_FDEF_INT_PUINT32(piDst);

    var i: SIZE_T = nWords;
    while (i > shiftWords) {
        i -= 1;
        var t: UINT64 = @as(UINT64, pSrc[i - shiftWords]) << 32;
        if (i > shiftWords) {
            t |= pSrc[i - shiftWords - 1];
        }
        pDst[i] = @truncate(t >> @as(u6, @intCast(32 - @as(u7, shiftBits))));
    }

    while (i > 0) {
        i -= 1;
        pDst[i] = 0;
    }
}

pub export fn SymCryptFdefIntDivPow2(
    piSrc: PCSYMCRYPT_INT,
    exp: SIZE_T,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    const ShiftType = std.math.Log2Int(NATIVE_UINT);
    var shiftWords: SIZE_T = exp / NATIVE_BITS;
    const shiftRightBits: ShiftType = @truncate(exp % NATIVE_BITS);
    const shiftLeftBits: ShiftType = @intCast((NATIVE_BITS - 1) - @as(usize, shiftRightBits));
    var i: SIZE_T = 0;

    const nWords: NATIVE_UINT = @as(NATIVE_UINT, piDst.nDigits) * SYMCRYPT_FDEF_DIGIT_NNATIVE_UINT;

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    const pSrc = SYMCRYPT_FDEF_INT_PCNATIVE_UINT(piSrc);
    const pDst = SYMCRYPT_FDEF_INT_PNATIVE_UINT(piDst);

    shiftWords = @min(shiftWords, @as(SIZE_T, @intCast(nWords)));
    if (shiftWords < nWords) {
        var lowWord: NATIVE_UINT = pSrc[shiftWords];
        while (i + shiftWords + 1 < nWords) {
            const highWord: NATIVE_UINT = pSrc[i + shiftWords + 1];

            const highPart: NATIVE_UINT = (highWord << shiftLeftBits) << 1;

            pDst[i] = (lowWord >> shiftRightBits) | highPart;

            lowWord = highWord;
            i += 1;
        }
        pDst[i] = lowWord >> shiftRightBits;
        i += 1;
    }

    macros.SYMCRYPT_ASSERT(i + shiftWords == nWords);

    SymCryptWipe(&pDst[@as(usize, @intCast(nWords)) - shiftWords], shiftWords * NATIVE_BYTES);
}

pub export fn SymCryptFdefIntShr1(
    highestBit: UINT32,
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    const nWords: UINT32 = piDst.nDigits * @as(UINT32, @intCast(SYMCRYPT_FDEF_DIGIT_NNATIVE_UINT));

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);
    macros.SYMCRYPT_ASSERT(highestBit < 2);

    const pSrc = SYMCRYPT_FDEF_INT_PCNATIVE_UINT(piSrc);
    const pDst = SYMCRYPT_FDEF_INT_PNATIVE_UINT(piDst);

    var i: SIZE_T = 0;
    var lowWord: NATIVE_UINT = pSrc[0];
    while (i + 1 < nWords) {
        const highWord: NATIVE_UINT = pSrc[i + 1];

        pDst[i] = (lowWord >> 1) | (highWord << (NATIVE_BITS - 1));

        lowWord = highWord;
        i += 1;
    }

    pDst[i] = (lowWord >> 1) | (@as(NATIVE_UINT, highestBit) << (NATIVE_BITS - 1));
}

pub export fn SymCryptFdefIntModPow2(
    piSrc: PCSYMCRYPT_INT,
    exp: SIZE_T,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    const expWords: SIZE_T = exp / 32;
    const expBits: u5 = @truncate(exp % 32);

    const nWords: UINT32 = piDst.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    const pSrc = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    const pDst = SYMCRYPT_FDEF_INT_PUINT32(piDst);

    if (piSrc != piDst) {
        @memcpy(pDst[0..nWords], pSrc[0..nWords]);
    }

    if (expWords >= nWords) {
        return;
    }

    var i: SIZE_T = expWords + 1;
    while (i < nWords) : (i += 1) {
        pDst[i] = 0;
    }

    if (expBits != 0) {
        const shift: u5 = @intCast(32 - @as(u6, expBits));
        pDst[expWords] &= @as(UINT32, 0xffffffff) >> shift;
    } else {
        pDst[expWords] = 0;
    }
}

pub export fn SymCryptFdefIntGetBit(
    piSrc: PCSYMCRYPT_INT,
    iBit: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(iBit < piSrc.nDigits * SYMCRYPT_FDEF_DIGIT_BITS);

    const shift: u5 = @truncate(iBit % 32);
    return (SYMCRYPT_FDEF_INT_PCUINT32(piSrc)[iBit / 32] >> shift) & 1;
}

pub export fn SymCryptFdefIntGetBits(
    piSrc: PCSYMCRYPT_INT,
    iBit: UINT32,
    nBits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(nBits > 0 and
        nBits < 33 and
        iBit < piSrc.nDigits * SYMCRYPT_FDEF_DIGIT_BITS and
        iBit + nBits <= piSrc.nDigits * SYMCRYPT_FDEF_DIGIT_BITS);

    const maskShift: u5 = @intCast(32 - nBits);
    const mainMask: UINT32 = @as(UINT32, 0xffffffff) >> maskShift;

    const pSrc = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    var result: UINT32 = pSrc[iBit / 32];

    const bitShift: u5 = @truncate(iBit % 32);
    result >>= bitShift;

    if ((iBit % 32 != 0) and (iBit / 32 + 1 < piSrc.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32)) {
        const upperShift: u5 = @intCast(32 - (iBit % 32));
        result |= pSrc[iBit / 32 + 1] << upperShift;
    }

    result &= mainMask;

    return result;
}

pub export fn SymCryptFdefIntSetBits(
    piDst: PSYMCRYPT_INT,
    value_in: UINT32,
    iBit: UINT32,
    nBits: UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(nBits > 0 and
        nBits < 33 and
        iBit < piDst.nDigits * SYMCRYPT_FDEF_DIGIT_BITS and
        iBit + nBits <= piDst.nDigits * SYMCRYPT_FDEF_DIGIT_BITS);

    const maskShift: u5 = @intCast(32 - nBits);
    const mainMask: UINT32 = @as(UINT32, 0xffffffff) >> maskShift;
    const value: UINT32 = value_in & mainMask;

    const pDst = SYMCRYPT_FDEF_INT_PUINT32(piDst);
    const bitShift: u5 = @truncate(iBit % 32);

    var alignedMask: UINT32 = mainMask << bitShift;
    var alignedVal: UINT32 = value << bitShift;

    pDst[iBit / 32] = (pDst[iBit / 32] & ~alignedMask) | alignedVal;

    if ((iBit % 32 != 0) and (iBit / 32 + 1 < piDst.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32)) {
        const upperShift: u5 = @intCast(32 - (iBit % 32));
        alignedMask = mainMask >> upperShift;
        alignedVal = value >> upperShift;

        pDst[iBit / 32 + 1] = (pDst[iBit / 32 + 1] & ~alignedMask) | alignedVal;
    }
}

pub export fn SymCryptFdefIntMulUint32(
    piSrc1: PCSYMCRYPT_INT,
    Src2: UINT32,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nWords: UINT32 = piDst.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piDst.nDigits);

    const pSrc1 = SYMCRYPT_FDEF_INT_PCUINT32(piSrc1);
    const pDst = SYMCRYPT_FDEF_INT_PUINT32(piDst);

    var c: UINT64 = 0;
    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        c +%= SYMCRYPT_MUL32x32TO64(pSrc1[i], Src2);
        pDst[i] = @truncate(c);
        c >>= 32;
    }

    return @truncate(c);
}

pub export fn SymCryptFdefIntMulSameSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefIntMulMixedSize(piSrc1, piSrc2, piDst, pbScratch, cbScratch);
}

pub export fn SymCryptFdefIntSquare(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nS: UINT32 = piSrc.nDigits;
    const nD: UINT32 = piDst.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(piDst.nDigits));

    macros.SYMCRYPT_ASSERT(2 * nS <= nD);

    SymCryptFdefRawSquare(SYMCRYPT_FDEF_INT_PCUINT32(piSrc), nS, SYMCRYPT_FDEF_INT_PUINT32(piDst));

    if (2 * nS < nD) {
        SymCryptWipe(
            &SYMCRYPT_FDEF_INT_PUINT32(piDst)[2 * nS * SYMCRYPT_FDEF_DIGIT_NUINT32],
            @as(SIZE_T, nD - 2 * nS) * SYMCRYPT_FDEF_DIGIT_SIZE,
        );
    }
}

pub export fn SymCryptFdefRawMulC(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    const nWords1: UINT32 = nDigits1 * SYMCRYPT_FDEF_DIGIT_NUINT32;
    const nWords2: UINT32 = nDigits2 * SYMCRYPT_FDEF_DIGIT_NUINT32;

    SymCryptWipe(pDst, @as(SIZE_T, nDigits1 + nDigits2) * SYMCRYPT_FDEF_DIGIT_SIZE);

    var i: UINT32 = 0;
    while (i < nWords1) : (i += 1) {
        const m: UINT32 = pSrc1[i];
        var c: UINT64 = 0;
        var j: UINT32 = 0;
        while (j < nWords2) : (j += 1) {
            c +%= SYMCRYPT_MUL32x32TO64(pSrc2[j], m);
            c +%= pDst[i + j];
            pDst[i + j] = @truncate(c);
            c >>= 32;
        }
        pDst[i + nWords2] = @truncate(c);
    }
}

extern fn SymCryptFdefRawMulAsm(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawMulMulx(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptFdefRawMul(
    pSrc1: PCUINT32,
    nDigits1: UINT32,
    pSrc2: PCUINT32,
    nDigits2: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURES_FOR_MULX)) {
            SymCryptFdefRawMulMulx(pSrc1, nDigits1, pSrc2, nDigits2, pDst);
        } else {
            SymCryptFdefRawMulAsm(pSrc1, nDigits1, pSrc2, nDigits2, pDst);
        }
    } else if (comptime (types.CPU_X86 or types.CPU_ARM64 or types.CPU_ARM)) {
        SymCryptFdefRawMulAsm(pSrc1, nDigits1, pSrc2, nDigits2, pDst);
    } else {
        SymCryptFdefRawMulC(pSrc1, nDigits1, pSrc2, nDigits2, pDst);
    }
}

pub export fn SymCryptFdefRawSquareC(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var m: UINT32 = 0;
    var c: UINT64 = 0;

    SymCryptWipe(pDst, @as(SIZE_T, 2 * nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE);

    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        m = pSrc[i];
        c = 0;
        var j: UINT32 = i + 1;
        while (j < nWords) : (j += 1) {
            c +%= SYMCRYPT_MUL32x32TO64(pSrc[j], m);
            c +%= pDst[i + j];
            pDst[i + j] = @truncate(c);
            c >>= 32;
        }
        pDst[i + nWords] = @truncate(c);
    }

    c = 0;
    i = 1;
    while (i < 2 * nWords) : (i += 1) {
        c |= (@as(UINT64, pDst[i]) << 1);
        pDst[i] = @truncate(c);
        c >>= 32;
    }

    c = 0;
    i = 0;
    while (i < nWords) : (i += 1) {
        m = pSrc[i];
        c +%= SYMCRYPT_MUL32x32TO64(m, m);
        c +%= pDst[2 * i];

        pDst[2 * i] = @truncate(c);
        c >>= 32;

        c +%= pDst[2 * i + 1];

        pDst[2 * i + 1] = @truncate(c);
        c >>= 32;
    }
}

extern fn SymCryptFdefRawSquareAsm(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefRawSquareMulx(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptFdefRawSquare(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pDst: PUINT32,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (SYMCRYPT_CPU_FEATURES_PRESENT(SYMCRYPT_CPU_FEATURES_FOR_MULX)) {
            SymCryptFdefRawSquareMulx(pSrc, nDigits, pDst);
        } else {
            SymCryptFdefRawSquareAsm(pSrc, nDigits, pDst);
        }
    } else if (comptime (types.CPU_ARM64 or types.CPU_ARM)) {
        SymCryptFdefRawSquareAsm(pSrc, nDigits, pDst);
    } else if (comptime types.CPU_X86) {
        SymCryptFdefRawMulAsm(pSrc, nDigits, pSrc, nDigits, pDst);
    } else {
        SymCryptFdefRawSquareC(pSrc, nDigits, pDst);
    }
}

pub export fn SymCryptFdefIntMulMixedSize(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nS1: UINT32 = piSrc1.nDigits;
    const nS2: UINT32 = piSrc2.nDigits;
    const nD: UINT32 = piDst.nDigits;

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_MUL(piDst.nDigits));

    macros.SYMCRYPT_ASSERT(nS1 + nS2 <= nD);

    SymCryptFdefRawMul(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc1),
        nS1,
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc2),
        nS2,
        SYMCRYPT_FDEF_INT_PUINT32(piDst),
    );

    if (nS1 + nS2 < nD) {
        SymCryptWipe(
            &SYMCRYPT_FDEF_INT_PUINT32(piDst)[(nS1 + nS2) * SYMCRYPT_FDEF_DIGIT_NUINT32],
            @as(SIZE_T, nD - (nS1 + nS2)) * SYMCRYPT_FDEF_DIGIT_SIZE,
        );
    }
}

pub export fn SymCryptFdefIntFromDivisor(pdSrc: PSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) PSYMCRYPT_INT {
    return &pdSrc.Int;
}

pub export fn SymCryptFdefIntToDivisor(
    piSrc: PCSYMCRYPT_INT,
    pdDst: PSYMCRYPT_DIVISOR,
    totalOperations: UINT32,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    _ = totalOperations;
    _ = flags;

    macros.SYMCRYPT_CHECK_MAGIC(piSrc);
    macros.SYMCRYPT_CHECK_MAGIC(pdDst);

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == pdDst.nDigits);

    fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_TO_DIVISOR(piSrc.nDigits));

    fdef_general.SymCryptFdefIntCopy(piSrc, &pdDst.Int);

    const nBits: UINT32 = fdef_general.SymCryptFdefIntBitsizeOfValue(&pdDst.Int);

    macros.SYMCRYPT_ASSERT(nBits != 0);
    if (nBits == 0) {
        fdef_general.SymCryptFdefIntSetValueUint32(1, &pdDst.Int);
    }

    pdDst.nBits = nBits;

    const nWords: UINT32 = (nBits + 31) / 32;
    var bitToTest: UINT32 = @as(UINT32, 1) << 31;
    var W: UINT32 = 0;
    const pDivInt = SYMCRYPT_FDEF_INT_PCUINT32(&pdDst.Int);
    const shift: u6 = @intCast(((nBits + 31) % 32) + 1);
    while (bitToTest > 0) {
        W |= bitToTest;
        var P: UINT64 = 0;
        var i: UINT32 = 0;
        while (i < nWords) : (i += 1) {
            P +%= SYMCRYPT_MUL32x32TO64(W, pDivInt[i]);
            P >>= 32;
            P +%= pDivInt[i];
        }
        P >>= shift;
        W ^= bitToTest & (0 -% (@as(UINT32, @truncate(P)) & 1));
        bitToTest >>= 1;
    }
    pdDst.td.fdef.W = W;

    macros.SYMCRYPT_SET_MAGIC(pdDst);
}

pub export fn SymCryptFdefRawMultSubUint32(
    pAcc: PUINT32,
    pSrc1: PCUINT32,
    Src2: UINT32,
    nUint32: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var tmul: UINT64 = 0;
    var c: UINT32 = 0;
    var i: UINT32 = 0;
    while (i < nUint32) : (i += 1) {
        tmul +%= SYMCRYPT_MUL32x32TO64(pSrc1[i], Src2);
        const tsub: UINT64 = @as(UINT64, pAcc[i]) -% @as(UINT32, @truncate(tmul)) -% c;
        pAcc[i] = @truncate(tsub);
        c = @as(UINT32, @truncate(tsub >> 32)) & 1;
        tmul >>= 32;
    }

    const tsub: UINT64 = @as(UINT64, pAcc[i]) -% @as(UINT32, @truncate(tmul)) -% c;
    pAcc[i] = @truncate(tsub);
    c = @as(UINT32, @truncate(tsub >> 32)) & 1;

    return c;
}

pub export fn SymCryptFdefRawMaskedAddSubdigit(
    pAcc: PUINT32,
    pSrc: PCUINT32,
    mask: UINT32,
    nUint32: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var t: UINT64 = 0;
    var i: UINT32 = 0;
    while (i < nUint32) : (i += 1) {
        t = t +% pAcc[i] +% (mask & pSrc[i]);
        pAcc[i] = @truncate(t);
        t >>= 32;
    }

    return @truncate(t);
}

pub export fn SymCryptFdefRawMaskedAdd(
    pAcc: PUINT32,
    pSrc: PCUINT32,
    mask: UINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefRawMaskedAddSubdigit(pAcc, pSrc, mask, nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32);
}

pub export fn SymCryptFdefRawMaskedSub(
    pAcc: PUINT32,
    pSrc: PCUINT32,
    mask: UINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    var c: UINT32 = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    var i: UINT32 = 0;
    while (i < nWords) : (i += 1) {
        var t: UINT64 = @as(UINT64, pAcc[i]) -% (mask & pSrc[i]) -% c;
        pAcc[i] = @truncate(t);
        t >>= 32;
        c = @as(UINT32, @truncate(t)) & 1;
    }

    return c;
}

pub export fn SymCryptFdefRawDivMod(
    pNum: PCUINT32,
    nDigits: UINT32,
    pdDivisor: PCSYMCRYPT_DIVISOR,
    pQuotient: ?PUINT32,
    pRemainder: ?PUINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    const activeDivWords: UINT32 = (pdDivisor.nBits + 8 * @sizeOf(UINT32) - 1) / (8 * @sizeOf(UINT32));
    const remainderWords: UINT32 = SYMCRYPT_OBJ_NUINT32(pdDivisor);

    const cbScratchNeeded: UINT32 = (nWords + 4) * @sizeOf(UINT32);
    const pTmp: PUINT32 = @ptrCast(@alignCast(pbScratch));

    macros.SYMCRYPT_ASSERT(cbScratch >= cbScratchNeeded);
    SYMCRYPT_ASSERT_ASYM_ALIGNED(pbScratch);

    if (nWords < activeDivWords) {
        if (pQuotient) |q| {
            SymCryptWipe(q, @as(SIZE_T, nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE);
        }

        if (pRemainder) |rem| {
            macros.SYMCRYPT_ASSERT(remainderWords >= nWords);
            @memcpy(rem[0..nWords], pNum[0..nWords]);
            SymCryptWipe(&rem[nWords], @as(SIZE_T, remainderWords - nWords) * @sizeOf(UINT32));
        }

        fdef_general.SymCryptFdefClaimScratch(pbScratch, cbScratch, cbScratchNeeded);
        return;
    }

    pTmp[0] = 0;
    pTmp[1] = 0;
    @memcpy(pTmp[2 .. 2 + nWords], pNum[0..nWords]);
    pTmp[nWords + 2] = 0;
    pTmp[nWords + 3] = 0;
    const shift: UINT32 = (0 -% pdDivisor.nBits) & 31;
    const rshift: u6 = @intCast(32 - shift);

    if (pQuotient) |q| {
        SymCryptWipe(&q[nWords - activeDivWords + 1], @as(SIZE_T, activeDivWords - 1) * @sizeOf(UINT32));
    }

    var nQ: UINT32 = nWords - activeDivWords + 1;
    const pDivInt = SYMCRYPT_FDEF_INT_PCUINT32(&pdDivisor.Int);

    while (true) {
        nQ -= 1;
        const X0: UINT32 = @truncate((((@as(UINT64, pTmp[nQ + activeDivWords + 2]) << 32) +% pTmp[nQ + activeDivWords + 1]) >> rshift));
        const X1: UINT32 = @truncate((((@as(UINT64, pTmp[nQ + activeDivWords + 1]) << 32) +% pTmp[nQ + activeDivWords + 0]) >> rshift));

        const W: UINT32 = @truncate(pdDivisor.td.fdef.W);
        const T: UINT64 = SYMCRYPT_MUL32x32TO64(W, X0) +% (@as(UINT64, X0) << 32) +% X1 +% ((W >> 1) & (0 -% (X1 >> 31)));
        var Qest: UINT32 = @truncate(T >> 32);
        Qest +%= 1;
        Qest +%= macros.SYMCRYPT_MASK32_ZERO(Qest);

        const c: UINT32 = SymCryptFdefRawMultSubUint32(pTmp + nQ + 2, pDivInt, Qest, activeDivWords);
        const Q: UINT32 = Qest -% c;
        const d: UINT32 = SymCryptFdefRawMaskedAddSubdigit(pTmp + nQ + 2, pDivInt, 0 -% c, activeDivWords);
        macros.SYMCRYPT_ASSERT(c == d);
        macros.SYMCRYPT_ASSERT(pTmp[nQ + activeDivWords + 2] == (0 -% c));

        if (pQuotient) |q| {
            q[nQ] = Q;
        }
        if (nQ == 0) break;
    }

    if (pRemainder) |rem| {
        @memcpy(rem[0..activeDivWords], pTmp[2 .. 2 + activeDivWords]);
        SymCryptWipe(&rem[activeDivWords], @as(SIZE_T, remainderWords - activeDivWords) * @sizeOf(UINT32));
    }
}

pub export fn SymCryptFdefIntDivMod(
    piSrc: PCSYMCRYPT_INT,
    pdDivisor: PCSYMCRYPT_DIVISOR,
    piQuotient: ?PSYMCRYPT_INT,
    piRemainder: ?PSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const nDigits: UINT32 = SYMCRYPT_OBJ_NDIGITS(piSrc);

    macros.SYMCRYPT_ASSERT(piQuotient == null or piQuotient.?.nDigits >= piSrc.nDigits);
    macros.SYMCRYPT_ASSERT(piRemainder == null or piRemainder.?.nDigits >= pdDivisor.nDigits);

    SymCryptFdefRawDivMod(
        SYMCRYPT_FDEF_INT_PCUINT32(piSrc),
        nDigits,
        pdDivisor,
        if (piQuotient) |q| SYMCRYPT_FDEF_INT_PUINT32(q) else null,
        if (piRemainder) |rem| SYMCRYPT_FDEF_INT_PUINT32(rem) else null,
        pbScratch,
        cbScratch,
    );

    if (piQuotient) |q| {
        if (q.nDigits > piSrc.nDigits) {
            SymCryptWipe(
                &SYMCRYPT_FDEF_INT_PUINT32(q)[piSrc.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32],
                @as(SIZE_T, q.nDigits - piSrc.nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE,
            );
        }
    }

    if (piRemainder) |rem| {
        if (rem.nDigits > pdDivisor.nDigits) {
            SymCryptWipe(
                &SYMCRYPT_FDEF_INT_PUINT32(rem)[pdDivisor.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32],
                @as(SIZE_T, rem.nDigits - pdDivisor.nDigits) * SYMCRYPT_FDEF_DIGIT_SIZE,
            );
        }
    }
}
