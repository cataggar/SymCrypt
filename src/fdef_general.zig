//
// fdef_general.zig   General functions of the default format.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const PCUINT32 = types.PCUINT32;
const UINT64 = types.UINT64;
const PUINT64 = types.PUINT64;
const PCUINT64 = types.PCUINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_INT = types.SYMCRYPT_INT;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const SYMCRYPT_DIVISOR = types.SYMCRYPT_DIVISOR;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PCSYMCRYPT_DIVISOR = types.PCSYMCRYPT_DIVISOR;
const SYMCRYPT_TRIALDIVISION_PRIME = types.SYMCRYPT_TRIALDIVISION_PRIME;
const PSYMCRYPT_TRIALDIVISION_PRIME = types.PSYMCRYPT_TRIALDIVISION_PRIME;
const PCSYMCRYPT_TRIALDIVISION_PRIME = types.PCSYMCRYPT_TRIALDIVISION_PRIME;
const SYMCRYPT_TRIALDIVISION_GROUP = types.SYMCRYPT_TRIALDIVISION_GROUP;
const PSYMCRYPT_TRIALDIVISION_GROUP = types.PSYMCRYPT_TRIALDIVISION_GROUP;
const PCSYMCRYPT_TRIALDIVISION_GROUP = types.PCSYMCRYPT_TRIALDIVISION_GROUP;
const SYMCRYPT_TRIALDIVISION_CONTEXT = types.SYMCRYPT_TRIALDIVISION_CONTEXT;
const PSYMCRYPT_TRIALDIVISION_CONTEXT = types.PSYMCRYPT_TRIALDIVISION_CONTEXT;
const PCSYMCRYPT_TRIALDIVISION_CONTEXT = types.PCSYMCRYPT_TRIALDIVISION_CONTEXT;
const SYMCRYPT_SMALL_PRIME_GROUPS_SPEC = types.SYMCRYPT_SMALL_PRIME_GROUPS_SPEC;
const SYMCRYPT_FDEF_DIGIT_SIZE = types.SYMCRYPT_FDEF_DIGIT_SIZE;
const SYMCRYPT_FDEF_DIGIT_BITS = types.SYMCRYPT_FDEF_DIGIT_BITS;
const SYMCRYPT_FDEF_DIGIT_NUINT32 = types.SYMCRYPT_FDEF_DIGIT_NUINT32;
const SYMCRYPT_FDEF_INT_PUINT32 = types.SYMCRYPT_FDEF_INT_PUINT32;
const SYMCRYPT_FDEF_INT_PCUINT32 = types.SYMCRYPT_FDEF_INT_PCUINT32;

const SYMCRYPT_TRIALDIVISION_DIGIT_REDUCTION_CYCLES: UINT64 = if (types.CPU_AMD64 or types.CPU_ARM64) 16 else 18;
const SYMCRYPT_TRIALDIVISION_DIVIDE_TEST_CYCLES: UINT64 = if (types.CPU_AMD64 or types.CPU_ARM64) 2 else 16;
const SYMCRYPT_RABINMILLER_DIGIT_CYCLES: UINT64 = if (types.CPU_AMD64 or types.CPU_ARM64) 43000 else 25300;
const SYMCRYPT_TRIALDIVISION_MAX_SMALL_PRIME: UINT32 = 1 << 22;
const SYMCRYPT_MAX_SMALL_PRIME_GROUP_PRODUCT: UINT32 = 0x1c71c71c;

pub export const g_SymCryptSmallPrimeGroupsSpec: [6]SYMCRYPT_SMALL_PRIME_GROUPS_SPEC = .{
    .{ .nGroups = 1, .nPrimes = 7, .maxPrime = 31 },
    .{ .nGroups = 1, .nPrimes = 5, .maxPrime = 53 },
    .{ .nGroups = 5, .nPrimes = 4, .maxPrime = 151 },
    .{ .nGroups = 34, .nPrimes = 3, .maxPrime = 787 },
    .{ .nGroups = 1156, .nPrimes = 2, .maxPrime = 21841 },
    .{ .nGroups = 0, .nPrimes = 1, .maxPrime = 0xffffffff },
};

extern fn SymCryptCallbackAlloc(cbData: SIZE_T) callconv(SYMCRYPT_CALL) PVOID;
extern fn SymCryptCallbackFree(pData: PVOID) callconv(SYMCRYPT_CALL) void;
const c_wipe = struct {
    extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
};

inline fn SymCryptWipe(pbData: anytype, cbData: SIZE_T) void {
    c_wipe.SymCryptWipe(@ptrCast(pbData), cbData);
}

inline fn SYMCRYPT_ASSERT_ASYM_ALIGNED(p: anytype) void {
    macros.SYMCRYPT_ASSERT((@intFromPtr(p) & (types.SYMCRYPT_ASYM_ALIGN_VALUE - 1)) == 0);
}

inline fn SYMCRYPT_OBJ_NDIGITS(p: anytype) UINT32 {
    return p.nDigits;
}

inline fn SYMCRYPT_OBJ_NBYTES(p: anytype) UINT32 {
    return p.nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
}

inline fn SYMCRYPT_OBJ_NUINT32(p: anytype) UINT32 {
    return p.nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
}

inline fn SYMCRYPT_MUL32x32TO64(a: UINT32, b: UINT32) UINT64 {
    return @as(UINT64, a) *% @as(UINT64, b);
}

pub export fn SymCryptFdefMaskedCopyC(
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    nDigits: UINT32,
    mask: UINT32,
) callconv(SYMCRYPT_CALL) void {
    const m64: UINT64 = @as(UINT64, 0) -% @as(UINT64, mask & 1);
    const pSrc: PCUINT64 = @ptrCast(@alignCast(pbSrc));
    const pDst: PUINT64 = @ptrCast(@alignCast(pbDst));

    macros.SYMCRYPT_ASSERT((mask +% 1) < 2);

    const nQwords: SIZE_T = @as(SIZE_T, nDigits) * (SYMCRYPT_FDEF_DIGIT_SIZE / @sizeOf(UINT64));
    var i: SIZE_T = 0;
    while (i < nQwords) : (i += 2) {
        const s0 = macros.SYMCRYPT_FORCE_READ64(&pSrc[i]);
        const d0 = macros.SYMCRYPT_FORCE_READ64(&pDst[i]);
        macros.SYMCRYPT_FORCE_WRITE64(&pDst[i], (s0 & m64) | (d0 & ~m64));

        const s1 = macros.SYMCRYPT_FORCE_READ64(&pSrc[i + 1]);
        const d1 = macros.SYMCRYPT_FORCE_READ64(&pDst[i + 1]);
        macros.SYMCRYPT_FORCE_WRITE64(&pDst[i + 1], (s1 & m64) | (d1 & ~m64));
    }
}

extern fn SymCryptFdefMaskedCopyAsm(
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    nDigits: UINT32,
    mask: UINT32,
) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptFdefMaskedCopy(
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    nDigits: UINT32,
    mask: UINT32,
) callconv(SYMCRYPT_CALL) void {
    if (comptime (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM64 or types.CPU_ARM)) {
        SYMCRYPT_ASSERT_ASYM_ALIGNED(pbSrc);
        SYMCRYPT_ASSERT_ASYM_ALIGNED(pbDst);
        SymCryptFdefMaskedCopyAsm(pbSrc, pbDst, nDigits, mask);
    } else {
        SymCryptFdefMaskedCopyC(pbSrc, pbDst, nDigits, mask);
    }
}

pub export fn SymCryptFdefConditionalSwapC(
    pbSrc1: PBYTE,
    pbSrc2: PBYTE,
    nDigits: UINT32,
    cond: UINT32,
) callconv(SYMCRYPT_CALL) void {
    const m64: UINT64 = @as(UINT64, 0) -% @as(UINT64, cond & 1);
    const pSrc1: PUINT64 = @ptrCast(@alignCast(pbSrc1));
    const pSrc2: PUINT64 = @ptrCast(@alignCast(pbSrc2));

    macros.SYMCRYPT_ASSERT(cond < 2);

    const nQwords: SIZE_T = @as(SIZE_T, nDigits) * (SYMCRYPT_FDEF_DIGIT_SIZE / @sizeOf(UINT64));
    var i: SIZE_T = 0;
    while (i < nQwords) : (i += 2) {
        const s1_0 = macros.SYMCRYPT_FORCE_READ64(&pSrc1[i]);
        const s2_0 = macros.SYMCRYPT_FORCE_READ64(&pSrc2[i]);
        const s1_1 = macros.SYMCRYPT_FORCE_READ64(&pSrc1[i + 1]);
        const s2_1 = macros.SYMCRYPT_FORCE_READ64(&pSrc2[i + 1]);

        const tmp1: UINT64 = (s1_0 ^ s2_0) & m64;
        const tmp2: UINT64 = (s1_1 ^ s2_1) & m64;

        macros.SYMCRYPT_FORCE_WRITE64(&pSrc1[i], s1_0 ^ tmp1);
        macros.SYMCRYPT_FORCE_WRITE64(&pSrc2[i], s2_0 ^ tmp1);
        macros.SYMCRYPT_FORCE_WRITE64(&pSrc1[i + 1], s1_1 ^ tmp2);
        macros.SYMCRYPT_FORCE_WRITE64(&pSrc2[i + 1], s2_1 ^ tmp2);
    }
}

pub export fn SymCryptFdefConditionalSwap(
    pbSrc1: PBYTE,
    pbSrc2: PBYTE,
    nDigits: UINT32,
    cond: UINT32,
) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefConditionalSwapC(pbSrc1, pbSrc2, nDigits, cond);
}

pub export fn SymCryptFdefDigitsFromBits(nBits: UINT32) callconv(.c) UINT32 {
    var res: UINT32 = undefined;

    if (nBits == 0) {
        res = 1;
    } else {
        macros.SYMCRYPT_ASSERT(nBits <= types.SYMCRYPT_INT_MAX_BITS);

        if (nBits > types.SYMCRYPT_INT_MAX_BITS) {
            res = 0;
        } else {
            res = types.SYMCRYPT_FDEF_DIGITS_FROM_BITS(nBits);
        }
    }

    return res;
}

pub export fn SymCryptFdefIntAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT {
    var p: PVOID = null;
    var res: ?PSYMCRYPT_INT = null;

    const cb: UINT32 = SymCryptFdefSizeofIntFromDigits(nDigits);

    if (cb != 0) {
        p = SymCryptCallbackAlloc(cb);
    }

    if (p) |ptr| {
        res = SymCryptFdefIntCreate(@ptrCast(ptr), cb, nDigits);
    }

    return res;
}

pub export fn SymCryptFdefSizeofIntFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(nDigits != 0);
    macros.SYMCRYPT_ASSERT(nDigits <= types.SYMCRYPT_FDEF_UPB_DIGITS);

    if (nDigits == 0 or nDigits > types.SYMCRYPT_FDEF_UPB_DIGITS) {
        return 0;
    }

    return @as(UINT32, @intCast(@offsetOf(SYMCRYPT_INT, "ti"))) + nDigits * SYMCRYPT_FDEF_DIGIT_SIZE;
}

pub export fn SymCryptFdefIntCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT {
    var pInt: ?PSYMCRYPT_INT = null;
    const cb: UINT32 = SymCryptFdefSizeofIntFromDigits(nDigits);

    macros.SYMCRYPT_ASSERT(cb >= @sizeOf(SYMCRYPT_INT));
    macros.SYMCRYPT_ASSERT(cbBuffer >= cb);
    if (cb == 0 or cbBuffer < cb) {
        return null;
    }

    SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);
    const pi: PSYMCRYPT_INT = @ptrCast(@alignCast(pbBuffer));

    pi.type = macros.multiCharConstant("gI") << 16;
    pi.nDigits = nDigits;
    pi.cbSize = cb;

    macros.SYMCRYPT_SET_MAGIC(pi);
    pInt = pi;

    return pInt;
}

pub export fn SymCryptFdefIntCopyFixup(
    pSrc: PCSYMCRYPT_INT,
    pDst: PSYMCRYPT_INT,
) callconv(.c) void {
    _ = pSrc;
    macros.SYMCRYPT_SET_MAGIC(pDst);
}

pub export fn SymCryptFdefIntCopy(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(.c) void {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc);
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    if (piSrc != piDst) {
        const cb: usize = SYMCRYPT_OBJ_NBYTES(piDst);
        const dstBytes: [*]u8 = @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piDst));
        const srcBytes: [*]const u8 = @ptrCast(SYMCRYPT_FDEF_INT_PCUINT32(piSrc));
        @memcpy(dstBytes[0..cb], srcBytes[0..cb]);
    }
}

pub export fn SymCryptFdefIntMaskedCopy(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
    mask: UINT32,
) callconv(.c) void {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc);
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    SymCryptFdefMaskedCopy(
        @ptrCast(SYMCRYPT_FDEF_INT_PCUINT32(piSrc)),
        @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piDst)),
        piSrc.nDigits,
        mask,
    );
}

pub export fn SymCryptFdefIntConditionalCopy(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
    cond: UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc);
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    macros.SYMCRYPT_ASSERT(piSrc.nDigits == piDst.nDigits);

    SymCryptFdefMaskedCopy(
        @ptrCast(SYMCRYPT_FDEF_INT_PCUINT32(piSrc)),
        @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piDst)),
        piSrc.nDigits,
        macros.SYMCRYPT_MASK32_NONZERO(cond),
    );
}

pub export fn SymCryptFdefIntConditionalSwap(
    piSrc1: PSYMCRYPT_INT,
    piSrc2: PSYMCRYPT_INT,
    cond: UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc1);
    macros.SYMCRYPT_CHECK_MAGIC(piSrc2);

    macros.SYMCRYPT_ASSERT(piSrc1.nDigits == piSrc2.nDigits);

    SymCryptFdefConditionalSwap(
        @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piSrc1)),
        @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piSrc2)),
        piSrc1.nDigits,
        cond,
    );
}

pub export fn SymCryptFdefIntBitsizeOfObject(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return SYMCRYPT_FDEF_DIGIT_BITS * piSrc.nDigits;
}

pub export fn SymCryptFdefNumberofDigitsFromInt(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return piSrc.nDigits;
}

pub export fn SymCryptFdefIntCopyMixedSize(
    piSrc: PCSYMCRYPT_INT,
    piDst: PSYMCRYPT_INT,
) callconv(.c) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.SYMCRYPT_CHECK_MAGIC(piSrc);
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    if (piSrc == piDst) {
        return scError;
    }

    const n: UINT32 = @min(piSrc.nDigits, piDst.nDigits);
    const cbCopy: usize = @as(usize, n) * SYMCRYPT_FDEF_DIGIT_SIZE;
    const dstBytes: [*]u8 = @ptrCast(SYMCRYPT_FDEF_INT_PUINT32(piDst));
    const srcBytes: [*]const u8 = @ptrCast(SYMCRYPT_FDEF_INT_PCUINT32(piSrc));
    @memcpy(dstBytes[0..cbCopy], srcBytes[0..cbCopy]);

    if (piDst.nDigits > n) {
        SymCryptWipe(
            &SYMCRYPT_FDEF_INT_PUINT32(piDst)[n * SYMCRYPT_FDEF_DIGIT_NUINT32],
            @as(SIZE_T, piDst.nDigits - n) * SYMCRYPT_FDEF_DIGIT_SIZE,
        );
    }

    if (piSrc.nDigits > n) {
        var p: PCUINT64 = @ptrCast(@alignCast(&SYMCRYPT_FDEF_INT_PCUINT32(piSrc)[n * SYMCRYPT_FDEF_DIGIT_NUINT32]));
        var v: UINT64 = 0;
        var i: UINT32 = (piSrc.nDigits - n) * (SYMCRYPT_FDEF_DIGIT_SIZE / @sizeOf(UINT64));
        while (i > 0) : (i -= 1) {
            v |= p[0];
            p += 1;
        }

        if (v != 0) {
            scError = .SYMCRYPT_BUFFER_TOO_SMALL;
            return scError;
        }
    }

    return scError;
}

pub export fn SymCryptFdefBitsizeOfUint32(v_in: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    var v: UINT32 = v_in;
    var vUpper: UINT32 = v & 0xffff0000;
    var mask: UINT32 = @truncate((@as(UINT64, 0) -% @as(UINT64, vUpper)) >> 32);
    var res: UINT32 = mask & 16;
    v = ((v & 0xffff) & ~mask) | ((vUpper >> 16) & mask);

    vUpper = v & 0xff00;
    mask = (0 -% vUpper) >> 16;
    res |= mask & 8;
    v = ((v & 0xff) & ~mask) | ((v >> 8) & mask);

    vUpper = v & 0xf0;
    mask = (0 -% vUpper) >> 16;
    res |= mask & 4;
    v = ((v & 0xf) & ~mask) | ((v >> 4) & mask);

    vUpper = v & 0xc;
    mask = (0 -% vUpper) >> 16;
    res |= mask & 2;
    v = ((v & 0x3) & ~mask) | ((v >> 2) & mask);

    const vBit1: UINT32 = (v >> 1) & 1;
    res |= vBit1;

    res += (v | vBit1) & 1;

    return res;
}

pub export fn SymCryptFdefIntBitsizeOfValue(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    var nUint32: UINT32 = SYMCRYPT_OBJ_NUINT32(piSrc);

    var res: UINT32 = 0;
    var msNonzeroWord: UINT32 = 0;
    var searchingMask: UINT32 = macros.SYMCRYPT_MASK32_SET;

    macros.SYMCRYPT_CHECK_MAGIC(piSrc);

    const pSrc = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    while (nUint32 > 0) {
        nUint32 -= 1;
        const d: UINT32 = pSrc[nUint32];

        const dIsNonzeroMask: UINT32 = macros.SYMCRYPT_MASK32_NONZERO(d);
        const foundMask: UINT32 = dIsNonzeroMask & searchingMask;
        res |= nUint32 & foundMask;
        msNonzeroWord |= d & foundMask;
        searchingMask &= ~foundMask;
    }

    res = res * 8 * @sizeOf(UINT32) + SymCryptFdefBitsizeOfUint32(msNonzeroWord);

    return res;
}

pub export fn SymCryptFdefIntSetValueUint32(
    u32Src: UINT32,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    SymCryptWipe(SYMCRYPT_FDEF_INT_PUINT32(piDst), SYMCRYPT_OBJ_NBYTES(piDst));
    SYMCRYPT_FDEF_INT_PUINT32(piDst)[0] = u32Src;
}

pub export fn SymCryptFdefIntSetValueUint64(
    u64Src: UINT64,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    SymCryptWipe(SYMCRYPT_FDEF_INT_PUINT32(piDst), SYMCRYPT_OBJ_NBYTES(piDst));
    SYMCRYPT_FDEF_INT_PUINT32(piDst)[0] = @truncate(u64Src);
    SYMCRYPT_FDEF_INT_PUINT32(piDst)[1] = @truncate(u64Src >> 32);
}

pub export fn SymCryptFdefRawSetValue(
    pbSrc_in: PCBYTE,
    cbSrc_in: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    pDst: PUINT32,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pbSrc: PCBYTE = pbSrc_in;
    var cbSrc: SIZE_T = cbSrc_in;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var b: UINT32 = 0;
    var step: isize = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    switch (format) {
        .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST => {
            step = 1;
        },
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST => {
            step = -1;
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    var idx: SIZE_T = if (step == 1) 0 else cbSrc;

    var windex: UINT32 = 0;
    while (windex < nWords) : (windex += 1) {
        var w: UINT32 = 0;
        var i: u5 = 0;
        while (i < 4) : (i += 1) {
            if (cbSrc > 0) {
                if (step == 1) {
                    b = pbSrc[idx];
                    idx += 1;
                } else {
                    idx -= 1;
                    b = pbSrc[idx];
                }
                cbSrc -= 1;
                w |= b << (8 * i);
            }
        }
        pDst[windex] = w;
    }

    b = 0;
    while (cbSrc > 0) {
        if (step == 1) {
            b |= pbSrc[idx];
            idx += 1;
        } else {
            idx -= 1;
            b |= pbSrc[idx];
        }
        cbSrc -= 1;
    }

    if (b > 0) {
        scError = .SYMCRYPT_BUFFER_TOO_SMALL;
        return scError;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptFdefIntSetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
    piDst: PSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.SYMCRYPT_CHECK_MAGIC(piDst);

    return SymCryptFdefRawSetValue(pbSrc, cbSrc, format, SYMCRYPT_FDEF_INT_PUINT32(piDst), piDst.nDigits);
}

pub export fn SymCryptFdefRawGetValue(
    pSrc: PCUINT32,
    nDigits: UINT32,
    pbDst_in: PBYTE,
    cbDst_in: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pbDst: PBYTE = pbDst_in;
    var cbDst: SIZE_T = cbDst_in;
    var step: isize = 0;
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    switch (format) {
        .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST => {
            step = 1;
        },
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST => {
            step = -1;
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    var idx: SIZE_T = if (step == 1) 0 else cbDst;

    var windex: UINT32 = 0;
    while (windex < nWords) : (windex += 1) {
        var w: UINT32 = pSrc[windex];
        var i: UINT32 = 0;
        while (i < 4) : (i += 1) {
            const b: UINT32 = w & 0xff;
            w >>= 8;

            if (cbDst > 0) {
                if (step == 1) {
                    pbDst[idx] = @truncate(b);
                    idx += 1;
                } else {
                    idx -= 1;
                    pbDst[idx] = @truncate(b);
                }
                cbDst -= 1;
            } else {
                if (b != 0) {
                    return .SYMCRYPT_BUFFER_TOO_SMALL;
                }
            }
        }
    }

    while (cbDst > 0) {
        if (step == 1) {
            pbDst[idx] = 0;
            idx += 1;
        } else {
            idx -= 1;
            pbDst[idx] = 0;
        }
        cbDst -= 1;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptFdefIntGetValue(
    piSrc: PCSYMCRYPT_INT,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    format: SYMCRYPT_NUMBER_FORMAT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.SYMCRYPT_CHECK_MAGIC(piSrc);

    return SymCryptFdefRawGetValue(SYMCRYPT_FDEF_INT_PCUINT32(piSrc), piSrc.nDigits, pbDst, cbDst, format);
}

pub export fn SymCryptFdefIntGetValueLsbits32(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return SYMCRYPT_FDEF_INT_PCUINT32(piSrc)[0];
}

pub export fn SymCryptFdefIntGetValueLsbits64(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT64 {
    const p: PCUINT32 = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    return (@as(UINT64, p[1]) << 32) | p[0];
}

pub export fn SymCryptFdefRawIsEqualUint32(
    pSrc1: PCUINT32,
    nDigits: UINT32,
    u32Src2: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    const nWords: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;

    var d: UINT32 = pSrc1[0] ^ u32Src2;
    var i: UINT32 = 1;
    while (i < nWords) : (i += 1) {
        d |= pSrc1[i];
    }

    return macros.SYMCRYPT_MASK32_ZERO(d);
}

pub export fn SymCryptFdefIntIsEqualUint32(
    piSrc1: PCSYMCRYPT_INT,
    u32Src2: UINT32,
) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefRawIsEqualUint32(SYMCRYPT_FDEF_INT_PCUINT32(piSrc1), piSrc1.nDigits, u32Src2);
}

pub export fn SymCryptFdefIntIsEqual(
    piSrc1: PCSYMCRYPT_INT,
    piSrc2: PCSYMCRYPT_INT,
) callconv(SYMCRYPT_CALL) UINT32 {
    const n1: UINT32 = SYMCRYPT_OBJ_NUINT32(piSrc1);
    const n2: UINT32 = SYMCRYPT_OBJ_NUINT32(piSrc2);
    const pSrc1: PCUINT32 = SYMCRYPT_FDEF_INT_PCUINT32(piSrc1);
    const pSrc2: PCUINT32 = SYMCRYPT_FDEF_INT_PCUINT32(piSrc2);

    const n: UINT32 = @min(n1, n2);
    var d: UINT32 = 0;
    var i: UINT32 = 0;
    while (i < n) : (i += 1) {
        d |= pSrc1[i] ^ pSrc2[i];
    }

    while (i < n1) : (i += 1) {
        d |= pSrc1[i];
    }

    while (i < n2) : (i += 1) {
        d |= pSrc2[i];
    }

    return macros.SYMCRYPT_MASK32_ZERO(d);
}

pub export fn SymCryptFdefDivisorAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DIVISOR {
    var p: PVOID = null;
    var res: ?PSYMCRYPT_DIVISOR = null;

    const cb: UINT32 = SymCryptFdefSizeofDivisorFromDigits(nDigits);

    if (cb != 0) {
        p = SymCryptCallbackAlloc(cb);
    }

    if (p) |ptr| {
        res = SymCryptFdefDivisorCreate(@ptrCast(ptr), cb, nDigits);
    }

    return res;
}

pub export fn SymCryptFdefSizeofDivisorFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(nDigits != 0);
    macros.SYMCRYPT_ASSERT(nDigits <= types.SYMCRYPT_FDEF_UPB_DIGITS);

    if (nDigits == 0 or nDigits > types.SYMCRYPT_FDEF_UPB_DIGITS) {
        return 0;
    }

    return @as(UINT32, @intCast(@offsetOf(SYMCRYPT_DIVISOR, "Int"))) + SymCryptFdefSizeofIntFromDigits(nDigits);
}

pub export fn SymCryptFdefDivisorCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    nDigits: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DIVISOR {
    const cb: UINT32 = SymCryptFdefSizeofDivisorFromDigits(nDigits);

    macros.SYMCRYPT_ASSERT(cb >= @sizeOf(SYMCRYPT_DIVISOR));
    macros.SYMCRYPT_ASSERT(cbBuffer >= cb);
    if (cb == 0 or cbBuffer < cb) {
        return null;
    }

    SYMCRYPT_ASSERT_ASYM_ALIGNED(pbBuffer);
    const pdDiv: PSYMCRYPT_DIVISOR = @ptrCast(@alignCast(pbBuffer));

    pdDiv.type = macros.multiCharConstant("gD") << 16;
    pdDiv.nDigits = nDigits;
    pdDiv.cbSize = cb;

    macros.SYMCRYPT_SET_MAGIC(pdDiv);

    _ = SymCryptFdefIntCreate(@ptrCast(&pdDiv.Int), cbBuffer - @offsetOf(SYMCRYPT_DIVISOR, "Int"), nDigits);

    return pdDiv;
}

pub export fn SymCryptFdefDivisorCopyFixup(
    pdSrc: PCSYMCRYPT_DIVISOR,
    pdDst: PSYMCRYPT_DIVISOR,
) callconv(.c) void {
    SymCryptFdefIntCopyFixup(&pdSrc.Int, &pdDst.Int);

    macros.SYMCRYPT_SET_MAGIC(pdDst);
}

pub export fn SymCryptFdefDivisorCopy(
    pdSrc: PCSYMCRYPT_DIVISOR,
    pdDst: PSYMCRYPT_DIVISOR,
) callconv(.c) void {
    macros.SYMCRYPT_CHECK_MAGIC(pdSrc);
    macros.SYMCRYPT_CHECK_MAGIC(pdDst);

    macros.SYMCRYPT_ASSERT(pdSrc.nDigits == pdDst.nDigits);

    if (pdSrc != pdDst) {
        const cb: usize = pdDst.cbSize;
        const dstBytes: [*]u8 = @ptrCast(pdDst);
        const srcBytes: [*]const u8 = @ptrCast(pdSrc);
        @memcpy(dstBytes[0..cb], srcBytes[0..cb]);

        SymCryptFdefDivisorCopyFixup(pdSrc, pdDst);
    }
}

pub export fn SymCryptFdefClaimScratch(pbScratch: PBYTE, cbScratch: SIZE_T, cbMin: SIZE_T) callconv(SYMCRYPT_CALL) void {
    if (types.DEBUG) {
        macros.SYMCRYPT_ASSERT(cbScratch >= cbMin);
        if (cbMin > 0) {
            SymCryptWipe(pbScratch, cbMin);
        }
    }
}

pub export fn SymCryptTestTrialdivisionMaxSmallPrime(
    pContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT,
) callconv(.c) UINT32 {
    return pContext.maxTrialPrime;
}

pub export fn SymCryptInverseMod2e64(m: UINT64) callconv(.c) UINT64 {
    const m32: UINT32 = @truncate(m);

    var inv32: UINT32 = m32 ^ (((m32 -% 1) *% 0x6) & 0x8);
    macros.SYMCRYPT_ASSERT(((m & 1) == 0) or (((inv32 *% m32) & 0xf) == 1));

    inv32 = inv32 *% (2 -% inv32 *% m32);
    macros.SYMCRYPT_ASSERT(((m & 1) == 0) or (((inv32 *% m32) & 0xff) == 1));

    inv32 = inv32 *% (2 -% inv32 *% m32);
    macros.SYMCRYPT_ASSERT(((m & 1) == 0) or (((inv32 *% m32) & 0xffff) == 1));

    inv32 = inv32 *% (2 -% inv32 *% m32);
    macros.SYMCRYPT_ASSERT(((m & 1) == 0) or ((inv32 *% m32) == 1));

    var inv64: UINT64 = inv32;
    inv64 = inv64 *% (2 -% inv64 *% m);
    macros.SYMCRYPT_ASSERT(((m & 1) == 0) or ((inv64 *% m) == 1));

    return inv64;
}

pub export fn SymCryptFdefInitTrialdivisionPrime(
    prime: UINT32,
    pPrime: PSYMCRYPT_TRIALDIVISION_PRIME,
) callconv(SYMCRYPT_CALL) void {
    pPrime.invMod2e64 = SymCryptInverseMod2e64(prime);
    pPrime.compareLimit = @as(UINT64, std.math.maxInt(UINT64)) / @as(UINT64, prime);
}

inline fn SymCryptIsMultipleOfSmallPrime(value: UINT64, pPrime: PCSYMCRYPT_TRIALDIVISION_PRIME) bool {
    return (value *% pPrime.invMod2e64) <= pPrime.compareLimit;
}

pub export fn SymCryptFdefInitTrialDivisionGroup(
    pGroup: PSYMCRYPT_TRIALDIVISION_GROUP,
    nPrimes: UINT32,
    primeProd: UINT32,
) callconv(SYMCRYPT_CALL) void {
    pGroup.nPrimes = nPrimes;

    const f: UINT32 = @truncate((@as(UINT64, 1) << 32) % primeProd);
    pGroup.factor[0] = f;
    var r: UINT32 = f;
    var i: usize = 1;
    while (i < 9) : (i += 1) {
        r = @truncate(SYMCRYPT_MUL32x32TO64(r, f) % primeProd);
        pGroup.factor[i] = r;
    }
}

pub export fn SymCryptGenerateSmallPrimes(maxPrime_in: UINT32, ppList: *?PUINT32) callconv(SYMCRYPT_CALL) UINT32 {
    var nPrimes: UINT32 = 0;
    var pList: ?PUINT32 = null;

    var maxPrime: UINT32 = @max(maxPrime_in, 32);
    maxPrime = @min(maxPrime, 1 << 24);

    const nSieve: UINT32 = (maxPrime - 1) / 2 + 1;

    const pSieveRaw = SymCryptCallbackAlloc(nSieve);
    if (pSieveRaw == null) {
        ppList.* = null;
        return 0;
    }
    const pSieve: PBYTE = @ptrCast(pSieveRaw.?);

    SymCryptWipe(pSieve, nSieve);

    var pi: UINT32 = 1;
    var p: UINT32 = 2 * pi + 1;
    while (true) {
        var si: UINT32 = 2 * (pi * pi + pi);
        if (si > nSieve) {
            break;
        }
        while (si < nSieve) {
            pSieve[si] = 1;
            si += p;
        }
        while (true) {
            pi += 1;
            if (pSieve[pi] == 0) break;
        }
        p = 2 * pi + 1;
    }

    // Eliminate 3, 5, and 17
    pSieve[1] = 1;
    pSieve[2] = 1;
    pSieve[8] = 1;

    var i: UINT32 = 1;
    while (i < nSieve) : (i += 1) {
        nPrimes += 1 - pSieve[i];
    }

    const pListRaw = SymCryptCallbackAlloc(@as(SIZE_T, nPrimes) * @sizeOf(UINT32));
    if (pListRaw) |raw| {
        const listPtr: PUINT32 = @ptrCast(@alignCast(raw));
        pList = listPtr;

        pi = 0;
        i = 1;
        while (i < nSieve) : (i += 1) {
            if (pSieve[i] == 0) {
                listPtr[pi] = 2 * i + 1;
                pi += 1;
            }
        }

        macros.SYMCRYPT_ASSERT(pi == nPrimes);
    }

    SymCryptWipe(pSieve, nSieve);
    SymCryptCallbackFree(pSieveRaw);

    ppList.* = pList;
    return nPrimes;
}

pub export fn SymCryptFdefCreateTrialDivisionContext(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_TRIALDIVISION_CONTEXT {
    var pRes: ?PSYMCRYPT_TRIALDIVISION_CONTEXT = null;
    var maxPrime: UINT32 = undefined;
    var nSmallPrimes: UINT32 = 0;
    var pSmallPrimeList: ?PUINT32 = null;

    if (nDigits <= 1000) {
        if (nDigits == 0) {
            return null;
        }

        const cRabinMillerCost: UINT64 = @as(UINT64, nDigits) * nDigits * nDigits * (SYMCRYPT_RABINMILLER_DIGIT_CYCLES * 8 / 10);
        var i: usize = 0;
        var minPrime: UINT32 = 0;
        var cPerPrimeCost: UINT64 = undefined;
        while (true) {
            const nPrimes: UINT32 = g_SymCryptSmallPrimeGroupsSpec[i].nPrimes;
            maxPrime = g_SymCryptSmallPrimeGroupsSpec[i].maxPrime;
            const nGroups: UINT32 = g_SymCryptSmallPrimeGroupsSpec[i].nGroups;
            cPerPrimeCost = @as(UINT64, nDigits) * SYMCRYPT_TRIALDIVISION_DIGIT_REDUCTION_CYCLES / nPrimes + SYMCRYPT_TRIALDIVISION_DIVIDE_TEST_CYCLES;

            if (nGroups == 0 or @as(UINT64, maxPrime) * cPerPrimeCost >= cRabinMillerCost) {
                break;
            }
            i += 1;
            minPrime = maxPrime;
        }

        var tmp64: UINT64 = cRabinMillerCost / cPerPrimeCost;
        tmp64 = @min(tmp64, SYMCRYPT_TRIALDIVISION_MAX_SMALL_PRIME);
        maxPrime = @truncate(tmp64);
        maxPrime = @max(maxPrime, minPrime);
    } else {
        maxPrime = SYMCRYPT_TRIALDIVISION_MAX_SMALL_PRIME;
    }

    nSmallPrimes = SymCryptGenerateSmallPrimes(maxPrime, &pSmallPrimeList);
    defer {
        if (pSmallPrimeList) |list| {
            SymCryptWipe(list, @as(SIZE_T, nSmallPrimes) * @sizeOf(UINT32));
            SymCryptCallbackFree(list);
        }
    }

    if (pSmallPrimeList == null) {
        return null;
    }

    var n: UINT32 = nSmallPrimes;
    var nG: UINT32 = 0;
    var nP: UINT32 = 0;
    var i: usize = 0;
    while (true) {
        const nPrimes: UINT32 = g_SymCryptSmallPrimeGroupsSpec[i].nPrimes;
        const nGroups: UINT32 = g_SymCryptSmallPrimeGroupsSpec[i].nGroups;

        if (n < nPrimes * nGroups or nGroups == 0) {
            n = n / nPrimes;
            nG += n;
            nP += n * nPrimes;
            n = 0;
            break;
        }

        nG += nGroups;
        nP += nPrimes * nGroups;
        n -= nPrimes * nGroups;
        i += 1;
    }

    const nBytes: UINT32 = @as(UINT32, @sizeOf(SYMCRYPT_TRIALDIVISION_CONTEXT)) +
        (nG + 1) * @as(UINT32, @sizeOf(SYMCRYPT_TRIALDIVISION_GROUP)) +
        (nP + 1) * @as(UINT32, @sizeOf(SYMCRYPT_TRIALDIVISION_PRIME)) +
        (nP + 1) * @as(UINT32, @sizeOf(UINT32));

    const pAllocRaw = SymCryptCallbackAlloc(nBytes);
    if (pAllocRaw == null) {
        return null;
    }

    var pAlloc: PBYTE = @ptrCast(pAllocRaw.?);
    const ctx: PSYMCRYPT_TRIALDIVISION_CONTEXT = @ptrCast(@alignCast(pAlloc));
    pAlloc += @sizeOf(SYMCRYPT_TRIALDIVISION_CONTEXT);

    ctx.nBytesAlloc = nBytes;

    ctx.pGroupList = @ptrCast(@alignCast(pAlloc));
    pAlloc += @as(usize, nG + 1) * @sizeOf(SYMCRYPT_TRIALDIVISION_GROUP);

    ctx.pPrimeList = @ptrCast(@alignCast(pAlloc));
    pAlloc += @as(usize, nP + 1) * @sizeOf(SYMCRYPT_TRIALDIVISION_PRIME);

    ctx.pPrimes = @ptrCast(@alignCast(pAlloc));
    pAlloc += @as(usize, nP + 1) * @sizeOf(UINT32);

    macros.SYMCRYPT_ASSERT(nBytes == (@intFromPtr(pAlloc) - @intFromPtr(ctx)));

    SymCryptFdefInitTrialdivisionPrime(3, &ctx.Primes3_5_17[0]);
    SymCryptFdefInitTrialdivisionPrime(5, &ctx.Primes3_5_17[1]);
    SymCryptFdefInitTrialdivisionPrime(17, &ctx.Primes3_5_17[2]);

    const smallPrimes = pSmallPrimeList.?;
    @memcpy(ctx.pPrimes[0..nP], smallPrimes[0..nP]);
    ctx.pPrimes[nP] = 0;
    ctx.maxTrialPrime = ctx.pPrimes[nP - 1];

    var iPrime: UINT32 = 0;
    while (iPrime < nP) : (iPrime += 1) {
        SymCryptFdefInitTrialdivisionPrime(ctx.pPrimes[iPrime], &ctx.pPrimeList[iPrime]);
    }

    ctx.pPrimeList[nP].invMod2e64 = 0;
    ctx.pPrimeList[nP].compareLimit = 0;

    var iGroup: UINT32 = 0;
    iPrime = 0;
    var iGroupSpec: usize = 0;
    var nPrimes: UINT32 = g_SymCryptSmallPrimeGroupsSpec[iGroupSpec].nPrimes;
    var nGroups: UINT32 = g_SymCryptSmallPrimeGroupsSpec[iGroupSpec].nGroups;
    while (iPrime < nP) {
        if (nGroups == 0) {
            iGroupSpec += 1;
            nPrimes = g_SymCryptSmallPrimeGroupsSpec[iGroupSpec].nPrimes;
            nGroups = g_SymCryptSmallPrimeGroupsSpec[iGroupSpec].nGroups;
            if (nGroups == 0) {
                nGroups = nG - iGroup;
            }
        }

        macros.SYMCRYPT_ASSERT(iPrime + nPrimes <= nP);
        var M: UINT32 = ctx.pPrimes[iPrime];
        iPrime += 1;
        var j: UINT32 = 1;
        while (j < nPrimes) : (j += 1) {
            macros.SYMCRYPT_ASSERT(M <= SYMCRYPT_MAX_SMALL_PRIME_GROUP_PRODUCT / ctx.pPrimes[iPrime]);
            M *= ctx.pPrimes[iPrime];
            iPrime += 1;
        }
        SymCryptFdefInitTrialDivisionGroup(&ctx.pGroupList[iGroup], nPrimes, M);
        iGroup += 1;

        nGroups -= 1;
    }

    macros.SYMCRYPT_ASSERT(iPrime == nP and iGroup == nG);

    ctx.pGroupList[iGroup].nPrimes = 0;
    pRes = ctx;

    return pRes;
}

pub export fn SymCryptFdefFreeTrialDivisionContext(pContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT) callconv(SYMCRYPT_CALL) void {
    SymCryptWipe(@constCast(pContext), pContext.nBytesAlloc);
    SymCryptCallbackFree(@ptrCast(@constCast(pContext)));
}

pub export fn SymCryptFdefIntFindSmallDivisor(
    pContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT,
    piSrc: PCSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    const pSrc: PCUINT32 = SYMCRYPT_FDEF_INT_PCUINT32(piSrc);
    var p: PCUINT32 = pSrc;
    const nDigits: UINT32 = piSrc.nDigits;
    const nUint32: UINT32 = nDigits * SYMCRYPT_FDEF_DIGIT_NUINT32;
    var Acc: UINT64 = 0;

    _ = pbScratch;
    _ = cbScratch;

    if ((pSrc[0] & 1) == 0) {
        return 2;
    }

    Acc = 0;
    p = pSrc;
    while (true) {
        if (comptime (SYMCRYPT_FDEF_DIGIT_SIZE == 16)) {
            Acc = Acc +% p[0] +% p[1] +% p[2] +% p[3];
            p += 4;
        } else if (comptime ((SYMCRYPT_FDEF_DIGIT_SIZE % 32) == 0)) {
            Acc = Acc +% p[0] +% p[1] +% p[2] +% p[3] +% p[4] +% p[5] +% p[6] +% p[7];
            p += 8;
        } else {
            @compileError("Unsupported SYMCRYPT_FDEF_DIGIT_SIZE");
        }
        if (@intFromPtr(p) >= @intFromPtr(pSrc + nUint32)) break;
    }

    if (SymCryptIsMultipleOfSmallPrime(Acc, &pContext.Primes3_5_17[0])) {
        return 3;
    }

    if (SymCryptIsMultipleOfSmallPrime(Acc, &pContext.Primes3_5_17[1])) {
        return 5;
    }

    if (SymCryptIsMultipleOfSmallPrime(Acc, &pContext.Primes3_5_17[2])) {
        return 17;
    }

    var iGroup: usize = 0;
    var iPrime: usize = 0;
    while (true) {
        const pGroup: PCSYMCRYPT_TRIALDIVISION_GROUP = &pContext.pGroupList[iGroup];
        var nPrimes: UINT32 = pGroup.nPrimes;
        if (nPrimes == 0) break;

        Acc = 0;
        p = pSrc + nUint32;

        if (comptime (SYMCRYPT_FDEF_DIGIT_SIZE == 16)) {
            if ((nUint32 & 4) != 0) {
                p -= 4;
                Acc =
                    @as(UINT64, p[0]) +%
                    SYMCRYPT_MUL32x32TO64(p[1], pGroup.factor[0]) +%
                    SYMCRYPT_MUL32x32TO64(p[2], pGroup.factor[1]) +%
                    SYMCRYPT_MUL32x32TO64(p[3], pGroup.factor[2]);
            } else {
                p -= 8;
                Acc =
                    @as(UINT64, p[0]) +%
                    SYMCRYPT_MUL32x32TO64(p[1], pGroup.factor[0]) +%
                    SYMCRYPT_MUL32x32TO64(p[2], pGroup.factor[1]) +%
                    SYMCRYPT_MUL32x32TO64(p[3], pGroup.factor[2]) +%
                    SYMCRYPT_MUL32x32TO64(p[4], pGroup.factor[3]) +%
                    SYMCRYPT_MUL32x32TO64(p[5], pGroup.factor[4]) +%
                    SYMCRYPT_MUL32x32TO64(p[6], pGroup.factor[5]) +%
                    SYMCRYPT_MUL32x32TO64(p[7], pGroup.factor[6]);
            }
        } else if (comptime ((SYMCRYPT_FDEF_DIGIT_SIZE % 32) == 0)) {
            p -= 8;
            Acc =
                @as(UINT64, p[0]) +%
                SYMCRYPT_MUL32x32TO64(p[1], pGroup.factor[0]) +%
                SYMCRYPT_MUL32x32TO64(p[2], pGroup.factor[1]) +%
                SYMCRYPT_MUL32x32TO64(p[3], pGroup.factor[2]) +%
                SYMCRYPT_MUL32x32TO64(p[4], pGroup.factor[3]) +%
                SYMCRYPT_MUL32x32TO64(p[5], pGroup.factor[4]) +%
                SYMCRYPT_MUL32x32TO64(p[6], pGroup.factor[5]) +%
                SYMCRYPT_MUL32x32TO64(p[7], pGroup.factor[6]);
        } else {
            @compileError("Unsupported SYMCRYPT_FDEF_DIGIT_SIZE");
        }

        while (@intFromPtr(p) > @intFromPtr(pSrc)) {
            p -= 8;
            Acc =
                @as(UINT64, p[0]) +%
                SYMCRYPT_MUL32x32TO64(p[1], pGroup.factor[0]) +%
                SYMCRYPT_MUL32x32TO64(p[2], pGroup.factor[1]) +%
                SYMCRYPT_MUL32x32TO64(p[3], pGroup.factor[2]) +%
                SYMCRYPT_MUL32x32TO64(p[4], pGroup.factor[3]) +%
                SYMCRYPT_MUL32x32TO64(p[5], pGroup.factor[4]) +%
                SYMCRYPT_MUL32x32TO64(p[6], pGroup.factor[5]) +%
                SYMCRYPT_MUL32x32TO64(p[7], pGroup.factor[6]) +%
                SYMCRYPT_MUL32x32TO64(@truncate(Acc), pGroup.factor[7]) +%
                SYMCRYPT_MUL32x32TO64(@truncate(Acc >> 32), pGroup.factor[8]);
        }

        while (nPrimes > 0) : (nPrimes -= 1) {
            if (SymCryptIsMultipleOfSmallPrime(Acc, &pContext.pPrimeList[iPrime])) {
                return pContext.pPrimes[iPrime];
            }
            iPrime += 1;
        }

        iGroup += 1;
    }

    return 0;
}
