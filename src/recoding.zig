//
// recoding.zig
// Algorithms for recoding the factors / exponents in various implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const types = @import("types.zig");
const macros = @import("macros.zig");

const UINT32 = types.UINT32;
const PUINT32 = types.PUINT32;
const SIZE_T = types.SIZE_T;

pub const SYMCRYPT_INT = opaque {};
pub const PSYMCRYPT_INT = *SYMCRYPT_INT;
pub const PCSYMCRYPT_INT = *const SYMCRYPT_INT;

extern fn SymCryptIntGetValueLsbits32(piSrc: PCSYMCRYPT_INT) callconv(types.SYMCRYPT_CALL) UINT32;
extern fn SymCryptIntSubUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32, piDst: PSYMCRYPT_INT) callconv(types.SYMCRYPT_CALL) UINT32;
extern fn SymCryptIntAddUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32, piDst: PSYMCRYPT_INT) callconv(types.SYMCRYPT_CALL) UINT32;
extern fn SymCryptIntMaskedCopy(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, mask: UINT32) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptIntDivPow2(piSrc: PCSYMCRYPT_INT, exp: SIZE_T, piDst: PSYMCRYPT_INT) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptIntBitsizeOfObject(piSrc: PCSYMCRYPT_INT) callconv(types.SYMCRYPT_CALL) UINT32;
extern fn SymCryptIntGetBits(piSrc: PCSYMCRYPT_INT, iBit: UINT32, nBits: UINT32) callconv(types.SYMCRYPT_CALL) UINT32;

pub export fn SymCryptFixedWindowRecoding(
    W: UINT32,
    piK: PSYMCRYPT_INT,
    piTmp: PSYMCRYPT_INT,
    absofKIs: PUINT32,
    sigofKIs: PUINT32,
    nRecodedDigits: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(W < 32);

    const wShift: u5 = @intCast(W);
    const wMinus1Shift: u5 = @intCast(W - 1);
    const mask: UINT32 = ~(@as(UINT32, 0xffffffff) << wShift); // Window mask = 2^w - 1
    const smask: UINT32 = @as(UINT32, 0x1) << wMinus1Shift; // Sign mask = 2^(w-1)

    var i: UINT32 = 0;
    while (i < nRecodedDigits - 1) : (i += 1) {
        var T1: UINT32 = SymCryptIntGetValueLsbits32(piK) & mask; // T1 = k mod 2^W

        sigofKIs[i] = macros.SYMCRYPT_MASK32_ZERO(T1 & smask);

        const T2: UINT32 = T1 & ~smask; // |k_i| in case A
        T1 = smask -% T1; // |k_i| in case B

        absofKIs[i] = ((T1 & sigofKIs[i]) | (T2 & ~sigofKIs[i])) >> 1;

        _ = SymCryptIntSubUint32(piK, T2, piTmp); // k - k_i in case (A)
        _ = SymCryptIntAddUint32(piK, T1, piK); // k - k_i in case (B)

        SymCryptIntMaskedCopy(piTmp, piK, ~sigofKIs[i]);

        SymCryptIntDivPow2(piK, W - 1, piK); // k := k / 2^(w-1)
    }

    sigofKIs[nRecodedDigits - 1] = 0;
    absofKIs[nRecodedDigits - 1] = (SymCryptIntGetValueLsbits32(piK) & mask & ~smask) >> 1;
}

pub export fn SymCryptWidthNafRecoding(
    W: UINT32,
    piK: PSYMCRYPT_INT,
    absofKIs: PUINT32,
    sigofKIs: PUINT32,
    nRecodedDigits: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(W < 32);

    const wShift: u5 = @intCast(W);
    const wMinus1Shift: u5 = @intCast(W - 1);
    const mask: UINT32 = ~(@as(UINT32, 0xffffffff) << wShift); // Window mask = 2^w - 1
    const modulus: UINT32 = mask +% 1; // 2^w
    const smask: UINT32 = @as(UINT32, 0x1) << wMinus1Shift; // Sign mask = 2^(w-1)

    var i: UINT32 = 0;
    while (i < nRecodedDigits) : (i += 1) {
        const T1: UINT32 = SymCryptIntGetValueLsbits32(piK) & mask; // T1 = k mod 2^W

        if ((T1 & 0x1) != 0) {
            if (T1 > smask) {
                sigofKIs[i] = 0xffffffff;
                absofKIs[i] = modulus -% T1; // 2^W - T1 = |T1 - 2^W|
                _ = SymCryptIntAddUint32(piK, absofKIs[i], piK); // k - k_i
            } else {
                sigofKIs[i] = 0x00000001;
                absofKIs[i] = T1;
                _ = SymCryptIntSubUint32(piK, absofKIs[i], piK); // k - k_i
            }
        } else {
            absofKIs[i] = 0;
            sigofKIs[i] = 0;
        }

        SymCryptIntDivPow2(piK, 1, piK); // k := k / 2
    }
}

pub export fn SymCryptPositiveWidthNafRecoding(
    W: UINT32,
    piK: PCSYMCRYPT_INT,
    nBitsExp: UINT32,
    absofKIs: PUINT32,
    nRecodedDigits: UINT32,
) callconv(types.SYMCRYPT_CALL) void {
    var cntrZ: UINT32 = W; // Counter that specifies when we filled the last non-zero NAF digit

    macros.SYMCRYPT_ASSERT(nRecodedDigits <= SymCryptIntBitsizeOfObject(piK));

    var i: UINT32 = 0;
    while (i < nRecodedDigits) : (i += 1) {
        const T1: UINT32 = SymCryptIntGetBits(piK, i, @min(W, nBitsExp - i));

        if ((cntrZ >= W) and ((T1 & 0x01) > 0)) {
            absofKIs[i] = T1;
            cntrZ = 0;
        } else {
            absofKIs[i] = 0;
        }

        cntrZ += 1;
    }
}
