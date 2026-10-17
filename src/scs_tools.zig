//
// scs_tools.zig
// Support tools for writing side-channel safe code.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const UINT32 = types.UINT32;
const INT32 = types.INT32;
const INT64 = types.INT64;
const NATIVE_UINT = types.NATIVE_UINT;
const NATIVE_INT = types.NATIVE_INT;
const NATIVE_BITS = types.NATIVE_BITS;
const NATIVE_BYTES = types.NATIVE_BYTES;
const NATIVE_BYTES_LOG2 = types.NATIVE_BYTES_LOG2;
const PCSYMCRYPT_UINT32_MAP = types.PCSYMCRYPT_UINT32_MAP;

const MIN_BUFFER_SIZE: SIZE_T = 32;
const NativeShift = std.math.Log2Int(NATIVE_UINT);

// ==============================================================================================
// Masking Functions (31-bit inputs)
// ==============================================================================================

pub export fn SymCryptMask32IsNonzeroU31(v: UINT32) callconv(types.SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(v < (@as(UINT32, 1) << 31));
    const sv: INT32 = @bitCast(v);
    return @bitCast((-%sv) >> 31);
}

pub export fn SymCryptMask32IsZeroU31(v: UINT32) callconv(types.SYMCRYPT_CALL) UINT32 {
    return ~SymCryptMask32IsNonzeroU31(v);
}

pub export fn SymCryptMask32NeqU31(a: UINT32, b: UINT32) callconv(types.SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(a < (@as(UINT32, 1) << 31));
    macros.SYMCRYPT_ASSERT(b < (@as(UINT32, 1) << 31));

    return SymCryptMask32IsNonzeroU31(a ^ b);
}

pub export fn SymCryptMask32LtU31(a: UINT32, b: UINT32) callconv(types.SYMCRYPT_CALL) UINT32 {
    macros.SYMCRYPT_ASSERT(a < (@as(UINT32, 1) << 31));
    macros.SYMCRYPT_ASSERT(b < (@as(UINT32, 1) << 31));

    // Casting to INT32 is defined as a and b are < 2^31
    const sa: INT32 = @bitCast(a);
    const sb: INT32 = @bitCast(b);
    return @bitCast((sa -% sb) >> 31);
}

// ==============================================================================================
// Masking Functions (32-bit inputs)
// ==============================================================================================

pub export fn SymCryptMask32EqU32(a: UINT32, b: UINT32) callconv(types.SYMCRYPT_CALL) UINT32 {
    const diff: INT64 = @intCast(a ^ b);
    const shifted: INT64 = (-%diff) >> 32;
    const u64_val: u64 = @bitCast(shifted);
    return ~@as(UINT32, @truncate(u64_val));
}

// ==============================================================================================
// Other Helper Functions
// ==============================================================================================

pub export fn SymCryptRoundUpPow2Sizet(v: SIZE_T) callconv(types.SYMCRYPT_CALL) SIZE_T {
    macros.SYMCRYPT_ASSERT(v <= (types.SIZE_T_MAX / 2) + 1);

    var res: SIZE_T = 1;
    while (res < v) {
        res +%= res;

        // Catch any overflows; should never happen but break to avoid infinite loop
        if (res == 0) {
            break;
        }
    }

    return res;
}

// ==============================================================================================
// Copy Data
// ==============================================================================================

pub export fn SymCryptScsCopy(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(cbSrc <= (@as(SIZE_T, 1) << 31) and cbDst <= (@as(SIZE_T, 1) << 31));

    const cbSrc32: UINT32 = @truncate(cbSrc);
    var i: UINT32 = 0;
    while (i < cbDst) : (i += 1) {
        const mask: u8 = @truncate(SymCryptMask32LtU31(i, cbSrc32));
        pbDst[i] ^= (pbSrc[i] ^ pbDst[i]) & mask;
    }
}

// ==============================================================================================
// Buffer Rotation
// ==============================================================================================

inline fn maskFromBit(bit: usize) NATIVE_UINT {
    const b: NATIVE_INT = @intCast(bit & 1);
    return @bitCast(-%b);
}

pub export fn SymCryptScsRotateBuffer(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    lshift_in: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var lshift: SIZE_T = lshift_in;
    var Mask: [16]NATIVE_UINT = undefined;

    macros.SYMCRYPT_ASSERT((cbBuffer & (cbBuffer - 1)) == 0 and cbBuffer >= MIN_BUFFER_SIZE);
    macros.SYMCRYPT_ASSERT(lshift < cbBuffer);

    const pBuf: [*]align(1) NATIVE_UINT = @ptrCast(pbBuffer);
    const n: UINT32 = @intCast(cbBuffer / NATIVE_BYTES);

    // First a rotate left by lshift % NATIVE_BYTES
    const a: UINT32 = @truncate(8 * (lshift & (NATIVE_BYTES - 1)));
    const a_native_int: NATIVE_INT = @intCast(a);
    var M: NATIVE_UINT = @bitCast((-%a_native_int) >> (NATIVE_BITS - 1));
    const b: UINT32 = (NATIVE_BITS - a) & @as(UINT32, @truncate(M));

    const a_shift: NativeShift = @intCast(a);
    const b_shift: NativeShift = @intCast(b);

    var i: UINT32 = n;
    var V: NATIVE_UINT = pBuf[0];
    while (true) {
        i -= 1;
        const T: NATIVE_UINT = pBuf[i];
        pBuf[i] = (T >> a_shift) | ((V << b_shift) & M);
        V = T;
        if (i == 0) break;
    }

    // Now that the rotation is word-aligned, we can start our word rotation
    lshift >>= NATIVE_BYTES_LOG2;

    macros.SYMCRYPT_ASSERT(n >= 4);

    M = maskFromBit(lshift);
    const M0: NATIVE_UINT = maskFromBit((lshift + 0) >> 1);
    const M1: NATIVE_UINT = maskFromBit((lshift + 1) >> 1);

    i = 0;
    while (i < n) : (i += 4) {
        var A: NATIVE_UINT = pBuf[i];
        var B: NATIVE_UINT = pBuf[i + 1];
        var C: NATIVE_UINT = pBuf[i + 2];
        var D: NATIVE_UINT = pBuf[i + 3];

        var T: NATIVE_UINT = (A ^ B) & M;
        A ^= T;
        B ^= T;

        T = (C ^ D) & M;
        C ^= T;
        D ^= T;

        T = (A ^ C) & M0;
        A ^= T;
        C ^= T;

        T = (B ^ D) & M1;
        B ^= T;
        D ^= T;

        pBuf[i] = A;
        pBuf[i + 1] = B;
        pBuf[i + 2] = C;
        pBuf[i + 3] = D;
    }

    // Do the swaps using the mask array
    var blockSize: UINT32 = 4;
    var blockSizeLog: u5 = 2;

    const blockSizeLimit: UINT32 = @min(@as(UINT32, Mask.len), n / 4);
    while (blockSize <= blockSizeLimit) {
        i = 0;
        while (i < blockSize) : (i += 1) {
            Mask[i] = maskFromBit((@as(SIZE_T, i) +% lshift) >> blockSizeLog);
        }

        i = 0;
        while (i < n) : (i += 2 * blockSize) {
            var j: UINT32 = 0;
            while (j < blockSize) : (j += 1) {
                var A: NATIVE_UINT = pBuf[i + j];
                var B: NATIVE_UINT = pBuf[i + j + blockSize];
                const T: NATIVE_UINT = (A ^ B) & Mask[j];
                A ^= T;
                B ^= T;
                pBuf[i + j] = A;
                pBuf[i + j + blockSize] = B;
            }
        }
        blockSize *= 2;
        blockSizeLog += 1;
    }

    while (blockSize < n) {
        i = 0;
        while (i < n) : (i += 2 * blockSize) {
            var j: UINT32 = 0;
            while (j < blockSize) : (j += 1) {
                M = maskFromBit((@as(SIZE_T, j) +% lshift) >> blockSizeLog);
                var A: NATIVE_UINT = pBuf[i + j];
                var B: NATIVE_UINT = pBuf[i + j + blockSize];
                const T: NATIVE_UINT = (A ^ B) & M;
                A ^= T;
                B ^= T;
                pBuf[i + j] = A;
                pBuf[i + j + blockSize] = B;
            }
        }
        blockSize *= 2;
        blockSizeLog += 1;
    }
}

// ==============================================================================================
// Map Uint32
// ==============================================================================================

pub export fn SymCryptMapUint32(
    u32Input: UINT32,
    u32Default: UINT32,
    pcMap: PCSYMCRYPT_UINT32_MAP,
    nMap: SIZE_T,
) callconv(types.SYMCRYPT_CALL) UINT32 {
    const mapPtr: [*]const types.SYMCRYPT_UINT32_MAP = @ptrCast(pcMap);
    var u32Output: UINT32 = u32Default;

    var i: SIZE_T = 0;
    while (i < nMap) : (i += 1) {
        const mask = SymCryptMask32EqU32(u32Input, mapPtr[i].from);
        u32Output ^= (u32Output ^ mapPtr[i].to) & mask;
    }

    return u32Output;
}
