//
// aes_neon.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// AES ARM64 NEON / Crypto Extensions implementations (ported from lib/aes-neon.c and lib/aes-pattern.c).
//

const std = @import("std");
const types = @import("types.zig");

const SYMCRYPT_AES_BLOCK_SIZE = types.SYMCRYPT_AES_BLOCK_SIZE;
const SYMCRYPT_GF128_BLOCK_SIZE = types.SYMCRYPT_GF128_BLOCK_SIZE;
const SYMCRYPT_GHASH_PMULL_HPOWERS: usize = 32;

const SYMCRYPT_AES_EXPANDED_KEY = types.SYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_GF128_ELEMENT = types.SYMCRYPT_GF128_ELEMENT;

const V16u8 = @Vector(16, u8);
const V16i8 = @Vector(16, i8);
const V4u32 = @Vector(4, u32);
const V2u64 = @Vector(2, u64);

inline fn load128(ptr: [*]const u8) V16u8 {
    return @as(*align(1) const V16u8, @ptrCast(ptr)).*;
}

inline fn store128(ptr: [*]u8, v: V16u8) void {
    @as(*align(1) V16u8, @ptrCast(ptr)).* = v;
}

inline fn loadKey(ptr: *const [4][4]u8) V16u8 {
    return @as(*align(1) const V16u8, @ptrCast(ptr)).*;
}

inline fn setN128U64(d0: u64, d1: u64) V16u8 {
    return @bitCast(V2u64{ d0, d1 });
}

inline fn vrev64q_u8(v: V16u8) V16u8 {
    return @shuffle(u8, v, undefined, [16]i32{
        7,  6,  5,  4,  3,  2,  1, 0,
        15, 14, 13, 12, 11, 10, 9, 8,
    });
}

inline fn vextq_u8(a: V16u8, b: V16u8, comptime n: comptime_int) V16u8 {
    const mask = comptime blk: {
        var m: [16]i32 = undefined;
        for (0..16) |i| {
            const idx = i + n;
            m[i] = if (idx < 16) @as(i32, @intCast(idx)) else -@as(i32, @intCast(idx - 16)) - 1;
        }
        break :blk m;
    };
    return @shuffle(u8, a, b, mask);
}

inline fn vextq_u32(a: V16u8, b: V16u8, comptime n: comptime_int) V16u8 {
    return vextq_u8(a, b, n * 4);
}

inline fn vaddq_u32(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) +% @as(V4u32, @bitCast(b)));
}

inline fn vsubq_u32(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) -% @as(V4u32, @bitCast(b)));
}

inline fn vaddq_u64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V2u64, @bitCast(a)) +% @as(V2u64, @bitCast(b)));
}

inline fn vsubq_u64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V2u64, @bitCast(a)) -% @as(V2u64, @bitCast(b)));
}

inline fn vshlq_n_u32(a: V16u8, comptime n: u5) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) << @splat(n));
}

inline fn vshrq_n_u32(a: V16u8, comptime n: u5) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) >> @splat(n));
}

inline fn vaeseq_u8(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm (
        \\.arch armv8-a+crypto
        \\aese %[res].16b, %[rk].16b
        : [res] "+w" (res),
        : [rk] "w" (rk),
    );
    return res;
}

inline fn vaesdq_u8(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm (
        \\.arch armv8-a+crypto
        \\aesd %[res].16b, %[rk].16b
        : [res] "+w" (res),
        : [rk] "w" (rk),
    );
    return res;
}

inline fn vaesimcq_u8(c: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm (
        \\.arch armv8-a+crypto
        \\aesimc %[res].16b, %[c].16b
        : [res] "=w" (res),
        : [c] "w" (c),
    );
    return res;
}

inline fn aese_aesmc(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm (
        \\.arch armv8-a+crypto
        \\aese %[res].16b, %[rk].16b
        \\aesmc %[res].16b, %[res].16b
        : [res] "+w" (res),
        : [rk] "w" (rk),
    );
    return res;
}

inline fn aesd_aesimc(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm (
        \\.arch armv8-a+crypto
        \\aesd %[res].16b, %[rk].16b
        \\aesimc %[res].16b, %[res].16b
        : [res] "+w" (res),
        : [rk] "w" (rk),
    );
    return res;
}

inline fn vmullq_p64(a: V16u8, b: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm (
        \\.arch armv8-a+crypto
        \\pmull %[res].1q, %[a].1d, %[b].1d
        : [res] "=w" (res),
        : [a] "w" (a),
          [b] "w" (b),
    );
    return res;
}

inline fn vmull_high_p64(a: V16u8, b: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm (
        \\.arch armv8-a+crypto
        \\pmull2 %[res].1q, %[a].2d, %[b].2d
        : [res] "=w" (res),
        : [a] "w" (a),
          [b] "w" (b),
    );
    return res;
}

inline fn vmull_low_p8(a: V16u8, b: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm (
        \\.arch armv8-a+crypto
        \\pmull %[res].8h, %[a].8b, %[b].8b
        : [res] "=w" (res),
        : [a] "w" (a),
          [b] "w" (b),
    );
    return res;
}

pub fn SymCryptAes4SboxNeon(
    pIn: [*]const u8,
    pOut: [*]u8,
) callconv(.c) void {
    const inVal = std.mem.readInt(u32, pIn[0..4], .little);
    var v: V16u8 = @bitCast(@as(V4u32, @splat(inVal)));
    const zero: V16u8 = @splat(0);
    v = vaeseq_u8(v, zero);
    const outVal = @as(V4u32, @bitCast(v))[0];
    std.mem.writeInt(u32, pOut[0..4], outVal, .little);
}

pub fn SymCryptAesCreateDecryptionRoundKeyNeon(
    pEncryptionRoundKey: [*]const u8,
    pDecryptionRoundKey: [*]u8,
) callconv(.c) void {
    store128(pDecryptionRoundKey, vaesimcq_u8(load128(pEncryptionRoundKey)));
}

inline fn aesEncrypt1(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aese_aesmc(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aese_aesmc(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aese_aesmc(c0.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaeseq_u8(c0.*, rk1) ^ rk2;
}

inline fn aesEncrypt4(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aese_aesmc(c0.*, rk);
        c1.* = aese_aesmc(c1.*, rk);
        c2.* = aese_aesmc(c2.*, rk);
        c3.* = aese_aesmc(c3.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aese_aesmc(c0.*, rk);
            c1.* = aese_aesmc(c1.*, rk);
            c2.* = aese_aesmc(c2.*, rk);
            c3.* = aese_aesmc(c3.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aese_aesmc(c0.*, rk);
                c1.* = aese_aesmc(c1.*, rk);
                c2.* = aese_aesmc(c2.*, rk);
                c3.* = aese_aesmc(c3.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaeseq_u8(c0.*, rk1) ^ rk2;
    c1.* = vaeseq_u8(c1.*, rk1) ^ rk2;
    c2.* = vaeseq_u8(c2.*, rk1) ^ rk2;
    c3.* = vaeseq_u8(c3.*, rk1) ^ rk2;
}

inline fn aesEncrypt8(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    c4: *V16u8,
    c5: *V16u8,
    c6: *V16u8,
    c7: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aese_aesmc(c0.*, rk);
        c1.* = aese_aesmc(c1.*, rk);
        c2.* = aese_aesmc(c2.*, rk);
        c3.* = aese_aesmc(c3.*, rk);
        c4.* = aese_aesmc(c4.*, rk);
        c5.* = aese_aesmc(c5.*, rk);
        c6.* = aese_aesmc(c6.*, rk);
        c7.* = aese_aesmc(c7.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aese_aesmc(c0.*, rk);
            c1.* = aese_aesmc(c1.*, rk);
            c2.* = aese_aesmc(c2.*, rk);
            c3.* = aese_aesmc(c3.*, rk);
            c4.* = aese_aesmc(c4.*, rk);
            c5.* = aese_aesmc(c5.*, rk);
            c6.* = aese_aesmc(c6.*, rk);
            c7.* = aese_aesmc(c7.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aese_aesmc(c0.*, rk);
                c1.* = aese_aesmc(c1.*, rk);
                c2.* = aese_aesmc(c2.*, rk);
                c3.* = aese_aesmc(c3.*, rk);
                c4.* = aese_aesmc(c4.*, rk);
                c5.* = aese_aesmc(c5.*, rk);
                c6.* = aese_aesmc(c6.*, rk);
                c7.* = aese_aesmc(c7.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaeseq_u8(c0.*, rk1) ^ rk2;
    c1.* = vaeseq_u8(c1.*, rk1) ^ rk2;
    c2.* = vaeseq_u8(c2.*, rk1) ^ rk2;
    c3.* = vaeseq_u8(c3.*, rk1) ^ rk2;
    c4.* = vaeseq_u8(c4.*, rk1) ^ rk2;
    c5.* = vaeseq_u8(c5.*, rk1) ^ rk2;
    c6.* = vaeseq_u8(c6.*, rk1) ^ rk2;
    c7.* = vaeseq_u8(c7.*, rk1) ^ rk2;
}

inline fn aesDecrypt1(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesd_aesimc(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesd_aesimc(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesd_aesimc(c0.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaesdq_u8(c0.*, rk1) ^ rk2;
}

inline fn aesDecrypt4(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesd_aesimc(c0.*, rk);
        c1.* = aesd_aesimc(c1.*, rk);
        c2.* = aesd_aesimc(c2.*, rk);
        c3.* = aesd_aesimc(c3.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesd_aesimc(c0.*, rk);
            c1.* = aesd_aesimc(c1.*, rk);
            c2.* = aesd_aesimc(c2.*, rk);
            c3.* = aesd_aesimc(c3.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesd_aesimc(c0.*, rk);
                c1.* = aesd_aesimc(c1.*, rk);
                c2.* = aesd_aesimc(c2.*, rk);
                c3.* = aesd_aesimc(c3.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaesdq_u8(c0.*, rk1) ^ rk2;
    c1.* = vaesdq_u8(c1.*, rk1) ^ rk2;
    c2.* = vaesdq_u8(c2.*, rk1) ^ rk2;
    c3.* = vaesdq_u8(c3.*, rk1) ^ rk2;
}

inline fn aesDecrypt8(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    c4: *V16u8,
    c5: *V16u8,
    c6: *V16u8,
    c7: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey - 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesd_aesimc(c0.*, rk);
        c1.* = aesd_aesimc(c1.*, rk);
        c2.* = aesd_aesimc(c2.*, rk);
        c3.* = aesd_aesimc(c3.*, rk);
        c4.* = aesd_aesimc(c4.*, rk);
        c5.* = aesd_aesimc(c5.*, rk);
        c6.* = aesd_aesimc(c6.*, rk);
        c7.* = aesd_aesimc(c7.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesd_aesimc(c0.*, rk);
            c1.* = aesd_aesimc(c1.*, rk);
            c2.* = aesd_aesimc(c2.*, rk);
            c3.* = aesd_aesimc(c3.*, rk);
            c4.* = aesd_aesimc(c4.*, rk);
            c5.* = aesd_aesimc(c5.*, rk);
            c6.* = aesd_aesimc(c6.*, rk);
            c7.* = aesd_aesimc(c7.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesd_aesimc(c0.*, rk);
                c1.* = aesd_aesimc(c1.*, rk);
                c2.* = aesd_aesimc(c2.*, rk);
                c3.* = aesd_aesimc(c3.*, rk);
                c4.* = aesd_aesimc(c4.*, rk);
                c5.* = aesd_aesimc(c5.*, rk);
                c6.* = aesd_aesimc(c6.*, rk);
                c7.* = aesd_aesimc(c7.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    const rk2 = loadKey(&keyPtr[1]);
    c0.* = vaesdq_u8(c0.*, rk1) ^ rk2;
    c1.* = vaesdq_u8(c1.*, rk1) ^ rk2;
    c2.* = vaesdq_u8(c2.*, rk1) ^ rk2;
    c3.* = vaesdq_u8(c3.*, rk1) ^ rk2;
    c4.* = vaesdq_u8(c4.*, rk1) ^ rk2;
    c5.* = vaesdq_u8(c5.*, rk1) ^ rk2;
    c6.* = vaesdq_u8(c6.*, rk1) ^ rk2;
    c7.* = vaesdq_u8(c7.*, rk1) ^ rk2;
}

pub fn SymCryptAesEncryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
) callconv(.c) void {
    var c = load128(pbSrc);
    aesEncrypt1(pExpandedKey, &c);
    store128(pbDst, c);
}

pub fn SymCryptAesDecryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
) callconv(.c) void {
    var c = load128(pbSrc);
    aesDecrypt1(pExpandedKey, &c);
    store128(pbDst, c);
}

inline fn aesEncrypt1Chain(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    mergedFirstRoundKey: V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[1]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey - 1;

    c0.* = aese_aesmc(c0.*, mergedFirstRoundKey);

    inline for (0..8) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aese_aesmc(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aese_aesmc(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aese_aesmc(c0.*, rk);
            }
        }
    }

    const rk1 = loadKey(&keyPtr[0]);
    c0.* = vaeseq_u8(c0.*, rk1);
}

pub fn SymCryptAesCbcEncryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var c = load128(pbChainingValue);
    const rk0 = loadKey(&pExpandedKey.RoundKey[0]);
    const rkLast = loadKey(&pExpandedKey.lastEncRoundKey[0]);
    const rk0AndLast = rk0 ^ rkLast;

    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;

    c ^= rkLast;

    while (rem >= SYMCRYPT_AES_BLOCK_SIZE) {
        const d = load128(src) ^ rk0AndLast;
        aesEncrypt1Chain(pExpandedKey, &c, d);
        store128(dst, c ^ rkLast);

        src += SYMCRYPT_AES_BLOCK_SIZE;
        dst += SYMCRYPT_AES_BLOCK_SIZE;
        rem -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    store128(pbChainingValue, c ^ rkLast);
}

pub fn SymCryptAesCbcDecryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var chain: V16u8 = undefined;
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;
    var d0: V16u8 = undefined;
    var d1: V16u8 = undefined;
    var d2: V16u8 = undefined;
    var d3: V16u8 = undefined;
    var d4: V16u8 = undefined;
    var d5: V16u8 = undefined;
    var d6: V16u8 = undefined;
    var d7: V16u8 = undefined;

    var cData = cbData / SYMCRYPT_AES_BLOCK_SIZE;
    if (cData == 0) {
        return;
    }

    var src = pbSrc;
    var dst = pbDst;
    chain = load128(pbChainingValue);

    while (cData >= 8) {
        c0 = load128(src + 0 * 16);
        d0 = c0;
        c1 = load128(src + 1 * 16);
        d1 = c1;
        c2 = load128(src + 2 * 16);
        d2 = c2;
        c3 = load128(src + 3 * 16);
        d3 = c3;
        c4 = load128(src + 4 * 16);
        d4 = c4;
        c5 = load128(src + 5 * 16);
        d5 = c5;
        c6 = load128(src + 6 * 16);
        d6 = c6;
        c7 = load128(src + 7 * 16);
        d7 = c7;

        aesDecrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        store128(dst + 0 * 16, c0 ^ chain);
        store128(dst + 1 * 16, c1 ^ d0);
        store128(dst + 2 * 16, c2 ^ d1);
        store128(dst + 3 * 16, c3 ^ d2);
        store128(dst + 4 * 16, c4 ^ d3);
        store128(dst + 5 * 16, c5 ^ d4);
        store128(dst + 6 * 16, c6 ^ d5);
        store128(dst + 7 * 16, c7 ^ d6);
        chain = d7;

        src += 8 * 16;
        dst += 8 * 16;
        cData -= 8;
    }

    if (cData >= 1) {
        c0 = load128(src + 0 * 16);
        d0 = c0;
        if (cData >= 2) {
            c1 = load128(src + 1 * 16);
            d1 = c1;
            if (cData >= 3) {
                c2 = load128(src + 2 * 16);
                d2 = c2;
                if (cData >= 4) {
                    c3 = load128(src + 3 * 16);
                    d3 = c3;
                    if (cData >= 5) {
                        c4 = load128(src + 4 * 16);
                        d4 = c4;
                        if (cData >= 6) {
                            c5 = load128(src + 5 * 16);
                            d5 = c5;
                            if (cData >= 7) {
                                c6 = load128(src + 6 * 16);
                            }
                        }
                    }
                }
            }
        }

        if (cData > 4) {
            aesDecrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);
            c0 ^= chain;
            c1 ^= d0;
            c2 ^= d1;
            c3 ^= d2;
            c4 ^= d3;
            c5 ^= d4;
            c6 ^= d5;
        } else if (cData > 1) {
            aesDecrypt4(pExpandedKey, &c0, &c1, &c2, &c3);
            c0 ^= chain;
            c1 ^= d0;
            c2 ^= d1;
            c3 ^= d2;
        } else {
            aesDecrypt1(pExpandedKey, &c0);
            c0 ^= chain;
        }

        chain = load128(src + (cData - 1) * 16);
        store128(dst + 0 * 16, c0);
        if (cData >= 2) {
            store128(dst + 1 * 16, c1);
            if (cData >= 3) {
                store128(dst + 2 * 16, c2);
                if (cData >= 4) {
                    store128(dst + 3 * 16, c3);
                    if (cData >= 5) {
                        store128(dst + 4 * 16, c4);
                        if (cData >= 6) {
                            store128(dst + 5 * 16, c5);
                            if (cData >= 7) {
                                store128(dst + 6 * 16, c6);
                            }
                        }
                    }
                }
            }
        }
    }

    store128(pbChainingValue, chain);
}

pub fn SymCryptAesCbcMacNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void {
    var c = load128(pbChainingValue);
    const rk0 = loadKey(&pExpandedKey.RoundKey[0]);
    const rkLast = loadKey(&pExpandedKey.lastEncRoundKey[0]);
    const rk0AndLast = rk0 ^ rkLast;

    var data = pbData;
    var rem = cbData;

    c ^= rkLast;

    while (rem >= SYMCRYPT_AES_BLOCK_SIZE) {
        const d = load128(data) ^ rk0AndLast;
        aesEncrypt1Chain(pExpandedKey, &c, d);

        data += SYMCRYPT_AES_BLOCK_SIZE;
        rem -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    store128(pbChainingValue, c ^ rkLast);
}

pub fn SymCryptAesEcbEncryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;

    while (rem >= 8 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src + 0 * 16);
        c1 = load128(src + 1 * 16);
        c2 = load128(src + 2 * 16);
        c3 = load128(src + 3 * 16);
        c4 = load128(src + 4 * 16);
        c5 = load128(src + 5 * 16);
        c6 = load128(src + 6 * 16);
        c7 = load128(src + 7 * 16);

        aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        store128(dst + 0 * 16, c0);
        store128(dst + 1 * 16, c1);
        store128(dst + 2 * 16, c2);
        store128(dst + 3 * 16, c3);
        store128(dst + 4 * 16, c4);
        store128(dst + 5 * 16, c5);
        store128(dst + 6 * 16, c6);
        store128(dst + 7 * 16, c7);

        src += 8 * 16;
        dst += 8 * 16;
        rem -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (rem >= 16) {
        c0 = load128(src + 0 * 16);
        if (rem >= 32) {
            c1 = load128(src + 1 * 16);
            if (rem >= 48) {
                c2 = load128(src + 2 * 16);
                if (rem >= 64) {
                    c3 = load128(src + 3 * 16);
                    if (rem >= 80) {
                        c4 = load128(src + 4 * 16);
                        if (rem >= 96) {
                            c5 = load128(src + 5 * 16);
                            if (rem >= 112) {
                                c6 = load128(src + 6 * 16);
                            }
                        }
                    }
                }
            }
        }

        if (rem >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
            aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);
        } else if (rem >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
            aesEncrypt4(pExpandedKey, &c0, &c1, &c2, &c3);
        } else {
            aesEncrypt1(pExpandedKey, &c0);
        }

        store128(dst + 0 * 16, c0);
        if (rem >= 32) {
            store128(dst + 1 * 16, c1);
            if (rem >= 48) {
                store128(dst + 2 * 16, c2);
                if (rem >= 64) {
                    store128(dst + 3 * 16, c3);
                    if (rem >= 80) {
                        store128(dst + 4 * 16, c4);
                        if (rem >= 96) {
                            store128(dst + 5 * 16, c5);
                            if (rem >= 112) {
                                store128(dst + 6 * 16, c6);
                            }
                        }
                    }
                }
            }
        }
    }
}

pub fn SymCryptAesEcbDecryptNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;

    while (rem >= 8 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src + 0 * 16);
        c1 = load128(src + 1 * 16);
        c2 = load128(src + 2 * 16);
        c3 = load128(src + 3 * 16);
        c4 = load128(src + 4 * 16);
        c5 = load128(src + 5 * 16);
        c6 = load128(src + 6 * 16);
        c7 = load128(src + 7 * 16);

        aesDecrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        store128(dst + 0 * 16, c0);
        store128(dst + 1 * 16, c1);
        store128(dst + 2 * 16, c2);
        store128(dst + 3 * 16, c3);
        store128(dst + 4 * 16, c4);
        store128(dst + 5 * 16, c5);
        store128(dst + 6 * 16, c6);
        store128(dst + 7 * 16, c7);

        src += 8 * 16;
        dst += 8 * 16;
        rem -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (rem >= 16) {
        c0 = load128(src + 0 * 16);
        if (rem >= 32) {
            c1 = load128(src + 1 * 16);
            if (rem >= 48) {
                c2 = load128(src + 2 * 16);
                if (rem >= 64) {
                    c3 = load128(src + 3 * 16);
                    if (rem >= 80) {
                        c4 = load128(src + 4 * 16);
                        if (rem >= 96) {
                            c5 = load128(src + 5 * 16);
                            if (rem >= 112) {
                                c6 = load128(src + 6 * 16);
                            }
                        }
                    }
                }
            }
        }

        if (rem >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
            aesDecrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);
        } else if (rem >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
            aesDecrypt4(pExpandedKey, &c0, &c1, &c2, &c3);
        } else {
            aesDecrypt1(pExpandedKey, &c0);
        }

        store128(dst + 0 * 16, c0);
        if (rem >= 32) {
            store128(dst + 1 * 16, c1);
            if (rem >= 48) {
                store128(dst + 2 * 16, c2);
                if (rem >= 64) {
                    store128(dst + 3 * 16, c3);
                    if (rem >= 80) {
                        store128(dst + 4 * 16, c4);
                        if (rem >= 96) {
                            store128(dst + 5 * 16, c5);
                            if (rem >= 112) {
                                store128(dst + 6 * 16, c6);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn aesCtrMsbXxNeon(
    comptime is64: bool,
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbDataIn: usize,
) void {
    const vadd = if (is64) vaddq_u64 else vaddq_u32;
    const vsub = if (is64) vsubq_u64 else vsubq_u32;

    var chain = load128(pbChainingValue);
    var src = pbSrc;
    var dst = pbDst;
    var cbData = cbDataIn & ~@as(usize, SYMCRYPT_AES_BLOCK_SIZE - 1);

    const chainIncrement1 = setN128U64(0, 1);
    const chainIncrement2 = setN128U64(0, 2);
    const chainIncrement8 = setN128U64(0, 8);

    var ctr0 = vrev64q_u8(chain);
    var ctr1 = vadd(ctr0, chainIncrement1);
    var ctr2 = vadd(ctr0, chainIncrement2);
    var ctr3 = vadd(ctr1, chainIncrement2);
    var ctr4 = vadd(ctr2, chainIncrement2);
    var ctr5 = vadd(ctr3, chainIncrement2);
    var ctr6 = vadd(ctr4, chainIncrement2);
    var ctr7 = vadd(ctr5, chainIncrement2);

    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    while (cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = vrev64q_u8(ctr0);
        c1 = vrev64q_u8(ctr1);
        c2 = vrev64q_u8(ctr2);
        c3 = vrev64q_u8(ctr3);
        c4 = vrev64q_u8(ctr4);
        c5 = vrev64q_u8(ctr5);
        c6 = vrev64q_u8(ctr6);
        c7 = vrev64q_u8(ctr7);

        ctr0 = vadd(ctr0, chainIncrement8);
        ctr1 = vadd(ctr1, chainIncrement8);
        ctr2 = vadd(ctr2, chainIncrement8);
        ctr3 = vadd(ctr3, chainIncrement8);
        ctr4 = vadd(ctr4, chainIncrement8);
        ctr5 = vadd(ctr5, chainIncrement8);
        ctr6 = vadd(ctr6, chainIncrement8);
        ctr7 = vadd(ctr7, chainIncrement8);

        aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        if (cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE) {
            break;
        }

        store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
        store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
        store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
        store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
        store128(dst + 4 * 16, load128(src + 4 * 16) ^ c4);
        store128(dst + 5 * 16, load128(src + 5 * 16) ^ c5);
        store128(dst + 6 * 16, load128(src + 6 * 16) ^ c6);
        store128(dst + 7 * 16, load128(src + 7 * 16) ^ c7);

        dst += 8 * 16;
        src += 8 * 16;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbData >= SYMCRYPT_AES_BLOCK_SIZE) {
        if (cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
            store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
            store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
            store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
            store128(dst + 4 * 16, load128(src + 4 * 16) ^ c4);
            chain = vsub(ctr5, chainIncrement8);

            if (cbData >= 96) {
                chain = vsub(ctr6, chainIncrement8);
                store128(dst + 5 * 16, load128(src + 5 * 16) ^ c5);
                if (cbData >= 112) {
                    chain = vsub(ctr7, chainIncrement8);
                    store128(dst + 6 * 16, load128(src + 6 * 16) ^ c6);
                }
            }
        } else if (cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
            chain = ctr2;

            c0 = vrev64q_u8(ctr0);
            c1 = vrev64q_u8(ctr1);
            c2 = vrev64q_u8(ctr2);
            c3 = vrev64q_u8(ctr3);

            aesEncrypt4(pExpandedKey, &c0, &c1, &c2, &c3);

            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
            store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
            if (cbData >= 48) {
                chain = ctr3;
                store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
                if (cbData >= 64) {
                    chain = ctr4;
                    store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
                }
            }
        } else {
            chain = ctr1;
            c0 = vrev64q_u8(ctr0);
            aesEncrypt1(pExpandedKey, &c0);
            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
        }
    } else {
        chain = ctr0;
    }

    chain = vrev64q_u8(chain);
    store128(pbChainingValue, chain);
}

pub fn SymCryptAesCtrMsb32Neon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    aesCtrMsbXxNeon(false, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

pub fn SymCryptAesCtrMsb64Neon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    aesCtrMsbXxNeon(true, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

const vAlphaMask: V16u8 = .{ 0x87, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };
const vAlphaMultiplier: V16u8 = setN128U64(0x0000000000000086, 0);

inline fn xtsMulAlpha(in: V16u8) V16u8 {
    const t1 = in << @as(@Vector(16, u3), @splat(1));
    var t2: V16u8 = @bitCast(@as(V16i8, @bitCast(in)) >> @as(@Vector(16, u3), @splat(7)));
    t2 = vextq_u8(t2, t2, 15);
    t2 = t2 & vAlphaMask;
    return t2 ^ t1;
}

inline fn xtsMulAlpha4(in: V16u8) V16u8 {
    const vZero: V16u8 = @splat(0);
    var t1 = vshlq_n_u32(in, 4);
    var t2 = vshrq_n_u32(in, 28);
    t1 ^= vextq_u32(vZero, t2, 3);
    t2 = vextq_u32(t2, vZero, 3);
    t2 = ((t2 ^ vshlq_n_u32(t2, 7)) ^ vshlq_n_u32(t2, 2)) ^ vshlq_n_u32(t2, 1);
    return t1 ^ t2;
}

inline fn xtsMulAlpha8(in: V16u8) V16u8 {
    const res = vextq_u8(in, in, 15);
    const t2 = vmull_low_p8(res, vAlphaMultiplier);
    return res ^ t2;
}

pub fn SymCryptXtsAesEncryptDataUnitNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var t0: V16u8 = undefined;
    var t1: V16u8 = undefined;
    var t2: V16u8 = undefined;
    var t3: V16u8 = undefined;
    var t4: V16u8 = undefined;
    var t5: V16u8 = undefined;
    var t6: V16u8 = undefined;
    var t7: V16u8 = undefined;
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var cbDataTail = cbData & ((8 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    var src = pbSrc;
    var dst = pbDst;
    t0 = load128(pbTweakBlock);

    if (cbDataMain > 0) {
        t4 = xtsMulAlpha4(t0);
        t1 = xtsMulAlpha(t0);
        t5 = xtsMulAlpha(t4);
        t2 = xtsMulAlpha(t1);
        t6 = xtsMulAlpha(t5);
        t3 = xtsMulAlpha(t2);
        t7 = xtsMulAlpha(t6);

        c0 = load128(src + 0 * 16) ^ t0;
        c1 = load128(src + 1 * 16) ^ t1;
        c2 = load128(src + 2 * 16) ^ t2;
        c3 = load128(src + 3 * 16) ^ t3;
        c4 = load128(src + 4 * 16) ^ t4;
        c5 = load128(src + 5 * 16) ^ t5;
        c6 = load128(src + 6 * 16) ^ t6;
        c7 = load128(src + 7 * 16) ^ t7;

        while (true) {
            src += 8 * SYMCRYPT_AES_BLOCK_SIZE;

            aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

            cbDataMain -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
            if (cbDataMain < 8 * SYMCRYPT_AES_BLOCK_SIZE) {
                break;
            }

            store128(dst + 0 * 16, c0 ^ t0);
            store128(dst + 1 * 16, c1 ^ t1);
            store128(dst + 2 * 16, c2 ^ t2);
            store128(dst + 3 * 16, c3 ^ t3);
            store128(dst + 4 * 16, c4 ^ t4);
            store128(dst + 5 * 16, c5 ^ t5);
            store128(dst + 6 * 16, c6 ^ t6);
            store128(dst + 7 * 16, c7 ^ t7);

            t0 = xtsMulAlpha8(t0);
            t1 = xtsMulAlpha8(t1);
            t2 = xtsMulAlpha8(t2);
            t3 = xtsMulAlpha8(t3);
            t4 = xtsMulAlpha8(t4);
            t5 = xtsMulAlpha8(t5);
            t6 = xtsMulAlpha8(t6);
            t7 = xtsMulAlpha8(t7);

            c0 = load128(src + 0 * 16) ^ t0;
            c1 = load128(src + 1 * 16) ^ t1;
            c2 = load128(src + 2 * 16) ^ t2;
            c3 = load128(src + 3 * 16) ^ t3;
            c4 = load128(src + 4 * 16) ^ t4;
            c5 = load128(src + 5 * 16) ^ t5;
            c6 = load128(src + 6 * 16) ^ t6;
            c7 = load128(src + 7 * 16) ^ t7;

            dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        }

        store128(dst + 0 * 16, c0 ^ t0);
        store128(dst + 1 * 16, c1 ^ t1);
        store128(dst + 2 * 16, c2 ^ t2);
        store128(dst + 3 * 16, c3 ^ t3);
        store128(dst + 4 * 16, c4 ^ t4);
        store128(dst + 5 * 16, c5 ^ t5);
        store128(dst + 6 * 16, c6 ^ t6);
        store128(dst + 7 * 16, c7 ^ t7);
        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        if (cbDataTail == 0) {
            return;
        }
        t0 = xtsMulAlpha8(t0);
    }

    while (cbDataTail >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        src += SYMCRYPT_AES_BLOCK_SIZE;
        aesEncrypt1(pExpandedKey, &c0);
        store128(dst, c0 ^ t0);
        dst += SYMCRYPT_AES_BLOCK_SIZE;
        t0 = xtsMulAlpha(t0);
        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    var tailBuf: [2 * SYMCRYPT_AES_BLOCK_SIZE]u8 = undefined;
    if (cbDataTail > SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        aesEncrypt1(pExpandedKey, &c0);
        store128(tailBuf[0..].ptr, c0 ^ t0);

        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;

        store128(tailBuf[SYMCRYPT_AES_BLOCK_SIZE..].ptr, load128(tailBuf[0..].ptr));
        @memcpy(tailBuf[0..cbDataTail], (src + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail]);
        @memcpy((dst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail], tailBuf[SYMCRYPT_AES_BLOCK_SIZE..][0..cbDataTail]);

        t0 = xtsMulAlpha(t0);
        c0 = load128(tailBuf[0..].ptr);
    } else {
        c0 = load128(src);
    }

    c0 ^= t0;
    aesEncrypt1(pExpandedKey, &c0);
    store128(dst, c0 ^ t0);
}

pub fn SymCryptXtsAesDecryptDataUnitNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var t0: V16u8 = undefined;
    var t1: V16u8 = undefined;
    var t2: V16u8 = undefined;
    var t3: V16u8 = undefined;
    var t4: V16u8 = undefined;
    var t5: V16u8 = undefined;
    var t6: V16u8 = undefined;
    var t7: V16u8 = undefined;
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var cbDataTail = cbData & ((8 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    var src = pbSrc;
    var dst = pbDst;
    t0 = load128(pbTweakBlock);

    if (cbDataMain > 0) {
        t4 = xtsMulAlpha4(t0);
        t1 = xtsMulAlpha(t0);
        t5 = xtsMulAlpha(t4);
        t2 = xtsMulAlpha(t1);
        t6 = xtsMulAlpha(t5);
        t3 = xtsMulAlpha(t2);
        t7 = xtsMulAlpha(t6);

        c0 = load128(src + 0 * 16) ^ t0;
        c1 = load128(src + 1 * 16) ^ t1;
        c2 = load128(src + 2 * 16) ^ t2;
        c3 = load128(src + 3 * 16) ^ t3;
        c4 = load128(src + 4 * 16) ^ t4;
        c5 = load128(src + 5 * 16) ^ t5;
        c6 = load128(src + 6 * 16) ^ t6;
        c7 = load128(src + 7 * 16) ^ t7;

        while (true) {
            src += 8 * SYMCRYPT_AES_BLOCK_SIZE;

            aesDecrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

            cbDataMain -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
            if (cbDataMain < 8 * SYMCRYPT_AES_BLOCK_SIZE) {
                break;
            }

            store128(dst + 0 * 16, c0 ^ t0);
            store128(dst + 1 * 16, c1 ^ t1);
            store128(dst + 2 * 16, c2 ^ t2);
            store128(dst + 3 * 16, c3 ^ t3);
            store128(dst + 4 * 16, c4 ^ t4);
            store128(dst + 5 * 16, c5 ^ t5);
            store128(dst + 6 * 16, c6 ^ t6);
            store128(dst + 7 * 16, c7 ^ t7);

            t0 = xtsMulAlpha8(t0);
            t1 = xtsMulAlpha8(t1);
            t2 = xtsMulAlpha8(t2);
            t3 = xtsMulAlpha8(t3);
            t4 = xtsMulAlpha8(t4);
            t5 = xtsMulAlpha8(t5);
            t6 = xtsMulAlpha8(t6);
            t7 = xtsMulAlpha8(t7);

            c0 = load128(src + 0 * 16) ^ t0;
            c1 = load128(src + 1 * 16) ^ t1;
            c2 = load128(src + 2 * 16) ^ t2;
            c3 = load128(src + 3 * 16) ^ t3;
            c4 = load128(src + 4 * 16) ^ t4;
            c5 = load128(src + 5 * 16) ^ t5;
            c6 = load128(src + 6 * 16) ^ t6;
            c7 = load128(src + 7 * 16) ^ t7;

            dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        }

        store128(dst + 0 * 16, c0 ^ t0);
        store128(dst + 1 * 16, c1 ^ t1);
        store128(dst + 2 * 16, c2 ^ t2);
        store128(dst + 3 * 16, c3 ^ t3);
        store128(dst + 4 * 16, c4 ^ t4);
        store128(dst + 5 * 16, c5 ^ t5);
        store128(dst + 6 * 16, c6 ^ t6);
        store128(dst + 7 * 16, c7 ^ t7);
        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        if (cbDataTail == 0) {
            return;
        }
        t0 = xtsMulAlpha8(t0);
    }

    while (cbDataTail >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        src += SYMCRYPT_AES_BLOCK_SIZE;
        aesDecrypt1(pExpandedKey, &c0);
        store128(dst, c0 ^ t0);
        dst += SYMCRYPT_AES_BLOCK_SIZE;
        t0 = xtsMulAlpha(t0);
        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    var tailBuf: [2 * SYMCRYPT_AES_BLOCK_SIZE]u8 = undefined;
    if (cbDataTail > SYMCRYPT_AES_BLOCK_SIZE) {
        t1 = xtsMulAlpha(t0);

        c0 = load128(src) ^ t1;
        aesDecrypt1(pExpandedKey, &c0);
        store128(tailBuf[0..].ptr, c0 ^ t1);

        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;

        store128(tailBuf[SYMCRYPT_AES_BLOCK_SIZE..].ptr, load128(tailBuf[0..].ptr));
        @memcpy(tailBuf[0..cbDataTail], (src + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail]);
        @memcpy((dst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail], tailBuf[SYMCRYPT_AES_BLOCK_SIZE..][0..cbDataTail]);

        c0 = load128(tailBuf[0..].ptr);
    } else {
        c0 = load128(src);
    }

    c0 ^= t0;
    aesDecrypt1(pExpandedKey, &c0);
    store128(dst, c0 ^ t0);
}

inline fn ghashHPower(table: [*]const SYMCRYPT_GF128_ELEMENT, ind: usize) V16u8 {
    return load128(@ptrCast(&table[SYMCRYPT_GHASH_PMULL_HPOWERS - ind]));
}

inline fn ghashHxPower(table: [*]const SYMCRYPT_GF128_ELEMENT, ind: usize) V16u8 {
    return load128(@ptrCast(&table[2 * SYMCRYPT_GHASH_PMULL_HPOWERS - ind]));
}

inline fn clmul3(
    opA: V16u8,
    opB: V16u8,
    opBx: V16u8,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    resl.* = vmullq_p64(opA, opB);
    resh.* = vmull_high_p64(opA, opB);
    const tmpA = opA ^ vextq_u8(opA, opA, 8);
    resm.* = vmullq_p64(tmpA, opBx);
}

inline fn clmulAcc3(
    r0: V16u8,
    r0x: V16u8,
    Hm: V16u8,
    Hmx: V16u8,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    const t0 = vmullq_p64(r0, Hm);
    const t1 = vmull_high_p64(r0, Hm);
    const t2 = vmullq_p64(r0x, Hmx);

    resl.* ^= t0;
    resh.* ^= t1;
    resm.* ^= t2;
}

inline fn clmul3Post(
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    resm.* ^= resl.* ^ resh.*;
}

inline fn modReduce(
    vMultiplicationConstant: V16u8,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
    state: *V16u8,
) void {
    var rl = resl.*;
    var rm = resm.*;
    const rh = resh.*;

    var t0 = vmullq_p64(rl, vMultiplicationConstant);
    rl = vextq_u8(rl, rl, 8);
    rm ^= t0 ^ rl;

    const rmShl1: V16u8 = @bitCast(@as(V2u64, @bitCast(rm)) << @splat(1));
    t0 = vmullq_p64(rmShl1, vMultiplicationConstant);

    rm = vextq_u8(rm, rm, 8);
    const r = rh ^ rm;

    const r32: V4u32 = @bitCast(r);
    const t1: V16u8 = @bitCast(r32 << @splat(1));
    const rShr31: V16u8 = @bitCast(r32 >> @splat(31));

    t0 ^= t1;
    const rExt = vextq_u8(rShr31, rShr31, 12);
    state.* = rExt ^ t0;
}

inline fn aesEncryptRound4Ghash1(
    roundKey: V16u8,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    gHashPointer: *[*]const u8,
    gHashExpandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    todo: *usize,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    c0.* = aese_aesmc(c0.*, roundKey);
    c1.* = aese_aesmc(c1.*, roundKey);
    c2.* = aese_aesmc(c2.*, roundKey);
    c3.* = aese_aesmc(c3.*, roundKey);

    var r0x = load128(gHashPointer.*);
    r0x = vrev64q_u8(r0x);
    const r0 = vextq_u8(r0x, r0x, 8);
    r0x ^= r0;
    gHashPointer.* += 16;

    var t1 = ghashHPower(gHashExpandedKeyTable, todo.*);
    const t0 = vmullq_p64(r0, t1);
    t1 = vmull_high_p64(r0, t1);

    resl.* ^= t0;
    resh.* ^= t1;

    t1 = ghashHxPower(gHashExpandedKeyTable, todo.*);
    t1 = vmullq_p64(r0x, t1);

    resm.* ^= t1;
    todo.* -= 1;
}

inline fn aesGcmEncrypt4(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    gHashPointer: *[*]const u8,
    gHashRounds: usize,
    gHashExpandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    todo: *usize,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    var roundKey = loadKey(&keyPtr[0]);
    keyPtr += 1;

    var i: usize = 0;
    while (i < gHashRounds) : (i += 1) {
        aesEncryptRound4Ghash1(
            roundKey,
            c0,
            c1,
            c2,
            c3,
            gHashPointer,
            gHashExpandedKeyTable,
            todo,
            resl,
            resm,
            resh,
        );
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
    }

    i = 0;
    while (i < (9 - gHashRounds)) : (i += 1) {
        c0.* = aese_aesmc(c0.*, roundKey);
        c1.* = aese_aesmc(c1.*, roundKey);
        c2.* = aese_aesmc(c2.*, roundKey);
        c3.* = aese_aesmc(c3.*, roundKey);
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            c0.* = aese_aesmc(c0.*, roundKey);
            c1.* = aese_aesmc(c1.*, roundKey);
            c2.* = aese_aesmc(c2.*, roundKey);
            c3.* = aese_aesmc(c3.*, roundKey);
            roundKey = loadKey(&keyPtr[0]);
            keyPtr += 1;
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                c0.* = aese_aesmc(c0.*, roundKey);
                c1.* = aese_aesmc(c1.*, roundKey);
                c2.* = aese_aesmc(c2.*, roundKey);
                c3.* = aese_aesmc(c3.*, roundKey);
                roundKey = loadKey(&keyPtr[0]);
                keyPtr += 1;
            }
        }
    }

    const rk2 = loadKey(&keyPtr[0]);
    c0.* = vaeseq_u8(c0.*, roundKey) ^ rk2;
    c1.* = vaeseq_u8(c1.*, roundKey) ^ rk2;
    c2.* = vaeseq_u8(c2.*, roundKey) ^ rk2;
    c3.* = vaeseq_u8(c3.*, roundKey) ^ rk2;
}

inline fn aesEncryptRound8Ghash1(
    roundKey: V16u8,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    c4: *V16u8,
    c5: *V16u8,
    c6: *V16u8,
    c7: *V16u8,
    gHashPointer: *[*]const u8,
    gHashExpandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    todo: *usize,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    c0.* = aese_aesmc(c0.*, roundKey);
    c1.* = aese_aesmc(c1.*, roundKey);
    c2.* = aese_aesmc(c2.*, roundKey);
    c3.* = aese_aesmc(c3.*, roundKey);
    c4.* = aese_aesmc(c4.*, roundKey);
    c5.* = aese_aesmc(c5.*, roundKey);
    c6.* = aese_aesmc(c6.*, roundKey);
    c7.* = aese_aesmc(c7.*, roundKey);

    var r0x = load128(gHashPointer.*);
    r0x = vrev64q_u8(r0x);
    const r0 = vextq_u8(r0x, r0x, 8);
    r0x ^= r0;
    gHashPointer.* += 16;

    var t1 = ghashHPower(gHashExpandedKeyTable, todo.*);
    const t0 = vmullq_p64(r0, t1);
    t1 = vmull_high_p64(r0, t1);

    resl.* ^= t0;
    resh.* ^= t1;

    t1 = ghashHxPower(gHashExpandedKeyTable, todo.*);
    t1 = vmullq_p64(r0x, t1);

    resm.* ^= t1;
    todo.* -= 1;
}

inline fn aesGcmEncrypt8(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
    c4: *V16u8,
    c5: *V16u8,
    c6: *V16u8,
    c7: *V16u8,
    gHashPointer: *[*]const u8,
    gHashRounds: usize,
    gHashExpandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    todo: *usize,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    var roundKey = loadKey(&keyPtr[0]);
    keyPtr += 1;

    var i: usize = 0;
    while (i < gHashRounds) : (i += 1) {
        aesEncryptRound8Ghash1(
            roundKey,
            c0,
            c1,
            c2,
            c3,
            c4,
            c5,
            c6,
            c7,
            gHashPointer,
            gHashExpandedKeyTable,
            todo,
            resl,
            resm,
            resh,
        );
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
    }

    i = 0;
    while (i < (9 - gHashRounds)) : (i += 1) {
        c0.* = aese_aesmc(c0.*, roundKey);
        c1.* = aese_aesmc(c1.*, roundKey);
        c2.* = aese_aesmc(c2.*, roundKey);
        c3.* = aese_aesmc(c3.*, roundKey);
        c4.* = aese_aesmc(c4.*, roundKey);
        c5.* = aese_aesmc(c5.*, roundKey);
        c6.* = aese_aesmc(c6.*, roundKey);
        c7.* = aese_aesmc(c7.*, roundKey);
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            c0.* = aese_aesmc(c0.*, roundKey);
            c1.* = aese_aesmc(c1.*, roundKey);
            c2.* = aese_aesmc(c2.*, roundKey);
            c3.* = aese_aesmc(c3.*, roundKey);
            c4.* = aese_aesmc(c4.*, roundKey);
            c5.* = aese_aesmc(c5.*, roundKey);
            c6.* = aese_aesmc(c6.*, roundKey);
            c7.* = aese_aesmc(c7.*, roundKey);
            roundKey = loadKey(&keyPtr[0]);
            keyPtr += 1;
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                c0.* = aese_aesmc(c0.*, roundKey);
                c1.* = aese_aesmc(c1.*, roundKey);
                c2.* = aese_aesmc(c2.*, roundKey);
                c3.* = aese_aesmc(c3.*, roundKey);
                c4.* = aese_aesmc(c4.*, roundKey);
                c5.* = aese_aesmc(c5.*, roundKey);
                c6.* = aese_aesmc(c6.*, roundKey);
                c7.* = aese_aesmc(c7.*, roundKey);
                roundKey = loadKey(&keyPtr[0]);
                keyPtr += 1;
            }
        }
    }

    const rk2 = loadKey(&keyPtr[0]);
    c0.* = vaeseq_u8(c0.*, roundKey) ^ rk2;
    c1.* = vaeseq_u8(c1.*, roundKey) ^ rk2;
    c2.* = vaeseq_u8(c2.*, roundKey) ^ rk2;
    c3.* = vaeseq_u8(c3.*, roundKey) ^ rk2;
    c4.* = vaeseq_u8(c4.*, roundKey) ^ rk2;
    c5.* = vaeseq_u8(c5.*, roundKey) ^ rk2;
    c6.* = vaeseq_u8(c6.*, roundKey) ^ rk2;
    c7.* = vaeseq_u8(c7.*, roundKey) ^ rk2;
}

pub fn SymCryptAesGcmEncryptStitchedNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var chain = load128(pbChainingValue);
    var src = pbSrc;
    var ghashSrc: [*]const u8 = pbDst;
    var dst = pbDst;

    const chainIncrement1 = setN128U64(0, 1);
    const chainIncrement2 = setN128U64(0, 2);
    const chainIncrement8 = setN128U64(0, 8);

    var ctr0: V16u8 = undefined;
    var ctr1: V16u8 = undefined;
    var ctr2: V16u8 = undefined;
    var ctr3: V16u8 = undefined;
    var ctr4: V16u8 = undefined;
    var ctr5: V16u8 = undefined;
    var ctr6: V16u8 = undefined;
    var ctr7: V16u8 = undefined;
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;
    var r0: V16u8 = undefined;
    var r0x: V16u8 = undefined;

    var state = load128(@ptrCast(pState));
    const vMultiplicationConstant = setN128U64(0xc200000000000000, 0);

    var a0: V16u8 = undefined;
    var a1: V16u8 = undefined;
    var a2: V16u8 = undefined;

    var nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;

    ctr0 = vrev64q_u8(chain);
    ctr1 = vaddq_u32(ctr0, chainIncrement1);
    ctr2 = vaddq_u32(ctr0, chainIncrement2);
    ctr3 = vaddq_u32(ctr1, chainIncrement2);
    ctr4 = vaddq_u32(ctr2, chainIncrement2);
    ctr5 = vaddq_u32(ctr3, chainIncrement2);
    ctr6 = vaddq_u32(ctr4, chainIncrement2);
    ctr7 = vaddq_u32(ctr5, chainIncrement2);

    var todo: usize = @min(nBlocks, SYMCRYPT_GHASH_PMULL_HPOWERS);
    clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);

    c0 = vrev64q_u8(ctr0);
    c1 = vrev64q_u8(ctr1);
    c2 = vrev64q_u8(ctr2);
    c3 = vrev64q_u8(ctr3);
    c4 = vrev64q_u8(ctr4);
    c5 = vrev64q_u8(ctr5);
    c6 = vrev64q_u8(ctr6);
    c7 = vrev64q_u8(ctr7);

    aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

    if (cbData >= 8 * SYMCRYPT_AES_BLOCK_SIZE) {
        ctr0 = vaddq_u32(ctr0, chainIncrement8);
        ctr1 = vaddq_u32(ctr1, chainIncrement8);
        ctr2 = vaddq_u32(ctr2, chainIncrement8);
        ctr3 = vaddq_u32(ctr3, chainIncrement8);
        ctr4 = vaddq_u32(ctr4, chainIncrement8);
        ctr5 = vaddq_u32(ctr5, chainIncrement8);
        ctr6 = vaddq_u32(ctr6, chainIncrement8);
        ctr7 = vaddq_u32(ctr7, chainIncrement8);

        store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
        store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
        store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
        store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
        store128(dst + 4 * 16, load128(src + 4 * 16) ^ c4);
        store128(dst + 5 * 16, load128(src + 5 * 16) ^ c5);
        store128(dst + 6 * 16, load128(src + 6 * 16) ^ c6);
        store128(dst + 7 * 16, load128(src + 7 * 16) ^ c7);

        dst += 8 * 16;
        src += 8 * 16;

        while (nBlocks >= 16) {
            c0 = vrev64q_u8(ctr0);
            c1 = vrev64q_u8(ctr1);
            c2 = vrev64q_u8(ctr2);
            c3 = vrev64q_u8(ctr3);
            c4 = vrev64q_u8(ctr4);
            c5 = vrev64q_u8(ctr5);
            c6 = vrev64q_u8(ctr6);
            c7 = vrev64q_u8(ctr7);

            ctr0 = vaddq_u32(ctr0, chainIncrement8);
            ctr1 = vaddq_u32(ctr1, chainIncrement8);
            ctr2 = vaddq_u32(ctr2, chainIncrement8);
            ctr3 = vaddq_u32(ctr3, chainIncrement8);
            ctr4 = vaddq_u32(ctr4, chainIncrement8);
            ctr5 = vaddq_u32(ctr5, chainIncrement8);
            ctr6 = vaddq_u32(ctr6, chainIncrement8);
            ctr7 = vaddq_u32(ctr7, chainIncrement8);

            aesGcmEncrypt8(
                pExpandedKey,
                &c0,
                &c1,
                &c2,
                &c3,
                &c4,
                &c5,
                &c6,
                &c7,
                &ghashSrc,
                8,
                expandedKeyTable,
                &todo,
                &a0,
                &a1,
                &a2,
            );

            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
            store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
            store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
            store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
            store128(dst + 4 * 16, load128(src + 4 * 16) ^ c4);
            store128(dst + 5 * 16, load128(src + 5 * 16) ^ c5);
            store128(dst + 6 * 16, load128(src + 6 * 16) ^ c6);
            store128(dst + 7 * 16, load128(src + 7 * 16) ^ c7);

            dst += 8 * 16;
            src += 8 * 16;
            nBlocks -= 8;

            if (todo == 0) {
                clmul3Post(&a0, &a1, &a2);
                modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);

                todo = @min(nBlocks, SYMCRYPT_GHASH_PMULL_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        }

        nBlocks -= 8;
        if (nBlocks > 0) {
            c0 = vrev64q_u8(ctr0);
            c1 = vrev64q_u8(ctr1);
            c2 = vrev64q_u8(ctr2);
            c3 = vrev64q_u8(ctr3);

            if (nBlocks > 4) {
                c4 = vrev64q_u8(ctr4);
                c5 = vrev64q_u8(ctr5);
                c6 = vrev64q_u8(ctr6);

                aesGcmEncrypt8(
                    pExpandedKey,
                    &c0,
                    &c1,
                    &c2,
                    &c3,
                    &c4,
                    &c5,
                    &c6,
                    &c7,
                    &ghashSrc,
                    8,
                    expandedKeyTable,
                    &todo,
                    &a0,
                    &a1,
                    &a2,
                );
            } else {
                aesGcmEncrypt4(
                    pExpandedKey,
                    &c0,
                    &c1,
                    &c2,
                    &c3,
                    &ghashSrc,
                    8,
                    expandedKeyTable,
                    &todo,
                    &a0,
                    &a1,
                    &a2,
                );
            }

            if (todo == 0) {
                clmul3Post(&a0, &a1, &a2);
                modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);

                todo = @min(nBlocks, SYMCRYPT_GHASH_PMULL_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        } else {
            todo = 8;
            while (todo > 0) : (todo -= 1) {
                r0x = vrev64q_u8(load128(ghashSrc));
                r0 = vextq_u8(r0x, r0x, 8);
                r0x ^= r0;
                ghashSrc += 16;

                clmulAcc3(r0, r0x, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }

            clmul3Post(&a0, &a1, &a2);
            modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);
        }
    }

    if (nBlocks > 0) {
        while (nBlocks >= 2) {
            ctr0 = vaddq_u32(ctr0, chainIncrement2);

            r0 = load128(src + 0 * 16) ^ c0;
            var r1 = load128(src + 1 * 16) ^ c1;

            store128(dst + 0 * 16, r0);
            store128(dst + 1 * 16, r1);

            r0x = vrev64q_u8(r0);
            var r1x = vrev64q_u8(r1);
            r0 = vextq_u8(r0x, r0x, 8);
            r1 = vextq_u8(r1x, r1x, 8);
            r0x ^= r0;
            r1x ^= r1;

            clmulAcc3(r0, r0x, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            clmulAcc3(r1, r1x, ghashHPower(expandedKeyTable, todo - 1), ghashHxPower(expandedKeyTable, todo - 1), &a0, &a1, &a2);

            dst += 2 * 16;
            src += 2 * 16;
            todo -= 2;
            nBlocks -= 2;
            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;
        }

        if (nBlocks > 0) {
            ctr0 = vaddq_u32(ctr0, chainIncrement1);

            r0 = load128(src + 0 * 16) ^ c0;
            store128(dst + 0 * 16, r0);
            r0x = vrev64q_u8(r0);
            r0 = vextq_u8(r0x, r0x, 8);
            r0x ^= r0;

            clmulAcc3(r0, r0x, ghashHPower(expandedKeyTable, 1), ghashHxPower(expandedKeyTable, 1), &a0, &a1, &a2);
        }

        clmul3Post(&a0, &a1, &a2);
        modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);
    }

    chain = vrev64q_u8(ctr0);
    store128(pbChainingValue, chain);
    store128(@ptrCast(pState), state);
}

pub fn SymCryptAesGcmDecryptStitchedNeon(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    var chain = load128(pbChainingValue);
    var src = pbSrc;
    var ghashSrc: [*]const u8 = pbSrc;
    var dst = pbDst;

    const chainIncrement1 = setN128U64(0, 1);
    const chainIncrement2 = setN128U64(0, 2);
    const chainIncrement8 = setN128U64(0, 8);

    var ctr0: V16u8 = undefined;
    var ctr1: V16u8 = undefined;
    var ctr2: V16u8 = undefined;
    var ctr3: V16u8 = undefined;
    var ctr4: V16u8 = undefined;
    var ctr5: V16u8 = undefined;
    var ctr6: V16u8 = undefined;
    var ctr7: V16u8 = undefined;
    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var state = load128(@ptrCast(pState));
    const vMultiplicationConstant = setN128U64(0xc200000000000000, 0);

    var a0: V16u8 = undefined;
    var a1: V16u8 = undefined;
    var a2: V16u8 = undefined;

    var nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;

    ctr0 = vrev64q_u8(chain);
    ctr1 = vaddq_u32(ctr0, chainIncrement1);
    ctr2 = vaddq_u32(ctr0, chainIncrement2);
    ctr3 = vaddq_u32(ctr1, chainIncrement2);
    ctr4 = vaddq_u32(ctr2, chainIncrement2);
    ctr5 = vaddq_u32(ctr3, chainIncrement2);
    ctr6 = vaddq_u32(ctr4, chainIncrement2);
    ctr7 = vaddq_u32(ctr5, chainIncrement2);

    var todo: usize = @min(nBlocks, SYMCRYPT_GHASH_PMULL_HPOWERS);
    clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);

    while (nBlocks >= 8) {
        c0 = vrev64q_u8(ctr0);
        c1 = vrev64q_u8(ctr1);
        c2 = vrev64q_u8(ctr2);
        c3 = vrev64q_u8(ctr3);
        c4 = vrev64q_u8(ctr4);
        c5 = vrev64q_u8(ctr5);
        c6 = vrev64q_u8(ctr6);
        c7 = vrev64q_u8(ctr7);

        ctr0 = vaddq_u32(ctr0, chainIncrement8);
        ctr1 = vaddq_u32(ctr1, chainIncrement8);
        ctr2 = vaddq_u32(ctr2, chainIncrement8);
        ctr3 = vaddq_u32(ctr3, chainIncrement8);
        ctr4 = vaddq_u32(ctr4, chainIncrement8);
        ctr5 = vaddq_u32(ctr5, chainIncrement8);
        ctr6 = vaddq_u32(ctr6, chainIncrement8);
        ctr7 = vaddq_u32(ctr7, chainIncrement8);

        aesGcmEncrypt8(
            pExpandedKey,
            &c0,
            &c1,
            &c2,
            &c3,
            &c4,
            &c5,
            &c6,
            &c7,
            &ghashSrc,
            8,
            expandedKeyTable,
            &todo,
            &a0,
            &a1,
            &a2,
        );

        store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
        store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);
        store128(dst + 2 * 16, load128(src + 2 * 16) ^ c2);
        store128(dst + 3 * 16, load128(src + 3 * 16) ^ c3);
        store128(dst + 4 * 16, load128(src + 4 * 16) ^ c4);
        store128(dst + 5 * 16, load128(src + 5 * 16) ^ c5);
        store128(dst + 6 * 16, load128(src + 6 * 16) ^ c6);
        store128(dst + 7 * 16, load128(src + 7 * 16) ^ c7);

        dst += 8 * 16;
        src += 8 * 16;
        nBlocks -= 8;

        if (todo == 0) {
            clmul3Post(&a0, &a1, &a2);
            modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);
            if (nBlocks > 0) {
                todo = @min(nBlocks, SYMCRYPT_GHASH_PMULL_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        }
    }

    if (nBlocks > 0) {
        c0 = vrev64q_u8(ctr0);
        c1 = vrev64q_u8(ctr1);
        c2 = vrev64q_u8(ctr2);
        c3 = vrev64q_u8(ctr3);

        if (nBlocks > 4) {
            c4 = vrev64q_u8(ctr4);
            c5 = vrev64q_u8(ctr5);
            c6 = vrev64q_u8(ctr6);

            aesGcmEncrypt8(
                pExpandedKey,
                &c0,
                &c1,
                &c2,
                &c3,
                &c4,
                &c5,
                &c6,
                &c7,
                &ghashSrc,
                nBlocks,
                expandedKeyTable,
                &todo,
                &a0,
                &a1,
                &a2,
            );
        } else {
            aesGcmEncrypt4(
                pExpandedKey,
                &c0,
                &c1,
                &c2,
                &c3,
                &ghashSrc,
                nBlocks,
                expandedKeyTable,
                &todo,
                &a0,
                &a1,
                &a2,
            );
        }
        clmul3Post(&a0, &a1, &a2);
        modReduce(vMultiplicationConstant, &a0, &a1, &a2, &state);

        while (nBlocks >= 2) {
            ctr0 = vaddq_u32(ctr0, chainIncrement2);

            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
            store128(dst + 1 * 16, load128(src + 1 * 16) ^ c1);

            dst += 2 * 16;
            src += 2 * 16;
            nBlocks -= 2;
            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;
        }

        if (nBlocks > 0) {
            ctr0 = vaddq_u32(ctr0, chainIncrement1);

            store128(dst + 0 * 16, load128(src + 0 * 16) ^ c0);
        }
    }

    chain = vrev64q_u8(ctr0);
    store128(pbChainingValue, chain);
    store128(@ptrCast(pState), state);
}

comptime {
    if (types.CPU_ARM64) {
        @export(&SymCryptAes4SboxNeon, .{ .name = "SymCryptAes4SboxNeon" });
        @export(&SymCryptAesCreateDecryptionRoundKeyNeon, .{ .name = "SymCryptAesCreateDecryptionRoundKeyNeon" });
        @export(&SymCryptAesEncryptNeon, .{ .name = "SymCryptAesEncryptNeon" });
        @export(&SymCryptAesDecryptNeon, .{ .name = "SymCryptAesDecryptNeon" });
        @export(&SymCryptAesCbcEncryptNeon, .{ .name = "SymCryptAesCbcEncryptNeon" });
        @export(&SymCryptAesCbcDecryptNeon, .{ .name = "SymCryptAesCbcDecryptNeon" });
        @export(&SymCryptAesCbcMacNeon, .{ .name = "SymCryptAesCbcMacNeon" });
        @export(&SymCryptAesEcbEncryptNeon, .{ .name = "SymCryptAesEcbEncryptNeon" });
        @export(&SymCryptAesEcbDecryptNeon, .{ .name = "SymCryptAesEcbDecryptNeon" });
        @export(&SymCryptAesCtrMsb32Neon, .{ .name = "SymCryptAesCtrMsb32Neon" });
        @export(&SymCryptAesCtrMsb64Neon, .{ .name = "SymCryptAesCtrMsb64Neon" });
        @export(&SymCryptXtsAesEncryptDataUnitNeon, .{ .name = "SymCryptXtsAesEncryptDataUnitNeon" });
        @export(&SymCryptXtsAesDecryptDataUnitNeon, .{ .name = "SymCryptXtsAesDecryptDataUnitNeon" });
        @export(&SymCryptAesGcmEncryptStitchedNeon, .{ .name = "SymCryptAesGcmEncryptStitchedNeon" });
        @export(&SymCryptAesGcmDecryptStitchedNeon, .{ .name = "SymCryptAesGcmDecryptStitchedNeon" });
    }
}
