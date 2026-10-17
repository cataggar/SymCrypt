//
// aes_xmm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// AES XMM (SSE / AES-NI / PCLMULQDQ) implementations (ported from lib/aes-xmm.c and lib/aes-pattern.c).
//

const std = @import("std");
const types = @import("types.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_AES_BLOCK_SIZE = types.SYMCRYPT_AES_BLOCK_SIZE;
const SYMCRYPT_GF128_BLOCK_SIZE = types.SYMCRYPT_GF128_BLOCK_SIZE;
const SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS: usize = 32;

const SYMCRYPT_AES_EXPANDED_KEY = types.SYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_GF128_ELEMENT = types.SYMCRYPT_GF128_ELEMENT;

pub const V16u8 = @Vector(16, u8);
pub const V4u32 = @Vector(4, u32);
pub const V4i32 = @Vector(4, i32);
pub const V2u64 = @Vector(2, u64);

pub inline fn load128(ptr: [*]const u8) V16u8 {
    return @as(*align(1) const V16u8, @ptrCast(ptr)).*;
}

pub inline fn store128(ptr: [*]u8, v: V16u8) void {
    @as(*align(1) V16u8, @ptrCast(ptr)).* = v;
}

pub inline fn loadKey(ptr: *const [4][4]u8) V16u8 {
    return @as(*align(1) const V16u8, @ptrCast(ptr)).*;
}

pub inline fn bswap128(v: V16u8) V16u8 {
    return @shuffle(u8, v, undefined, [16]i32{
        15, 14, 13, 12, 11, 10, 9, 8,
        7,  6,  5,  4,  3,  2,  1, 0,
    });
}

pub inline fn addEpi32(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) +% @as(V4u32, @bitCast(b)));
}

pub inline fn subEpi32(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V4u32, @bitCast(a)) -% @as(V4u32, @bitCast(b)));
}

pub inline fn addEpi64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V2u64, @bitCast(a)) +% @as(V2u64, @bitCast(b)));
}

pub inline fn subEpi64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@as(V2u64, @bitCast(a)) -% @as(V2u64, @bitCast(b)));
}

pub inline fn setEpi32(e3: u32, e2: u32, e1: u32, e0: u32) V16u8 {
    return @bitCast(V4u32{ e0, e1, e2, e3 });
}

pub inline fn srliSi128_8(a: V16u8) V16u8 {
    const zero: V2u64 = @splat(0);
    return @bitCast(@shuffle(u64, @as(V2u64, @bitCast(a)), zero, [2]i32{ 1, -1 }));
}

pub inline fn unpackloEpi64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@shuffle(u64, @as(V2u64, @bitCast(a)), @as(V2u64, @bitCast(b)), [2]i32{ 0, -1 }));
}

pub inline fn unpackhiEpi64(a: V16u8, b: V16u8) V16u8 {
    return @bitCast(@shuffle(u64, @as(V2u64, @bitCast(a)), @as(V2u64, @bitCast(b)), [2]i32{ 1, -2 }));
}

pub inline fn aesenc(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm ("aesenc %[rk], %[res]"
        : [res] "+x" (res),
        : [rk] "x" (rk),
    );
    return res;
}

pub inline fn aesenclast(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm ("aesenclast %[rk], %[res]"
        : [res] "+x" (res),
        : [rk] "x" (rk),
    );
    return res;
}

pub inline fn aesdec(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm ("aesdec %[rk], %[res]"
        : [res] "+x" (res),
        : [rk] "x" (rk),
    );
    return res;
}

pub inline fn aesdeclast(c: V16u8, rk: V16u8) V16u8 {
    var res = c;
    asm ("aesdeclast %[rk], %[res]"
        : [res] "+x" (res),
        : [rk] "x" (rk),
    );
    return res;
}

pub inline fn aesimc(a: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm ("aesimc %[a], %[res]"
        : [res] "=x" (res),
        : [a] "x" (a),
    );
    return res;
}

pub inline fn aeskeygenassist0(a: V16u8) V16u8 {
    var res: V16u8 = undefined;
    asm ("aeskeygenassist $0x0, %[a], %[res]"
        : [res] "=x" (res),
        : [a] "x" (a),
    );
    return res;
}

pub inline fn clmul128(a: V16u8, b: V16u8, comptime imm: u8) V16u8 {
    var res = a;
    asm ("pclmulqdq %[imm], %[b], %[res]"
        : [res] "+x" (res),
        : [b] "x" (b),
          [imm] "i" (imm),
    );
    return res;
}

pub fn SymCryptAes4SboxXmm(
    pIn: [*]const u8,
    pOut: [*]u8,
) callconv(SYMCRYPT_CALL) void {
    const inVal = std.mem.readInt(u32, pIn[0..4], .little);
    var x: V16u8 = @bitCast(@as(V4u32, @splat(inVal)));
    x = aeskeygenassist0(x);
    const outVal = @as(V4u32, @bitCast(x))[0];
    std.mem.writeInt(u32, pOut[0..4], outVal, .little);
}

pub fn SymCryptAesCreateDecryptionRoundKeyXmm(
    pEncryptionRoundKey: [*]const u8,
    pDecryptionRoundKey: [*]u8,
) callconv(SYMCRYPT_CALL) void {
    store128(pDecryptionRoundKey, aesimc(load128(pEncryptionRoundKey)));
}

pub inline fn aesEncrypt1(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    c0.* ^= loadKey(&keyPtr[0]);
    keyPtr += 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, rk);
            }
        }
    }

    c0.* = aesenclast(c0.*, loadKey(&keyPtr[0]));
}

inline fn aesEncrypt1Chain(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    d: V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[1]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, rk);
            }
        }
    }

    c0.* = aesenclast(c0.*, d);
}

pub inline fn aesEncrypt4(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    var rk = loadKey(&keyPtr[0]);
    keyPtr += 1;
    c0.* ^= rk;
    c1.* ^= rk;
    c2.* ^= rk;
    c3.* ^= rk;

    inline for (0..9) |_| {
        rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, rk);
        c1.* = aesenc(c1.*, rk);
        c2.* = aesenc(c2.*, rk);
        c3.* = aesenc(c3.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, rk);
            c1.* = aesenc(c1.*, rk);
            c2.* = aesenc(c2.*, rk);
            c3.* = aesenc(c3.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, rk);
                c1.* = aesenc(c1.*, rk);
                c2.* = aesenc(c2.*, rk);
                c3.* = aesenc(c3.*, rk);
            }
        }
    }

    rk = loadKey(&keyPtr[0]);
    c0.* = aesenclast(c0.*, rk);
    c1.* = aesenclast(c1.*, rk);
    c2.* = aesenclast(c2.*, rk);
    c3.* = aesenclast(c3.*, rk);
}

pub inline fn aesEncrypt8(
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
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    var rk = loadKey(&keyPtr[0]);
    keyPtr += 1;
    c0.* ^= rk;
    c1.* ^= rk;
    c2.* ^= rk;
    c3.* ^= rk;
    c4.* ^= rk;
    c5.* ^= rk;
    c6.* ^= rk;
    c7.* ^= rk;

    inline for (0..9) |_| {
        rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, rk);
        c1.* = aesenc(c1.*, rk);
        c2.* = aesenc(c2.*, rk);
        c3.* = aesenc(c3.*, rk);
        c4.* = aesenc(c4.*, rk);
        c5.* = aesenc(c5.*, rk);
        c6.* = aesenc(c6.*, rk);
        c7.* = aesenc(c7.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, rk);
            c1.* = aesenc(c1.*, rk);
            c2.* = aesenc(c2.*, rk);
            c3.* = aesenc(c3.*, rk);
            c4.* = aesenc(c4.*, rk);
            c5.* = aesenc(c5.*, rk);
            c6.* = aesenc(c6.*, rk);
            c7.* = aesenc(c7.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, rk);
                c1.* = aesenc(c1.*, rk);
                c2.* = aesenc(c2.*, rk);
                c3.* = aesenc(c3.*, rk);
                c4.* = aesenc(c4.*, rk);
                c5.* = aesenc(c5.*, rk);
                c6.* = aesenc(c6.*, rk);
                c7.* = aesenc(c7.*, rk);
            }
        }
    }

    rk = loadKey(&keyPtr[0]);
    c0.* = aesenclast(c0.*, rk);
    c1.* = aesenclast(c1.*, rk);
    c2.* = aesenclast(c2.*, rk);
    c3.* = aesenclast(c3.*, rk);
    c4.* = aesenclast(c4.*, rk);
    c5.* = aesenclast(c5.*, rk);
    c6.* = aesenclast(c6.*, rk);
    c7.* = aesenclast(c7.*, rk);
}

pub inline fn aesDecrypt1(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;

    c0.* ^= loadKey(&keyPtr[0]);
    keyPtr += 1;

    inline for (0..9) |_| {
        const rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesdec(c0.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            const rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesdec(c0.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                const rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesdec(c0.*, rk);
            }
        }
    }

    c0.* = aesdeclast(c0.*, loadKey(&keyPtr[0]));
}

pub inline fn aesDecrypt4(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    c0: *V16u8,
    c1: *V16u8,
    c2: *V16u8,
    c3: *V16u8,
) void {
    var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;

    var rk = loadKey(&keyPtr[0]);
    keyPtr += 1;
    c0.* ^= rk;
    c1.* ^= rk;
    c2.* ^= rk;
    c3.* ^= rk;

    inline for (0..9) |_| {
        rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesdec(c0.*, rk);
        c1.* = aesdec(c1.*, rk);
        c2.* = aesdec(c2.*, rk);
        c3.* = aesdec(c3.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesdec(c0.*, rk);
            c1.* = aesdec(c1.*, rk);
            c2.* = aesdec(c2.*, rk);
            c3.* = aesdec(c3.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesdec(c0.*, rk);
                c1.* = aesdec(c1.*, rk);
                c2.* = aesdec(c2.*, rk);
                c3.* = aesdec(c3.*, rk);
            }
        }
    }

    rk = loadKey(&keyPtr[0]);
    c0.* = aesdeclast(c0.*, rk);
    c1.* = aesdeclast(c1.*, rk);
    c2.* = aesdeclast(c2.*, rk);
    c3.* = aesdeclast(c3.*, rk);
}

pub inline fn aesDecrypt8(
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
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;

    var rk = loadKey(&keyPtr[0]);
    keyPtr += 1;
    c0.* ^= rk;
    c1.* ^= rk;
    c2.* ^= rk;
    c3.* ^= rk;
    c4.* ^= rk;
    c5.* ^= rk;
    c6.* ^= rk;
    c7.* ^= rk;

    inline for (0..9) |_| {
        rk = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesdec(c0.*, rk);
        c1.* = aesdec(c1.*, rk);
        c2.* = aesdec(c2.*, rk);
        c3.* = aesdec(c3.*, rk);
        c4.* = aesdec(c4.*, rk);
        c5.* = aesdec(c5.*, rk);
        c6.* = aesdec(c6.*, rk);
        c7.* = aesdec(c7.*, rk);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            rk = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesdec(c0.*, rk);
            c1.* = aesdec(c1.*, rk);
            c2.* = aesdec(c2.*, rk);
            c3.* = aesdec(c3.*, rk);
            c4.* = aesdec(c4.*, rk);
            c5.* = aesdec(c5.*, rk);
            c6.* = aesdec(c6.*, rk);
            c7.* = aesdec(c7.*, rk);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                rk = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesdec(c0.*, rk);
                c1.* = aesdec(c1.*, rk);
                c2.* = aesdec(c2.*, rk);
                c3.* = aesdec(c3.*, rk);
                c4.* = aesdec(c4.*, rk);
                c5.* = aesdec(c5.*, rk);
                c6.* = aesdec(c6.*, rk);
                c7.* = aesdec(c7.*, rk);
            }
        }
    }

    rk = loadKey(&keyPtr[0]);
    c0.* = aesdeclast(c0.*, rk);
    c1.* = aesdeclast(c1.*, rk);
    c2.* = aesdeclast(c2.*, rk);
    c3.* = aesdeclast(c3.*, rk);
    c4.* = aesdeclast(c4.*, rk);
    c5.* = aesdeclast(c5.*, rk);
    c6.* = aesdeclast(c6.*, rk);
    c7.* = aesdeclast(c7.*, rk);
}

pub fn SymCryptAesEncryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
) callconv(SYMCRYPT_CALL) void {
    var c = load128(pbSrc);
    aesEncrypt1(pExpandedKey, &c);
    store128(pbDst, c);
}

pub fn SymCryptAesDecryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
) callconv(SYMCRYPT_CALL) void {
    var c = load128(pbSrc);
    aesDecrypt1(pExpandedKey, &c);
    store128(pbDst, c);
}

pub fn SymCryptAesCbcEncryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    if (cbData < SYMCRYPT_AES_BLOCK_SIZE) return;

    var c = load128(pbChainingValue);
    const rk0 = loadKey(&pExpandedKey.RoundKey[0]);
    const rkLast = loadKey(&pExpandedKey.lastEncRoundKey[0]);

    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;

    var d = load128(src) ^ rk0;
    c ^= d;
    src += SYMCRYPT_AES_BLOCK_SIZE;
    rem -= SYMCRYPT_AES_BLOCK_SIZE;

    while (rem >= SYMCRYPT_AES_BLOCK_SIZE) {
        d = load128(src) ^ rk0;
        aesEncrypt1Chain(pExpandedKey, &c, d ^ rkLast);
        store128(dst, c ^ d);

        dst += SYMCRYPT_AES_BLOCK_SIZE;
        src += SYMCRYPT_AES_BLOCK_SIZE;
        rem -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    aesEncrypt1Chain(pExpandedKey, &c, rkLast);
    store128(dst, c);
    store128(pbChainingValue, c);
}

pub fn SymCryptAesCbcDecryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    if (cbData < SYMCRYPT_AES_BLOCK_SIZE) return;

    var chain = load128(pbChainingValue);
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

    var src = pbSrc;
    var dst = pbDst;
    var rem = cbData;

    while (rem >= 8 * SYMCRYPT_AES_BLOCK_SIZE) {
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
        rem -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (rem >= 16) {
        c0 = load128(src + 0 * 16);
        d0 = c0;
        if (rem >= 32) {
            c1 = load128(src + 1 * 16);
            d1 = c1;
            if (rem >= 48) {
                c2 = load128(src + 2 * 16);
                d2 = c2;
                if (rem >= 64) {
                    c3 = load128(src + 3 * 16);
                    d3 = c3;
                    if (rem >= 80) {
                        c4 = load128(src + 4 * 16);
                        d4 = c4;
                        if (rem >= 96) {
                            c5 = load128(src + 5 * 16);
                            d5 = c5;
                            if (rem >= 112) {
                                c6 = load128(src + 6 * 16);
                                d6 = c6;
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

        c0 ^= chain;
        chain = d0;
        store128(dst + 0 * 16, c0);
        if (rem >= 32) {
            c1 ^= chain;
            chain = d1;
            store128(dst + 1 * 16, c1);
            if (rem >= 48) {
                c2 ^= chain;
                chain = d2;
                store128(dst + 2 * 16, c2);
                if (rem >= 64) {
                    c3 ^= chain;
                    chain = d3;
                    store128(dst + 3 * 16, c3);
                    if (rem >= 80) {
                        c4 ^= chain;
                        chain = d4;
                        store128(dst + 4 * 16, c4);
                        if (rem >= 96) {
                            c5 ^= chain;
                            chain = d5;
                            store128(dst + 5 * 16, c5);
                            if (rem >= 112) {
                                c6 ^= chain;
                                chain = d6;
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

pub fn SymCryptAesCbcMacXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbData: [*]const u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    if (cbData < SYMCRYPT_AES_BLOCK_SIZE) return;

    var c = load128(pbChainingValue);
    const rk0 = loadKey(&pExpandedKey.RoundKey[0]);
    const rkLast = loadKey(&pExpandedKey.lastEncRoundKey[0]);

    var data = pbData;
    var rem = cbData;

    var d = load128(data) ^ rk0;
    c ^= d;
    data += SYMCRYPT_AES_BLOCK_SIZE;
    rem -= SYMCRYPT_AES_BLOCK_SIZE;

    const rk0AndLast = rk0 ^ rkLast;

    while (rem >= SYMCRYPT_AES_BLOCK_SIZE) {
        d = load128(data) ^ rk0AndLast;
        aesEncrypt1Chain(pExpandedKey, &c, d);
        data += SYMCRYPT_AES_BLOCK_SIZE;
        rem -= SYMCRYPT_AES_BLOCK_SIZE;
    }
    aesEncrypt1Chain(pExpandedKey, &c, rkLast);
    store128(pbChainingValue, c);
}

pub fn SymCryptAesEcbEncryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
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

pub fn SymCryptAesEcbDecryptXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
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

fn aesCtrMsbXxXmm(
    comptime is64: bool,
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbDataIn: usize,
) void {
    const mmAdd = if (is64) addEpi64 else addEpi32;
    const mmSub = if (is64) subEpi64 else subEpi32;

    var chain = bswap128(load128(pbChainingValue));
    var src = pbSrc;
    var dst = pbDst;
    var cbData = cbDataIn & ~@as(usize, SYMCRYPT_AES_BLOCK_SIZE - 1);

    const chainIncrement1 = setEpi32(0, 0, 0, 1);
    const chainIncrement2 = setEpi32(0, 0, 0, 2);
    const chainIncrement3 = setEpi32(0, 0, 0, 3);

    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    while (cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = chain;
        c1 = mmAdd(chain, chainIncrement1);
        c2 = mmAdd(chain, chainIncrement2);
        c3 = mmAdd(c1, chainIncrement2);
        c4 = mmAdd(c2, chainIncrement2);
        c5 = mmAdd(c3, chainIncrement2);
        c6 = mmAdd(c4, chainIncrement2);
        c7 = mmAdd(c5, chainIncrement2);
        chain = mmAdd(c6, chainIncrement2);

        c0 = bswap128(c0);
        c1 = bswap128(c1);
        c2 = bswap128(c2);
        c3 = bswap128(c3);
        c4 = bswap128(c4);
        c5 = bswap128(c5);
        c6 = bswap128(c6);
        c7 = bswap128(c7);

        aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

        if (cbData < 8 * SYMCRYPT_AES_BLOCK_SIZE) {
            break;
        }

        store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
        store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
        store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
        store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
        store128(dst + 4 * 16, c4 ^ load128(src + 4 * 16));
        store128(dst + 5 * 16, c5 ^ load128(src + 5 * 16));
        store128(dst + 6 * 16, c6 ^ load128(src + 6 * 16));
        store128(dst + 7 * 16, c7 ^ load128(src + 7 * 16));

        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        src += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbData >= SYMCRYPT_AES_BLOCK_SIZE) {
        if (cbData >= 5 * SYMCRYPT_AES_BLOCK_SIZE) {
            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
            store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
            store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
            store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
            store128(dst + 4 * 16, c4 ^ load128(src + 4 * 16));
            chain = mmSub(chain, chainIncrement3);

            if (cbData >= 96) {
                chain = mmAdd(chain, chainIncrement1);
                store128(dst + 5 * 16, c5 ^ load128(src + 5 * 16));
                if (cbData >= 112) {
                    chain = mmAdd(chain, chainIncrement1);
                    store128(dst + 6 * 16, c6 ^ load128(src + 6 * 16));
                }
            }
        } else if (cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
            c0 = chain;
            c1 = mmAdd(chain, chainIncrement1);
            c2 = mmAdd(chain, chainIncrement2);
            c3 = mmAdd(c1, chainIncrement2);
            chain = c2;

            c0 = bswap128(c0);
            c1 = bswap128(c1);
            c2 = bswap128(c2);
            c3 = bswap128(c3);

            aesEncrypt4(pExpandedKey, &c0, &c1, &c2, &c3);

            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
            store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
            if (cbData >= 48) {
                chain = mmAdd(chain, chainIncrement1);
                store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
                if (cbData >= 64) {
                    chain = mmAdd(chain, chainIncrement1);
                    store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
                }
            }
        } else {
            c0 = chain;
            chain = mmAdd(chain, chainIncrement1);
            c0 = bswap128(c0);
            aesEncrypt1(pExpandedKey, &c0);
            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
        }
    }

    chain = bswap128(chain);
    store128(pbChainingValue, chain);
}

pub fn SymCryptAesCtrMsb32Xmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    aesCtrMsbXxXmm(false, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

pub fn SymCryptAesCtrMsb64Xmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    aesCtrMsbXxXmm(true, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

pub inline fn xtsMulAlpha(in: V16u8) V16u8 {
    const xts_alpha_mask: V4u32 = .{ 0x87, 1, 1, 1 };
    const t1 = @as(V4u32, @bitCast(in)) << @splat(1);
    const sra: V4u32 = @bitCast(@as(V4i32, @bitCast(in)) >> @splat(31));
    const t2 = @shuffle(u32, sra, undefined, [4]i32{ 3, 0, 1, 2 }) & xts_alpha_mask;
    return @bitCast(t1 ^ t2);
}

pub inline fn xtsMulAlpha2(in: V16u8) V16u8 {
    const zero: V4u32 = @splat(0);
    const in32: V4u32 = @bitCast(in);
    var t1 = in32 << @splat(2);
    var t2 = in32 >> @splat(30);
    t1 ^= @shuffle(u32, t2, zero, [4]i32{ -1, 0, 1, 2 });
    t2 = @shuffle(u32, t2, zero, [4]i32{ 3, -1, -1, -1 });
    t2 = (t2 << @splat(7)) ^ (t2 << @splat(2)) ^ (t2 << @splat(1)) ^ t2;
    return @bitCast(t1 ^ t2);
}

pub inline fn xtsMulAlpha4(in: V16u8) V16u8 {
    const zero: V4u32 = @splat(0);
    const in32: V4u32 = @bitCast(in);
    var t1 = in32 << @splat(4);
    var t2 = in32 >> @splat(28);
    t1 ^= @shuffle(u32, t2, zero, [4]i32{ -1, 0, 1, 2 });
    t2 = @shuffle(u32, t2, zero, [4]i32{ 3, -1, -1, -1 });
    t2 = (t2 << @splat(7)) ^ (t2 << @splat(2)) ^ (t2 << @splat(1)) ^ t2;
    return @bitCast(t1 ^ t2);
}

pub inline fn xtsMulAlpha8(in: V16u8) V16u8 {
    const zero: V4u32 = @splat(0);
    const in32: V4u32 = @bitCast(in);
    var t1 = in32 << @splat(8);
    var t2 = in32 >> @splat(24);
    t1 ^= @shuffle(u32, t2, zero, [4]i32{ -1, 0, 1, 2 });
    t2 = @shuffle(u32, t2, zero, [4]i32{ 3, -1, -1, -1 });
    t2 = (t2 << @splat(7)) ^ (t2 << @splat(2)) ^ (t2 << @splat(1)) ^ t2;
    return @bitCast(t1 ^ t2);
}

inline fn xtsMulAlphaScalar(low: *u64, high: *u64) void {
    const t1: u64 = @as(u64, @bitCast(@as(i64, @bitCast(high.*)) >> 63)) & 0x87;
    high.* = (high.* << 1) | (low.* >> 63);
    low.* = (low.* << 1) ^ t1;
}

pub fn SymCryptXtsAesEncryptDataUnitXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbScratch: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    const tweakBuffer: [*]SYMCRYPT_GF128_ELEMENT = @ptrCast(@alignCast(pbScratch));
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey;

    var cbDataTail = cbData & ((8 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    var c0 = load128(pbTweakBlock);
    var c1 = xtsMulAlpha(c0);
    var c2 = xtsMulAlpha(c1);
    var c3 = xtsMulAlpha(c2);
    var c4 = xtsMulAlpha4(c0);
    var c5 = xtsMulAlpha(c4);
    var c6 = xtsMulAlpha(c5);
    var c7 = xtsMulAlpha(c6);

    store128(@ptrCast(&tweakBuffer[0]), c0);
    store128(@ptrCast(&tweakBuffer[1]), c1);
    store128(@ptrCast(&tweakBuffer[2]), c2);
    store128(@ptrCast(&tweakBuffer[3]), c3);
    store128(@ptrCast(&tweakBuffer[4]), c4);
    store128(@ptrCast(&tweakBuffer[5]), c5);
    store128(@ptrCast(&tweakBuffer[6]), c6);
    store128(@ptrCast(&tweakBuffer[7]), c7);

    var lastTweakLow = tweakBuffer[7].ull[0];
    var lastTweakHigh = tweakBuffer[7].ull[1];

    const firstRoundKey = loadKey(&pExpandedKey.RoundKey[0]);
    const lastRoundKey = loadKey(&pExpandedKey.lastEncRoundKey[0]);

    var src = pbSrc;
    var dst = pbDst;

    while (cbDataMain > 0) {
        c0 = load128(@ptrCast(&tweakBuffer[0])) ^ firstRoundKey ^ load128(src + 0 * 16);
        c1 = load128(@ptrCast(&tweakBuffer[1])) ^ firstRoundKey ^ load128(src + 1 * 16);
        c2 = load128(@ptrCast(&tweakBuffer[2])) ^ firstRoundKey ^ load128(src + 2 * 16);
        c3 = load128(@ptrCast(&tweakBuffer[3])) ^ firstRoundKey ^ load128(src + 3 * 16);
        c4 = load128(@ptrCast(&tweakBuffer[4])) ^ firstRoundKey ^ load128(src + 4 * 16);
        c5 = load128(@ptrCast(&tweakBuffer[5])) ^ firstRoundKey ^ load128(src + 5 * 16);
        c6 = load128(@ptrCast(&tweakBuffer[6])) ^ firstRoundKey ^ load128(src + 6 * 16);
        c7 = load128(@ptrCast(&tweakBuffer[7])) ^ firstRoundKey ^ load128(src + 7 * 16);

        var keyPtr: [*]const [4][4]u8 = @ptrCast(&pExpandedKey.RoundKey[1]);

        for (0..8) |loopIdx| {
            const roundkey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0 = aesenc(c0, roundkey);
            c1 = aesenc(c1, roundkey);
            c2 = aesenc(c2, roundkey);
            c3 = aesenc(c3, roundkey);
            c4 = aesenc(c4, roundkey);
            c5 = aesenc(c5, roundkey);
            c6 = aesenc(c6, roundkey);
            c7 = aesenc(c7, roundkey);

            store128(@ptrCast(&tweakBuffer[8 + loopIdx]), load128(@ptrCast(&tweakBuffer[loopIdx])) ^ lastRoundKey);
            xtsMulAlphaScalar(&lastTweakLow, &lastTweakHigh);
            tweakBuffer[loopIdx].ull[0] = lastTweakLow;
            tweakBuffer[loopIdx].ull[1] = lastTweakHigh;
        }

        while (true) {
            const roundkey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0 = aesenc(c0, roundkey);
            c1 = aesenc(c1, roundkey);
            c2 = aesenc(c2, roundkey);
            c3 = aesenc(c3, roundkey);
            c4 = aesenc(c4, roundkey);
            c5 = aesenc(c5, roundkey);
            c6 = aesenc(c6, roundkey);
            c7 = aesenc(c7, roundkey);
            if (@intFromPtr(keyPtr) >= @intFromPtr(keyLimit)) break;
        }

        store128(dst + 0 * 16, aesenclast(c0, load128(@ptrCast(&tweakBuffer[8]))));
        store128(dst + 1 * 16, aesenclast(c1, load128(@ptrCast(&tweakBuffer[9]))));
        store128(dst + 2 * 16, aesenclast(c2, load128(@ptrCast(&tweakBuffer[10]))));
        store128(dst + 3 * 16, aesenclast(c3, load128(@ptrCast(&tweakBuffer[11]))));
        store128(dst + 4 * 16, aesenclast(c4, load128(@ptrCast(&tweakBuffer[12]))));
        store128(dst + 5 * 16, aesenclast(c5, load128(@ptrCast(&tweakBuffer[13]))));
        store128(dst + 6 * 16, aesenclast(c6, load128(@ptrCast(&tweakBuffer[14]))));
        store128(dst + 7 * 16, aesenclast(c7, load128(@ptrCast(&tweakBuffer[15]))));

        src += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbDataMain -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbDataTail == 0) {
        return;
    }

    var t0 = load128(@ptrCast(&tweakBuffer[0]));

    while (cbDataTail >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        src += SYMCRYPT_AES_BLOCK_SIZE;
        aesEncrypt1(pExpandedKey, &c0);
        store128(dst, c0 ^ t0);
        dst += SYMCRYPT_AES_BLOCK_SIZE;
        t0 = xtsMulAlpha(t0);
        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbDataTail > SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        aesEncrypt1(pExpandedKey, &c0);
        store128(@ptrCast(&tweakBuffer[0]), c0 ^ t0);

        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;

        store128(@ptrCast(&tweakBuffer[1]), load128(@ptrCast(&tweakBuffer[0])));
        const tb0Bytes: [*]u8 = @ptrCast(&tweakBuffer[0]);
        const tb1Bytes: [*]const u8 = @ptrCast(&tweakBuffer[1]);
        @memcpy(tb0Bytes[0..cbDataTail], (src + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail]);
        @memcpy((dst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail], tb1Bytes[0..cbDataTail]);

        t0 = xtsMulAlpha(t0);
        c0 = load128(@ptrCast(&tweakBuffer[0]));
    } else {
        c0 = load128(src);
    }

    c0 ^= t0;
    aesEncrypt1(pExpandedKey, &c0);
    store128(dst, c0 ^ t0);
}

pub fn SymCryptXtsAesDecryptDataUnitXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: [*]u8,
    pbScratch: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    const tweakBuffer: [*]SYMCRYPT_GF128_ELEMENT = @ptrCast(@alignCast(pbScratch));
    const keyLimit: [*]const [4][4]u8 = pExpandedKey.lastDecRoundKey;

    var cbDataTail = cbData & ((8 * SYMCRYPT_AES_BLOCK_SIZE) - 1);
    if (cbDataTail > 0 and cbDataTail < SYMCRYPT_AES_BLOCK_SIZE) {
        cbDataTail += 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }
    var cbDataMain = cbData - cbDataTail;

    var c0 = load128(pbTweakBlock);
    var c1 = xtsMulAlpha(c0);
    var c2 = xtsMulAlpha(c1);
    var c3 = xtsMulAlpha(c2);
    var c4 = xtsMulAlpha4(c0);
    var c5 = xtsMulAlpha(c4);
    var c6 = xtsMulAlpha(c5);
    var c7 = xtsMulAlpha(c6);

    store128(@ptrCast(&tweakBuffer[0]), c0);
    store128(@ptrCast(&tweakBuffer[1]), c1);
    store128(@ptrCast(&tweakBuffer[2]), c2);
    store128(@ptrCast(&tweakBuffer[3]), c3);
    store128(@ptrCast(&tweakBuffer[4]), c4);
    store128(@ptrCast(&tweakBuffer[5]), c5);
    store128(@ptrCast(&tweakBuffer[6]), c6);
    store128(@ptrCast(&tweakBuffer[7]), c7);

    var lastTweakLow = tweakBuffer[7].ull[0];
    var lastTweakHigh = tweakBuffer[7].ull[1];

    const firstRoundKey = loadKey(&pExpandedKey.lastEncRoundKey[0]);
    const lastRoundKey = loadKey(&pExpandedKey.lastDecRoundKey[0]);

    var src = pbSrc;
    var dst = pbDst;

    while (cbDataMain > 0) {
        c0 = load128(@ptrCast(&tweakBuffer[0])) ^ firstRoundKey ^ load128(src + 0 * 16);
        c1 = load128(@ptrCast(&tweakBuffer[1])) ^ firstRoundKey ^ load128(src + 1 * 16);
        c2 = load128(@ptrCast(&tweakBuffer[2])) ^ firstRoundKey ^ load128(src + 2 * 16);
        c3 = load128(@ptrCast(&tweakBuffer[3])) ^ firstRoundKey ^ load128(src + 3 * 16);
        c4 = load128(@ptrCast(&tweakBuffer[4])) ^ firstRoundKey ^ load128(src + 4 * 16);
        c5 = load128(@ptrCast(&tweakBuffer[5])) ^ firstRoundKey ^ load128(src + 5 * 16);
        c6 = load128(@ptrCast(&tweakBuffer[6])) ^ firstRoundKey ^ load128(src + 6 * 16);
        c7 = load128(@ptrCast(&tweakBuffer[7])) ^ firstRoundKey ^ load128(src + 7 * 16);

        var keyPtr: [*]const [4][4]u8 = pExpandedKey.lastEncRoundKey + 1;

        for (0..8) |loopIdx| {
            const roundkey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0 = aesdec(c0, roundkey);
            c1 = aesdec(c1, roundkey);
            c2 = aesdec(c2, roundkey);
            c3 = aesdec(c3, roundkey);
            c4 = aesdec(c4, roundkey);
            c5 = aesdec(c5, roundkey);
            c6 = aesdec(c6, roundkey);
            c7 = aesdec(c7, roundkey);

            store128(@ptrCast(&tweakBuffer[8 + loopIdx]), load128(@ptrCast(&tweakBuffer[loopIdx])) ^ lastRoundKey);
            xtsMulAlphaScalar(&lastTweakLow, &lastTweakHigh);
            tweakBuffer[loopIdx].ull[0] = lastTweakLow;
            tweakBuffer[loopIdx].ull[1] = lastTweakHigh;
        }

        while (true) {
            const roundkey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0 = aesdec(c0, roundkey);
            c1 = aesdec(c1, roundkey);
            c2 = aesdec(c2, roundkey);
            c3 = aesdec(c3, roundkey);
            c4 = aesdec(c4, roundkey);
            c5 = aesdec(c5, roundkey);
            c6 = aesdec(c6, roundkey);
            c7 = aesdec(c7, roundkey);
            if (@intFromPtr(keyPtr) >= @intFromPtr(keyLimit)) break;
        }

        store128(dst + 0 * 16, aesdeclast(c0, load128(@ptrCast(&tweakBuffer[8]))));
        store128(dst + 1 * 16, aesdeclast(c1, load128(@ptrCast(&tweakBuffer[9]))));
        store128(dst + 2 * 16, aesdeclast(c2, load128(@ptrCast(&tweakBuffer[10]))));
        store128(dst + 3 * 16, aesdeclast(c3, load128(@ptrCast(&tweakBuffer[11]))));
        store128(dst + 4 * 16, aesdeclast(c4, load128(@ptrCast(&tweakBuffer[12]))));
        store128(dst + 5 * 16, aesdeclast(c5, load128(@ptrCast(&tweakBuffer[13]))));
        store128(dst + 6 * 16, aesdeclast(c6, load128(@ptrCast(&tweakBuffer[14]))));
        store128(dst + 7 * 16, aesdeclast(c7, load128(@ptrCast(&tweakBuffer[15]))));

        src += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        cbDataMain -= 8 * SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbDataTail == 0) {
        return;
    }

    var t0 = load128(@ptrCast(&tweakBuffer[0]));

    while (cbDataTail >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        c0 = load128(src) ^ t0;
        src += SYMCRYPT_AES_BLOCK_SIZE;
        aesDecrypt1(pExpandedKey, &c0);
        store128(dst, c0 ^ t0);
        dst += SYMCRYPT_AES_BLOCK_SIZE;
        t0 = xtsMulAlpha(t0);
        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbDataTail > SYMCRYPT_AES_BLOCK_SIZE) {
        const t1 = xtsMulAlpha(t0);
        c0 = load128(src) ^ t1;
        aesDecrypt1(pExpandedKey, &c0);
        store128(@ptrCast(&tweakBuffer[0]), c0 ^ t1);

        cbDataTail -= SYMCRYPT_AES_BLOCK_SIZE;

        store128(@ptrCast(&tweakBuffer[1]), load128(@ptrCast(&tweakBuffer[0])));
        const tb0Bytes: [*]u8 = @ptrCast(&tweakBuffer[0]);
        const tb1Bytes: [*]const u8 = @ptrCast(&tweakBuffer[1]);
        @memcpy(tb0Bytes[0..cbDataTail], (src + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail]);
        @memcpy((dst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbDataTail], tb1Bytes[0..cbDataTail]);

        c0 = load128(@ptrCast(&tweakBuffer[0]));
    } else {
        c0 = load128(src);
    }

    c0 ^= t0;
    aesDecrypt1(pExpandedKey, &c0);
    store128(dst, c0 ^ t0);
}

pub inline fn ghashHPower(table: [*]const SYMCRYPT_GF128_ELEMENT, ind: usize) V16u8 {
    return load128(@ptrCast(&table[SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS - ind]));
}

pub inline fn ghashHxPower(table: [*]const SYMCRYPT_GF128_ELEMENT, ind: usize) V16u8 {
    return load128(@ptrCast(&table[2 * SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS - ind]));
}

pub inline fn clmul3(
    opA: V16u8,
    opB: V16u8,
    opBx: V16u8,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    resl.* = clmul128(opA, opB, 0x00);
    resh.* = clmul128(opA, opB, 0x11);
    const tmpA = opA ^ srliSi128_8(opA);
    resm.* = clmul128(tmpA, opBx, 0x00);
}

pub inline fn clmulAcc3(
    opA: V16u8,
    opB: V16u8,
    opBx: V16u8,
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    var tmpl: V16u8 = undefined;
    var tmpm: V16u8 = undefined;
    var tmph: V16u8 = undefined;
    clmul3(opA, opB, opBx, &tmpl, &tmpm, &tmph);
    resl.* ^= tmpl;
    resm.* ^= tmpm;
    resh.* ^= tmph;
}

pub inline fn clmul3Post(
    resl: *V16u8,
    resm: *V16u8,
    resh: *V16u8,
) void {
    resm.* ^= resl.* ^ resh.*;
}

pub inline fn modReduce(
    vMultiplicationConstant: V16u8,
    rlIn: V16u8,
    rmIn: V16u8,
    rh: V16u8,
    res: *V16u8,
) void {
    var rl = rlIn;
    var rm = rmIn;

    var t0 = clmul128(rl, vMultiplicationConstant, 0x00);
    rl = @bitCast(@shuffle(u32, @as(V4u32, @bitCast(rl)), undefined, [4]i32{ 2, 3, 0, 1 }));
    rm ^= t0 ^ rl;

    const rmShl1: V16u8 = @bitCast(@as(V2u64, @bitCast(rm)) << @splat(1));
    t0 = clmul128(rmShl1, vMultiplicationConstant, 0x00);

    rm = @bitCast(@shuffle(u32, @as(V4u32, @bitCast(rm)), undefined, [4]i32{ 2, 3, 0, 1 }));
    const r = rh ^ rm;

    const r32: V4u32 = @bitCast(r);
    const t1: V16u8 = @bitCast(r32 << @splat(1));
    const rShr31 = r32 >> @splat(31);

    t0 ^= t1;
    const rShuf: V16u8 = @bitCast(@shuffle(u32, rShr31, undefined, [4]i32{ 3, 0, 1, 2 }));
    res.* = rShuf ^ t0;
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
    c0.* = aesenc(c0.*, roundKey);
    c1.* = aesenc(c1.*, roundKey);
    c2.* = aesenc(c2.*, roundKey);
    c3.* = aesenc(c3.*, roundKey);

    const r0 = bswap128(load128(gHashPointer.*));
    gHashPointer.* += SYMCRYPT_AES_BLOCK_SIZE;
    clmulAcc3(r0, ghashHPower(gHashExpandedKeyTable, todo.*), ghashHxPower(gHashExpandedKeyTable, todo.*), resl, resm, resh);
    todo.* -= 1;
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
    c0.* = aesenc(c0.*, roundKey);
    c1.* = aesenc(c1.*, roundKey);
    c2.* = aesenc(c2.*, roundKey);
    c3.* = aesenc(c3.*, roundKey);
    c4.* = aesenc(c4.*, roundKey);
    c5.* = aesenc(c5.*, roundKey);
    c6.* = aesenc(c6.*, roundKey);
    c7.* = aesenc(c7.*, roundKey);

    const r0 = bswap128(load128(gHashPointer.*));
    gHashPointer.* += SYMCRYPT_AES_BLOCK_SIZE;
    clmulAcc3(r0, ghashHPower(gHashExpandedKeyTable, todo.*), ghashHxPower(gHashExpandedKeyTable, todo.*), resl, resm, resh);
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
    c0.* ^= roundKey;
    c1.* ^= roundKey;
    c2.* ^= roundKey;
    c3.* ^= roundKey;

    var i: usize = 0;
    while (i < gHashRounds) : (i += 1) {
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
        aesEncryptRound4Ghash1(roundKey, c0, c1, c2, c3, gHashPointer, gHashExpandedKeyTable, todo, resl, resm, resh);
    }

    i = 0;
    while (i < (9 - gHashRounds)) : (i += 1) {
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, roundKey);
        c1.* = aesenc(c1.*, roundKey);
        c2.* = aesenc(c2.*, roundKey);
        c3.* = aesenc(c3.*, roundKey);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            roundKey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, roundKey);
            c1.* = aesenc(c1.*, roundKey);
            c2.* = aesenc(c2.*, roundKey);
            c3.* = aesenc(c3.*, roundKey);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                roundKey = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, roundKey);
                c1.* = aesenc(c1.*, roundKey);
                c2.* = aesenc(c2.*, roundKey);
                c3.* = aesenc(c3.*, roundKey);
            }
        }
    }

    roundKey = loadKey(&keyPtr[0]);
    c0.* = aesenclast(c0.*, roundKey);
    c1.* = aesenclast(c1.*, roundKey);
    c2.* = aesenclast(c2.*, roundKey);
    c3.* = aesenclast(c3.*, roundKey);
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
    c0.* ^= roundKey;
    c1.* ^= roundKey;
    c2.* ^= roundKey;
    c3.* ^= roundKey;
    c4.* ^= roundKey;
    c5.* ^= roundKey;
    c6.* ^= roundKey;
    c7.* ^= roundKey;

    var i: usize = 0;
    while (i < gHashRounds) : (i += 1) {
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
        aesEncryptRound8Ghash1(roundKey, c0, c1, c2, c3, c4, c5, c6, c7, gHashPointer, gHashExpandedKeyTable, todo, resl, resm, resh);
    }

    i = 0;
    while (i < (9 - gHashRounds)) : (i += 1) {
        roundKey = loadKey(&keyPtr[0]);
        keyPtr += 1;
        c0.* = aesenc(c0.*, roundKey);
        c1.* = aesenc(c1.*, roundKey);
        c2.* = aesenc(c2.*, roundKey);
        c3.* = aesenc(c3.*, roundKey);
        c4.* = aesenc(c4.*, roundKey);
        c5.* = aesenc(c5.*, roundKey);
        c6.* = aesenc(c6.*, roundKey);
        c7.* = aesenc(c7.*, roundKey);
    }

    if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        inline for (0..2) |_| {
            roundKey = loadKey(&keyPtr[0]);
            keyPtr += 1;
            c0.* = aesenc(c0.*, roundKey);
            c1.* = aesenc(c1.*, roundKey);
            c2.* = aesenc(c2.*, roundKey);
            c3.* = aesenc(c3.*, roundKey);
            c4.* = aesenc(c4.*, roundKey);
            c5.* = aesenc(c5.*, roundKey);
            c6.* = aesenc(c6.*, roundKey);
            c7.* = aesenc(c7.*, roundKey);
        }
        if (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
            inline for (0..2) |_| {
                roundKey = loadKey(&keyPtr[0]);
                keyPtr += 1;
                c0.* = aesenc(c0.*, roundKey);
                c1.* = aesenc(c1.*, roundKey);
                c2.* = aesenc(c2.*, roundKey);
                c3.* = aesenc(c3.*, roundKey);
                c4.* = aesenc(c4.*, roundKey);
                c5.* = aesenc(c5.*, roundKey);
                c6.* = aesenc(c6.*, roundKey);
                c7.* = aesenc(c7.*, roundKey);
            }
        }
    }

    roundKey = loadKey(&keyPtr[0]);
    c0.* = aesenclast(c0.*, roundKey);
    c1.* = aesenclast(c1.*, roundKey);
    c2.* = aesenclast(c2.*, roundKey);
    c3.* = aesenclast(c3.*, roundKey);
    c4.* = aesenclast(c4.*, roundKey);
    c5.* = aesenclast(c5.*, roundKey);
    c6.* = aesenclast(c6.*, roundKey);
    c7.* = aesenclast(c7.*, roundKey);
}

pub fn SymCryptAesGcmEncryptStitchedXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    var chain = bswap128(load128(pbChainingValue));
    const vMultiplicationConstant = setEpi32(0, 0, 0xc2000000, 0);

    const chainIncrement1 = setEpi32(0, 0, 0, 1);
    const chainIncrement2 = setEpi32(0, 0, 0, 2);
    const chainIncrement8 = setEpi32(0, 0, 0, 8);

    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var state = load128(@ptrCast(pState));
    var a0: V16u8 = undefined;
    var a1: V16u8 = undefined;
    var a2: V16u8 = undefined;

    var nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    var src = pbSrc;
    var dst = pbDst;
    var ghashSrc: [*]const u8 = pbDst;

    var todo: usize = @min(nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS);
    clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);

    c0 = chain;
    c1 = addEpi32(chain, chainIncrement1);
    c2 = addEpi32(chain, chainIncrement2);
    c3 = addEpi32(c1, chainIncrement2);
    c4 = addEpi32(c2, chainIncrement2);
    c5 = addEpi32(c3, chainIncrement2);
    c6 = addEpi32(c4, chainIncrement2);
    c7 = addEpi32(c5, chainIncrement2);

    c0 = bswap128(c0);
    c1 = bswap128(c1);
    c2 = bswap128(c2);
    c3 = bswap128(c3);
    c4 = bswap128(c4);
    c5 = bswap128(c5);
    c6 = bswap128(c6);
    c7 = bswap128(c7);

    aesEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7);

    if (nBlocks >= 8) {
        chain = addEpi32(chain, chainIncrement8);

        store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
        store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
        store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
        store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
        store128(dst + 4 * 16, c4 ^ load128(src + 4 * 16));
        store128(dst + 5 * 16, c5 ^ load128(src + 5 * 16));
        store128(dst + 6 * 16, c6 ^ load128(src + 6 * 16));
        store128(dst + 7 * 16, c7 ^ load128(src + 7 * 16));

        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        src += 8 * SYMCRYPT_AES_BLOCK_SIZE;

        while (nBlocks >= 16) {
            c0 = chain;
            c1 = addEpi32(chain, chainIncrement1);
            c2 = addEpi32(chain, chainIncrement2);
            c3 = addEpi32(c1, chainIncrement2);
            c4 = addEpi32(c2, chainIncrement2);
            c5 = addEpi32(c3, chainIncrement2);
            c6 = addEpi32(c4, chainIncrement2);
            c7 = addEpi32(c5, chainIncrement2);
            chain = addEpi32(c6, chainIncrement2);

            c0 = bswap128(c0);
            c1 = bswap128(c1);
            c2 = bswap128(c2);
            c3 = bswap128(c3);
            c4 = bswap128(c4);
            c5 = bswap128(c5);
            c6 = bswap128(c6);
            c7 = bswap128(c7);

            aesGcmEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7, &ghashSrc, 8, expandedKeyTable, &todo, &a0, &a1, &a2);

            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
            store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
            store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
            store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
            store128(dst + 4 * 16, c4 ^ load128(src + 4 * 16));
            store128(dst + 5 * 16, c5 ^ load128(src + 5 * 16));
            store128(dst + 6 * 16, c6 ^ load128(src + 6 * 16));
            store128(dst + 7 * 16, c7 ^ load128(src + 7 * 16));

            dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
            src += 8 * SYMCRYPT_AES_BLOCK_SIZE;
            nBlocks -= 8;

            if (todo == 0) {
                clmul3Post(&a0, &a1, &a2);
                modReduce(vMultiplicationConstant, a0, a1, a2, &state);

                todo = @min(nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        }

        nBlocks -= 8;
        if (nBlocks > 0) {
            c0 = chain;
            c1 = addEpi32(chain, chainIncrement1);
            c2 = addEpi32(chain, chainIncrement2);
            c3 = addEpi32(c1, chainIncrement2);
            c4 = addEpi32(c2, chainIncrement2);

            c0 = bswap128(c0);
            c1 = bswap128(c1);
            c2 = bswap128(c2);
            c3 = bswap128(c3);

            if (nBlocks > 4) {
                c5 = addEpi32(c4, chainIncrement1);
                c6 = addEpi32(c4, chainIncrement2);

                c4 = bswap128(c4);
                c5 = bswap128(c5);
                c6 = bswap128(c6);

                aesGcmEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7, &ghashSrc, 8, expandedKeyTable, &todo, &a0, &a1, &a2);
            } else {
                aesGcmEncrypt4(pExpandedKey, &c0, &c1, &c2, &c3, &ghashSrc, 8, expandedKeyTable, &todo, &a0, &a1, &a2);
            }
        } else {
            for (0..8) |_| {
                const r0 = bswap128(load128(ghashSrc));
                ghashSrc += SYMCRYPT_AES_BLOCK_SIZE;
                clmulAcc3(r0, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
                todo -= 1;
            }
        }

        if (todo == 0) {
            clmul3Post(&a0, &a1, &a2);
            modReduce(vMultiplicationConstant, a0, a1, a2, &state);
            if (nBlocks > 0) {
                todo = @min(nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        }
    }

    if (nBlocks > 0) {
        while (todo >= 2) {
            var r0 = c0 ^ load128(src + 0 * 16);
            store128(dst + 0 * 16, r0);
            r0 = bswap128(r0);

            var r1 = c1 ^ load128(src + 1 * 16);
            store128(dst + 1 * 16, r1);
            r1 = bswap128(r1);

            dst += 2 * SYMCRYPT_AES_BLOCK_SIZE;
            src += 2 * SYMCRYPT_AES_BLOCK_SIZE;

            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;

            chain = addEpi32(chain, chainIncrement2);

            clmulAcc3(r0, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            clmulAcc3(r1, ghashHPower(expandedKeyTable, todo - 1), ghashHxPower(expandedKeyTable, todo - 1), &a0, &a1, &a2);
            todo -= 2;
        }

        if (todo > 0) {
            var r0 = c0 ^ load128(src + 0 * 16);
            store128(dst + 0 * 16, r0);
            r0 = bswap128(r0);

            chain = addEpi32(chain, chainIncrement1);

            clmulAcc3(r0, ghashHPower(expandedKeyTable, 1), ghashHxPower(expandedKeyTable, 1), &a0, &a1, &a2);
        }

        clmul3Post(&a0, &a1, &a2);
        modReduce(vMultiplicationConstant, a0, a1, a2, &state);
    }

    chain = bswap128(chain);
    store128(pbChainingValue, chain);
    store128(@ptrCast(pState), state);
}

pub fn SymCryptAesGcmDecryptStitchedXmm(
    pExpandedKey: *const SYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: [*]u8,
    expandedKeyTable: [*]const SYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(SYMCRYPT_CALL) void {
    var chain = bswap128(load128(pbChainingValue));
    const vMultiplicationConstant = setEpi32(0, 0, 0xc2000000, 0);

    const chainIncrement1 = setEpi32(0, 0, 0, 1);
    const chainIncrement2 = setEpi32(0, 0, 0, 2);

    var c0: V16u8 = undefined;
    var c1: V16u8 = undefined;
    var c2: V16u8 = undefined;
    var c3: V16u8 = undefined;
    var c4: V16u8 = undefined;
    var c5: V16u8 = undefined;
    var c6: V16u8 = undefined;
    var c7: V16u8 = undefined;

    var state = load128(@ptrCast(pState));
    var a0: V16u8 = undefined;
    var a1: V16u8 = undefined;
    var a2: V16u8 = undefined;

    var nBlocks = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    var src = pbSrc;
    var dst = pbDst;
    var ghashSrc: [*]const u8 = pbSrc;

    var todo: usize = @min(nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS);
    clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);

    while (nBlocks >= 8) {
        c0 = chain;
        c1 = addEpi32(chain, chainIncrement1);
        c2 = addEpi32(chain, chainIncrement2);
        c3 = addEpi32(c1, chainIncrement2);
        c4 = addEpi32(c2, chainIncrement2);
        c5 = addEpi32(c3, chainIncrement2);
        c6 = addEpi32(c4, chainIncrement2);
        c7 = addEpi32(c5, chainIncrement2);
        chain = addEpi32(c6, chainIncrement2);

        c0 = bswap128(c0);
        c1 = bswap128(c1);
        c2 = bswap128(c2);
        c3 = bswap128(c3);
        c4 = bswap128(c4);
        c5 = bswap128(c5);
        c6 = bswap128(c6);
        c7 = bswap128(c7);

        aesGcmEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7, &ghashSrc, 8, expandedKeyTable, &todo, &a0, &a1, &a2);

        store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
        store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));
        store128(dst + 2 * 16, c2 ^ load128(src + 2 * 16));
        store128(dst + 3 * 16, c3 ^ load128(src + 3 * 16));
        store128(dst + 4 * 16, c4 ^ load128(src + 4 * 16));
        store128(dst + 5 * 16, c5 ^ load128(src + 5 * 16));
        store128(dst + 6 * 16, c6 ^ load128(src + 6 * 16));
        store128(dst + 7 * 16, c7 ^ load128(src + 7 * 16));

        dst += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        src += 8 * SYMCRYPT_AES_BLOCK_SIZE;
        nBlocks -= 8;

        if (todo == 0) {
            clmul3Post(&a0, &a1, &a2);
            modReduce(vMultiplicationConstant, a0, a1, a2, &state);
            if (nBlocks > 0) {
                todo = @min(nBlocks, SYMCRYPT_GHASH_PCLMULQDQ_HPOWERS);
                clmul3(state, ghashHPower(expandedKeyTable, todo), ghashHxPower(expandedKeyTable, todo), &a0, &a1, &a2);
            }
        }
    }

    if (nBlocks > 0) {
        c0 = chain;
        c1 = addEpi32(chain, chainIncrement1);
        c2 = addEpi32(chain, chainIncrement2);
        c3 = addEpi32(c1, chainIncrement2);
        c4 = addEpi32(c2, chainIncrement2);

        c0 = bswap128(c0);
        c1 = bswap128(c1);
        c2 = bswap128(c2);
        c3 = bswap128(c3);

        if (nBlocks > 4) {
            c5 = addEpi32(c4, chainIncrement1);
            c6 = addEpi32(c4, chainIncrement2);

            c4 = bswap128(c4);
            c5 = bswap128(c5);
            c6 = bswap128(c6);

            aesGcmEncrypt8(pExpandedKey, &c0, &c1, &c2, &c3, &c4, &c5, &c6, &c7, &ghashSrc, nBlocks, expandedKeyTable, &todo, &a0, &a1, &a2);
        } else {
            aesGcmEncrypt4(pExpandedKey, &c0, &c1, &c2, &c3, &ghashSrc, nBlocks, expandedKeyTable, &todo, &a0, &a1, &a2);
        }

        clmul3Post(&a0, &a1, &a2);
        modReduce(vMultiplicationConstant, a0, a1, a2, &state);

        while (nBlocks >= 2) {
            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
            store128(dst + 1 * 16, c1 ^ load128(src + 1 * 16));

            dst += 2 * SYMCRYPT_AES_BLOCK_SIZE;
            src += 2 * SYMCRYPT_AES_BLOCK_SIZE;

            c0 = c2;
            c1 = c3;
            c2 = c4;
            c3 = c5;
            c4 = c6;

            chain = addEpi32(chain, chainIncrement2);
            nBlocks -= 2;
        }

        if (nBlocks > 0) {
            store128(dst + 0 * 16, c0 ^ load128(src + 0 * 16));
            chain = addEpi32(chain, chainIncrement1);
        }
    }

    chain = bswap128(chain);
    store128(pbChainingValue, chain);
    store128(@ptrCast(pState), state);
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptAes4SboxXmm, .{ .name = "SymCryptAes4SboxXmm" });
        @export(&SymCryptAesCreateDecryptionRoundKeyXmm, .{ .name = "SymCryptAesCreateDecryptionRoundKeyXmm" });
        @export(&SymCryptAesEncryptXmm, .{ .name = "SymCryptAesEncryptXmm" });
        @export(&SymCryptAesDecryptXmm, .{ .name = "SymCryptAesDecryptXmm" });
        @export(&SymCryptAesCbcEncryptXmm, .{ .name = "SymCryptAesCbcEncryptXmm" });
        @export(&SymCryptAesCbcDecryptXmm, .{ .name = "SymCryptAesCbcDecryptXmm" });
        @export(&SymCryptAesCbcMacXmm, .{ .name = "SymCryptAesCbcMacXmm" });
        @export(&SymCryptAesEcbEncryptXmm, .{ .name = "SymCryptAesEcbEncryptXmm" });
        @export(&SymCryptAesEcbDecryptXmm, .{ .name = "SymCryptAesEcbDecryptXmm" });
        @export(&SymCryptAesCtrMsb32Xmm, .{ .name = "SymCryptAesCtrMsb32Xmm" });
        @export(&SymCryptAesCtrMsb64Xmm, .{ .name = "SymCryptAesCtrMsb64Xmm" });
        @export(&SymCryptXtsAesEncryptDataUnitXmm, .{ .name = "SymCryptXtsAesEncryptDataUnitXmm" });
        @export(&SymCryptXtsAesDecryptDataUnitXmm, .{ .name = "SymCryptXtsAesDecryptDataUnitXmm" });
        @export(&SymCryptAesGcmEncryptStitchedXmm, .{ .name = "SymCryptAesGcmEncryptStitchedXmm" });
        @export(&SymCryptAesGcmDecryptStitchedXmm, .{ .name = "SymCryptAesGcmDecryptStitchedXmm" });
    }
}
