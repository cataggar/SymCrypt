//
// sha256_ymm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// YMM (AVX2) 8-block message schedule implementation for SHA-256,
// ported from lib/sha256-ymm.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha256 = @import("sha256.zig");

const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_SHA256_INPUT_BLOCK_SIZE = sha256.SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
const SYMCRYPT_SHA256_CHAINING_STATE = sha256.SYMCRYPT_SHA256_CHAINING_STATE;
const SymCryptSha256K = &sha256.SymCryptSha256K;

const V8U32 = @Vector(8, u32);
const V32U8 = @Vector(32, u8);

// Endianness transformation for 8 32-bit values in a YMM register
pub const BYTE_REVERSE_32X2: [8]UINT32 align(32) = .{
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
    0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
};

inline fn mm256Zeroupper() void {
    if (comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx))
    {
        asm volatile ("vzeroupper");
    }
}

inline fn maj(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z | y) & x) | (z & y));
}

inline fn ch(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn csigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 2) ^ macros.ROR32(x, 13) ^ macros.ROR32(x, 22);
}

inline fn csigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 6) ^ macros.ROR32(x, 11) ^ macros.ROR32(x, 25);
}

inline fn lsigma0(x: UINT32) UINT32 {
    return macros.ROR32(x, 7) ^ macros.ROR32(x, 18) ^ (x >> 3);
}

inline fn lsigma1(x: UINT32) UINT32 {
    return macros.ROR32(x, 17) ^ macros.ROR32(x, 19) ^ (x >> 10);
}

inline fn lsigma0Ymm(x: V8U32) V8U32 {
    return (x << @splat(25)) ^ (x >> @splat(7)) ^
        (x << @splat(14)) ^ (x >> @splat(18)) ^
        (x >> @splat(3));
}

inline fn lsigma1Ymm(x: V8U32) V8U32 {
    return (x << @splat(15)) ^ (x >> @splat(17)) ^
        (x << @splat(13)) ^ (x >> @splat(19)) ^
        (x >> @splat(10));
}

inline fn loaduByteReverse32x2(ptr: PCBYTE) V8U32 {
    const raw: V32U8 = @bitCast(std.mem.readInt(u256, ptr[0..32], .little));
    const rev = @shuffle(u8, raw, undefined, [32]i32{
        3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12,
        19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28,
    });
    return @bitCast(rev);
}

inline fn mm256UnpackloEpi32(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 0, -1, 1, -2, 4, -5, 5, -6 });
}

inline fn mm256UnpackhiEpi32(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 2, -3, 3, -4, 6, -7, 7, -8 });
}

inline fn mm256UnpackloEpi64(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 0, 1, -1, -2, 4, 5, -5, -6 });
}

inline fn mm256UnpackhiEpi64(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 2, 3, -3, -4, 6, 7, -7, -8 });
}

inline fn mm256Permute2x128_0x20(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
}

inline fn mm256Permute2x128_0x31(a: V8U32, b: V8U32) V8U32 {
    return @shuffle(u32, a, b, [8]i32{ 4, 5, 6, 7, -5, -6, -7, -8 });
}

const WxArray = [64]V8U32;

inline fn sha256MsgLoad8Blocks(Wx: *WxArray, pbData: PCBYTE, bl: usize) void {
    var i: usize = 0;
    while (i < bl) : (i += 1) {
        const base = i * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
        Wx[i + 0] = loaduByteReverse32x2(pbData + base + 0);
        Wx[i + 8] = loaduByteReverse32x2(pbData + base + 32);
    }
}

inline fn sha256MsgTransposeHalf8Blocks(Wx: *WxArray, comptime ind: usize) void {
    const s1 = mm256UnpackloEpi32(Wx[8 * ind + 0], Wx[8 * ind + 1]);
    const s2 = mm256UnpackloEpi32(Wx[8 * ind + 2], Wx[8 * ind + 3]);
    const s3 = mm256UnpackloEpi32(Wx[8 * ind + 4], Wx[8 * ind + 5]);
    const s4 = mm256UnpackloEpi32(Wx[8 * ind + 6], Wx[8 * ind + 7]);
    const s5 = mm256UnpackhiEpi32(Wx[8 * ind + 0], Wx[8 * ind + 1]);
    const s6 = mm256UnpackhiEpi32(Wx[8 * ind + 2], Wx[8 * ind + 3]);
    const s7 = mm256UnpackhiEpi32(Wx[8 * ind + 4], Wx[8 * ind + 5]);
    const s8 = mm256UnpackhiEpi32(Wx[8 * ind + 6], Wx[8 * ind + 7]);
    const u_1 = mm256UnpackloEpi64(s1, s2);
    const u_2 = mm256UnpackloEpi64(s3, s4);
    const u_3 = mm256UnpackloEpi64(s5, s6);
    const u_4 = mm256UnpackloEpi64(s7, s8);
    const u_5 = mm256UnpackhiEpi64(s1, s2);
    const u_6 = mm256UnpackhiEpi64(s3, s4);
    const u_7 = mm256UnpackhiEpi64(s5, s6);
    const u_8 = mm256UnpackhiEpi64(s7, s8);
    Wx[8 * ind + 0] = mm256Permute2x128_0x20(u_1, u_2);
    Wx[8 * ind + 1] = mm256Permute2x128_0x20(u_5, u_6);
    Wx[8 * ind + 2] = mm256Permute2x128_0x20(u_3, u_4);
    Wx[8 * ind + 3] = mm256Permute2x128_0x20(u_7, u_8);
    Wx[8 * ind + 4] = mm256Permute2x128_0x31(u_1, u_2);
    Wx[8 * ind + 5] = mm256Permute2x128_0x31(u_5, u_6);
    Wx[8 * ind + 6] = mm256Permute2x128_0x31(u_3, u_4);
    Wx[8 * ind + 7] = mm256Permute2x128_0x31(u_7, u_8);
}

inline fn sha256MsgTranspose8Blocks(Wx: *WxArray) void {
    sha256MsgTransposeHalf8Blocks(Wx, 0);
    sha256MsgTransposeHalf8Blocks(Wx, 1);
}

inline fn sha256MsgExpand8Blocks1Round(Wx: *WxArray, r: usize) void {
    Wx[r] = Wx[r - 16] +% Wx[r - 7] +% lsigma0Ymm(Wx[r - 15]) +% lsigma1Ymm(Wx[r - 2]);
    Wx[r - 16] +%= @splat(SymCryptSha256K[r - 16]);
}

inline fn sha256MsgExpand8Blocks4Rounds(Wx: *WxArray, r: usize) void {
    sha256MsgExpand8Blocks1Round(Wx, r + 0);
    sha256MsgExpand8Blocks1Round(Wx, r + 1);
    sha256MsgExpand8Blocks1Round(Wx, r + 2);
    sha256MsgExpand8Blocks1Round(Wx, r + 3);
}

inline fn cround8Blocks(Wx: *const WxArray, ah: *[8]UINT32, comptime r16: usize, rb: usize, bl: usize) void {
    const T2: UINT32 = csigma0(ah[(r16 + 7) & 7]) +% maj(ah[(r16 + 7) & 7], ah[(r16 + 6) & 7], ah[(r16 + 5) & 7]);
    const T1: UINT32 = csigma1(ah[(r16 + 3) & 7]) +% ch(ah[(r16 + 3) & 7], ah[(r16 + 2) & 7], ah[(r16 + 1) & 7]) +% @as([8]UINT32, Wx[rb + r16])[bl];
    ah[(r16 + 4) & 7] +%= T1 +% ah[r16 & 7];
    ah[r16 & 7] +%= T1 +% T2;
}

inline fn cround(ah: *[8]UINT32, comptime r16: usize, r: usize, Wt: UINT32) void {
    ah[r16 & 7] +%= csigma1(ah[(r16 + 3) & 7]) +% ch(ah[(r16 + 3) & 7], ah[(r16 + 2) & 7], ah[(r16 + 1) & 7]) +% SymCryptSha256K[r] +% Wt;
    ah[(r16 + 4) & 7] +%= ah[r16 & 7];
    ah[r16 & 7] +%= csigma0(ah[(r16 + 7) & 7]) +% maj(ah[(r16 + 7) & 7], ah[(r16 + 6) & 7], ah[(r16 + 5) & 7]);
}

inline fn iround(Wx_ul: *[16]UINT32, ah: *[8]UINT32, Wt: *UINT32, pbData: PCBYTE, comptime r: usize) void {
    Wt.* = macros.LOAD_MSBFIRST32(pbData + 4 * r);
    Wx_ul[r] = Wt.*;
    cround(ah, r, r, Wt.*);
}

inline fn fround(Wx_ul: *[16]UINT32, ah: *[8]UINT32, Wt: *UINT32, comptime r16: usize, rb: usize) void {
    Wt.* = lsigma1(Wx_ul[(r16 + 16 - 2) & 15]) +% Wx_ul[(r16 + 16 - 7) & 15] +%
        lsigma0(Wx_ul[(r16 + 16 - 15) & 15]) +% Wx_ul[r16 & 15];
    Wx_ul[r16] = Wt.*;
    cround(ah, r16, r16 + rb, Wt.*);
}

pub fn SymCryptSha256AppendBlocks_ymm_8blocks(
    pChain: *SYMCRYPT_SHA256_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var Wx: WxArray align(32) = undefined;
    const Wx_ul: *[16]UINT32 = @ptrCast(&Wx);
    var ah: [8]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var Wt: UINT32 = 0;
    const uWipeSize: UINT32 = if (cbData >= (5 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE))
        (64 * 8 * @sizeOf(UINT32))
    else
        (16 * @sizeOf(UINT32));

    mm256Zeroupper();

    while (cbData >= (5 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE)) {
        const numBlocks: SIZE_T = if (cbData >= 8 * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE)
            8
        else
            (cbData / SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);

        sha256MsgLoad8Blocks(&Wx, pbData, numBlocks);
        sha256MsgTranspose8Blocks(&Wx);

        {
            ah[7] = pChain.H[0];
            ah[6] = pChain.H[1];
            ah[5] = pChain.H[2];
            ah[4] = pChain.H[3];
            ah[3] = pChain.H[4];
            ah[2] = pChain.H[5];
            ah[1] = pChain.H[6];
            ah[0] = pChain.H[7];

            var r: usize = 0;
            while (r < 64) : (r += 8) {
                if (r < 48) {
                    sha256MsgExpand8Blocks4Rounds(&Wx, r + 16);
                } else {
                    Wx[r + 0] +%= @splat(SymCryptSha256K[r + 0]);
                    Wx[r + 1] +%= @splat(SymCryptSha256K[r + 1]);
                    Wx[r + 2] +%= @splat(SymCryptSha256K[r + 2]);
                    Wx[r + 3] +%= @splat(SymCryptSha256K[r + 3]);
                }

                cround8Blocks(&Wx, &ah, 0, r, 0);
                cround8Blocks(&Wx, &ah, 1, r, 0);
                cround8Blocks(&Wx, &ah, 2, r, 0);
                cround8Blocks(&Wx, &ah, 3, r, 0);

                if (r < 48) {
                    sha256MsgExpand8Blocks4Rounds(&Wx, r + 20);
                } else {
                    Wx[r + 4] +%= @splat(SymCryptSha256K[r + 4]);
                    Wx[r + 5] +%= @splat(SymCryptSha256K[r + 5]);
                    Wx[r + 6] +%= @splat(SymCryptSha256K[r + 6]);
                    Wx[r + 7] +%= @splat(SymCryptSha256K[r + 7]);
                }

                cround8Blocks(&Wx, &ah, 4, r, 0);
                cround8Blocks(&Wx, &ah, 5, r, 0);
                cround8Blocks(&Wx, &ah, 6, r, 0);
                cround8Blocks(&Wx, &ah, 7, r, 0);
            }

            pChain.H[0] +%= ah[7];
            pChain.H[1] +%= ah[6];
            pChain.H[2] +%= ah[5];
            pChain.H[3] +%= ah[4];
            pChain.H[4] +%= ah[3];
            pChain.H[5] +%= ah[2];
            pChain.H[6] +%= ah[1];
            pChain.H[7] +%= ah[0];
        }

        var bl: usize = 1;
        while (bl < numBlocks) : (bl += 1) {
            ah[7] = pChain.H[0];
            ah[6] = pChain.H[1];
            ah[5] = pChain.H[2];
            ah[4] = pChain.H[3];
            ah[3] = pChain.H[4];
            ah[2] = pChain.H[5];
            ah[1] = pChain.H[6];
            ah[0] = pChain.H[7];

            var iterCount: usize = 0;
            while (iterCount < (64 / 16)) : (iterCount += 1) {
                const roundBase = iterCount * 16;
                cround8Blocks(&Wx, &ah, 0, roundBase, bl);
                cround8Blocks(&Wx, &ah, 1, roundBase, bl);
                cround8Blocks(&Wx, &ah, 2, roundBase, bl);
                cround8Blocks(&Wx, &ah, 3, roundBase, bl);
                cround8Blocks(&Wx, &ah, 4, roundBase, bl);
                cround8Blocks(&Wx, &ah, 5, roundBase, bl);
                cround8Blocks(&Wx, &ah, 6, roundBase, bl);
                cround8Blocks(&Wx, &ah, 7, roundBase, bl);
                cround8Blocks(&Wx, &ah, 8, roundBase, bl);
                cround8Blocks(&Wx, &ah, 9, roundBase, bl);
                cround8Blocks(&Wx, &ah, 10, roundBase, bl);
                cround8Blocks(&Wx, &ah, 11, roundBase, bl);
                cround8Blocks(&Wx, &ah, 12, roundBase, bl);
                cround8Blocks(&Wx, &ah, 13, roundBase, bl);
                cround8Blocks(&Wx, &ah, 14, roundBase, bl);
                cround8Blocks(&Wx, &ah, 15, roundBase, bl);
            }

            pChain.H[0] +%= ah[7];
            pChain.H[1] +%= ah[6];
            pChain.H[2] +%= ah[5];
            pChain.H[3] +%= ah[4];
            pChain.H[4] +%= ah[3];
            pChain.H[5] +%= ah[2];
            pChain.H[6] +%= ah[1];
            pChain.H[7] +%= ah[0];
        }

        pbData += (numBlocks * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);
        cbData -= (numBlocks * SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);
    }

    mm256Zeroupper();

    while (cbData >= SYMCRYPT_SHA256_INPUT_BLOCK_SIZE) {
        ah[7] = pChain.H[0];
        ah[6] = pChain.H[1];
        ah[5] = pChain.H[2];
        ah[4] = pChain.H[3];
        ah[3] = pChain.H[4];
        ah[2] = pChain.H[5];
        ah[1] = pChain.H[6];
        ah[0] = pChain.H[7];

        iround(Wx_ul, &ah, &Wt, pbData, 0);
        iround(Wx_ul, &ah, &Wt, pbData, 1);
        iround(Wx_ul, &ah, &Wt, pbData, 2);
        iround(Wx_ul, &ah, &Wt, pbData, 3);
        iround(Wx_ul, &ah, &Wt, pbData, 4);
        iround(Wx_ul, &ah, &Wt, pbData, 5);
        iround(Wx_ul, &ah, &Wt, pbData, 6);
        iround(Wx_ul, &ah, &Wt, pbData, 7);
        iround(Wx_ul, &ah, &Wt, pbData, 8);
        iround(Wx_ul, &ah, &Wt, pbData, 9);
        iround(Wx_ul, &ah, &Wt, pbData, 10);
        iround(Wx_ul, &ah, &Wt, pbData, 11);
        iround(Wx_ul, &ah, &Wt, pbData, 12);
        iround(Wx_ul, &ah, &Wt, pbData, 13);
        iround(Wx_ul, &ah, &Wt, pbData, 14);
        iround(Wx_ul, &ah, &Wt, pbData, 15);

        var iterCount: usize = 1;
        while (iterCount < (64 / 16)) : (iterCount += 1) {
            const roundBase = iterCount * 16;
            fround(Wx_ul, &ah, &Wt, 0, roundBase);
            fround(Wx_ul, &ah, &Wt, 1, roundBase);
            fround(Wx_ul, &ah, &Wt, 2, roundBase);
            fround(Wx_ul, &ah, &Wt, 3, roundBase);
            fround(Wx_ul, &ah, &Wt, 4, roundBase);
            fround(Wx_ul, &ah, &Wt, 5, roundBase);
            fround(Wx_ul, &ah, &Wt, 6, roundBase);
            fround(Wx_ul, &ah, &Wt, 7, roundBase);
            fround(Wx_ul, &ah, &Wt, 8, roundBase);
            fround(Wx_ul, &ah, &Wt, 9, roundBase);
            fround(Wx_ul, &ah, &Wt, 10, roundBase);
            fround(Wx_ul, &ah, &Wt, 11, roundBase);
            fround(Wx_ul, &ah, &Wt, 12, roundBase);
            fround(Wx_ul, &ah, &Wt, 13, roundBase);
            fround(Wx_ul, &ah, &Wt, 14, roundBase);
            fround(Wx_ul, &ah, &Wt, 15, roundBase);
        }

        pChain.H[0] +%= ah[7];
        pChain.H[1] +%= ah[6];
        pChain.H[2] +%= ah[5];
        pChain.H[3] +%= ah[4];
        pChain.H[4] +%= ah[3];
        pChain.H[5] +%= ah[2];
        pChain.H[6] +%= ah[1];
        pChain.H[7] +%= ah[0];

        pbData += SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
        cbData -= SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
    }

    pcbRemaining.* = cbData;

    hash.SymCryptWipe(@ptrCast(&Wx), uWipeSize);
    hash.SymCryptWipeKnownSize(@ptrCast(&ah), @sizeOf(@TypeOf(ah)));
    macros.FORCE_WRITE32(&Wt, 0);
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&BYTE_REVERSE_32X2, .{ .name = "BYTE_REVERSE_32X2" });
        @export(&SymCryptSha256AppendBlocks_ymm_8blocks, .{ .name = "SymCryptSha256AppendBlocks_ymm_8blocks" });
    }
}
