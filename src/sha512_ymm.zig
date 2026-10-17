//
// sha512_ymm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// YMM (AVX2) 1-block, 2-block, and 4-block message schedule implementations for SHA-512,
// ported from lib/sha512-ymm.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha512 = @import("sha512.zig");

const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_SHA512_INPUT_BLOCK_SIZE = sha512.SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
const SYMCRYPT_SHA512_CHAINING_STATE = sha512.SYMCRYPT_SHA512_CHAINING_STATE;
const SymCryptSha512K = &sha512.SymCryptSha512K;

const V4U64 = @Vector(4, u64);
const V32U8 = @Vector(32, u8);

// Endianness transformation for 4 64-bit values in a YMM register
pub const BYTE_REVERSE_64X2: [4]UINT64 align(32) = .{
    0x0001020304050607, 0x08090a0b0c0d0e0f,
    0x0001020304050607, 0x08090a0b0c0d0e0f,
};

// Rotate right each 64-bit value in a YMM register by 1 byte
pub const BYTE_ROTATE_64: [4]UINT64 align(32) = .{
    0x0007060504030201, 0x080f0e0d0c0b0a09,
    0x0007060504030201, 0x080f0e0d0c0b0a09,
};

inline fn mm256Zeroupper() void {
    if (comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx))
    {
        asm volatile ("vzeroupper");
    }
}

inline fn maj(x: UINT64, y: UINT64, z: UINT64) UINT64 {
    return (((z | y) & x) | (z & y));
}

inline fn ch(x: UINT64, y: UINT64, z: UINT64) UINT64 {
    return (((z ^ y) & x) ^ z);
}

inline fn csigma0(x: UINT64) UINT64 {
    return macros.ROR64(x, 28) ^ macros.ROR64(x, 34) ^ macros.ROR64(x, 39);
}

inline fn csigma1(x: UINT64) UINT64 {
    return macros.ROR64(x, 14) ^ macros.ROR64(x, 18) ^ macros.ROR64(x, 41);
}

inline fn lsigma0(x: UINT64) UINT64 {
    return macros.ROR64(x ^ macros.ROR64(x, 7), 1) ^ (x >> 7);
}

inline fn lsigma1(x: UINT64) UINT64 {
    return macros.ROR64(x ^ macros.ROR64(x, 42), 19) ^ (x >> 6);
}

inline fn ymmRor(a: V4U64, comptime n: u6) V4U64 {
    const inv: u6 = @intCast(64 - @as(u7, n));
    return (a << @splat(inv)) ^ (a >> @splat(n));
}

inline fn ymmShr(a: V4U64, comptime n: u6) V4U64 {
    return a >> @splat(n);
}

inline fn ymmRor8(a: V4U64) V4U64 {
    const raw: V32U8 = @bitCast(a);
    const rot = @shuffle(u8, raw, undefined, [32]i32{
        1,  2,  3,  4,  5,  6,  7,  0,  9,  10, 11, 12, 13, 14, 15, 8,
        17, 18, 19, 20, 21, 22, 23, 16, 25, 26, 27, 28, 29, 30, 31, 24,
    });
    return @bitCast(rot);
}

inline fn ymmLsigma0(x: V4U64) V4U64 {
    return ymmRor(x, 1) ^ ymmRor8(x) ^ ymmShr(x, 7);
}

inline fn ymmLsigma1(x: V4U64) V4U64 {
    return ymmRor(x, 19) ^ ymmRor(x, 61) ^ ymmShr(x, 6);
}

inline fn loaduByteReverse64x2(ptr: PCBYTE) V4U64 {
    const raw: V32U8 = @bitCast(std.mem.readInt(u256, ptr[0..32], .little));
    const rev = @shuffle(u8, raw, undefined, [32]i32{
        7,  6,  5,  4,  3,  2,  1,  0,
        15, 14, 13, 12, 11, 10, 9,  8,
        23, 22, 21, 20, 19, 18, 17, 16,
        31, 30, 29, 28, 27, 26, 25, 24,
    });
    return @bitCast(rev);
}

inline fn mm256UnpackloEpi64(a: V4U64, b: V4U64) V4U64 {
    return @shuffle(u64, a, b, [4]i32{ 0, -1, 2, -3 });
}

inline fn mm256UnpackhiEpi64(a: V4U64, b: V4U64) V4U64 {
    return @shuffle(u64, a, b, [4]i32{ 1, -2, 3, -4 });
}

inline fn mm256Permute2x128_0x20(a: V4U64, b: V4U64) V4U64 {
    return @shuffle(u64, a, b, [4]i32{ 0, 1, -1, -2 });
}

inline fn mm256Permute2x128_0x31(a: V4U64, b: V4U64) V4U64 {
    return @shuffle(u64, a, b, [4]i32{ 2, 3, -3, -4 });
}

// ============================================================================
// 1-Block YMM Implementation
// ============================================================================

inline fn cround1Block(
    Wx_ul: *const [80]UINT64,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
) void {
    const T1: UINT64 = csigma1(e) +% ch(e, f, g) +% Wx_ul[r] +% SymCryptSha512K[r];
    const T2: UINT64 = csigma0(a) +% maj(a, b, c);
    h.* +%= T1;
    d.* +%= h.*;
    h.* +%= T2;
}

inline fn sha512MsgExpand1Block4Rounds(Wx_ul: *[80]UINT64, rnd: usize) void {
    const w_m15 = V4U64{ Wx_ul[rnd - 15], Wx_ul[rnd - 14], Wx_ul[rnd - 13], Wx_ul[rnd - 12] };
    const w_m16 = V4U64{ Wx_ul[rnd - 16], Wx_ul[rnd - 15], Wx_ul[rnd - 14], Wx_ul[rnd - 13] };
    const w_m7 = V4U64{ Wx_ul[rnd - 7], Wx_ul[rnd - 6], Wx_ul[rnd - 5], Wx_ul[rnd - 4] };
    const expanded = ymmLsigma0(w_m15) +% w_m16 +% w_m7;
    Wx_ul[rnd + 0] = expanded[0] +% lsigma1(Wx_ul[rnd - 2]);
    Wx_ul[rnd + 1] = expanded[1] +% lsigma1(Wx_ul[rnd - 1]);
    Wx_ul[rnd + 2] = expanded[2] +% lsigma1(Wx_ul[rnd + 0]);
    Wx_ul[rnd + 3] = expanded[3] +% lsigma1(Wx_ul[rnd + 1]);
}

pub fn SymCryptSha512AppendBlocks_ymm_1block(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setEvalBranchQuota(10000);
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var Wx: [80]UINT64 align(32) = undefined;

    mm256Zeroupper();

    while (cbData >= SYMCRYPT_SHA512_INPUT_BLOCK_SIZE) {
        var A = pChain.H[0];
        var B = pChain.H[1];
        var C = pChain.H[2];
        var D = pChain.H[3];
        var E = pChain.H[4];
        var F = pChain.H[5];
        var G = pChain.H[6];
        var H = pChain.H[7];

        for (0..4) |k| {
            const v = loaduByteReverse64x2(pbData + k * 32);
            Wx[4 * k + 0] = v[0];
            Wx[4 * k + 1] = v[1];
            Wx[4 * k + 2] = v[2];
            Wx[4 * k + 3] = v[3];
        }

        var iterCount: usize = 0;
        while (iterCount < (64 / 16)) : (iterCount += 1) {
            const roundBase = iterCount * 16;

            cround1Block(&Wx, A, B, C, &D, E, F, G, &H, roundBase + 0);
            cround1Block(&Wx, H, A, B, &C, D, E, F, &G, roundBase + 1);
            cround1Block(&Wx, G, H, A, &B, C, D, E, &F, roundBase + 2);
            cround1Block(&Wx, F, G, H, &A, B, C, D, &E, roundBase + 3);
            sha512MsgExpand1Block4Rounds(&Wx, roundBase + 16);

            cround1Block(&Wx, E, F, G, &H, A, B, C, &D, roundBase + 4);
            cround1Block(&Wx, D, E, F, &G, H, A, B, &C, roundBase + 5);
            cround1Block(&Wx, C, D, E, &F, G, H, A, &B, roundBase + 6);
            cround1Block(&Wx, B, C, D, &E, F, G, H, &A, roundBase + 7);
            sha512MsgExpand1Block4Rounds(&Wx, roundBase + 20);

            cround1Block(&Wx, A, B, C, &D, E, F, G, &H, roundBase + 8);
            cround1Block(&Wx, H, A, B, &C, D, E, F, &G, roundBase + 9);
            cround1Block(&Wx, G, H, A, &B, C, D, E, &F, roundBase + 10);
            cround1Block(&Wx, F, G, H, &A, B, C, D, &E, roundBase + 11);
            sha512MsgExpand1Block4Rounds(&Wx, roundBase + 24);

            cround1Block(&Wx, E, F, G, &H, A, B, C, &D, roundBase + 12);
            cround1Block(&Wx, D, E, F, &G, H, A, B, &C, roundBase + 13);
            cround1Block(&Wx, C, D, E, &F, G, H, A, &B, roundBase + 14);
            cround1Block(&Wx, B, C, D, &E, F, G, H, &A, roundBase + 15);
            sha512MsgExpand1Block4Rounds(&Wx, roundBase + 28);
        }

        cround1Block(&Wx, A, B, C, &D, E, F, G, &H, 64 + 0);
        cround1Block(&Wx, H, A, B, &C, D, E, F, &G, 64 + 1);
        cround1Block(&Wx, G, H, A, &B, C, D, E, &F, 64 + 2);
        cround1Block(&Wx, F, G, H, &A, B, C, D, &E, 64 + 3);
        cround1Block(&Wx, E, F, G, &H, A, B, C, &D, 64 + 4);
        cround1Block(&Wx, D, E, F, &G, H, A, B, &C, 64 + 5);
        cround1Block(&Wx, C, D, E, &F, G, H, A, &B, 64 + 6);
        cround1Block(&Wx, B, C, D, &E, F, G, H, &A, 64 + 7);
        cround1Block(&Wx, A, B, C, &D, E, F, G, &H, 64 + 8);
        cround1Block(&Wx, H, A, B, &C, D, E, F, &G, 64 + 9);
        cround1Block(&Wx, G, H, A, &B, C, D, E, &F, 64 + 10);
        cround1Block(&Wx, F, G, H, &A, B, C, D, &E, 64 + 11);
        cround1Block(&Wx, E, F, G, &H, A, B, C, &D, 64 + 12);
        cround1Block(&Wx, D, E, F, &G, H, A, B, &C, 64 + 13);
        cround1Block(&Wx, C, D, E, &F, G, H, A, &B, 64 + 14);
        cround1Block(&Wx, B, C, D, &E, F, G, H, &A, 64 + 15);

        pChain.H[0] +%= A;
        pChain.H[1] +%= B;
        pChain.H[2] +%= C;
        pChain.H[3] +%= D;
        pChain.H[4] +%= E;
        pChain.H[5] +%= F;
        pChain.H[6] +%= G;
        pChain.H[7] +%= H;

        pbData += SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
        cbData -= SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
    }

    pcbRemaining.* = cbData;

    mm256Zeroupper();

    hash.SymCryptWipeKnownSize(@ptrCast(&Wx), @sizeOf(@TypeOf(Wx)));
}

// ============================================================================
// 2-Block YMM Implementation
// ============================================================================

const Wx2BlocksArray = [40]V4U64;

inline fn cround2Blocks(
    Wx: *const Wx2BlocksArray,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    bl: usize,
) void {
    const T1: UINT64 = csigma1(e) +% ch(e, f, g) +% @as([4]UINT64, Wx[r / 2])[2 * bl + (r & 1)] +% SymCryptSha512K[r];
    const T2: UINT64 = csigma0(a) +% maj(a, b, c);
    h.* +%= T1;
    d.* +%= h.*;
    h.* +%= T2;
}

inline fn sha512MsgExpand2Blocks2Rounds(Wx: *Wx2BlocksArray, ind: usize) void {
    // _mm256_permute4x64_epi64(_mm256_blend_epi32(a, b, 0x33), 0xb1) selects [a[1], b[0], a[3], b[2]]
    const t1 = @shuffle(u64, Wx[ind + 0], Wx[ind + 1], [4]i32{ 1, -1, 3, -3 });
    const t2 = @shuffle(u64, Wx[ind + 4], Wx[ind + 5], [4]i32{ 1, -1, 3, -3 });
    Wx[ind + 8] = Wx[ind] +% ymmLsigma0(t1) +% ymmLsigma1(Wx[ind + 7]) +% t2;
}

inline fn sha512_2BlocksRoundStitched16x(
    Wx: *Wx2BlocksArray,
    A: *UINT64,
    B: *UINT64,
    C: *UINT64,
    D: *UINT64,
    E: *UINT64,
    F: *UINT64,
    G: *UINT64,
    H: *UINT64,
    rb: usize,
    ind: usize,
) void {
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 0);
    cround2Blocks(Wx, A.*, B.*, C.*, D, E.*, F.*, G.*, H, 2 * (rb + ind) + 0, 0);
    cround2Blocks(Wx, H.*, A.*, B.*, C, D.*, E.*, F.*, G, 2 * (rb + ind) + 1, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 1);
    cround2Blocks(Wx, G.*, H.*, A.*, B, C.*, D.*, E.*, F, 2 * (rb + ind) + 2, 0);
    cround2Blocks(Wx, F.*, G.*, H.*, A, B.*, C.*, D.*, E, 2 * (rb + ind) + 3, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 2);
    cround2Blocks(Wx, E.*, F.*, G.*, H, A.*, B.*, C.*, D, 2 * (rb + ind) + 4, 0);
    cround2Blocks(Wx, D.*, E.*, F.*, G, H.*, A.*, B.*, C, 2 * (rb + ind) + 5, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 3);
    cround2Blocks(Wx, C.*, D.*, E.*, F, G.*, H.*, A.*, B, 2 * (rb + ind) + 6, 0);
    cround2Blocks(Wx, B.*, C.*, D.*, E, F.*, G.*, H.*, A, 2 * (rb + ind) + 7, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 4);
    cround2Blocks(Wx, A.*, B.*, C.*, D, E.*, F.*, G.*, H, 2 * (rb + ind) + 8, 0);
    cround2Blocks(Wx, H.*, A.*, B.*, C, D.*, E.*, F.*, G, 2 * (rb + ind) + 9, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 5);
    cround2Blocks(Wx, G.*, H.*, A.*, B, C.*, D.*, E.*, F, 2 * (rb + ind) + 10, 0);
    cround2Blocks(Wx, F.*, G.*, H.*, A, B.*, C.*, D.*, E, 2 * (rb + ind) + 11, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 6);
    cround2Blocks(Wx, E.*, F.*, G.*, H, A.*, B.*, C.*, D, 2 * (rb + ind) + 12, 0);
    cround2Blocks(Wx, D.*, E.*, F.*, G, H.*, A.*, B.*, C, 2 * (rb + ind) + 13, 0);
    sha512MsgExpand2Blocks2Rounds(Wx, rb + ind + 7);
    cround2Blocks(Wx, C.*, D.*, E.*, F, G.*, H.*, A.*, B, 2 * (rb + ind) + 14, 0);
    cround2Blocks(Wx, B.*, C.*, D.*, E, F.*, G.*, H.*, A, 2 * (rb + ind) + 15, 0);
}

pub fn SymCryptSha512AppendBlocks_ymm_2blocks(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setEvalBranchQuota(10000);
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var Wx: Wx2BlocksArray align(32) = undefined;
    var w1: [4]V4U64 = undefined;
    var w2: [4]V4U64 = @splat(@splat(0));

    mm256Zeroupper();

    while (cbData >= SYMCRYPT_SHA512_INPUT_BLOCK_SIZE) {
        var numBlocks: SIZE_T = 1;
        w1[0] = loaduByteReverse64x2(pbData + 0 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 0 * 32);
        w1[1] = loaduByteReverse64x2(pbData + 0 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 1 * 32);
        w1[2] = loaduByteReverse64x2(pbData + 0 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 2 * 32);
        w1[3] = loaduByteReverse64x2(pbData + 0 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 3 * 32);

        if (cbData >= (2 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE)) {
            numBlocks = 2;
            w2[0] = loaduByteReverse64x2(pbData + 1 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 0 * 32);
            w2[1] = loaduByteReverse64x2(pbData + 1 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 1 * 32);
            w2[2] = loaduByteReverse64x2(pbData + 1 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 2 * 32);
            w2[3] = loaduByteReverse64x2(pbData + 1 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE + 3 * 32);
        }

        {
            var A = pChain.H[0];
            var B = pChain.H[1];
            var C = pChain.H[2];
            var D = pChain.H[3];
            var E = pChain.H[4];
            var F = pChain.H[5];
            var G = pChain.H[6];
            var H = pChain.H[7];

            Wx[0] = mm256Permute2x128_0x20(w1[0], w2[0]);
            Wx[1] = mm256Permute2x128_0x31(w1[0], w2[0]);
            Wx[2] = mm256Permute2x128_0x20(w1[1], w2[1]);
            Wx[3] = mm256Permute2x128_0x31(w1[1], w2[1]);
            Wx[4] = mm256Permute2x128_0x20(w1[2], w2[2]);
            Wx[5] = mm256Permute2x128_0x31(w1[2], w2[2]);
            Wx[6] = mm256Permute2x128_0x20(w1[3], w2[3]);
            Wx[7] = mm256Permute2x128_0x31(w1[3], w2[3]);

            sha512_2BlocksRoundStitched16x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 0, 0);
            sha512_2BlocksRoundStitched16x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 0, 8);
            sha512_2BlocksRoundStitched16x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 16, 0);
            sha512_2BlocksRoundStitched16x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 16, 8);

            cround2Blocks(&Wx, A, B, C, &D, E, F, G, &H, 64 + 0, 0);
            cround2Blocks(&Wx, H, A, B, &C, D, E, F, &G, 64 + 1, 0);
            cround2Blocks(&Wx, G, H, A, &B, C, D, E, &F, 64 + 2, 0);
            cround2Blocks(&Wx, F, G, H, &A, B, C, D, &E, 64 + 3, 0);
            cround2Blocks(&Wx, E, F, G, &H, A, B, C, &D, 64 + 4, 0);
            cround2Blocks(&Wx, D, E, F, &G, H, A, B, &C, 64 + 5, 0);
            cround2Blocks(&Wx, C, D, E, &F, G, H, A, &B, 64 + 6, 0);
            cround2Blocks(&Wx, B, C, D, &E, F, G, H, &A, 64 + 7, 0);

            cround2Blocks(&Wx, A, B, C, &D, E, F, G, &H, 72 + 0, 0);
            cround2Blocks(&Wx, H, A, B, &C, D, E, F, &G, 72 + 1, 0);
            cround2Blocks(&Wx, G, H, A, &B, C, D, E, &F, 72 + 2, 0);
            cround2Blocks(&Wx, F, G, H, &A, B, C, D, &E, 72 + 3, 0);
            cround2Blocks(&Wx, E, F, G, &H, A, B, C, &D, 72 + 4, 0);
            cround2Blocks(&Wx, D, E, F, &G, H, A, B, &C, 72 + 5, 0);
            cround2Blocks(&Wx, C, D, E, &F, G, H, A, &B, 72 + 6, 0);
            cround2Blocks(&Wx, B, C, D, &E, F, G, H, &A, 72 + 7, 0);

            pChain.H[0] +%= A;
            pChain.H[1] +%= B;
            pChain.H[2] +%= C;
            pChain.H[3] +%= D;
            pChain.H[4] +%= E;
            pChain.H[5] +%= F;
            pChain.H[6] +%= G;
            pChain.H[7] +%= H;
        }

        if (numBlocks > 1) {
            var A = pChain.H[0];
            var B = pChain.H[1];
            var C = pChain.H[2];
            var D = pChain.H[3];
            var E = pChain.H[4];
            var F = pChain.H[5];
            var G = pChain.H[6];
            var H = pChain.H[7];

            var iterCount: usize = 0;
            while (iterCount < (80 / 8)) : (iterCount += 1) {
                const roundBase = iterCount * 8;
                cround2Blocks(&Wx, A, B, C, &D, E, F, G, &H, roundBase + 0, 1);
                cround2Blocks(&Wx, H, A, B, &C, D, E, F, &G, roundBase + 1, 1);
                cround2Blocks(&Wx, G, H, A, &B, C, D, E, &F, roundBase + 2, 1);
                cround2Blocks(&Wx, F, G, H, &A, B, C, D, &E, roundBase + 3, 1);
                cround2Blocks(&Wx, E, F, G, &H, A, B, C, &D, roundBase + 4, 1);
                cround2Blocks(&Wx, D, E, F, &G, H, A, B, &C, roundBase + 5, 1);
                cround2Blocks(&Wx, C, D, E, &F, G, H, A, &B, roundBase + 6, 1);
                cround2Blocks(&Wx, B, C, D, &E, F, G, H, &A, roundBase + 7, 1);
            }

            pChain.H[0] +%= A;
            pChain.H[1] +%= B;
            pChain.H[2] +%= C;
            pChain.H[3] +%= D;
            pChain.H[4] +%= E;
            pChain.H[5] +%= F;
            pChain.H[6] +%= G;
            pChain.H[7] +%= H;
        }

        pbData += (numBlocks * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);
        cbData -= (numBlocks * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);
    }

    pcbRemaining.* = cbData;

    mm256Zeroupper();

    hash.SymCryptWipeKnownSize(@ptrCast(&Wx), @sizeOf(@TypeOf(Wx)));
    hash.SymCryptWipeKnownSize(@ptrCast(&w1), @sizeOf(@TypeOf(w1)));
    hash.SymCryptWipeKnownSize(@ptrCast(&w2), @sizeOf(@TypeOf(w2)));
}

// ============================================================================
// 4-Block YMM Implementation
// ============================================================================

const Wx4BlocksArray = [80]V4U64;

inline fn sha512MsgLoad4Blocks(Wx: *Wx4BlocksArray, pbData: PCBYTE, bl: usize) void {
    var i: usize = 0;
    while (i < bl) : (i += 1) {
        const base = i * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
        Wx[i + 0] = loaduByteReverse64x2(pbData + base + 0);
        Wx[i + 4] = loaduByteReverse64x2(pbData + base + 32);
        Wx[i + 8] = loaduByteReverse64x2(pbData + base + 64);
        Wx[i + 12] = loaduByteReverse64x2(pbData + base + 96);
    }
}

inline fn sha512MsgTransposeQuarter4Blocks(Wx: *Wx4BlocksArray, comptime ind: usize) void {
    const t1 = mm256UnpackloEpi64(Wx[4 * ind + 0], Wx[4 * ind + 1]);
    const t2 = mm256UnpackloEpi64(Wx[4 * ind + 2], Wx[4 * ind + 3]);
    const t3 = mm256UnpackhiEpi64(Wx[4 * ind + 0], Wx[4 * ind + 1]);
    const t4 = mm256UnpackhiEpi64(Wx[4 * ind + 2], Wx[4 * ind + 3]);
    Wx[4 * ind + 0] = mm256Permute2x128_0x20(t1, t2);
    Wx[4 * ind + 1] = mm256Permute2x128_0x20(t3, t4);
    Wx[4 * ind + 2] = mm256Permute2x128_0x31(t1, t2);
    Wx[4 * ind + 3] = mm256Permute2x128_0x31(t3, t4);
}

inline fn sha512MsgTranspose4Blocks(Wx: *Wx4BlocksArray) void {
    sha512MsgTransposeQuarter4Blocks(Wx, 0);
    sha512MsgTransposeQuarter4Blocks(Wx, 1);
    sha512MsgTransposeQuarter4Blocks(Wx, 2);
    sha512MsgTransposeQuarter4Blocks(Wx, 3);
}

inline fn sha512MsgExpand4Blocks1Round(Wx: *Wx4BlocksArray, r: usize) void {
    Wx[r] = Wx[r - 16] +% Wx[r - 7] +% ymmLsigma0(Wx[r - 15]) +% ymmLsigma1(Wx[r - 2]);
    Wx[r - 16] +%= @splat(SymCryptSha512K[r - 16]);
}

inline fn sha512MsgExpand4Blocks4Rounds(Wx: *Wx4BlocksArray, r: usize) void {
    sha512MsgExpand4Blocks1Round(Wx, r + 0);
    sha512MsgExpand4Blocks1Round(Wx, r + 1);
    sha512MsgExpand4Blocks1Round(Wx, r + 2);
    sha512MsgExpand4Blocks1Round(Wx, r + 3);
}

inline fn cround4Blocks(
    Wx: *const Wx4BlocksArray,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    bl: usize,
) void {
    const T1: UINT64 = csigma1(e) +% ch(e, f, g) +% @as([4]UINT64, Wx[r])[bl];
    const T2: UINT64 = csigma0(a) +% maj(a, b, c);
    h.* +%= T1;
    d.* +%= h.*;
    h.* +%= T2;
}

inline fn croundSingle(
    Wx_ul: *[16]UINT64,
    Wt: UINT64,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    comptime r16: usize,
) void {
    Wx_ul[r16] = Wt;
    const T1: UINT64 = csigma1(e) +% ch(e, f, g) +% Wt +% SymCryptSha512K[r];
    const T2: UINT64 = csigma0(a) +% maj(a, b, c);
    h.* +%= T1;
    d.* +%= h.*;
    h.* +%= T2;
}

inline fn iroundSingle(
    Wx_ul: *[16]UINT64,
    pbData: PCBYTE,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    comptime r: usize,
) void {
    const Wt = macros.LOAD_MSBFIRST64(pbData + 8 * r);
    croundSingle(Wx_ul, Wt, a, b, c, d, e, f, g, h, r, r);
}

inline fn froundSingle(
    Wx_ul: *[16]UINT64,
    a: UINT64,
    b: UINT64,
    c: UINT64,
    d: *UINT64,
    e: UINT64,
    f: UINT64,
    g: UINT64,
    h: *UINT64,
    r: usize,
    comptime r16: usize,
) void {
    const Wt = lsigma1(Wx_ul[(r16 + 16 - 2) & 15]) +% Wx_ul[(r16 + 16 - 7) & 15] +%
        lsigma0(Wx_ul[(r16 + 16 - 15) & 15]) +% Wx_ul[r16 & 15];
    croundSingle(Wx_ul, Wt, a, b, c, d, e, f, g, h, r, r16);
}

inline fn sha512_4BlocksFinalRounds8x(
    Wx: *Wx4BlocksArray,
    A: *UINT64,
    B: *UINT64,
    C: *UINT64,
    D: *UINT64,
    E: *UINT64,
    F: *UINT64,
    G: *UINT64,
    H: *UINT64,
    comptime rnd: usize,
) void {
    Wx[rnd + 0] +%= @splat(SymCryptSha512K[rnd + 0]);
    Wx[rnd + 1] +%= @splat(SymCryptSha512K[rnd + 1]);
    Wx[rnd + 2] +%= @splat(SymCryptSha512K[rnd + 2]);
    Wx[rnd + 3] +%= @splat(SymCryptSha512K[rnd + 3]);
    cround4Blocks(Wx, A.*, B.*, C.*, D, E.*, F.*, G.*, H, rnd + 0, 0);
    cround4Blocks(Wx, H.*, A.*, B.*, C, D.*, E.*, F.*, G, rnd + 1, 0);
    cround4Blocks(Wx, G.*, H.*, A.*, B, C.*, D.*, E.*, F, rnd + 2, 0);
    cround4Blocks(Wx, F.*, G.*, H.*, A, B.*, C.*, D.*, E, rnd + 3, 0);
    Wx[rnd + 4] +%= @splat(SymCryptSha512K[rnd + 4]);
    Wx[rnd + 5] +%= @splat(SymCryptSha512K[rnd + 5]);
    Wx[rnd + 6] +%= @splat(SymCryptSha512K[rnd + 6]);
    Wx[rnd + 7] +%= @splat(SymCryptSha512K[rnd + 7]);
    cround4Blocks(Wx, E.*, F.*, G.*, H, A.*, B.*, C.*, D, rnd + 4, 0);
    cround4Blocks(Wx, D.*, E.*, F.*, G, H.*, A.*, B.*, C, rnd + 5, 0);
    cround4Blocks(Wx, C.*, D.*, E.*, F, G.*, H.*, A.*, B, rnd + 6, 0);
    cround4Blocks(Wx, B.*, C.*, D.*, E, F.*, G.*, H.*, A, rnd + 7, 0);
}

pub fn SymCryptSha512AppendBlocks_ymm_4blocks(
    pChain: *SYMCRYPT_SHA512_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    @setEvalBranchQuota(10000);
    @setRuntimeSafety(false);
    var pbData = pbData_in;
    var cbData = cbData_in;

    var Wx: Wx4BlocksArray align(32) = undefined;
    const Wx_ul: *[16]UINT64 = @ptrCast(&Wx);
    const uWipeSize: UINT32 = if (cbData >= (3 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE))
        (80 * 4 * @sizeOf(UINT64))
    else
        (16 * @sizeOf(UINT64));

    mm256Zeroupper();

    while (cbData >= (3 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE)) {
        const numBlocks: SIZE_T = if (cbData >= 4 * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE)
            4
        else
            (cbData / SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);

        sha512MsgLoad4Blocks(&Wx, pbData, numBlocks);
        sha512MsgTranspose4Blocks(&Wx);

        var A = pChain.H[0];
        var B = pChain.H[1];
        var C = pChain.H[2];
        var D = pChain.H[3];
        var E = pChain.H[4];
        var F = pChain.H[5];
        var G = pChain.H[6];
        var H = pChain.H[7];

        var iterCount: usize = 0;
        while (iterCount < (64 / 8)) : (iterCount += 1) {
            const roundBase = iterCount * 8;

            sha512MsgExpand4Blocks4Rounds(&Wx, roundBase + 16);
            cround4Blocks(&Wx, A, B, C, &D, E, F, G, &H, roundBase + 0, 0);
            cround4Blocks(&Wx, H, A, B, &C, D, E, F, &G, roundBase + 1, 0);
            cround4Blocks(&Wx, G, H, A, &B, C, D, E, &F, roundBase + 2, 0);
            cround4Blocks(&Wx, F, G, H, &A, B, C, D, &E, roundBase + 3, 0);

            sha512MsgExpand4Blocks4Rounds(&Wx, roundBase + 20);
            cround4Blocks(&Wx, E, F, G, &H, A, B, C, &D, roundBase + 4, 0);
            cround4Blocks(&Wx, D, E, F, &G, H, A, B, &C, roundBase + 5, 0);
            cround4Blocks(&Wx, C, D, E, &F, G, H, A, &B, roundBase + 6, 0);
            cround4Blocks(&Wx, B, C, D, &E, F, G, H, &A, roundBase + 7, 0);
        }

        sha512_4BlocksFinalRounds8x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 64);
        sha512_4BlocksFinalRounds8x(&Wx, &A, &B, &C, &D, &E, &F, &G, &H, 72);

        pChain.H[0] +%= A;
        pChain.H[1] +%= B;
        pChain.H[2] +%= C;
        pChain.H[3] +%= D;
        pChain.H[4] +%= E;
        pChain.H[5] +%= F;
        pChain.H[6] +%= G;
        pChain.H[7] +%= H;

        var bl: usize = 1;
        while (bl < numBlocks) : (bl += 1) {
            A = pChain.H[0];
            B = pChain.H[1];
            C = pChain.H[2];
            D = pChain.H[3];
            E = pChain.H[4];
            F = pChain.H[5];
            G = pChain.H[6];
            H = pChain.H[7];

            iterCount = 0;
            while (iterCount < (80 / 8)) : (iterCount += 1) {
                const roundBase = iterCount * 8;

                cround4Blocks(&Wx, A, B, C, &D, E, F, G, &H, roundBase + 0, bl);
                cround4Blocks(&Wx, H, A, B, &C, D, E, F, &G, roundBase + 1, bl);
                cround4Blocks(&Wx, G, H, A, &B, C, D, E, &F, roundBase + 2, bl);
                cround4Blocks(&Wx, F, G, H, &A, B, C, D, &E, roundBase + 3, bl);
                cround4Blocks(&Wx, E, F, G, &H, A, B, C, &D, roundBase + 4, bl);
                cround4Blocks(&Wx, D, E, F, &G, H, A, B, &C, roundBase + 5, bl);
                cround4Blocks(&Wx, C, D, E, &F, G, H, A, &B, roundBase + 6, bl);
                cround4Blocks(&Wx, B, C, D, &E, F, G, H, &A, roundBase + 7, bl);
            }

            pChain.H[0] +%= A;
            pChain.H[1] +%= B;
            pChain.H[2] +%= C;
            pChain.H[3] +%= D;
            pChain.H[4] +%= E;
            pChain.H[5] +%= F;
            pChain.H[6] +%= G;
            pChain.H[7] +%= H;
        }

        pbData += (numBlocks * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);
        cbData -= (numBlocks * SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);
    }

    mm256Zeroupper();

    while (cbData >= SYMCRYPT_SHA512_INPUT_BLOCK_SIZE) {
        var A = pChain.H[0];
        var B = pChain.H[1];
        var C = pChain.H[2];
        var D = pChain.H[3];
        var E = pChain.H[4];
        var F = pChain.H[5];
        var G = pChain.H[6];
        var H = pChain.H[7];

        iroundSingle(Wx_ul, pbData, A, B, C, &D, E, F, G, &H, 0);
        iroundSingle(Wx_ul, pbData, H, A, B, &C, D, E, F, &G, 1);
        iroundSingle(Wx_ul, pbData, G, H, A, &B, C, D, E, &F, 2);
        iroundSingle(Wx_ul, pbData, F, G, H, &A, B, C, D, &E, 3);
        iroundSingle(Wx_ul, pbData, E, F, G, &H, A, B, C, &D, 4);
        iroundSingle(Wx_ul, pbData, D, E, F, &G, H, A, B, &C, 5);
        iroundSingle(Wx_ul, pbData, C, D, E, &F, G, H, A, &B, 6);
        iroundSingle(Wx_ul, pbData, B, C, D, &E, F, G, H, &A, 7);
        iroundSingle(Wx_ul, pbData, A, B, C, &D, E, F, G, &H, 8);
        iroundSingle(Wx_ul, pbData, H, A, B, &C, D, E, F, &G, 9);
        iroundSingle(Wx_ul, pbData, G, H, A, &B, C, D, E, &F, 10);
        iroundSingle(Wx_ul, pbData, F, G, H, &A, B, C, D, &E, 11);
        iroundSingle(Wx_ul, pbData, E, F, G, &H, A, B, C, &D, 12);
        iroundSingle(Wx_ul, pbData, D, E, F, &G, H, A, B, &C, 13);
        iroundSingle(Wx_ul, pbData, C, D, E, &F, G, H, A, &B, 14);
        iroundSingle(Wx_ul, pbData, B, C, D, &E, F, G, H, &A, 15);

        var iterCount: usize = 1;
        while (iterCount < (80 / 16)) : (iterCount += 1) {
            const roundBase = iterCount * 16;

            froundSingle(Wx_ul, A, B, C, &D, E, F, G, &H, roundBase + 0, 0);
            froundSingle(Wx_ul, H, A, B, &C, D, E, F, &G, roundBase + 1, 1);
            froundSingle(Wx_ul, G, H, A, &B, C, D, E, &F, roundBase + 2, 2);
            froundSingle(Wx_ul, F, G, H, &A, B, C, D, &E, roundBase + 3, 3);
            froundSingle(Wx_ul, E, F, G, &H, A, B, C, &D, roundBase + 4, 4);
            froundSingle(Wx_ul, D, E, F, &G, H, A, B, &C, roundBase + 5, 5);
            froundSingle(Wx_ul, C, D, E, &F, G, H, A, &B, roundBase + 6, 6);
            froundSingle(Wx_ul, B, C, D, &E, F, G, H, &A, roundBase + 7, 7);
            froundSingle(Wx_ul, A, B, C, &D, E, F, G, &H, roundBase + 8, 8);
            froundSingle(Wx_ul, H, A, B, &C, D, E, F, &G, roundBase + 9, 9);
            froundSingle(Wx_ul, G, H, A, &B, C, D, E, &F, roundBase + 10, 10);
            froundSingle(Wx_ul, F, G, H, &A, B, C, D, &E, roundBase + 11, 11);
            froundSingle(Wx_ul, E, F, G, &H, A, B, C, &D, roundBase + 12, 12);
            froundSingle(Wx_ul, D, E, F, &G, H, A, B, &C, roundBase + 13, 13);
            froundSingle(Wx_ul, C, D, E, &F, G, H, A, &B, roundBase + 14, 14);
            froundSingle(Wx_ul, B, C, D, &E, F, G, H, &A, roundBase + 15, 15);
        }

        pChain.H[0] +%= A;
        pChain.H[1] +%= B;
        pChain.H[2] +%= C;
        pChain.H[3] +%= D;
        pChain.H[4] +%= E;
        pChain.H[5] +%= F;
        pChain.H[6] +%= G;
        pChain.H[7] +%= H;

        pbData += SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
        cbData -= SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
    }

    pcbRemaining.* = cbData;

    hash.SymCryptWipe(@ptrCast(&Wx), uWipeSize);
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&BYTE_REVERSE_64X2, .{ .name = "BYTE_REVERSE_64X2" });
        @export(&BYTE_ROTATE_64, .{ .name = "BYTE_ROTATE_64" });
        @export(&SymCryptSha512AppendBlocks_ymm_1block, .{ .name = "SymCryptSha512AppendBlocks_ymm_1block" });
        @export(&SymCryptSha512AppendBlocks_ymm_2blocks, .{ .name = "SymCryptSha512AppendBlocks_ymm_2blocks" });
        @export(&SymCryptSha512AppendBlocks_ymm_4blocks, .{ .name = "SymCryptSha512AppendBlocks_ymm_4blocks" });
    }
}
