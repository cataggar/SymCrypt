//
// sha256_par_ymm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// All YMM code for SHA256 Parallel operations, ported from lib/sha256Par-ymm.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const sha256 = @import("sha256.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PSYMCRYPT_SHA256_CHAINING_STATE = sha256.PSYMCRYPT_SHA256_CHAINING_STATE;
const SymCryptSha256K = &sha256.SymCryptSha256K;

const V8U32 = @Vector(8, u32);
const V32U8 = @Vector(32, u8);

inline fn mm256Zeroupper() void {
    if (comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx))
    {
        asm volatile ("vzeroupper");
    }
}

inline fn majYmm(x: V8U32, y: V8U32, z: V8U32) V8U32 {
    return ((z | y) & x) | (z & y);
}

inline fn chYmm(x: V8U32, y: V8U32, z: V8U32) V8U32 {
    return ((z ^ y) & x) ^ z;
}

inline fn csigma0Ymm(x: V8U32) V8U32 {
    return (x << @splat(30)) ^ (x >> @splat(2)) ^
        (x << @splat(19)) ^ (x >> @splat(13)) ^
        (x << @splat(10)) ^ (x >> @splat(22));
}

inline fn csigma1Ymm(x: V8U32) V8U32 {
    return (x << @splat(26)) ^ (x >> @splat(6)) ^
        (x << @splat(21)) ^ (x >> @splat(11)) ^
        (x << @splat(7)) ^ (x >> @splat(25));
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

inline fn loadu256(ptr: PCBYTE) V8U32 {
    return @bitCast(std.mem.readInt(u256, ptr[0..32], .little));
}

inline fn storeu256(ptr: [*]u8, v: V8U32) void {
    std.mem.writeInt(u256, ptr[0..32], @bitCast(v), .little);
}

inline fn byteReverse32(v: V8U32) V8U32 {
    const raw: V32U8 = @bitCast(v);
    const rev = @shuffle(u8, raw, undefined, [32]i32{
        3,  2,  1,  0,  7,  6,  5,  4,  11, 10, 9,  8,  15, 14, 13, 12,
        19, 18, 17, 16, 23, 22, 21, 20, 27, 26, 25, 24, 31, 30, 29, 28,
    });
    return @bitCast(rev);
}

inline fn ymmTranspose32(
    r0: *V8U32,
    r1: *V8U32,
    r2: *V8U32,
    r3: *V8U32,
    r4: *V8U32,
    r5: *V8U32,
    r6: *V8U32,
    r7: *V8U32,
    s0: V8U32,
    s1: V8U32,
    s2: V8U32,
    s3: V8U32,
    s4: V8U32,
    s5: V8U32,
    s6: V8U32,
    s7: V8U32,
) void {
    const t0 = @shuffle(u32, s0, s1, [8]i32{ 0, -1, 1, -2, 4, -5, 5, -6 });
    const t1 = @shuffle(u32, s0, s1, [8]i32{ 2, -3, 3, -4, 6, -7, 7, -8 });
    const t2 = @shuffle(u32, s2, s3, [8]i32{ 0, -1, 1, -2, 4, -5, 5, -6 });
    const t3 = @shuffle(u32, s2, s3, [8]i32{ 2, -3, 3, -4, 6, -7, 7, -8 });
    const t4 = @shuffle(u32, s4, s5, [8]i32{ 0, -1, 1, -2, 4, -5, 5, -6 });
    const t5 = @shuffle(u32, s4, s5, [8]i32{ 2, -3, 3, -4, 6, -7, 7, -8 });
    const t6 = @shuffle(u32, s6, s7, [8]i32{ 0, -1, 1, -2, 4, -5, 5, -6 });
    const t7 = @shuffle(u32, s6, s7, [8]i32{ 2, -3, 3, -4, 6, -7, 7, -8 });

    const u_0 = @shuffle(u32, t0, t2, [8]i32{ 0, 1, -1, -2, 4, 5, -5, -6 });
    const u_1 = @shuffle(u32, t0, t2, [8]i32{ 2, 3, -3, -4, 6, 7, -7, -8 });
    const u_2 = @shuffle(u32, t1, t3, [8]i32{ 0, 1, -1, -2, 4, 5, -5, -6 });
    const u_3 = @shuffle(u32, t1, t3, [8]i32{ 2, 3, -3, -4, 6, 7, -7, -8 });
    const u_4 = @shuffle(u32, t4, t6, [8]i32{ 0, 1, -1, -2, 4, 5, -5, -6 });
    const u_5 = @shuffle(u32, t4, t6, [8]i32{ 2, 3, -3, -4, 6, 7, -7, -8 });
    const u_6 = @shuffle(u32, t5, t7, [8]i32{ 0, 1, -1, -2, 4, 5, -5, -6 });
    const u_7 = @shuffle(u32, t5, t7, [8]i32{ 2, 3, -3, -4, 6, 7, -7, -8 });

    r0.* = @shuffle(u32, u_0, u_4, [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
    r1.* = @shuffle(u32, u_1, u_5, [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
    r2.* = @shuffle(u32, u_2, u_6, [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
    r3.* = @shuffle(u32, u_3, u_7, [8]i32{ 0, 1, 2, 3, -1, -2, -3, -4 });
    r4.* = @shuffle(u32, u_0, u_4, [8]i32{ 4, 5, 6, 7, -5, -6, -7, -8 });
    r5.* = @shuffle(u32, u_1, u_5, [8]i32{ 4, 5, 6, 7, -5, -6, -7, -8 });
    r6.* = @shuffle(u32, u_2, u_6, [8]i32{ 4, 5, 6, 7, -5, -6, -7, -8 });
    r7.* = @shuffle(u32, u_3, u_7, [8]i32{ 4, 5, 6, 7, -5, -6, -7, -8 });
}

inline fn expand(W: [*]V8U32, b: *V8U32, c: *V8U32, d: V8U32, r: usize) void {
    c.* = W[r - 15];
    b.* = d +% lsigma1Ymm(b.*) +% W[r - 7] +% lsigma0Ymm(c.*);
    W[r] = b.*;
}

inline fn doRound(buf: [*]V8U32, a: V8U32, b: V8U32, c: V8U32, d: *V8U32, r: usize) void {
    const wBase: usize = 12;
    var t: V8U32 = buf[wBase + r];
    t +%= csigma1Ymm(buf[wBase + r - 5]);
    t +%= buf[wBase + r - 8];
    t +%= chYmm(buf[wBase + r - 5], buf[wBase + r - 6], buf[wBase + r - 7]);
    t +%= @splat(SymCryptSha256K[r]);
    buf[wBase + r - 4] = t +% d.*;
    d.* = t +% csigma0Ymm(a) +% majYmm(c, b, a);
}

pub fn SymCryptParallelSha256AppendBlocks_ymm(
    pChain: [*]PSYMCRYPT_SHA256_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes_in: SIZE_T,
    pScratch: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var nBytes = nBytes_in;
    const buf: [*]V8U32 = @ptrCast(@alignCast(pScratch));
    const ha: [*]V8U32 = buf + 4;
    const W: [*]V8U32 = buf + 12;

    mm256Zeroupper();

    var T0 = loadu256(@ptrCast(&pChain[0].H[0]));
    var T1 = loadu256(@ptrCast(&pChain[1].H[0]));
    var T2 = loadu256(@ptrCast(&pChain[2].H[0]));
    var T3 = loadu256(@ptrCast(&pChain[3].H[0]));
    var T4 = loadu256(@ptrCast(&pChain[4].H[0]));
    var T5 = loadu256(@ptrCast(&pChain[5].H[0]));
    var T6 = loadu256(@ptrCast(&pChain[6].H[0]));
    var T7 = loadu256(@ptrCast(&pChain[7].H[0]));

    ymmTranspose32(&ha[7], &ha[6], &ha[5], &ha[4], &ha[3], &ha[2], &ha[1], &ha[0], T0, T1, T2, T3, T4, T5, T6, T7);

    buf[0] = ha[4];
    buf[1] = ha[5];
    buf[2] = ha[6];
    buf[3] = ha[7];

    while (nBytes >= 64) {
        var r: usize = 0;
        while (r < 16) : (r += 8) {
            T0 = byteReverse32(loadu256(ppByte[0]));
            ppByte[0] += 32;
            T1 = byteReverse32(loadu256(ppByte[1]));
            ppByte[1] += 32;
            T2 = byteReverse32(loadu256(ppByte[2]));
            ppByte[2] += 32;
            T3 = byteReverse32(loadu256(ppByte[3]));
            ppByte[3] += 32;
            T4 = byteReverse32(loadu256(ppByte[4]));
            ppByte[4] += 32;
            T5 = byteReverse32(loadu256(ppByte[5]));
            ppByte[5] += 32;
            T6 = byteReverse32(loadu256(ppByte[6]));
            ppByte[6] += 32;
            T7 = byteReverse32(loadu256(ppByte[7]));
            ppByte[7] += 32;

            ymmTranspose32(&W[r], &W[r + 1], &W[r + 2], &W[r + 3], &W[r + 4], &W[r + 5], &W[r + 6], &W[r + 7], T0, T1, T2, T3, T4, T5, T6, T7);
        }

        var A: V8U32 = W[15];
        var B: V8U32 = W[14];
        var C: V8U32 = undefined;
        var D: V8U32 = W[0];

        r = 16;
        while (r < 64) : (r += 2) {
            expand(W, &B, &C, D, r);
            expand(W, &A, &D, C, r + 1);
        }

        A = ha[7];
        B = ha[6];
        C = ha[5];
        D = ha[4];

        r = 0;
        while (r < 64) : (r += 4) {
            doRound(buf, A, B, C, &D, r);
            doRound(buf, D, A, B, &C, r + 1);
            doRound(buf, C, D, A, &B, r + 2);
            doRound(buf, B, C, D, &A, r + 3);
        }

        ha[7] = buf[3] +% A;
        buf[3] = ha[7];
        ha[6] = buf[2] +% B;
        buf[2] = ha[6];
        ha[5] = buf[1] +% C;
        buf[1] = ha[5];
        ha[4] = buf[0] +% D;
        buf[0] = ha[4];
        ha[3] +%= buf[12 + 64 - 5];
        ha[2] +%= buf[12 + 64 - 6];
        ha[1] +%= buf[12 + 64 - 7];
        ha[0] +%= buf[12 + 64 - 8];

        nBytes -= 64;
    }

    ymmTranspose32(&T0, &T1, &T2, &T3, &T4, &T5, &T6, &T7, ha[7], ha[6], ha[5], ha[4], ha[3], ha[2], ha[1], ha[0]);
    storeu256(@ptrCast(&pChain[0].H[0]), T0);
    storeu256(@ptrCast(&pChain[1].H[0]), T1);
    storeu256(@ptrCast(&pChain[2].H[0]), T2);
    storeu256(@ptrCast(&pChain[3].H[0]), T3);
    storeu256(@ptrCast(&pChain[4].H[0]), T4);
    storeu256(@ptrCast(&pChain[5].H[0]), T5);
    storeu256(@ptrCast(&pChain[6].H[0]), T6);
    storeu256(@ptrCast(&pChain[7].H[0]), T7);

    mm256Zeroupper();
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptParallelSha256AppendBlocks_ymm, .{ .name = "SymCryptParallelSha256AppendBlocks_ymm" });
    }
}
