//
// sha512_par_ymm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// All YMM code for SHA-512/SHA-384 Parallel operations, ported from lib/sha512Par-ymm.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const sha512 = @import("sha512.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PSYMCRYPT_SHA512_CHAINING_STATE = sha512.PSYMCRYPT_SHA512_CHAINING_STATE;
const SymCryptSha512K = &sha512.SymCryptSha512K;

const V4U64 = @Vector(4, u64);
const V32U8 = @Vector(32, u8);

inline fn mm256Zeroupper() void {
    if (comptime (builtin.cpu.arch == .x86_64 or builtin.cpu.arch == .x86) and
        std.Target.x86.featureSetHas(builtin.cpu.features, .avx))
    {
        asm volatile ("vzeroupper");
    }
}

inline fn majYmm(x: V4U64, y: V4U64, z: V4U64) V4U64 {
    return ((z | y) & x) | (z & y);
}

inline fn chYmm(x: V4U64, y: V4U64, z: V4U64) V4U64 {
    return ((z ^ y) & x) ^ z;
}

inline fn csigma0Ymm(x: V4U64) V4U64 {
    return (x << @splat(36)) ^ (x >> @splat(28)) ^
        (x << @splat(30)) ^ (x >> @splat(34)) ^
        (x << @splat(25)) ^ (x >> @splat(39));
}

inline fn csigma1Ymm(x: V4U64) V4U64 {
    return (x << @splat(50)) ^ (x >> @splat(14)) ^
        (x << @splat(46)) ^ (x >> @splat(18)) ^
        (x << @splat(23)) ^ (x >> @splat(41));
}

inline fn lsigma0Ymm(x: V4U64) V4U64 {
    return (x << @splat(63)) ^ (x >> @splat(1)) ^
        (x << @splat(56)) ^ (x >> @splat(8)) ^
        (x >> @splat(7));
}

inline fn lsigma1Ymm(x: V4U64) V4U64 {
    return (x << @splat(45)) ^ (x >> @splat(19)) ^
        (x << @splat(3)) ^ (x >> @splat(61)) ^
        (x >> @splat(6));
}

inline fn loadu256(ptr: PCBYTE) V4U64 {
    return @bitCast(std.mem.readInt(u256, ptr[0..32], .little));
}

inline fn storeu256(ptr: [*]u8, v: V4U64) void {
    std.mem.writeInt(u256, ptr[0..32], @bitCast(v), .little);
}

inline fn byteReverse64(v: V4U64) V4U64 {
    const raw: V32U8 = @bitCast(v);
    const rev = @shuffle(u8, raw, undefined, [32]i32{
        7,  6,  5,  4,  3,  2,  1,  0,
        15, 14, 13, 12, 11, 10, 9,  8,
        23, 22, 21, 20, 19, 18, 17, 16,
        31, 30, 29, 28, 27, 26, 25, 24,
    });
    return @bitCast(rev);
}

inline fn ymmTranspose64(
    r0: *V4U64,
    r1: *V4U64,
    r2: *V4U64,
    r3: *V4U64,
    s0: V4U64,
    s1: V4U64,
    s2: V4U64,
    s3: V4U64,
) void {
    const t0 = @shuffle(u64, s0, s1, [4]i32{ 0, -1, 2, -3 });
    const t1 = @shuffle(u64, s0, s1, [4]i32{ 1, -2, 3, -4 });
    const t2 = @shuffle(u64, s2, s3, [4]i32{ 0, -1, 2, -3 });
    const t3 = @shuffle(u64, s2, s3, [4]i32{ 1, -2, 3, -4 });

    r0.* = @shuffle(u64, t0, t2, [4]i32{ 0, 1, -1, -2 });
    r1.* = @shuffle(u64, t1, t3, [4]i32{ 0, 1, -1, -2 });
    r2.* = @shuffle(u64, t0, t2, [4]i32{ 2, 3, -3, -4 });
    r3.* = @shuffle(u64, t1, t3, [4]i32{ 2, 3, -3, -4 });
}

inline fn expand(W: [*]V4U64, b: *V4U64, c: *V4U64, d: V4U64, r: usize) void {
    c.* = W[r - 15];
    b.* = d +% lsigma1Ymm(b.*) +% W[r - 7] +% lsigma0Ymm(c.*);
    W[r] = b.*;
}

inline fn doRound(buf: [*]V4U64, a: V4U64, b: V4U64, c: V4U64, d: *V4U64, r: usize) void {
    const wBase: usize = 12;
    var t: V4U64 = buf[wBase + r];
    t +%= csigma1Ymm(buf[wBase + r - 5]);
    t +%= buf[wBase + r - 8];
    t +%= chYmm(buf[wBase + r - 5], buf[wBase + r - 6], buf[wBase + r - 7]);
    t +%= @splat(SymCryptSha512K[r]);
    buf[wBase + r - 4] = t +% d.*;
    d.* = t +% csigma0Ymm(a) +% majYmm(c, b, a);
}

pub fn SymCryptParallelSha512AppendBlocks_ymm(
    pChain: [*]PSYMCRYPT_SHA512_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes_in: SIZE_T,
    pScratch: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var nBytes = nBytes_in;
    const buf: [*]V4U64 = @ptrCast(@alignCast(pScratch));
    const ha: [*]V4U64 = buf + 4;
    const W: [*]V4U64 = buf + 12;

    mm256Zeroupper();

    var T0 = loadu256(@ptrCast(&pChain[0].H[0]));
    var T1 = loadu256(@ptrCast(&pChain[1].H[0]));
    var T2 = loadu256(@ptrCast(&pChain[2].H[0]));
    var T3 = loadu256(@ptrCast(&pChain[3].H[0]));

    ymmTranspose64(&ha[7], &ha[6], &ha[5], &ha[4], T0, T1, T2, T3);

    T0 = loadu256(@ptrCast(&pChain[0].H[4]));
    T1 = loadu256(@ptrCast(&pChain[1].H[4]));
    T2 = loadu256(@ptrCast(&pChain[2].H[4]));
    T3 = loadu256(@ptrCast(&pChain[3].H[4]));

    ymmTranspose64(&ha[3], &ha[2], &ha[1], &ha[0], T0, T1, T2, T3);

    buf[0] = ha[4];
    buf[1] = ha[5];
    buf[2] = ha[6];
    buf[3] = ha[7];

    while (nBytes >= 128) {
        var r: usize = 0;
        while (r < 16) : (r += 4) {
            T0 = byteReverse64(loadu256(ppByte[0]));
            ppByte[0] += 32;
            T1 = byteReverse64(loadu256(ppByte[1]));
            ppByte[1] += 32;
            T2 = byteReverse64(loadu256(ppByte[2]));
            ppByte[2] += 32;
            T3 = byteReverse64(loadu256(ppByte[3]));
            ppByte[3] += 32;

            ymmTranspose64(&W[r], &W[r + 1], &W[r + 2], &W[r + 3], T0, T1, T2, T3);
        }

        var A: V4U64 = W[15];
        var B: V4U64 = W[14];
        var C: V4U64 = undefined;
        var D: V4U64 = W[0];

        r = 16;
        while (r < 80) : (r += 2) {
            expand(W, &B, &C, D, r);
            expand(W, &A, &D, C, r + 1);
        }

        A = ha[7];
        B = ha[6];
        C = ha[5];
        D = ha[4];

        r = 0;
        while (r < 80) : (r += 4) {
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
        ha[3] +%= buf[12 + 80 - 5];
        ha[2] +%= buf[12 + 80 - 6];
        ha[1] +%= buf[12 + 80 - 7];
        ha[0] +%= buf[12 + 80 - 8];

        nBytes -= 128;
    }

    ymmTranspose64(&T0, &T1, &T2, &T3, ha[7], ha[6], ha[5], ha[4]);
    storeu256(@ptrCast(&pChain[0].H[0]), T0);
    storeu256(@ptrCast(&pChain[1].H[0]), T1);
    storeu256(@ptrCast(&pChain[2].H[0]), T2);
    storeu256(@ptrCast(&pChain[3].H[0]), T3);

    ymmTranspose64(&T0, &T1, &T2, &T3, ha[3], ha[2], ha[1], ha[0]);
    storeu256(@ptrCast(&pChain[0].H[4]), T0);
    storeu256(@ptrCast(&pChain[1].H[4]), T1);
    storeu256(@ptrCast(&pChain[2].H[4]), T2);
    storeu256(@ptrCast(&pChain[3].H[4]), T3);

    mm256Zeroupper();
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptParallelSha512AppendBlocks_ymm, .{ .name = "SymCryptParallelSha512AppendBlocks_ymm" });
    }
}
