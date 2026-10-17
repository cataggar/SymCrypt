//
// sha256_par.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement SHA2-256 from FIPS 180-2 in parallel mode,
// ported from lib/sha256Par.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha256 = @import("sha256.zig");
const parhash = @import("parhash.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

const SYMCRYPT_SHA256_RESULT_SIZE = sha256.SYMCRYPT_SHA256_RESULT_SIZE;
const SYMCRYPT_SHA256_INPUT_BLOCK_SIZE = sha256.SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
const SYMCRYPT_SHA256_STATE = sha256.SYMCRYPT_SHA256_STATE;
const PSYMCRYPT_SHA256_STATE = sha256.PSYMCRYPT_SHA256_STATE;
const SYMCRYPT_SHA256_CHAINING_STATE = sha256.SYMCRYPT_SHA256_CHAINING_STATE;
const PSYMCRYPT_SHA256_CHAINING_STATE = sha256.PSYMCRYPT_SHA256_CHAINING_STATE;

const PSYMCRYPT_COMMON_HASH_STATE = hash.PSYMCRYPT_COMMON_HASH_STATE;
const SYMCRYPT_PARALLEL_HASH = parhash.SYMCRYPT_PARALLEL_HASH;
const PCSYMCRYPT_PARALLEL_HASH = parhash.PCSYMCRYPT_PARALLEL_HASH;
const SYMCRYPT_PARALLEL_HASH_OPERATION = parhash.SYMCRYPT_PARALLEL_HASH_OPERATION;
const PCSYMRYPT_PARALLEL_HASH_OPERATION = parhash.PCSYMRYPT_PARALLEL_HASH_OPERATION;
const PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = parhash.PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE;
const PAR_SCRATCH_ELEMENTS_256 = parhash.PAR_SCRATCH_ELEMENTS_256;
const SYMCRYPT_SIMD_ELEMENT_SIZE = parhash.SYMCRYPT_SIMD_ELEMENT_SIZE;

// ==============================================================================================
// Platform Configuration & CPU Feature Helpers
// ==============================================================================================

const SUPPORT_PARALLEL: bool = types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM;
const MIN_PARALLEL: usize = if (types.CPU_X86 or types.CPU_AMD64) 2 else if (types.CPU_ARM) 3 else 1;
const MAX_PARALLEL: usize = if (types.CPU_X86 or types.CPU_AMD64) 8 else if (types.CPU_ARM) 4 else 1;

const SYMCRYPT_CPU_FEATURES = UINT32;
extern var g_SymCryptCpuFeaturesNotPresent: SYMCRYPT_CPU_FEATURES;
extern fn SymCryptCpuFeaturesNeverPresent() callconv(SYMCRYPT_CALL) SYMCRYPT_CPU_FEATURES;

inline fn cpuFeaturesPresent(features: SYMCRYPT_CPU_FEATURES) bool {
    return ((features & SymCryptCpuFeaturesNeverPresent()) == 0) and ((features & g_SymCryptCpuFeaturesNotPresent) == 0);
}

const SYMCRYPT_XSTATE_SAVE_SIZE: usize = if (builtin.cpu.arch == .x86) 32 else 56;
const SYMCRYPT_EXTENDED_SAVE_DATA = extern struct {
    data: [SYMCRYPT_XSTATE_SAVE_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

extern fn SymCryptSaveXmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptRestoreXmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptSaveYmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptRestoreYmm(pSaveData: *SYMCRYPT_EXTENDED_SAVE_DATA) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptParallelSha256AppendBlocks_ymm(
    pChain: [*]PSYMCRYPT_SHA256_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes: SIZE_T,
    pScratch: PBYTE,
) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// Init & Process Functions
// ==============================================================================================

pub export fn SymCryptParallelSha256Init(
    pStates: [*]SYMCRYPT_SHA256_STATE,
    nStates: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var i: SIZE_T = 0;
    while (i < nStates) : (i += 1) {
        sha256.SymCryptSha256Init(&pStates[i]);
    }
}

pub export fn SymCryptParallelSha256Result1(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pScratch: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    pRes: *BOOLEAN,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    _ = pParHash;
    var bytesInBuffer: UINT32 = pState.bytesInBuffer;
    const stateBuf: [*]BYTE = @ptrCast(&pState.buffer);

    stateBuf[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;
    hash.SymCryptWipe(@ptrCast(stateBuf + bytesInBuffer), SYMCRYPT_SHA256_INPUT_BLOCK_SIZE - bytesInBuffer);

    pScratch.pbData = stateBuf;
    pScratch.cbData = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;

    if (bytesInBuffer > SYMCRYPT_SHA256_INPUT_BLOCK_SIZE - 8) {
        pScratch.processingState = parhash.STATE_RESULT2;
    } else {
        macros.STORE_MSBFIRST64(stateBuf + (SYMCRYPT_SHA256_INPUT_BLOCK_SIZE - 8), pState.dataLengthL *% 8);
        pScratch.processingState = parhash.STATE_RESULT_DONE;
    }

    pRes.* = types.TRUE;
    return types.TRUE;
}

pub export fn SymCryptParallelSha256Result2(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pScratch: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    pRes: *BOOLEAN,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    _ = pParHash;
    const stateBuf: [*]BYTE = @ptrCast(&pState.buffer);

    hash.SymCryptWipe(@ptrCast(stateBuf), SYMCRYPT_SHA256_INPUT_BLOCK_SIZE);
    macros.STORE_MSBFIRST64(stateBuf + (SYMCRYPT_SHA256_INPUT_BLOCK_SIZE - 8), pState.dataLengthL *% 8);
    pScratch.pbData = stateBuf;
    pScratch.cbData = SYMCRYPT_SHA256_INPUT_BLOCK_SIZE;
    pScratch.processingState = parhash.STATE_RESULT_DONE;
    pRes.* = types.TRUE;
    return types.TRUE;
}

pub export fn SymCryptParallelSha256ResultDone(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pOp: PCSYMRYPT_PARALLEL_HASH_OPERATION,
) callconv(SYMCRYPT_CALL) void {
    _ = pParHash;
    const pSha256State: PSYMCRYPT_SHA256_STATE = @ptrCast(pState);

    macros.ASSERT(pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_RESULT);
    macros.ASSERT(pOp.cbBuffer == SYMCRYPT_SHA256_RESULT_SIZE);

    macros.SymCryptUint32ToMsbFirst(&pSha256State.chain.H, pOp.pbBuffer, 8);
    hash.SymCryptWipeKnownSize(@ptrCast(pSha256State), @sizeOf(SYMCRYPT_SHA256_STATE));
    sha256.SymCryptSha256Init(pSha256State);
}

pub export fn SymCryptParallelSha256Process(
    pStates: [*]SYMCRYPT_SHA256_STATE,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (comptime !SUPPORT_PARALLEL) {
        return parhash.SymCryptParallelHashProcess_serial(
            SymCryptParallelSha256Algorithm,
            @ptrCast(pStates),
            nStates,
            pOperations,
            nOperations,
            pbScratch,
            cbScratch,
        );
    }

    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (comptime types.CPU_X86 or types.CPU_AMD64) {
        var saveState: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;

        if (cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_AVX2) and SymCryptSaveYmm(&saveState) == .SYMCRYPT_NO_ERROR) {
            const maxParallel: UINT32 = 8;
            scError = parhash.SymCryptParallelHashProcess(
                SymCryptParallelSha256Algorithm,
                @ptrCast(pStates),
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
                maxParallel,
            );
            SymCryptRestoreYmm(&saveState);
        } else if (cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_SSSE3) and SymCryptSaveXmm(&saveState) == .SYMCRYPT_NO_ERROR) {
            const maxParallel: UINT32 = 4;
            scError = parhash.SymCryptParallelHashProcess(
                SymCryptParallelSha256Algorithm,
                @ptrCast(pStates),
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
                maxParallel,
            );
            SymCryptRestoreXmm(&saveState);
        } else {
            scError = parhash.SymCryptParallelHashProcess_serial(
                SymCryptParallelSha256Algorithm,
                @ptrCast(pStates),
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
            );
        }
    } else if (comptime types.CPU_ARM) {
        const maxParallel: UINT32 = MAX_PARALLEL;
        if (cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_NEON)) {
            scError = parhash.SymCryptParallelHashProcess(
                SymCryptParallelSha256Algorithm,
                @ptrCast(pStates),
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
                maxParallel,
            );
        } else {
            scError = parhash.SymCryptParallelHashProcess_serial(
                SymCryptParallelSha256Algorithm,
                @ptrCast(pStates),
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
            );
        }
    } else {
        scError = parhash.SymCryptParallelHashProcess_serial(
            SymCryptParallelSha256Algorithm,
            @ptrCast(pStates),
            nStates,
            pOperations,
            nOperations,
            pbScratch,
            cbScratch,
        );
    }

    return scError;
}

// ==============================================================================================
// Vectorized 4-Way SHA-256 Implementations (XMM & NEON)
// ==============================================================================================

const V4U32 = @Vector(4, u32);
const V16U8 = @Vector(16, u8);

inline fn v4Maj(x: V4U32, y: V4U32, z: V4U32) V4U32 {
    return ((z | y) & x) | (z & y);
}

inline fn v4Ch(x: V4U32, y: V4U32, z: V4U32) V4U32 {
    return ((z ^ y) & x) ^ z;
}

inline fn v4Ror32(x: V4U32, comptime n: u5) V4U32 {
    const inv: u5 = @intCast(32 - @as(u6, n));
    return (x << @splat(inv)) ^ (x >> @splat(n));
}

inline fn v4Shr32(x: V4U32, comptime n: u5) V4U32 {
    return x >> @splat(n);
}

inline fn v4Csigma0(x: V4U32) V4U32 {
    return v4Ror32(x, 2) ^ v4Ror32(x, 13) ^ v4Ror32(x, 22);
}

inline fn v4Csigma1(x: V4U32) V4U32 {
    return v4Ror32(x, 6) ^ v4Ror32(x, 11) ^ v4Ror32(x, 25);
}

inline fn v4Lsigma0(x: V4U32) V4U32 {
    return v4Ror32(x, 7) ^ v4Ror32(x, 18) ^ v4Shr32(x, 3);
}

inline fn v4Lsigma1(x: V4U32) V4U32 {
    return v4Ror32(x, 17) ^ v4Ror32(x, 19) ^ v4Shr32(x, 10);
}

inline fn v4Loadu(ptr: PCBYTE) V4U32 {
    return @bitCast(std.mem.readInt(u128, ptr[0..16], .little));
}

inline fn v4Storeu(ptr: [*]u8, v: V4U32) void {
    std.mem.writeInt(u128, ptr[0..16], @bitCast(v), .little);
}

inline fn v4ByteReverse32(v: V4U32) V4U32 {
    const bytes: V16U8 = @bitCast(v);
    const rev = @shuffle(u8, bytes, undefined, [16]i32{
        3,  2,  1,  0,
        7,  6,  5,  4,
        11, 10, 9,  8,
        15, 14, 13, 12,
    });
    return @bitCast(rev);
}

inline fn v4Transpose32(
    r0: *V4U32,
    r1: *V4U32,
    r2: *V4U32,
    r3: *V4U32,
    s0: V4U32,
    s1: V4U32,
    s2: V4U32,
    s3: V4U32,
) void {
    const t0 = @shuffle(u32, s0, s1, [4]i32{ 0, -1, 1, -2 });
    const t1 = @shuffle(u32, s0, s1, [4]i32{ 2, -3, 3, -4 });
    const t2 = @shuffle(u32, s2, s3, [4]i32{ 0, -1, 1, -2 });
    const t3 = @shuffle(u32, s2, s3, [4]i32{ 2, -3, 3, -4 });

    r0.* = @shuffle(u32, t0, t2, [4]i32{ 0, 1, -1, -2 });
    r1.* = @shuffle(u32, t0, t2, [4]i32{ 2, 3, -3, -4 });
    r2.* = @shuffle(u32, t1, t3, [4]i32{ 0, 1, -1, -2 });
    r3.* = @shuffle(u32, t1, t3, [4]i32{ 2, 3, -3, -4 });
}

inline fn v4Expand(W: [*]V4U32, b: *V4U32, c: *V4U32, d: V4U32, r: usize) void {
    c.* = W[r - 15];
    b.* = d +% v4Lsigma1(b.*) +% W[r - 7] +% v4Lsigma0(c.*);
    W[r] = b.*;
}

inline fn v4DoRound(buf: [*]V4U32, a: V4U32, b: V4U32, c: V4U32, d: *V4U32, r: usize) void {
    const wBase: usize = 12;
    var t: V4U32 = buf[wBase + r];
    t +%= v4Csigma1(buf[wBase + r - 5]);
    t +%= buf[wBase + r - 8];
    t +%= v4Ch(buf[wBase + r - 5], buf[wBase + r - 6], buf[wBase + r - 7]);
    t +%= @splat(sha256.SymCryptSha256K[r]);
    buf[wBase + r - 4] = t +% d.*;
    d.* = t +% v4Csigma0(a) +% v4Maj(c, b, a);
}

pub fn SymCryptParallelSha256AppendBlocks_xmm(
    pChain: [*]PSYMCRYPT_SHA256_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes_in: SIZE_T,
    pScratch: [*]V4U32,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var nBytes = nBytes_in;
    const buf: [*]V4U32 = pScratch;
    const ha: [*]V4U32 = buf + 4;
    const W: [*]V4U32 = buf + 12;

    var T0 = v4Loadu(@ptrCast(&pChain[0].H[0]));
    var T1 = v4Loadu(@ptrCast(&pChain[1].H[0]));
    var T2 = v4Loadu(@ptrCast(&pChain[2].H[0]));
    var T3 = v4Loadu(@ptrCast(&pChain[3].H[0]));

    v4Transpose32(&ha[7], &ha[6], &ha[5], &ha[4], T0, T1, T2, T3);

    T0 = v4Loadu(@ptrCast(&pChain[0].H[4]));
    T1 = v4Loadu(@ptrCast(&pChain[1].H[4]));
    T2 = v4Loadu(@ptrCast(&pChain[2].H[4]));
    T3 = v4Loadu(@ptrCast(&pChain[3].H[4]));

    v4Transpose32(&ha[3], &ha[2], &ha[1], &ha[0], T0, T1, T2, T3);

    buf[0] = ha[4];
    buf[1] = ha[5];
    buf[2] = ha[6];
    buf[3] = ha[7];

    while (nBytes >= 64) {
        var r: usize = 0;
        while (r < 16) : (r += 4) {
            T0 = v4ByteReverse32(v4Loadu(ppByte[0]));
            ppByte[0] += 16;
            T1 = v4ByteReverse32(v4Loadu(ppByte[1]));
            ppByte[1] += 16;
            T2 = v4ByteReverse32(v4Loadu(ppByte[2]));
            ppByte[2] += 16;
            T3 = v4ByteReverse32(v4Loadu(ppByte[3]));
            ppByte[3] += 16;

            v4Transpose32(&W[r], &W[r + 1], &W[r + 2], &W[r + 3], T0, T1, T2, T3);
        }

        var A: V4U32 = W[15];
        var B: V4U32 = W[14];
        var C: V4U32 = undefined;
        var D: V4U32 = W[0];

        r = 16;
        while (r < 64) : (r += 2) {
            v4Expand(W, &B, &C, D, r);
            v4Expand(W, &A, &D, C, r + 1);
        }

        A = ha[7];
        B = ha[6];
        C = ha[5];
        D = ha[4];

        r = 0;
        while (r < 64) : (r += 4) {
            v4DoRound(buf, A, B, C, &D, r);
            v4DoRound(buf, D, A, B, &C, r + 1);
            v4DoRound(buf, C, D, A, &B, r + 2);
            v4DoRound(buf, B, C, D, &A, r + 3);
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

    v4Transpose32(&T0, &T1, &T2, &T3, ha[7], ha[6], ha[5], ha[4]);
    v4Storeu(@ptrCast(&pChain[0].H[0]), T0);
    v4Storeu(@ptrCast(&pChain[1].H[0]), T1);
    v4Storeu(@ptrCast(&pChain[2].H[0]), T2);
    v4Storeu(@ptrCast(&pChain[3].H[0]), T3);

    v4Transpose32(&T0, &T1, &T2, &T3, ha[3], ha[2], ha[1], ha[0]);
    v4Storeu(@ptrCast(&pChain[0].H[4]), T0);
    v4Storeu(@ptrCast(&pChain[1].H[4]), T1);
    v4Storeu(@ptrCast(&pChain[2].H[4]), T2);
    v4Storeu(@ptrCast(&pChain[3].H[4]), T3);
}

pub fn SymCryptParallelSha256AppendBlocks_neon(
    pChain: [*]PSYMCRYPT_SHA256_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes: SIZE_T,
    pScratch: [*]V4U32,
) callconv(SYMCRYPT_CALL) void {
    SymCryptParallelSha256AppendBlocks_xmm(pChain, ppByte, nBytes, pScratch);
    hash.SymCryptWipeKnownSize(@ptrCast(pScratch), @sizeOf(*V4U32));
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptParallelSha256AppendBlocks_xmm, .{ .name = "SymCryptParallelSha256AppendBlocks_xmm" });
    } else if (types.CPU_ARM) {
        @export(&SymCryptParallelSha256AppendBlocks_neon, .{ .name = "SymCryptParallelSha256AppendBlocks_neon" });
    }
}

// ==============================================================================================
// Parallel Append & Serial Fallback
// ==============================================================================================

pub export fn SymCryptParallelSha256AppendBytes_serial(
    pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    nPar: SIZE_T,
    nBytes: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var tmp: SIZE_T = 0;

    macros.ASSERT(nBytes % SYMCRYPT_SHA256_INPUT_BLOCK_SIZE == 0);
    macros.ASSERT(nPar >= 1 and nPar <= MAX_PARALLEL);

    var i: SIZE_T = 0;
    while (i < nPar) : (i += 1) {
        macros.ASSERT(pWork[i].cbData >= nBytes);
        const pState: PSYMCRYPT_SHA256_STATE = @ptrCast(@alignCast(pWork[i].hashState.?));
        sha256.SymCryptSha256AppendBlocks(&pState.chain, pWork[i].pbData, nBytes, &tmp);
        pWork[i].pbData += nBytes;
        pWork[i].cbData -= nBytes;
    }
}

pub export fn SymCryptParallelSha256Append(
    pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    nPar: SIZE_T,
    nBytes: SIZE_T,
    pbSimdScratch: PBYTE,
    cbSimdScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var apChain: [MAX_PARALLEL]PSYMCRYPT_SHA256_CHAINING_STATE = undefined;
    var apData: [MAX_PARALLEL]PCBYTE = undefined;
    var maxParallel: UINT32 = undefined;

    macros.ASSERT(cbSimdScratch >= PAR_SCRATCH_ELEMENTS_256 * SYMCRYPT_SIMD_ELEMENT_SIZE);
    macros.ASSERT((@intFromPtr(pbSimdScratch) & (SYMCRYPT_SIMD_ELEMENT_SIZE -| 1)) == 0);

    if (comptime types.CPU_X86 or types.CPU_AMD64) {
        maxParallel = @intCast((nPar + 3) & ~@as(SIZE_T, 3));
        macros.ASSERT(maxParallel == 4 or (maxParallel == 8 and cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_AVX2)));
    } else if (comptime types.CPU_ARM) {
        maxParallel = 4;
    }

    macros.ASSERT(nPar >= 1 and nPar <= maxParallel);

    if (nPar < MIN_PARALLEL) {
        SymCryptParallelSha256AppendBytes_serial(pWork, nPar, nBytes);
        return;
    }

    var i: SIZE_T = 0;
    while (i < nPar) : (i += 1) {
        macros.ASSERT(pWork[i].cbData >= nBytes);
        const pState: PSYMCRYPT_SHA256_STATE = @ptrCast(@alignCast(pWork[i].hashState.?));
        apChain[i] = &pState.chain;
        apData[i] = pWork[i].pbData;
        pWork[i].pbData += nBytes;
        pWork[i].cbData -= nBytes;
    }

    while (i < maxParallel) : (i += 1) {
        apChain[i] = apChain[0];
        apData[i] = apData[0];
    }

    if (comptime types.CPU_X86 or types.CPU_AMD64) {
        if (maxParallel == 8) {
            SymCryptParallelSha256AppendBlocks_ymm(&apChain, &apData, nBytes, pbSimdScratch);
        } else {
            SymCryptParallelSha256AppendBlocks_xmm(&apChain, &apData, nBytes, @ptrCast(@alignCast(pbSimdScratch)));
        }
    } else if (comptime types.CPU_ARM) {
        SymCryptParallelSha256AppendBlocks_neon(&apChain, &apData, nBytes, @ptrCast(@alignCast(pbSimdScratch)));
    }
}

// ==============================================================================================
// Algorithm Descriptor & Self-Test
// ==============================================================================================

pub export const SymCryptParallelSha256Algorithm_default: SYMCRYPT_PARALLEL_HASH align(SYMCRYPT_ALIGN_VALUE) = if (SUPPORT_PARALLEL) .{
    .pHash = &sha256.SymCryptSha256Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_256 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = &SymCryptParallelSha256Result1,
    .parResult2Func = &SymCryptParallelSha256Result2,
    .parResultDoneFunc = &SymCryptParallelSha256ResultDone,
    .parAppendFunc = &SymCryptParallelSha256Append,
} else .{
    .pHash = &sha256.SymCryptSha256Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_256 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = null,
    .parResult2Func = null,
    .parResultDoneFunc = null,
    .parAppendFunc = null,
};

pub export const SymCryptParallelSha256Algorithm: PCSYMCRYPT_PARALLEL_HASH = &SymCryptParallelSha256Algorithm_default;

const N_SELFTEST_STATES: usize = 5;

pub export fn SymCryptParallelSha256Selftest() callconv(SYMCRYPT_CALL) void {
    var states: [N_SELFTEST_STATES]SYMCRYPT_SHA256_STATE = undefined;
    var result: [N_SELFTEST_STATES][SYMCRYPT_SHA256_RESULT_SIZE]BYTE = undefined;
    var op: [2 * N_SELFTEST_STATES]SYMCRYPT_PARALLEL_HASH_OPERATION = undefined;
    var scratch: [parhash.SYMCRYPT_PARALLEL_SHA256_FIXED_SCRATCH + N_SELFTEST_STATES * parhash.SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH]BYTE = undefined;

    SymCryptParallelSha256Init(&states, N_SELFTEST_STATES);

    var i: usize = 0;
    while (i < N_SELFTEST_STATES) : (i += 1) {
        op[2 * i].iHash = i;
        op[2 * i].hashOperation = .SYMCRYPT_HASH_OPERATION_APPEND;
        op[2 * i].pbBuffer = @constCast(&hash.SymCryptTestMsg3);
        op[2 * i].cbBuffer = hash.SymCryptTestMsg3.len;
        op[2 * i].next = null;
        op[2 * i + 1].iHash = i;
        op[2 * i + 1].hashOperation = .SYMCRYPT_HASH_OPERATION_RESULT;
        op[2 * i + 1].pbBuffer = &result[i];
        op[2 * i + 1].cbBuffer = SYMCRYPT_SHA256_RESULT_SIZE;
        op[2 * i + 1].next = null;
    }

    const scError = SymCryptParallelSha256Process(&states, N_SELFTEST_STATES, &op, 2 * N_SELFTEST_STATES, &scratch, scratch.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("PS25"));
    }

    i = 0;
    while (i < N_SELFTEST_STATES) : (i += 1) {
        hash.SymCryptInjectError(&result[i], SYMCRYPT_SHA256_RESULT_SIZE);

        if (!std.mem.eql(u8, &result[i], &sha256.SymCryptSha256KATAnswer)) {
            macros.SymCryptFatal(comptime macros.multiCharConstant("PS25"));
        }
    }
}
