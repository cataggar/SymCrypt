//
// sha512_par.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement SHA-512/SHA-384 from FIPS 180-2 in parallel mode,
// ported from lib/sha512Par.c.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const sha512 = @import("sha512.zig");
const parhash = @import("parhash.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

const SYMCRYPT_SHA384_RESULT_SIZE = sha512.SYMCRYPT_SHA384_RESULT_SIZE;
const SYMCRYPT_SHA512_RESULT_SIZE = sha512.SYMCRYPT_SHA512_RESULT_SIZE;
const SYMCRYPT_SHA512_INPUT_BLOCK_SIZE = sha512.SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
const SYMCRYPT_SHA384_STATE = sha512.SYMCRYPT_SHA384_STATE;
const PSYMCRYPT_SHA384_STATE = sha512.PSYMCRYPT_SHA384_STATE;
const SYMCRYPT_SHA512_STATE = sha512.SYMCRYPT_SHA512_STATE;
const PSYMCRYPT_SHA512_STATE = sha512.PSYMCRYPT_SHA512_STATE;
const SYMCRYPT_SHA512_CHAINING_STATE = sha512.SYMCRYPT_SHA512_CHAINING_STATE;
const PSYMCRYPT_SHA512_CHAINING_STATE = sha512.PSYMCRYPT_SHA512_CHAINING_STATE;

const PSYMCRYPT_COMMON_HASH_STATE = hash.PSYMCRYPT_COMMON_HASH_STATE;
const SYMCRYPT_PARALLEL_HASH = parhash.SYMCRYPT_PARALLEL_HASH;
const PCSYMCRYPT_PARALLEL_HASH = parhash.PCSYMCRYPT_PARALLEL_HASH;
const SYMCRYPT_PARALLEL_HASH_OPERATION = parhash.SYMCRYPT_PARALLEL_HASH_OPERATION;
const PCSYMRYPT_PARALLEL_HASH_OPERATION = parhash.PCSYMRYPT_PARALLEL_HASH_OPERATION;
const PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = parhash.PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE;
const PAR_SCRATCH_ELEMENTS_512 = parhash.PAR_SCRATCH_ELEMENTS_512;
const SYMCRYPT_SIMD_ELEMENT_SIZE = parhash.SYMCRYPT_SIMD_ELEMENT_SIZE;

// ==============================================================================================
// Platform Configuration & CPU Feature Helpers
// ==============================================================================================

const SUPPORT_PARALLEL: bool = types.CPU_X86 or types.CPU_AMD64;
const MIN_PARALLEL: usize = 2;
const MAX_PARALLEL: usize = 4;

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

extern fn SymCryptParallelSha512AppendBlocks_ymm(
    pChain: [*]PSYMCRYPT_SHA512_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes: SIZE_T,
    pScratch: PBYTE,
) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// Init & Process Functions
// ==============================================================================================

pub export fn SymCryptParallelSha512Init(
    pStates: [*]SYMCRYPT_SHA512_STATE,
    nStates: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var i: SIZE_T = 0;
    while (i < nStates) : (i += 1) {
        sha512.SymCryptSha512Init(&pStates[i]);
    }
}

pub export fn SymCryptParallelSha384Init(
    pStates: [*]SYMCRYPT_SHA384_STATE,
    nStates: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var i: SIZE_T = 0;
    while (i < nStates) : (i += 1) {
        sha512.SymCryptSha384Init(&pStates[i]);
    }
}

pub export fn SymCryptParallelSha512Result1(
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
    hash.SymCryptWipe(@ptrCast(stateBuf + bytesInBuffer), SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - bytesInBuffer);

    pScratch.pbData = stateBuf;
    pScratch.cbData = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;

    if (bytesInBuffer > SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - 16) {
        pScratch.processingState = parhash.STATE_RESULT2;
    } else {
        macros.STORE_MSBFIRST64(
            stateBuf + (SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - 16),
            (pState.dataLengthH << 3) +% (pState.dataLengthL >> 61),
        );
        macros.STORE_MSBFIRST64(
            stateBuf + (SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - 8),
            pState.dataLengthL << 3,
        );
        pScratch.processingState = parhash.STATE_RESULT_DONE;
    }

    pRes.* = types.TRUE;
    return types.TRUE;
}

pub export fn SymCryptParallelSha512Result2(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pScratch: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    pRes: *BOOLEAN,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    _ = pParHash;
    const stateBuf: [*]BYTE = @ptrCast(&pState.buffer);

    hash.SymCryptWipe(@ptrCast(stateBuf), SYMCRYPT_SHA512_INPUT_BLOCK_SIZE);
    macros.STORE_MSBFIRST64(
        stateBuf + (SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - 16),
        (pState.dataLengthH << 3) +% (pState.dataLengthL >> 61),
    );
    macros.STORE_MSBFIRST64(
        stateBuf + (SYMCRYPT_SHA512_INPUT_BLOCK_SIZE - 8),
        pState.dataLengthL << 3,
    );
    pScratch.pbData = stateBuf;
    pScratch.cbData = SYMCRYPT_SHA512_INPUT_BLOCK_SIZE;
    pScratch.processingState = parhash.STATE_RESULT_DONE;
    pRes.* = types.TRUE;
    return types.TRUE;
}

pub export fn SymCryptParallelSha512ResultDone(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pOp: PCSYMRYPT_PARALLEL_HASH_OPERATION,
) callconv(SYMCRYPT_CALL) void {
    _ = pParHash;
    const pSha512State: PSYMCRYPT_SHA512_STATE = @ptrCast(pState);

    macros.ASSERT(pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_RESULT);
    macros.ASSERT(pOp.cbBuffer == SYMCRYPT_SHA512_RESULT_SIZE);

    macros.SymCryptUint64ToMsbFirst(&pSha512State.chain.H, pOp.pbBuffer, 8);
    hash.SymCryptWipeKnownSize(@ptrCast(pSha512State), @sizeOf(SYMCRYPT_SHA512_STATE));
    sha512.SymCryptSha512Init(pSha512State);
}

pub export fn SymCryptParallelSha384ResultDone(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pOp: PCSYMRYPT_PARALLEL_HASH_OPERATION,
) callconv(SYMCRYPT_CALL) void {
    _ = pParHash;
    const pSha384State: PSYMCRYPT_SHA384_STATE = @ptrCast(pState);

    macros.ASSERT(pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_RESULT);
    macros.ASSERT(pOp.cbBuffer == SYMCRYPT_SHA384_RESULT_SIZE);

    macros.SymCryptUint64ToMsbFirst(&pSha384State.chain.H, pOp.pbBuffer, 6);
    hash.SymCryptWipeKnownSize(@ptrCast(pSha384State), @sizeOf(SYMCRYPT_SHA384_STATE));
    sha512.SymCryptSha384Init(pSha384State);
}

pub export fn SymCryptParallelSha512Sha384Process(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pStates: PVOID,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (comptime types.CPU_AMD64 or types.CPU_X86) {
        var saveState: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;

        if (cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_AVX2 | types.SYMCRYPT_CPU_FEATURE_SSSE3) and
            SymCryptSaveYmm(&saveState) == .SYMCRYPT_NO_ERROR)
        {
            const maxParallel: UINT32 = 4;
            scError = parhash.SymCryptParallelHashProcess(
                pParHash,
                pStates,
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
                maxParallel,
            );
            SymCryptRestoreYmm(&saveState);
        } else if (cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_SSSE3) and
            SymCryptSaveXmm(&saveState) == .SYMCRYPT_NO_ERROR)
        {
            const maxParallel: UINT32 = 2;
            scError = parhash.SymCryptParallelHashProcess(
                pParHash,
                pStates,
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
                pParHash,
                pStates,
                nStates,
                pOperations,
                nOperations,
                pbScratch,
                cbScratch,
            );
        }
    } else {
        scError = parhash.SymCryptParallelHashProcess_serial(
            pParHash,
            pStates,
            nStates,
            pOperations,
            nOperations,
            pbScratch,
            cbScratch,
        );
    }

    return scError;
}

pub export fn SymCryptParallelSha512Process(
    pStates: [*]SYMCRYPT_SHA512_STATE,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (comptime !SUPPORT_PARALLEL) {
        return parhash.SymCryptParallelHashProcess_serial(
            SymCryptParallelSha512Algorithm,
            @ptrCast(pStates),
            nStates,
            pOperations,
            nOperations,
            pbScratch,
            cbScratch,
        );
    }
    return SymCryptParallelSha512Sha384Process(
        SymCryptParallelSha512Algorithm,
        @ptrCast(pStates),
        nStates,
        pOperations,
        nOperations,
        pbScratch,
        cbScratch,
    );
}

pub export fn SymCryptParallelSha384Process(
    pStates: [*]SYMCRYPT_SHA384_STATE,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (comptime !SUPPORT_PARALLEL) {
        return parhash.SymCryptParallelHashProcess_serial(
            SymCryptParallelSha384Algorithm,
            @ptrCast(pStates),
            nStates,
            pOperations,
            nOperations,
            pbScratch,
            cbScratch,
        );
    }
    return SymCryptParallelSha512Sha384Process(
        SymCryptParallelSha384Algorithm,
        @ptrCast(pStates),
        nStates,
        pOperations,
        nOperations,
        pbScratch,
        cbScratch,
    );
}

// ==============================================================================================
// Vectorized 2-Way SHA-512 Implementation (XMM)
// ==============================================================================================

const V2U64 = @Vector(2, u64);
const V16U8 = @Vector(16, u8);

inline fn v2Maj(x: V2U64, y: V2U64, z: V2U64) V2U64 {
    return ((z | y) & x) | (z & y);
}

inline fn v2Ch(x: V2U64, y: V2U64, z: V2U64) V2U64 {
    return ((z ^ y) & x) ^ z;
}

inline fn v2Ror64(x: V2U64, comptime n: u6) V2U64 {
    const inv: u6 = @intCast(64 - @as(u7, n));
    return (x << @splat(inv)) ^ (x >> @splat(n));
}

inline fn v2Shr64(x: V2U64, comptime n: u6) V2U64 {
    return x >> @splat(n);
}

inline fn v2Csigma0(x: V2U64) V2U64 {
    return v2Ror64(x, 28) ^ v2Ror64(x, 34) ^ v2Ror64(x, 39);
}

inline fn v2Csigma1(x: V2U64) V2U64 {
    return v2Ror64(x, 14) ^ v2Ror64(x, 18) ^ v2Ror64(x, 41);
}

inline fn v2Lsigma0(x: V2U64) V2U64 {
    return v2Ror64(x, 1) ^ v2Ror64(x, 8) ^ v2Shr64(x, 7);
}

inline fn v2Lsigma1(x: V2U64) V2U64 {
    return v2Ror64(x, 19) ^ v2Ror64(x, 61) ^ v2Shr64(x, 6);
}

inline fn v2Loadu(ptr: PCBYTE) V2U64 {
    return @bitCast(std.mem.readInt(u128, ptr[0..16], .little));
}

inline fn v2Storeu(ptr: [*]u8, v: V2U64) void {
    std.mem.writeInt(u128, ptr[0..16], @bitCast(v), .little);
}

inline fn v2ByteReverse64(v: V2U64) V2U64 {
    const bytes: V16U8 = @bitCast(v);
    const rev = @shuffle(u8, bytes, undefined, [16]i32{
        7,  6,  5,  4,  3,  2,  1, 0,
        15, 14, 13, 12, 11, 10, 9, 8,
    });
    return @bitCast(rev);
}

inline fn v2Transpose64(r0: *V2U64, r1: *V2U64, s0: V2U64, s1: V2U64) void {
    r0.* = @shuffle(u64, s0, s1, [2]i32{ 0, -1 });
    r1.* = @shuffle(u64, s0, s1, [2]i32{ 1, -2 });
}

inline fn v2Expand(W: [*]V2U64, b: *V2U64, c: *V2U64, d: V2U64, r: usize) void {
    c.* = W[r - 15];
    b.* = d +% v2Lsigma1(b.*) +% W[r - 7] +% v2Lsigma0(c.*);
    W[r] = b.*;
}

inline fn v2DoRound(buf: [*]V2U64, a: V2U64, b: V2U64, c: V2U64, d: *V2U64, r: usize) void {
    const wBase: usize = 12;
    var t: V2U64 = buf[wBase + r];
    t +%= v2Csigma1(buf[wBase + r - 5]);
    t +%= buf[wBase + r - 8];
    t +%= v2Ch(buf[wBase + r - 5], buf[wBase + r - 6], buf[wBase + r - 7]);
    t +%= @splat(sha512.SymCryptSha512K[r]);
    buf[wBase + r - 4] = t +% d.*;
    d.* = t +% v2Csigma0(a) +% v2Maj(c, b, a);
}

pub fn SymCryptParallelSha512AppendBlocks_xmm(
    pChain: [*]PSYMCRYPT_SHA512_CHAINING_STATE,
    ppByte: [*]PCBYTE,
    nBytes_in: SIZE_T,
    pScratch: [*]V2U64,
) callconv(SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var nBytes = nBytes_in;
    const buf: [*]V2U64 = pScratch;
    const ha: [*]V2U64 = buf + 4;
    const W: [*]V2U64 = buf + 12;

    var T0 = v2Loadu(@ptrCast(&pChain[0].H[0]));
    var T1 = v2Loadu(@ptrCast(&pChain[1].H[0]));
    v2Transpose64(&ha[7], &ha[6], T0, T1);

    T0 = v2Loadu(@ptrCast(&pChain[0].H[2]));
    T1 = v2Loadu(@ptrCast(&pChain[1].H[2]));
    v2Transpose64(&ha[5], &ha[4], T0, T1);

    T0 = v2Loadu(@ptrCast(&pChain[0].H[4]));
    T1 = v2Loadu(@ptrCast(&pChain[1].H[4]));
    v2Transpose64(&ha[3], &ha[2], T0, T1);

    T0 = v2Loadu(@ptrCast(&pChain[0].H[6]));
    T1 = v2Loadu(@ptrCast(&pChain[1].H[6]));
    v2Transpose64(&ha[1], &ha[0], T0, T1);

    buf[0] = ha[4];
    buf[1] = ha[5];
    buf[2] = ha[6];
    buf[3] = ha[7];

    while (nBytes >= 128) {
        var r: usize = 0;
        while (r < 16) : (r += 2) {
            T0 = v2ByteReverse64(v2Loadu(ppByte[0]));
            ppByte[0] += 16;
            T1 = v2ByteReverse64(v2Loadu(ppByte[1]));
            ppByte[1] += 16;

            v2Transpose64(&W[r], &W[r + 1], T0, T1);
        }

        var A: V2U64 = W[15];
        var B: V2U64 = W[14];
        var C: V2U64 = undefined;
        var D: V2U64 = W[0];

        r = 16;
        while (r < 80) : (r += 2) {
            v2Expand(W, &B, &C, D, r);
            v2Expand(W, &A, &D, C, r + 1);
        }

        A = ha[7];
        B = ha[6];
        C = ha[5];
        D = ha[4];

        r = 0;
        while (r < 80) : (r += 4) {
            v2DoRound(buf, A, B, C, &D, r);
            v2DoRound(buf, D, A, B, &C, r + 1);
            v2DoRound(buf, C, D, A, &B, r + 2);
            v2DoRound(buf, B, C, D, &A, r + 3);
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

    v2Transpose64(&T0, &T1, ha[7], ha[6]);
    v2Storeu(@ptrCast(&pChain[0].H[0]), T0);
    v2Storeu(@ptrCast(&pChain[1].H[0]), T1);

    v2Transpose64(&T0, &T1, ha[5], ha[4]);
    v2Storeu(@ptrCast(&pChain[0].H[2]), T0);
    v2Storeu(@ptrCast(&pChain[1].H[2]), T1);

    v2Transpose64(&T0, &T1, ha[3], ha[2]);
    v2Storeu(@ptrCast(&pChain[0].H[4]), T0);
    v2Storeu(@ptrCast(&pChain[1].H[4]), T1);

    v2Transpose64(&T0, &T1, ha[1], ha[0]);
    v2Storeu(@ptrCast(&pChain[0].H[6]), T0);
    v2Storeu(@ptrCast(&pChain[1].H[6]), T1);
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptParallelSha512AppendBlocks_xmm, .{ .name = "SymCryptParallelSha512AppendBlocks_xmm" });
    }
}

// ==============================================================================================
// Parallel Append & Serial Fallback
// ==============================================================================================

pub export fn SymCryptParallelSha512AppendBytes_serial(
    pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    nPar: SIZE_T,
    nBytes: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var tmp: SIZE_T = 0;

    macros.ASSERT(nBytes % SYMCRYPT_SHA512_INPUT_BLOCK_SIZE == 0);
    macros.ASSERT(nPar >= 1 and nPar <= MAX_PARALLEL);

    var i: SIZE_T = 0;
    while (i < nPar) : (i += 1) {
        macros.ASSERT(pWork[i].cbData >= nBytes);
        const pState: PSYMCRYPT_SHA512_STATE = @ptrCast(@alignCast(pWork[i].hashState.?));
        if (comptime types.CPU_X86) {
            sha512.SymCryptSha512AppendBlocks_xmm(&pState.chain, pWork[i].pbData, nBytes, &tmp);
        } else {
            sha512.SymCryptSha512AppendBlocks(&pState.chain, pWork[i].pbData, nBytes, &tmp);
        }
        pWork[i].pbData += nBytes;
        pWork[i].cbData -= nBytes;
    }
}

pub export fn SymCryptParallelSha512Append(
    pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    nPar: SIZE_T,
    nBytes: SIZE_T,
    pbSimdScratch: PBYTE,
    cbSimdScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var apChain: [MAX_PARALLEL]PSYMCRYPT_SHA512_CHAINING_STATE = undefined;
    var apData: [MAX_PARALLEL]PCBYTE = undefined;
    var maxParallel: UINT32 = undefined;

    macros.ASSERT(cbSimdScratch >= PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE);
    macros.ASSERT((@intFromPtr(pbSimdScratch) & (SYMCRYPT_SIMD_ELEMENT_SIZE -| 1)) == 0);

    if (comptime types.CPU_X86 or types.CPU_AMD64) {
        maxParallel = @intCast((nPar + 1) & ~@as(SIZE_T, 1));
        macros.ASSERT(maxParallel == 2 or (maxParallel == 4 and cpuFeaturesPresent(types.SYMCRYPT_CPU_FEATURE_AVX2)));
    } else if (comptime types.CPU_ARM) {
        maxParallel = 2;
    }

    macros.ASSERT(nPar >= 1 and nPar <= maxParallel);

    if (nPar < MIN_PARALLEL) {
        SymCryptParallelSha512AppendBytes_serial(pWork, nPar, nBytes);
        return;
    }

    var i: SIZE_T = 0;
    while (i < nPar) : (i += 1) {
        macros.ASSERT(pWork[i].cbData >= nBytes);
        const pState: PSYMCRYPT_SHA512_STATE = @ptrCast(@alignCast(pWork[i].hashState.?));
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
        if (maxParallel == 4) {
            SymCryptParallelSha512AppendBlocks_ymm(&apChain, &apData, nBytes, pbSimdScratch);
        } else {
            SymCryptParallelSha512AppendBlocks_xmm(&apChain, &apData, nBytes, @ptrCast(@alignCast(pbSimdScratch)));
        }
    }
}

// ==============================================================================================
// Algorithm Descriptors & Self-Tests
// ==============================================================================================

pub export const SymCryptParallelSha512Algorithm_default: SYMCRYPT_PARALLEL_HASH align(SYMCRYPT_ALIGN_VALUE) = if (SUPPORT_PARALLEL) .{
    .pHash = &sha512.SymCryptSha512Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = &SymCryptParallelSha512Result1,
    .parResult2Func = &SymCryptParallelSha512Result2,
    .parResultDoneFunc = &SymCryptParallelSha512ResultDone,
    .parAppendFunc = &SymCryptParallelSha512Append,
} else .{
    .pHash = &sha512.SymCryptSha512Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = null,
    .parResult2Func = null,
    .parResultDoneFunc = null,
    .parAppendFunc = null,
};

pub export const SymCryptParallelSha384Algorithm_default: SYMCRYPT_PARALLEL_HASH align(SYMCRYPT_ALIGN_VALUE) = if (SUPPORT_PARALLEL) .{
    .pHash = &sha512.SymCryptSha384Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = &SymCryptParallelSha512Result1,
    .parResult2Func = &SymCryptParallelSha512Result2,
    .parResultDoneFunc = &SymCryptParallelSha384ResultDone,
    .parAppendFunc = &SymCryptParallelSha512Append,
} else .{
    .pHash = &sha512.SymCryptSha384Algorithm_default,
    .parScratchFixed = @intCast(PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE),
    .parResult1Func = null,
    .parResult2Func = null,
    .parResultDoneFunc = null,
    .parAppendFunc = null,
};

pub export const SymCryptParallelSha384Algorithm: PCSYMCRYPT_PARALLEL_HASH = &SymCryptParallelSha384Algorithm_default;
pub export const SymCryptParallelSha512Algorithm: PCSYMCRYPT_PARALLEL_HASH = &SymCryptParallelSha512Algorithm_default;

const N_SELFTEST_STATES: usize = 3;

pub export fn SymCryptParallelSha384Selftest() callconv(SYMCRYPT_CALL) void {
    var states: [N_SELFTEST_STATES]SYMCRYPT_SHA384_STATE = undefined;
    var result: [N_SELFTEST_STATES][SYMCRYPT_SHA384_RESULT_SIZE]BYTE = undefined;
    var op: [2 * N_SELFTEST_STATES]SYMCRYPT_PARALLEL_HASH_OPERATION = undefined;
    var scratch: [parhash.SYMCRYPT_PARALLEL_SHA384_FIXED_SCRATCH + N_SELFTEST_STATES * parhash.SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH]BYTE = undefined;

    SymCryptParallelSha384Init(&states, N_SELFTEST_STATES);

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
        op[2 * i + 1].cbBuffer = SYMCRYPT_SHA384_RESULT_SIZE;
        op[2 * i + 1].next = null;
    }

    const scError = SymCryptParallelSha384Process(&states, N_SELFTEST_STATES, &op, 2 * N_SELFTEST_STATES, &scratch, scratch.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("PS38"));
    }

    i = 0;
    while (i < N_SELFTEST_STATES) : (i += 1) {
        hash.SymCryptInjectError(&result[i], SYMCRYPT_SHA384_RESULT_SIZE);

        if (!std.mem.eql(u8, &result[i], &sha512.SymCryptSha384KATAnswer)) {
            macros.SymCryptFatal(comptime macros.multiCharConstant("PS38"));
        }
    }
}

pub export fn SymCryptParallelSha512Selftest() callconv(SYMCRYPT_CALL) void {
    var states: [N_SELFTEST_STATES]SYMCRYPT_SHA512_STATE = undefined;
    var result: [N_SELFTEST_STATES][SYMCRYPT_SHA512_RESULT_SIZE]BYTE = undefined;
    var op: [2 * N_SELFTEST_STATES]SYMCRYPT_PARALLEL_HASH_OPERATION = undefined;
    var scratch: [parhash.SYMCRYPT_PARALLEL_SHA512_FIXED_SCRATCH + N_SELFTEST_STATES * parhash.SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH]BYTE = undefined;

    SymCryptParallelSha512Init(&states, N_SELFTEST_STATES);

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
        op[2 * i + 1].cbBuffer = SYMCRYPT_SHA512_RESULT_SIZE;
        op[2 * i + 1].next = null;
    }

    const scError = SymCryptParallelSha512Process(&states, N_SELFTEST_STATES, &op, 2 * N_SELFTEST_STATES, &scratch, scratch.len);
    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("PS51"));
    }

    i = 0;
    while (i < N_SELFTEST_STATES) : (i += 1) {
        hash.SymCryptInjectError(&result[i], SYMCRYPT_SHA512_RESULT_SIZE);

        if (!std.mem.eql(u8, &result[i], &sha512.SymCryptSha512KATAnswer)) {
            macros.SymCryptFatal(comptime macros.multiCharConstant("PS51"));
        }
    }
}
