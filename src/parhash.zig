//
// parhash.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Code shared with all the parallel hash implementations, ported from lib/parhash.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_HASH_OPERATION_TYPE = types.SYMCRYPT_HASH_OPERATION_TYPE;
const PSYMCRYPT_COMMON_HASH_STATE = hash.PSYMCRYPT_COMMON_HASH_STATE;

// ==============================================================================================
// Parallel Hash Constants, Enums, and Structures
// ==============================================================================================

pub const STATE_NEXT: BYTE = 0;
pub const STATE_DATA_START: BYTE = 1;
pub const STATE_DATA_END: BYTE = 2;
pub const STATE_RESULT2: BYTE = 3;
pub const STATE_RESULT_DONE: BYTE = 4;

pub const SYMCRYPT_SIMD_ELEMENT_SIZE: usize = if (types.CPU_X86 or types.CPU_AMD64)
    32
else if (types.CPU_ARM or types.CPU_ARM64)
    16
else
    0;

pub const PAR_SCRATCH_ELEMENTS_256: usize = 4 + 8 + 64;
pub const PAR_SCRATCH_ELEMENTS_512: usize = 4 + 8 + 80;

pub const SYMCRYPT_PARALLEL_SHA256_FIXED_SCRATCH: usize = if (SYMCRYPT_SIMD_ELEMENT_SIZE > 0)
    PAR_SCRATCH_ELEMENTS_256 * SYMCRYPT_SIMD_ELEMENT_SIZE + SYMCRYPT_SIMD_ELEMENT_SIZE - 1 + SYMCRYPT_ALIGN_VALUE - 1
else
    SYMCRYPT_ALIGN_VALUE - 1;

pub const SYMCRYPT_PARALLEL_SHA384_FIXED_SCRATCH: usize = if (SYMCRYPT_SIMD_ELEMENT_SIZE > 0)
    PAR_SCRATCH_ELEMENTS_512 * SYMCRYPT_SIMD_ELEMENT_SIZE + SYMCRYPT_SIMD_ELEMENT_SIZE - 1 + SYMCRYPT_ALIGN_VALUE - 1
else
    SYMCRYPT_ALIGN_VALUE - 1;

pub const SYMCRYPT_PARALLEL_SHA512_FIXED_SCRATCH: usize = SYMCRYPT_PARALLEL_SHA384_FIXED_SCRATCH;

pub const SYMCRYPT_PARALLEL_HASH_OPERATION = extern struct {
    iHash: SIZE_T,
    hashOperation: SYMCRYPT_HASH_OPERATION_TYPE,
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
    next: ?*SYMCRYPT_PARALLEL_HASH_OPERATION,
};
pub const PSYMCRYPT_PARALLEL_HASH_OPERATION = *SYMCRYPT_PARALLEL_HASH_OPERATION;
pub const PCSYMRYPT_PARALLEL_HASH_OPERATION = *const SYMCRYPT_PARALLEL_HASH_OPERATION;

pub const SYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = extern struct {
    hashState: PVOID align(SYMCRYPT_ALIGN_VALUE),
    processingState: BYTE,
    bytesAlreadyProcessed: BYTE,
    bytes: UINT64,
    next: ?*SYMCRYPT_PARALLEL_HASH_OPERATION,
    pbData: PCBYTE,
    cbData: SIZE_T,
};
pub const PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = *SYMCRYPT_PARALLEL_HASH_SCRATCH_STATE;

pub const SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH: usize =
    @sizeOf(SYMCRYPT_PARALLEL_HASH_SCRATCH_STATE) + @sizeOf(PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE);

pub const PSYMCRYPT_PARALLEL_HASH_RESULT_FUNC = *const fn (
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pScratch: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    pRes: *BOOLEAN,
) callconv(SYMCRYPT_CALL) BOOLEAN;

pub const PSYMCRYPT_PARALLEL_HASH_RESULT_DONE_FUNC = *const fn (
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pOp: PCSYMRYPT_PARALLEL_HASH_OPERATION,
) callconv(SYMCRYPT_CALL) void;

pub const PSYMCRYPT_PARALLEL_APPEND_FUNC = *const fn (
    pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
    nPar: SIZE_T,
    nBytes: SIZE_T,
    pbSimdScratch: PBYTE,
    cbSimdScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub const SYMCRYPT_PARALLEL_HASH = extern struct {
    pHash: PCSYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE),
    parScratchFixed: UINT32,
    parResult1Func: ?PSYMCRYPT_PARALLEL_HASH_RESULT_FUNC,
    parResult2Func: ?PSYMCRYPT_PARALLEL_HASH_RESULT_FUNC,
    parResultDoneFunc: ?PSYMCRYPT_PARALLEL_HASH_RESULT_DONE_FUNC,
    parAppendFunc: ?PSYMCRYPT_PARALLEL_APPEND_FUNC,
};
pub const PSYMCRYPT_PARALLEL_HASH = *SYMCRYPT_PARALLEL_HASH;
pub const PCSYMCRYPT_PARALLEL_HASH = *const SYMCRYPT_PARALLEL_HASH;

extern fn qsort(
    base: ?*anyopaque,
    nmemb: usize,
    size: usize,
    compar: *const fn (?*const anyopaque, ?*const anyopaque) callconv(.c) c_int,
) callconv(.c) void;

// ==============================================================================================
// Parallel Hash Orchestration Functions
// ==============================================================================================

pub export fn SymCryptParallelHashProcess_serial(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pStates: PVOID,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pHash: PCSYMCRYPT_HASH = pParHash.pHash;
    var op: [*]SYMCRYPT_PARALLEL_HASH_OPERATION = pOperations;

    const minScratch: SIZE_T = @as(SIZE_T, pParHash.parScratchFixed) + nStates * SYMCRYPT_PARALLEL_HASH_PER_STATE_SCRATCH;
    if (cbScratch < minScratch) {
        scError = .SYMCRYPT_BUFFER_TOO_SMALL;
        return scError;
    }
    hash.SymCryptWipe(@ptrCast(pbScratch), minScratch);

    var i: SIZE_T = 0;
    while (i < nOperations) : (i += 1) {
        if (op[0].iHash >= nStates) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }
        const statePtr: PVOID = @ptrCast(@as([*]BYTE, @ptrCast(pStates.?)) + @as(SIZE_T, pHash.stateSize) * op[0].iHash);
        switch (op[0].hashOperation) {
            .SYMCRYPT_HASH_OPERATION_APPEND => {
                pHash.appendFunc.?(statePtr, op[0].pbBuffer, op[0].cbBuffer);
            },
            .SYMCRYPT_HASH_OPERATION_RESULT => {
                if (op[0].cbBuffer != pHash.resultSize) {
                    scError = .SYMCRYPT_INVALID_ARGUMENT;
                    return scError;
                }
                pHash.resultFunc.?(statePtr, @ptrCast(op[0].pbBuffer));
            },
            else => {
                scError = .SYMCRYPT_INVALID_ARGUMENT;
                return scError;
            },
        }
        op += 1;
    }

    return scError;
}

pub export fn SymCryptParallelHashSetNextWork(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pScratch: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE,
) callconv(SYMCRYPT_CALL) BOOLEAN {
    const pState: PSYMCRYPT_COMMON_HASH_STATE = @ptrCast(@alignCast(pScratch.hashState.?));
    const pHash: PCSYMCRYPT_HASH = pParHash.pHash;
    const stateBuf: [*]BYTE = @ptrCast(&pState.buffer);
    var res: BOOLEAN = types.FALSE;

    while (true) {
        const pOpOpt = pScratch.next;
        switch (pScratch.processingState) {
            STATE_NEXT => {
                const pOp = pOpOpt orelse return types.FALSE;
                const bytesInBuffer: SIZE_T = pState.bytesInBuffer;

                if (pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_APPEND) {
                    pState.dataLengthL +%= pOp.cbBuffer;
                    if (pState.dataLengthL < pOp.cbBuffer) {
                        pState.dataLengthH +%= 1;
                    }

                    if (bytesInBuffer > 0) {
                        macros.ASSERT(pHash.inputBlockSize > bytesInBuffer);

                        const todo: SIZE_T = @min(@as(SIZE_T, pHash.inputBlockSize) - bytesInBuffer, pOp.cbBuffer);
                        @memcpy((stateBuf + bytesInBuffer)[0..todo], pOp.pbBuffer[0..todo]);
                        pState.bytesInBuffer += @intCast(todo);
                        if (pState.bytesInBuffer == pHash.inputBlockSize) {
                            pScratch.pbData = stateBuf;
                            pScratch.cbData = pHash.inputBlockSize;
                            if (todo == pOp.cbBuffer) {
                                pScratch.next = pOp.next;
                            } else {
                                pScratch.processingState = STATE_DATA_START;
                                macros.ASSERT(todo <= 0xff);
                                pScratch.bytesAlreadyProcessed = @intCast(todo);
                            }

                            pState.bytesInBuffer = 0;
                            return types.TRUE;
                        } else {
                            pScratch.next = pOp.next;
                            continue;
                        }
                    } else {
                        pScratch.pbData = pOp.pbBuffer;
                        pScratch.cbData = pOp.cbBuffer;
                        pScratch.processingState = STATE_DATA_END;

                        if (pScratch.cbData >= pHash.inputBlockSize) {
                            return types.TRUE;
                        } else {
                            continue;
                        }
                    }
                } else {
                    macros.ASSERT(pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_RESULT);

                    if (pParHash.parResult1Func.?(pParHash, pState, pScratch, &res) != types.FALSE) {
                        return res;
                    }
                }
            },
            STATE_DATA_START => {
                const pOp = pOpOpt.?;
                macros.ASSERT(pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_APPEND and pOp.cbBuffer >= pScratch.bytesAlreadyProcessed);

                pScratch.pbData = pOp.pbBuffer + pScratch.bytesAlreadyProcessed;
                pScratch.cbData = pOp.cbBuffer - pScratch.bytesAlreadyProcessed;
                if (pScratch.cbData >= pHash.inputBlockSize) {
                    pScratch.processingState = STATE_DATA_END;
                    return types.TRUE;
                }

                // Fall through to STATE_DATA_END
                if (pScratch.cbData > 0) {
                    macros.ASSERT(pScratch.cbData < pHash.inputBlockSize);
                    @memcpy(stateBuf[0..pScratch.cbData], pScratch.pbData[0..pScratch.cbData]);
                    pState.bytesInBuffer = @intCast(pScratch.cbData);
                }
                pScratch.next = pOp.next;
                pScratch.processingState = STATE_NEXT;
                continue;
            },
            STATE_DATA_END => {
                const pOp = pOpOpt.?;
                if (pScratch.cbData > 0) {
                    macros.ASSERT(pScratch.cbData < pHash.inputBlockSize);
                    @memcpy(stateBuf[0..pScratch.cbData], pScratch.pbData[0..pScratch.cbData]);
                    pState.bytesInBuffer = @intCast(pScratch.cbData);
                }
                pScratch.next = pOp.next;
                pScratch.processingState = STATE_NEXT;
                continue;
            },
            STATE_RESULT2 => {
                if (pParHash.parResult2Func.?(pParHash, pState, pScratch, &res) != types.FALSE) {
                    return res;
                }
                continue;
            },
            STATE_RESULT_DONE => {
                const pOp = pOpOpt.?;
                pParHash.parResultDoneFunc.?(pParHash, pState, pOp);

                pScratch.next = pOp.next;
                pScratch.processingState = STATE_NEXT;
                continue;
            },
            else => unreachable,
        }
    }
}

pub export fn compareRequestSize(p1: PCVOID, p2: PCVOID) callconv(.c) c_int {
    const pp1: *const PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = @ptrCast(@alignCast(p1.?));
    const pp2: *const PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = @ptrCast(@alignCast(p2.?));

    const c1: UINT64 = pp1.*.bytes;
    const c2: UINT64 = pp2.*.bytes;

    if (c1 < c2) {
        return 1;
    } else if (c1 > c2) {
        return -1;
    } else {
        return 0;
    }
}

pub export fn SymCryptParallelHashProcess(
    pParHash: PCSYMCRYPT_PARALLEL_HASH,
    pStates: PVOID,
    nStates: SIZE_T,
    pOperations: [*]SYMCRYPT_PARALLEL_HASH_OPERATION,
    nOperations: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
    maxParallel: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (nOperations == 0) {
        return scError;
    }

    const pHash: PCSYMCRYPT_HASH = pParHash.pHash;

    const scratchAddr: usize = @intFromPtr(pbScratch);
    const scratchEndAddr: usize = scratchAddr + cbScratch;
    const alignedScratchAddr: usize = (scratchAddr + SYMCRYPT_ALIGN_VALUE - 1) & ~(SYMCRYPT_ALIGN_VALUE - 1);

    const pScratchState: [*]SYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = @ptrFromInt(alignedScratchAddr);
    const pWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = @ptrCast(@alignCast(pScratchState + nStates));

    const workEndAddr: usize = @intFromPtr(pWork + nStates);
    const simdMask: usize = if (SYMCRYPT_SIMD_ELEMENT_SIZE > 0) SYMCRYPT_SIMD_ELEMENT_SIZE - 1 else 0;
    const fixedScratchAddr: usize = (workEndAddr + simdMask) & ~simdMask;
    const pbFixedScratch: PBYTE = @ptrFromInt(fixedScratchAddr);
    const cbFixedScratch: SIZE_T = pParHash.parScratchFixed;

    if (fixedScratchAddr + cbFixedScratch > scratchEndAddr) {
        scError = .SYMCRYPT_BUFFER_TOO_SMALL;
        return scError;
    }

    const scratchStateBytes: [*]BYTE = @ptrCast(pScratchState);
    @memset(scratchStateBytes[0 .. nStates * @sizeOf(SYMCRYPT_PARALLEL_HASH_SCRATCH_STATE)], 0);
    var nWork: SIZE_T = 0;

    var opIdx: SIZE_T = nOperations;
    while (opIdx > 0) {
        opIdx -= 1;
        const pOp: *SYMCRYPT_PARALLEL_HASH_OPERATION = &pOperations[opIdx];

        if (pOp.iHash >= nStates) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }

        const pSc: PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = &pScratchState[pOp.iHash];

        if (pSc.hashState == null) {
            macros.ASSERT(nWork < nStates);
            pSc.hashState = @ptrCast(@as([*]BYTE, @ptrCast(pStates.?)) + @as(SIZE_T, pHash.stateSize) * pOp.iHash);
            pWork[nWork] = pSc;
            nWork += 1;
        }

        if (pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_APPEND) {
            pSc.bytes +%= pOp.cbBuffer;
        } else if (pOp.hashOperation == .SYMCRYPT_HASH_OPERATION_RESULT) {
            pSc.bytes +%= pHash.inputBlockSize;
        } else {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }

        pOp.next = pSc.next;
        pSc.next = pOp;
    }

    macros.ASSERT(nWork > 0);
    const singleSize: UINT64 = pWork[0].bytes;
    var sameSize: bool = true;
    var i: SIZE_T = 0;
    while (i < nWork) {
        if (SymCryptParallelHashSetNextWork(pParHash, pWork[i]) == types.FALSE) {
            pWork[i] = pWork[nWork - 1];
            nWork -= 1;
            continue;
        }

        if (pWork[i].bytes != singleSize) {
            sameSize = false;
        }
        i += 1;
    }

    if (!sameSize) {
        qsort(@ptrCast(pWork), nWork, @sizeOf(PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE), &compareRequestSize);
    }

    var nPar: SIZE_T = @min(nWork, @as(SIZE_T, maxParallel));
    var pNextWork: [*]PSYMCRYPT_PARALLEL_HASH_SCRATCH_STATE = pWork + nPar;

    while (nWork > 0) {
        var todo: SIZE_T = pWork[0].cbData;
        var j: SIZE_T = 1;
        while (j < nPar) : (j += 1) {
            todo = @min(todo, pWork[j].cbData);
        }

        const nBytes: SIZE_T = todo & ~(@as(SIZE_T, pHash.inputBlockSize) - 1);

        pParHash.parAppendFunc.?(pWork, nPar, nBytes, pbFixedScratch, cbFixedScratch);

        var k: SIZE_T = 0;
        while (k < nPar) {
            if (pWork[k].cbData < pHash.inputBlockSize) {
                if (SymCryptParallelHashSetNextWork(pParHash, pWork[k]) == types.FALSE) {
                    if (nWork > nPar) {
                        pWork[k] = pNextWork[0];
                        pNextWork += 1;
                        nWork -= 1;
                        k += 1;
                    } else {
                        nPar -= 1;
                        pWork[k] = pWork[nPar];
                        nWork -= 1;
                    }
                    continue;
                }
            }
            k += 1;
        }
    }
    hash.SymCryptWipe(@ptrCast(pbFixedScratch), cbFixedScratch);

    return scError;
}

comptime {
    std.debug.assert((SYMCRYPT_SIMD_ELEMENT_SIZE & (SYMCRYPT_SIMD_ELEMENT_SIZE -| 1)) == 0);
}
