//
// hash_pattern.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Comptime generic helpers equivalent to lib/hash_pattern.c and lib/hash_buffer_pattern.c.
//

const types = @import("types.zig");
const macros = @import("macros.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

/// Generates all-in-one hash, state copy, and type-erased vtable wrapper functions
/// equivalent to lib/hash_pattern.c.
pub fn HashPattern(
    comptime StateType: type,
    comptime ChainType: type,
    comptime initFn: *const fn (*StateType) callconv(SYMCRYPT_CALL) void,
    comptime appendFn: *const fn (*StateType, PCBYTE, SIZE_T) callconv(SYMCRYPT_CALL) void,
    comptime resultFn: *const fn (*StateType, PBYTE) callconv(SYMCRYPT_CALL) void,
    comptime appendBlocksFn: *const fn (*ChainType, PCBYTE, SIZE_T, *SIZE_T) callconv(SYMCRYPT_CALL) void,
) type {
    return struct {
        pub noinline fn hash(
            pbData: PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            var state: StateType = undefined;
            initFn(&state);
            appendFn(&state, pbData, cbData);
            resultFn(&state, pbResult);
        }

        pub fn stateCopy(
            pSrc: *const StateType,
            pDst: *StateType,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pSrc);
            pDst.* = pSrc.*;
            macros.SET_MAGIC(pDst);
        }

        pub fn initVoid(pState: PVOID) callconv(SYMCRYPT_CALL) void {
            initFn(@ptrCast(@alignCast(pState.?)));
        }

        pub fn appendVoid(pState: PVOID, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
            appendFn(@ptrCast(@alignCast(pState.?)), pbData, cbData);
        }

        pub fn resultVoid(pState: PVOID, pbResult: PVOID) callconv(SYMCRYPT_CALL) void {
            resultFn(@ptrCast(@alignCast(pState.?)), @ptrCast(pbResult.?));
        }

        pub fn appendBlocksVoid(pChain: PVOID, pbData: PCBYTE, cbData: SIZE_T, pcbRemaining: *SIZE_T) callconv(SYMCRYPT_CALL) void {
            appendBlocksFn(@ptrCast(@alignCast(pChain.?)), pbData, cbData, pcbRemaining);
        }

        pub fn stateCopyVoid(pSrc: PCVOID, pDst: PVOID) callconv(SYMCRYPT_CALL) void {
            stateCopy(@ptrCast(@alignCast(pSrc.?)), @ptrCast(@alignCast(pDst.?)));
        }
    };
}

/// Comptime generic buffer append helper equivalent to lib/hash_buffer_pattern.c
/// (where appendBlocksFn takes (&state.chain, ptr, cbData)).
pub inline fn hashBufferAppend(
    comptime input_block_size: usize,
    state: anytype,
    bytes_in_buffer_init: usize,
    pbData: PCBYTE,
    cbData: SIZE_T,
    comptime appendBlocksFn: anytype,
) void {
    comptime {
        if (input_block_size == 0 or (input_block_size & (input_block_size - 1)) != 0) {
            @compileError("input_block_size must be a power of 2");
        }
    }

    var bytesInBuffer: SIZE_T = bytes_in_buffer_init & (input_block_size - 1);
    var currPbData = pbData;
    var currCbData = cbData;

    if (bytesInBuffer > 0) {
        const freeInBuffer: SIZE_T = input_block_size - bytesInBuffer;
        if (currCbData < freeInBuffer) {
            // All the data will fit in the buffer.
            // Bulk data processing is skipped and the data will be copied at the end.
        } else {
            @memcpy(state.buffer[bytesInBuffer .. bytesInBuffer + freeInBuffer], currPbData[0..freeInBuffer]);
            currPbData += freeInBuffer;
            currCbData -= freeInBuffer;
            appendBlocksFn(&state.chain, &state.buffer, input_block_size);
            bytesInBuffer = 0;
        }
    }

    if (currCbData >= input_block_size) {
        const cbDataRoundedDown: SIZE_T = currCbData & ~@as(SIZE_T, input_block_size - 1);
        appendBlocksFn(&state.chain, currPbData, cbDataRoundedDown);
        currPbData += cbDataRoundedDown;
        currCbData -= cbDataRoundedDown;
    }

    if (currCbData > 0) {
        @memcpy(state.buffer[bytesInBuffer .. bytesInBuffer + currCbData], currPbData[0..currCbData]);
    }
}

/// Comptime generic buffer append helper for hash states whose appendBlocksFn
/// takes (&state.chain, ptr, cbData, &tmp) (such as SHA-256 and SHA-512).
pub inline fn hashBufferAppendWithRemaining(
    comptime input_block_size: UINT32,
    comptime update_high_length: bool,
    pState: anytype,
    pbData: PCBYTE,
    cbData: SIZE_T,
    comptime appendBlocksFn: anytype,
) void {
    var bytesInBuffer: UINT32 = undefined;
    var freeInBuffer: UINT32 = undefined;
    var tmp: SIZE_T = 0;
    var currPbData = pbData;
    var currCbData = cbData;

    macros.CHECK_MAGIC(pState);

    pState.dataLengthL +%= currCbData;
    if (update_high_length) {
        if (pState.dataLengthL < currCbData) {
            pState.dataLengthH +%= 1;
        }
    }

    bytesInBuffer = pState.bytesInBuffer;

    if (bytesInBuffer > 0) {
        macros.ASSERT(input_block_size > bytesInBuffer);

        freeInBuffer = input_block_size - bytesInBuffer;
        if (currCbData < freeInBuffer) {
            // All the data will fit in the buffer.
        } else {
            @memcpy(pState.buffer[bytesInBuffer .. bytesInBuffer + freeInBuffer], currPbData[0..freeInBuffer]);
            currPbData += freeInBuffer;
            currCbData -= freeInBuffer;
            appendBlocksFn(&pState.chain, &pState.buffer, input_block_size, &tmp);
            bytesInBuffer = 0;
        }
    }

    if (currCbData >= input_block_size) {
        appendBlocksFn(&pState.chain, currPbData, currCbData, &tmp);
        macros.ASSERT(tmp < input_block_size);
        currPbData += currCbData - tmp;
        currCbData = tmp;
    }

    macros.ASSERT(currCbData < input_block_size);

    if (currCbData > 0) {
        @memcpy(pState.buffer[bytesInBuffer .. bytesInBuffer + currCbData], currPbData[0..currCbData]);
        bytesInBuffer += @intCast(currCbData);
    }

    pState.bytesInBuffer = bytesInBuffer;
}
