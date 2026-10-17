//
// tls_cbc_verify.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const INT32 = types.INT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const NATIVE_UINT = types.NATIVE_UINT;
const NATIVE_INT = types.NATIVE_INT;
const NATIVE_BITS = types.NATIVE_BITS;
const NATIVE_BYTES = types.NATIVE_BYTES;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

const NATIVE_01: NATIVE_UINT = if (NATIVE_BYTES == 8)
    0x0101010101010101
else if (NATIVE_BYTES == 4)
    0x01010101
else
    @compileError("Unexpected NATIVE_BYTES value");

const MASKNB_INWORD_RELEVANTBITS: INT32 = ~@as(INT32, NATIVE_BYTES - 1) & 0x0fffffff;

const NativeShift = std.math.Log2Int(NATIVE_UINT);

inline fn MASK32_LT(a: UINT32, b: UINT32) UINT32 {
    const diff: INT32 = @bitCast(a -% b);
    return @bitCast(diff >> 31);
}

inline fn MASK32_EQ(a: UINT32, b: UINT32) UINT32 {
    const x: INT32 = @bitCast(a ^ b);
    const neg: INT32 = 0 -% x;
    return ~@as(UINT32, @bitCast(neg >> 31));
}

inline fn MASKNB_BROADCAST(b: UINT32) NATIVE_UINT {
    return @as(NATIVE_UINT, b) *% NATIVE_01;
}

inline fn SymCryptNMaskGe(wordStart: UINT32, boundary: UINT32) NATIVE_UINT {
    const boundaryNative: NATIVE_INT = @bitCast(@as(NATIVE_UINT, boundary));
    const wordStartNative: NATIVE_INT = @bitCast(@as(NATIVE_UINT, wordStart));
    const anySet: NATIVE_INT = (boundaryNative -% wordStartNative -% NATIVE_BYTES) >> (NATIVE_BITS - 1);
    const diff32: INT32 = @bitCast(boundary -% wordStart);
    var shift: UINT32 = 8 * (@as(UINT32, @bitCast(diff32)) & (NATIVE_BYTES - 1));
    const maskAll: UINT32 = @bitCast((~diff32) >> 31);
    shift &= maskAll;
    return @as(NATIVE_UINT, @bitCast(anySet)) << @as(NativeShift, @intCast(shift));
}

inline fn SymCryptNMaskEq(wordStart: UINT32, boundary: UINT32) NATIVE_UINT {
    const diff32: INT32 = @bitCast(boundary -% wordStart);
    const masked: UINT32 = @bitCast(diff32 & MASKNB_INWORD_RELEVANTBITS);
    const neg: NATIVE_INT = 0 -% @as(NATIVE_INT, @bitCast(@as(NATIVE_UINT, masked)));
    const inWord: NATIVE_UINT = ~@as(NATIVE_UINT, @bitCast(neg >> (NATIVE_BITS - 1)));
    const shift: NativeShift = @intCast(8 * (@as(UINT32, @bitCast(diff32)) & (NATIVE_BYTES - 1)));
    return inWord & (@as(NATIVE_UINT, 0xff) << shift);
}

inline fn SymCryptNMaskEq80(wordStart: UINT32, boundary: UINT32) NATIVE_UINT {
    const diff32: INT32 = @bitCast(boundary -% wordStart);
    const masked: UINT32 = @bitCast(diff32 & MASKNB_INWORD_RELEVANTBITS);
    const neg: NATIVE_INT = 0 -% @as(NATIVE_INT, @bitCast(@as(NATIVE_UINT, masked)));
    const inWord: NATIVE_UINT = ~@as(NATIVE_UINT, @bitCast(neg >> (NATIVE_BITS - 1)));
    const shift: NativeShift = @intCast(8 * (@as(UINT32, @bitCast(diff32)) & (NATIVE_BYTES - 1)));
    return inWord & (@as(NATIVE_UINT, 0x80) << shift);
}

pub const SYMCRYPT_COMMON_HASH_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [1]BYTE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_COMMON_HASH_STATE = *SYMCRYPT_COMMON_HASH_STATE;

extern fn SymCryptRoundUpPow2Sizet(v: SIZE_T) callconv(SYMCRYPT_CALL) SIZE_T;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptScsRotateBuffer(pbBuffer: PBYTE, cbBuffer: SIZE_T, lshift: SIZE_T) callconv(SYMCRYPT_CALL) void;

inline fn readNativeUnaligned(ptr: PCBYTE) NATIVE_UINT {
    const p: *align(1) const NATIVE_UINT = @ptrCast(ptr);
    return p.*;
}

inline fn writeNativeUnaligned(ptr: PBYTE, val: NATIVE_UINT) void {
    const p: *align(1) NATIVE_UINT = @ptrCast(ptr);
    p.* = val;
}

inline fn orNativeUnaligned(ptr: PBYTE, val: NATIVE_UINT) void {
    const p: *align(1) NATIVE_UINT = @ptrCast(ptr);
    p.* |= val;
}

inline fn readU32Unaligned(ptr: PCBYTE) UINT32 {
    const p: *align(1) const UINT32 = @ptrCast(ptr);
    return p.*;
}

inline fn writeU32Unaligned(ptr: PBYTE, val: UINT32) void {
    const p: *align(1) UINT32 = @ptrCast(ptr);
    p.* = val;
}

inline fn orU32Unaligned(ptr: PBYTE, val: UINT32) void {
    const p: *align(1) UINT32 = @ptrCast(ptr);
    p.* |= val;
}

pub export fn SymCryptTlsCbcHmacVerifyCore(
    pHash: PCSYMCRYPT_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pbDataIn: PCBYTE,
    cbDataIn: SIZE_T,
    pbMacValue: PBYTE,
    pbHashResult: PBYTE,
    pu32PaddingError: *UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var nPaddingError: NATIVE_UINT = 0;
    var pbData: PCBYTE = pbDataIn;
    var cbData: SIZE_T = cbDataIn;
    var tmp: SIZE_T = 0;
    const cbMacValue: UINT32 = pHash.inputBlockSize / 2;

    macros.SYMCRYPT_ASSERT(cbMacValue == SymCryptRoundUpPow2Sizet(pHash.resultSize));

    var u32_val: UINT32 = pHash.resultSize + 256;
    if (cbData > u32_val) {
        pHash.appendFunc.?(@ptrCast(pState), pbData, cbData - u32_val);
        pbData += cbData - u32_val;
        cbData = u32_val;
    }

    if (cbData < pHash.resultSize + 1) {
        scError = .SYMCRYPT_BUFFER_TOO_SMALL;
        nPaddingError |= nPaddingError >> (NATIVE_BITS / 2);
        pu32PaddingError.* = @truncate(nPaddingError);
        return scError;
    }

    SymCryptWipe(@ptrCast(pbMacValue), cbMacValue);
    SymCryptWipe(@ptrCast(pbHashResult), pHash.resultSize);

    var cbPad: UINT32 = pbData[cbData - 1];
    cbData -= 1;

    const maxPadLength: UINT32 = @as(UINT32, @truncate(cbData)) - pHash.resultSize;
    u32_val = MASK32_LT(maxPadLength, cbPad);
    cbPad = cbPad +% ((maxPadLength -% cbPad) & u32_val);
    nPaddingError |= u32_val;

    const cbHashPrefix: UINT32 = @truncate(pState.dataLengthL);
    const cbExtendedData: UINT32 = @as(UINT32, @truncate(cbData)) +% cbHashPrefix;
    var next: UINT32 = cbHashPrefix;

    const totalBytesHashed: UINT32 = cbExtendedData -% pHash.resultSize -% cbPad;
    var hashPaddingFinalBytes: [4]BYTE = undefined;
    macros.SYMCRYPT_STORE_MSBFIRST32(&hashPaddingFinalBytes, totalBytesHashed *% 8);
    const hashPaddingFinal: UINT32 = readU32Unaligned(&hashPaddingFinalBytes);

    var resultHashBlockIndex: UINT32 = totalBytesHashed +% 1 +% pHash.inputBlockSize / 8;
    var lastHashBlockIndex: UINT32 = resultHashBlockIndex +% cbPad;

    resultHashBlockIndex = (resultHashBlockIndex +% pHash.inputBlockSize -% 1) & ~(pHash.inputBlockSize - 1);
    lastHashBlockIndex = (lastHashBlockIndex +% pHash.inputBlockSize -% 1) & ~(pHash.inputBlockSize - 1);

    const iPaddingStart: UINT32 = cbExtendedData -% cbPad;
    const iMacStart: UINT32 = iPaddingStart -% pHash.resultSize;

    macros.SYMCRYPT_ASSERT(iMacStart < cbExtendedData);

    const stateBufPtr: PBYTE = @ptrCast(&pState.buffer);
    const stateChainPtr: PBYTE = @as(PBYTE, @ptrCast(pState)) + pHash.chainOffset;
    const appendBlockFunc = pHash.appendBlockFunc.?;

    if ((next & (NATIVE_BYTES - 1)) != 0) {
        const backOffset: UINT32 = next & (NATIVE_BYTES - 1);

        macros.SYMCRYPT_ASSERT(((next ^ pState.bytesInBuffer) & (NATIVE_BYTES - 1)) == 0);

        const w: NATIVE_UINT = readNativeUnaligned(pbData);
        const m: NATIVE_UINT = SymCryptNMaskGe(next, iMacStart);
        const mInData: NATIVE_UINT = ~m;
        const mInMac: NATIVE_UINT = m;

        var data: NATIVE_UINT = w & mInData;
        data |= SymCryptNMaskEq80(next, iMacStart);

        const shiftAmt: NativeShift = @intCast(8 * backOffset);
        const bufLocPtr: PBYTE = stateBufPtr + (pState.bytesInBuffer - backOffset);
        const oldVal: NATIVE_UINT = readNativeUnaligned(bufLocPtr);
        const keepMask: NATIVE_UINT = (@as(NATIVE_UINT, 1) << shiftAmt) -% 1;
        writeNativeUnaligned(bufLocPtr, (oldVal & keepMask) | (data << shiftAmt));
        pState.bytesInBuffer += NATIVE_BYTES - backOffset;

        orNativeUnaligned(pbMacValue + ((next -% backOffset) & (cbMacValue - 1)), (w & mInMac) << shiftAmt);

        if (pState.bytesInBuffer == pHash.inputBlockSize) {
            appendBlockFunc(@ptrCast(stateChainPtr), stateBufPtr, pHash.inputBlockSize, &tmp);
            pState.bytesInBuffer = 0;
        }

        next +%= NATIVE_BYTES - backOffset;
    }

    var padBytes: NATIVE_UINT = MASKNB_BROADCAST(cbPad);

    while (next <= cbExtendedData - NATIVE_BYTES) {
        const w: NATIVE_UINT = readNativeUnaligned(pbData + (next - cbHashPrefix));

        var m: NATIVE_UINT = SymCryptNMaskGe(next, iMacStart);
        var mInMac: NATIVE_UINT = m;
        const mInData: NATIVE_UINT = ~m;

        m = SymCryptNMaskGe(next, iPaddingStart);
        const mInPadding: NATIVE_UINT = m;
        mInMac &= ~m;

        var data: NATIVE_UINT = w & mInData;
        data |= SymCryptNMaskEq80(next, iMacStart);

        writeNativeUnaligned(stateBufPtr + pState.bytesInBuffer, data);
        pState.bytesInBuffer += NATIVE_BYTES;

        if (pState.bytesInBuffer == pHash.inputBlockSize) {
            const m32ResultBlock: UINT32 = MASK32_EQ(next, resultHashBlockIndex -% NATIVE_BYTES);
            orU32Unaligned(stateBufPtr + (pHash.inputBlockSize - 4), hashPaddingFinal & m32ResultBlock);

            appendBlockFunc(@ptrCast(stateChainPtr), stateBufPtr, pHash.inputBlockSize, &tmp);
            macros.SYMCRYPT_ASSERT(tmp == 0);

            const mResultBlock: NATIVE_UINT = @bitCast(@as(NATIVE_INT, @as(INT32, @bitCast(m32ResultBlock))));

            var i: UINT32 = 0;
            while (i < pHash.resultSize / NATIVE_BYTES) : (i += 1) {
                const chainWord = readNativeUnaligned(stateChainPtr + i * NATIVE_BYTES);
                orNativeUnaligned(pbHashResult + i * NATIVE_BYTES, chainWord & mResultBlock);
            }
            if ((pHash.resultSize & (NATIVE_BYTES - 1)) != 0) {
                const chainTail = readU32Unaligned(stateChainPtr + (pHash.resultSize - 4));
                orU32Unaligned(pbHashResult + (pHash.resultSize - 4), chainTail & @as(UINT32, @truncate(mResultBlock)));
            }
            pState.bytesInBuffer = 0;
        }

        orNativeUnaligned(pbMacValue + (next & (cbMacValue - 1)), w & mInMac);

        nPaddingError |= (w ^ padBytes) & mInPadding;

        next +%= NATIVE_BYTES;
    }

    if (next < cbExtendedData) {
        var w: NATIVE_UINT = readNativeUnaligned(pbData + (cbData - NATIVE_BYTES));
        const shiftAmt: NativeShift = @intCast(8 * (next -% cbExtendedData +% NATIVE_BYTES));
        w >>= shiftAmt;
        padBytes >>= shiftAmt;

        const m: NATIVE_UINT = SymCryptNMaskGe(next, iPaddingStart);
        const mInPadding: NATIVE_UINT = m;
        const mInMac: NATIVE_UINT = ~m;

        orNativeUnaligned(pbMacValue + (next & (cbMacValue - 1)), w & mInMac);

        nPaddingError |= (w ^ padBytes) & mInPadding;
        next = cbExtendedData;
    }

    if (next < lastHashBlockIndex) {
        SymCryptWipe(@ptrCast(stateBufPtr + pState.bytesInBuffer), pHash.inputBlockSize - pState.bytesInBuffer);

        writeU32Unaligned(stateBufPtr + (pHash.inputBlockSize - 4), hashPaddingFinal);

        appendBlockFunc(@ptrCast(stateChainPtr), stateBufPtr, pHash.inputBlockSize, &tmp);
        macros.SYMCRYPT_ASSERT(tmp == 0);

        const m32ResultBlock: UINT32 = MASK32_EQ(lastHashBlockIndex, resultHashBlockIndex);
        const mResultBlock: NATIVE_UINT = @bitCast(@as(NATIVE_INT, @as(INT32, @bitCast(m32ResultBlock))));

        var i: UINT32 = 0;
        while (i < pHash.resultSize / NATIVE_BYTES) : (i += 1) {
            const chainWord = readNativeUnaligned(stateChainPtr + i * NATIVE_BYTES);
            orNativeUnaligned(pbHashResult + i * NATIVE_BYTES, chainWord & mResultBlock);
        }
        if ((pHash.resultSize & (NATIVE_BYTES - 1)) != 0) {
            const chainTail = readU32Unaligned(stateChainPtr + (pHash.resultSize - 4));
            orU32Unaligned(pbHashResult + (pHash.resultSize - 4), chainTail & @as(UINT32, @truncate(mResultBlock)));
        }
        pState.bytesInBuffer = 0;
    }

    SymCryptScsRotateBuffer(pbMacValue, cbMacValue, iMacStart & (cbMacValue - 1));

    nPaddingError |= nPaddingError >> (NATIVE_BITS / 2);
    pu32PaddingError.* = @truncate(nPaddingError);

    return scError;
}

pub export fn SymCryptTlsCbcHmacVerify(
    pMacAlgorithm: PCSYMCRYPT_MAC,
    pExpandedKey: PVOID,
    pState: PVOID,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var abMacValue: [64]BYTE align(8) = undefined;
    var abHashResult: [48]BYTE align(8) = undefined;
    var u32PaddingError: UINT32 = 0;
    const pHashState: PSYMCRYPT_COMMON_HASH_STATE = @ptrCast(@alignCast(pState.?));
    const pHashAlgorithm: PCSYMCRYPT_HASH = pMacAlgorithm.ppHashAlgorithm.?.*.?;

    macros.SYMCRYPT_ASSERT((pHashAlgorithm.inputBlockSize / 2) <= 64);
    macros.SYMCRYPT_ASSERT(pHashAlgorithm.resultSize <= 48);

    _ = SymCryptTlsCbcHmacVerifyCore(
        pHashAlgorithm,
        pHashState,
        pbData,
        cbData,
        &abMacValue,
        &abHashResult,
        &u32PaddingError,
    );

    const stateChainPtr: PBYTE = @as(PBYTE, @ptrCast(pHashState)) + pHashAlgorithm.chainOffset;
    const keyOuterChainPtr: PCBYTE = @as(PCBYTE, @ptrCast(pExpandedKey.?)) + pMacAlgorithm.outerChainingStateOffset;
    @memcpy(stateChainPtr[0..pHashAlgorithm.chainSize], keyOuterChainPtr[0..pHashAlgorithm.chainSize]);

    const stateBufPtr: PBYTE = @ptrCast(&pHashState.buffer);
    if (pMacAlgorithm.resultSize <= 32) {
        const hashResU32: [*]const UINT32 = @ptrCast(&abHashResult);
        macros.SymCryptUint32ToMsbFirst(hashResU32, stateBufPtr, pHashAlgorithm.resultSize / 4);
    } else {
        const hashResU64: [*]const UINT64 = @ptrCast(&abHashResult);
        macros.SymCryptUint64ToMsbFirst(hashResU64, stateBufPtr, pMacAlgorithm.resultSize / 8);
    }
    pHashState.bytesInBuffer = pHashAlgorithm.resultSize;
    pHashState.dataLengthL = pHashAlgorithm.resultSize + pHashAlgorithm.inputBlockSize;

    pHashAlgorithm.resultFunc.?(@ptrCast(pHashState), @ptrCast(&abHashResult));

    var i: UINT32 = 0;
    while (i < pHashAlgorithm.resultSize / 4) : (i += 1) {
        u32PaddingError |= readU32Unaligned((&abHashResult)[4 * i ..].ptr) ^ readU32Unaligned((&abMacValue)[4 * i ..].ptr);
    }

    return if (u32PaddingError == 0) .SYMCRYPT_NO_ERROR else .SYMCRYPT_AUTHENTICATION_FAILURE;
}
