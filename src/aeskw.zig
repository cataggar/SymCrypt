//
// aeskw.zig    Implementation of the AES-KW(P) block cipher modes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const aescmac = @import("aescmac.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PCSYMCRYPT_AES_EXPANDED_KEY = aescmac.PCSYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_AES_BLOCK_SIZE = aescmac.SYMCRYPT_AES_BLOCK_SIZE;

const SYMCRYPT_AES_SEMIBLOCK_SIZE: usize = SYMCRYPT_AES_BLOCK_SIZE / 2;

pub export const SymCryptAesKwDefaultICV: UINT64 = 0xA6A6A6A6A6A6A6A6;
pub export const SymCryptAesKwpDefaultICV: UINT32 = 0xA65959A6;

pub export const SymCryptAesKWMinPlaintextLen: SIZE_T = 16;
pub export const SymCryptAesKWMaxPlaintextLen: SIZE_T = (1 << 31) - 8;
pub export const SymCryptAesKWMinCiphertextLen: SIZE_T = 24;
pub export const SymCryptAesKWMaxCiphertextLen: SIZE_T = 1 << 31;

pub export const SymCryptAesKWPMinPlaintextLen: SIZE_T = 1;
pub export const SymCryptAesKWPMaxPlaintextLen: SIZE_T = (1 << 31) - 8;
pub export const SymCryptAesKWPMinCiphertextLen: SIZE_T = 16;
pub export const SymCryptAesKWPMaxCiphertextLen: SIZE_T = 1 << 31;

extern fn SymCryptAesEncrypt(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptAesDecrypt(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptCallbackAlloc(nBytes: SIZE_T) callconv(SYMCRYPT_CALL) PVOID;
extern fn SymCryptCallbackFree(pMem: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptMask32LtU31(a: UINT32, b: UINT32) callconv(SYMCRYPT_CALL) UINT32;

inline fn wipeKnownSize16(buf: *[16]BYTE) void {
    const ptr: [*]u8 = @ptrCast(buf);
    macros.FORCE_WRITE64(ptr, 0);
    macros.FORCE_WRITE64(ptr + 8, 0);
}

fn symCryptAesKwxInternalWrap(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbBuf: PBYTE,
    cbBuf: UINT32,
) void {
    var activeBlock: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const nSemiBlocks: UINT32 = cbBuf / @as(UINT32, @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE));
    var encryptionIdx: UINT64 = 1;
    var lowHalfTemp: UINT64 = 0;

    macros.SYMCRYPT_ASSERT((cbBuf & (@as(UINT32, @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE)) - 1)) == 0);
    macros.SYMCRYPT_ASSERT(cbBuf >= SymCryptAesKWMinCiphertextLen);
    macros.SYMCRYPT_ASSERT(cbBuf <= SymCryptAesKWMaxCiphertextLen);

    @memcpy(activeBlock[0..SYMCRYPT_AES_SEMIBLOCK_SIZE], pbBuf[0..SYMCRYPT_AES_SEMIBLOCK_SIZE]);

    var outerLoopCnt: UINT32 = 0;
    while (outerLoopCnt < 6) : (outerLoopCnt += 1) {
        var innerLoopCnt: UINT32 = 1;
        while (innerLoopCnt < nSemiBlocks) : (innerLoopCnt += 1) {
            const bufOffset: SIZE_T = @as(SIZE_T, innerLoopCnt) * SYMCRYPT_AES_SEMIBLOCK_SIZE;

            @memcpy(
                activeBlock[SYMCRYPT_AES_SEMIBLOCK_SIZE..SYMCRYPT_AES_BLOCK_SIZE],
                (pbBuf + bufOffset)[0..SYMCRYPT_AES_SEMIBLOCK_SIZE],
            );

            SymCryptAesEncrypt(pExpandedKey, &activeBlock, &activeBlock);

            @memcpy(
                (pbBuf + bufOffset)[0..SYMCRYPT_AES_SEMIBLOCK_SIZE],
                activeBlock[SYMCRYPT_AES_SEMIBLOCK_SIZE..SYMCRYPT_AES_BLOCK_SIZE],
            );

            lowHalfTemp = macros.SYMCRYPT_LOAD_LSBFIRST64(&activeBlock);
            lowHalfTemp ^= macros.SYMCRYPT_BSWAP64(encryptionIdx);
            macros.SYMCRYPT_STORE_LSBFIRST64(&activeBlock, lowHalfTemp);

            encryptionIdx += 1;
        }
    }

    macros.SYMCRYPT_ASSERT((encryptionIdx - 1) == @as(UINT64, nSemiBlocks - 1) * 6);

    macros.SYMCRYPT_STORE_LSBFIRST64(pbBuf, lowHalfTemp);

    wipeKnownSize16(&activeBlock);
}

fn symCryptAesKwxInternalUnwrap(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbBuf: PBYTE,
    cbBuf: UINT32,
) void {
    var activeBlock: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const nSemiBlocks: UINT32 = cbBuf / @as(UINT32, @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE));
    var decryptionIdx: UINT64 = 6 * @as(UINT64, nSemiBlocks - 1);
    var lowHalfTemp: UINT64 = 0;

    macros.SYMCRYPT_ASSERT((cbBuf & (@as(UINT32, @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE)) - 1)) == 0);
    macros.SYMCRYPT_ASSERT(cbBuf >= SymCryptAesKWMinCiphertextLen);
    macros.SYMCRYPT_ASSERT(cbBuf <= SymCryptAesKWMaxCiphertextLen);

    lowHalfTemp = macros.SYMCRYPT_LOAD_LSBFIRST64(pbBuf);

    var outerLoopCnt: UINT32 = 0;
    while (outerLoopCnt < 6) : (outerLoopCnt += 1) {
        var innerLoopCnt: UINT32 = nSemiBlocks - 1;
        while (innerLoopCnt > 0) : (innerLoopCnt -= 1) {
            const bufOffset: SIZE_T = @as(SIZE_T, innerLoopCnt) * SYMCRYPT_AES_SEMIBLOCK_SIZE;

            lowHalfTemp ^= macros.SYMCRYPT_BSWAP64(decryptionIdx);
            macros.SYMCRYPT_STORE_LSBFIRST64(&activeBlock, lowHalfTemp);

            @memcpy(
                activeBlock[SYMCRYPT_AES_SEMIBLOCK_SIZE..SYMCRYPT_AES_BLOCK_SIZE],
                (pbBuf + bufOffset)[0..SYMCRYPT_AES_SEMIBLOCK_SIZE],
            );

            SymCryptAesDecrypt(pExpandedKey, &activeBlock, &activeBlock);

            @memcpy(
                (pbBuf + bufOffset)[0..SYMCRYPT_AES_SEMIBLOCK_SIZE],
                activeBlock[SYMCRYPT_AES_SEMIBLOCK_SIZE..SYMCRYPT_AES_BLOCK_SIZE],
            );

            decryptionIdx -= 1;

            lowHalfTemp = macros.SYMCRYPT_LOAD_LSBFIRST64(&activeBlock);
        }
    }

    macros.SYMCRYPT_ASSERT(decryptionIdx == 0);

    macros.SYMCRYPT_STORE_LSBFIRST64(pbBuf, lowHalfTemp);

    wipeKnownSize16(&activeBlock);
}

pub export fn SymCryptAesKwEncrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbSrc < SymCryptAesKWMinPlaintextLen or
        cbSrc > SymCryptAesKWMaxPlaintextLen or
        (cbSrc & (SYMCRYPT_AES_SEMIBLOCK_SIZE - 1)) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: UINT32 = @as(UINT32, @truncate(cbSrc)) + @as(UINT32, @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE));
    if (cbDst < cbScratch) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    const rawScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const pbScratch: PBYTE = @ptrCast(rawScratch);
    defer {
        SymCryptWipe(rawScratch, cbScratch);
        SymCryptCallbackFree(rawScratch);
    }

    macros.SYMCRYPT_STORE_LSBFIRST64(pbScratch, SymCryptAesKwDefaultICV);
    @memcpy((pbScratch + 8)[0..cbSrc], pbSrc[0..cbSrc]);

    symCryptAesKwxInternalWrap(pExpandedKey, pbScratch, cbScratch);

    @memcpy(pbDst[0..cbScratch], pbScratch[0..cbScratch]);
    pcbResult.* = cbScratch;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptAesKwDecrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbSrc < SymCryptAesKWMinCiphertextLen or
        cbSrc > SymCryptAesKWMaxCiphertextLen or
        (cbSrc & (SYMCRYPT_AES_SEMIBLOCK_SIZE - 1)) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: UINT32 = @truncate(cbSrc);
    const outLen: SIZE_T = cbScratch - SYMCRYPT_AES_SEMIBLOCK_SIZE;
    if (cbDst < outLen) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    const rawScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const pbScratch: PBYTE = @ptrCast(rawScratch);
    defer {
        SymCryptWipe(rawScratch, cbScratch);
        SymCryptCallbackFree(rawScratch);
    }

    @memcpy(pbScratch[0..cbSrc], pbSrc[0..cbSrc]);

    symCryptAesKwxInternalUnwrap(pExpandedKey, pbScratch, cbScratch);

    if (macros.SYMCRYPT_LOAD_LSBFIRST64(pbScratch) != SymCryptAesKwDefaultICV) {
        return .SYMCRYPT_AUTHENTICATION_FAILURE;
    }

    @memcpy(pbDst[0..outLen], (pbScratch + SYMCRYPT_AES_SEMIBLOCK_SIZE)[0..outLen]);
    pcbResult.* = outLen;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptAesKwpEncrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbSrc < SymCryptAesKWPMinPlaintextLen or
        cbSrc > SymCryptAesKWPMaxPlaintextLen)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const semiblock32: UINT32 = @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE);
    var cbPad: UINT32 = semiblock32 - (@as(UINT32, @truncate(cbSrc)) & (semiblock32 - 1));
    if (cbPad == semiblock32) {
        cbPad = 0;
    }

    const cbScratch: UINT32 = @as(UINT32, @truncate(cbSrc)) + semiblock32 + cbPad;
    if (cbDst < cbScratch) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    macros.SYMCRYPT_ASSERT(cbScratch >= 16);

    const rawScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const pbScratch: PBYTE = @ptrCast(rawScratch);
    defer {
        SymCryptWipe(rawScratch, cbScratch);
        SymCryptCallbackFree(rawScratch);
    }

    macros.SYMCRYPT_STORE_LSBFIRST32(pbScratch, SymCryptAesKwpDefaultICV);
    macros.SYMCRYPT_STORE_MSBFIRST32(pbScratch + 4, @truncate(cbSrc));
    macros.SYMCRYPT_STORE_LSBFIRST64(pbScratch + (cbScratch - SYMCRYPT_AES_SEMIBLOCK_SIZE), 0);
    @memcpy((pbScratch + 8)[0..cbSrc], pbSrc[0..cbSrc]);

    if (cbScratch == SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesEncrypt(pExpandedKey, pbScratch, pbScratch);
    } else {
        symCryptAesKwxInternalWrap(pExpandedKey, pbScratch, cbScratch);
    }

    @memcpy(pbDst[0..cbScratch], pbScratch[0..cbScratch]);
    pcbResult.* = cbScratch;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptAesKwpDecrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var mVerificationError: UINT32 = 0;
    var mIsPlaintext: UINT32 = 0;

    if (cbSrc < SymCryptAesKWPMinCiphertextLen or
        cbSrc > SymCryptAesKWPMaxCiphertextLen or
        (cbSrc & (SYMCRYPT_AES_SEMIBLOCK_SIZE - 1)) != 0)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbScratch: UINT32 = @truncate(cbSrc);
    if (cbDst < cbScratch - SYMCRYPT_AES_SEMIBLOCK_SIZE - 7) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    const rawScratch = SymCryptCallbackAlloc(cbScratch) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    const pbScratch: PBYTE = @ptrCast(rawScratch);
    defer {
        SymCryptWipe(rawScratch, cbScratch);
        SymCryptCallbackFree(rawScratch);
    }

    @memcpy(pbScratch[0..cbSrc], pbSrc[0..cbSrc]);

    if (cbScratch == SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesDecrypt(pExpandedKey, pbScratch, pbScratch);
    } else {
        symCryptAesKwxInternalUnwrap(pExpandedKey, pbScratch, cbScratch);
    }

    mVerificationError |= macros.SYMCRYPT_LOAD_LSBFIRST32(pbScratch) ^ SymCryptAesKwpDefaultICV;

    const cbPlaintext: UINT32 = macros.SYMCRYPT_LOAD_MSBFIRST32(pbScratch + 4);
    const semiblock32: UINT32 = @intCast(SYMCRYPT_AES_SEMIBLOCK_SIZE);
    const cbPad: UINT32 = @as(UINT32, @truncate(cbSrc)) -% cbPlaintext -% semiblock32;
    mVerificationError |= cbPad & 0xfffffff8;

    var i: UINT32 = 1;
    while (i < semiblock32) : (i += 1) {
        mIsPlaintext = SymCryptMask32LtU31(i, semiblock32 - (cbPad & 7));
        mVerificationError |= @as(UINT32, pbScratch[cbScratch - semiblock32 + i]) & ~mIsPlaintext;
    }

    if (mVerificationError != 0) {
        return .SYMCRYPT_AUTHENTICATION_FAILURE;
    }

    if (cbDst < cbPlaintext) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    @memcpy(pbDst[0..cbPlaintext], (pbScratch + SYMCRYPT_AES_SEMIBLOCK_SIZE)[0..cbPlaintext]);
    pcbResult.* = cbPlaintext;

    return .SYMCRYPT_NO_ERROR;
}
