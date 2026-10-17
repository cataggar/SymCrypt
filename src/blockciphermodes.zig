//
// blockciphermodes.zig   generic implementation of all block cipher modes
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const SYMCRYPT_MAX_BLOCK_SIZE = types.SYMCRYPT_MAX_BLOCK_SIZE;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

inline fn wipeKnownSize(buf: anytype) void {
    const bytes = std.mem.asBytes(buf);
    if (comptime (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)) {
        const limit: usize = if (types.CPU_X86 or types.CPU_ARM) 32 else 64;
        if (bytes.len <= limit) {
            const ptr: [*]u8 = @ptrCast(bytes.ptr);
            var cbData: usize = bytes.len;
            if ((cbData & 1) != 0) {
                cbData -= 1;
                macros.FORCE_WRITE8(ptr + cbData, 0);
            }
            if ((cbData & 2) != 0) {
                cbData -= 2;
                macros.FORCE_WRITE16(ptr + cbData, 0);
            }
            if ((cbData & 4) != 0) {
                cbData -= 4;
                macros.FORCE_WRITE32(ptr + cbData, 0);
            }
            if ((cbData & 8) != 0) {
                cbData -= 8;
                macros.FORCE_WRITE64(ptr + cbData, 0);
            }
            if ((cbData & 16) != 0) {
                cbData -= 16;
                macros.FORCE_WRITE64(ptr + cbData, 0);
                macros.FORCE_WRITE64(ptr + cbData + 8, 0);
            }
            if ((cbData & 32) != 0) {
                cbData -= 32;
                macros.FORCE_WRITE64(ptr + cbData, 0);
                macros.FORCE_WRITE64(ptr + cbData + 8, 0);
                macros.FORCE_WRITE64(ptr + cbData + 16, 0);
                macros.FORCE_WRITE64(ptr + cbData + 24, 0);
            }
            if (comptime limit >= 64) {
                if ((cbData & 64) != 0) {
                    cbData -= 64;
                    macros.FORCE_WRITE64(ptr + cbData, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 8, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 16, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 24, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 32, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 40, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 48, 0);
                    macros.FORCE_WRITE64(ptr + cbData + 56, 0);
                }
            }
            return;
        }
    }
    SymCryptWipe(@ptrCast(bytes.ptr), bytes.len);
}

pub export fn SymCryptEcbEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const cbToDo: SIZE_T = cbData & ~(pBlockCipher.blockSize - 1);

    if (pBlockCipher.ecbEncryptFunc) |ecbEncryptFunc| {
        ecbEncryptFunc(pExpandedKey, pbSrc, pbDst, cbData);
        return;
    }

    const encryptFunc = pBlockCipher.encryptFunc.?;
    var i: SIZE_T = 0;
    while (i < cbToDo) : (i += pBlockCipher.blockSize) {
        encryptFunc(pExpandedKey, pbSrc + i, pbDst + i);
    }
}

pub export fn SymCryptEcbDecrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const cbToDo: SIZE_T = cbData & ~(pBlockCipher.blockSize - 1);

    if (pBlockCipher.ecbDecryptFunc) |ecbDecryptFunc| {
        ecbDecryptFunc(pExpandedKey, pbSrc, pbDst, cbData);
        return;
    }

    const decryptFunc = pBlockCipher.decryptFunc.?;
    var i: SIZE_T = 0;
    while (i < cbToDo) : (i += pBlockCipher.blockSize) {
        decryptFunc(pExpandedKey, pbSrc + i, pbDst + i);
    }
}

pub export fn SymCryptCbcEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var pSrc: PCBYTE = pbSrc;
    var pDst: PBYTE = pbDst;

    if (pBlockCipher.cbcEncryptFunc) |cbcEncryptFunc| {
        cbcEncryptFunc(pExpandedKey, pbChainingValue, pSrc, pDst, cbData);
        return;
    }

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const pbSrcEnd: PCBYTE = pbSrc + (cbData & ~(blockSize - 1));
    const encryptFunc = pBlockCipher.encryptFunc.?;

    @memcpy(buf[0..blockSize], pbChainingValue[0..blockSize]);
    while (@intFromPtr(pSrc) < @intFromPtr(pbSrcEnd)) {
        SymCryptXorBytes(pSrc, &buf, &buf, blockSize);
        encryptFunc(pExpandedKey, &buf, &buf);
        @memcpy(pDst[0..blockSize], buf[0..blockSize]);
        pSrc += blockSize;
        pDst += blockSize;
    }

    @memcpy(pbChainingValue[0..blockSize], buf[0..blockSize]);
    wipeKnownSize(&buf);
}

pub export fn SymCryptCbcDecrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [3 * SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const chain: PBYTE = buf[0..SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const ciphertext: PBYTE = buf[SYMCRYPT_MAX_BLOCK_SIZE .. 2 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const tmp: PBYTE = buf[2 * SYMCRYPT_MAX_BLOCK_SIZE .. 3 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;

    if (pBlockCipher.cbcDecryptFunc) |cbcDecryptFunc| {
        cbcDecryptFunc(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        return;
    }

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const pbSrcEnd: PCBYTE = pbSrc + (cbData & ~(blockSize - 1));
    const decryptFunc = pBlockCipher.decryptFunc.?;
    var pSrc: PCBYTE = pbSrc;
    var pDst: PBYTE = pbDst;

    @memcpy(chain[0..blockSize], pbChainingValue[0..blockSize]);

    while (@intFromPtr(pSrc) < @intFromPtr(pbSrcEnd)) {
        @memcpy(ciphertext[0..blockSize], pSrc[0..blockSize]);
        decryptFunc(pExpandedKey, ciphertext, tmp);
        SymCryptXorBytes(tmp, chain, pDst, blockSize);
        @memcpy(chain[0..blockSize], ciphertext[0..blockSize]);
        pDst += blockSize;
        pSrc += blockSize;
    }

    @memcpy(pbChainingValue[0..blockSize], chain[0..blockSize]);
    wipeKnownSize(&buf);
}

pub export fn SymCryptCbcMac(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [32]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    if (pBlockCipher.cbcMacFunc) |cbcMacFunc| {
        cbcMacFunc(pExpandedKey, pbChainingValue, pbSrc, cbData);
        return;
    }

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const pbSrcEnd: PCBYTE = pbSrc + (cbData & ~(blockSize - 1));
    const encryptFunc = pBlockCipher.encryptFunc.?;

    @memcpy(buf[0..blockSize], pbChainingValue[0..blockSize]);
    var p: PCBYTE = pbSrc;
    while (@intFromPtr(p) < @intFromPtr(pbSrcEnd)) {
        SymCryptXorBytes(p, &buf, &buf, blockSize);
        encryptFunc(pExpandedKey, &buf, &buf);
        p += blockSize;
    }

    @memcpy(pbChainingValue[0..blockSize], buf[0..blockSize]);
    wipeKnownSize(&buf);
}

pub export fn SymCryptCtrMsb32(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const count: PBYTE = buf[0..SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const keystream: PBYTE = buf[SYMCRYPT_MAX_BLOCK_SIZE .. 2 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const pbSrcEnd: PCBYTE = pbSrc + (cbData & ~(blockSize - 1));
    const encryptFunc = pBlockCipher.encryptFunc.?;
    var pSrc: PCBYTE = pbSrc;
    var pDst: PBYTE = pbDst;

    @memcpy(count[0..blockSize], pbChainingValue[0..blockSize]);
    while (@intFromPtr(pSrc) < @intFromPtr(pbSrcEnd)) {
        encryptFunc(pExpandedKey, count, keystream);
        SymCryptXorBytes(keystream, pSrc, pDst, blockSize);

        macros.SYMCRYPT_STORE_MSBFIRST32(
            count + (blockSize - 4),
            1 +% macros.SYMCRYPT_LOAD_MSBFIRST32(count + (blockSize - 4)),
        );

        pSrc += blockSize;
        pDst += blockSize;
    }

    @memcpy(pbChainingValue[0..blockSize], count[0..blockSize]);
    wipeKnownSize(&buf);
}

pub export fn SymCryptCtrMsb64(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const count: PBYTE = buf[0..SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const keystream: PBYTE = buf[SYMCRYPT_MAX_BLOCK_SIZE .. 2 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;

    if (pBlockCipher.ctrMsb64Func) |ctrMsb64Func| {
        ctrMsb64Func(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        return;
    }

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const pbSrcEnd: PCBYTE = pbSrc + (cbData & ~(blockSize - 1));
    const encryptFunc = pBlockCipher.encryptFunc.?;
    var pSrc: PCBYTE = pbSrc;
    var pDst: PBYTE = pbDst;

    @memcpy(count[0..blockSize], pbChainingValue[0..blockSize]);
    while (@intFromPtr(pSrc) < @intFromPtr(pbSrcEnd)) {
        encryptFunc(pExpandedKey, count, keystream);
        SymCryptXorBytes(keystream, pSrc, pDst, blockSize);

        macros.SYMCRYPT_STORE_MSBFIRST64(
            count + (blockSize - 8),
            1 +% macros.SYMCRYPT_LOAD_MSBFIRST64(count + (blockSize - 8)),
        );

        pSrc += blockSize;
        pDst += blockSize;
    }

    @memcpy(pbChainingValue[0..blockSize], count[0..blockSize]);
    wipeKnownSize(&buf);
}

pub export fn SymCryptCfbEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    cbShiftIn: SIZE_T,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrcIn: PCBYTE,
    pbDstIn: PBYTE,
    cbDataIn: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const chain: PBYTE = buf[0..SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const tmp: PBYTE = buf[SYMCRYPT_MAX_BLOCK_SIZE .. 2 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const cbShift: SIZE_T = if (cbShiftIn != 1) blockSize else 1;
    const encryptFunc = pBlockCipher.encryptFunc.?;

    var pbSrc: PCBYTE = pbSrcIn;
    var pbDst: PBYTE = pbDstIn;
    var cbData: SIZE_T = cbDataIn;

    @memcpy(chain[0..blockSize], pbChainingValue[0..blockSize]);
    while (cbData >= cbShift) {
        encryptFunc(pExpandedKey, chain, tmp);
        SymCryptXorBytes(pbSrc, tmp, tmp, cbShift);
        @memcpy(pbDst[0..cbShift], tmp[0..cbShift]);

        std.mem.copyForwards(u8, chain[0 .. blockSize - cbShift], chain[cbShift..blockSize]);
        @memcpy(chain[blockSize - cbShift .. blockSize], tmp[0..cbShift]);

        pbDst += cbShift;
        pbSrc += cbShift;
        cbData -= cbShift;
    }

    @memcpy(pbChainingValue[0..blockSize], chain[0..blockSize]);
}

pub export fn SymCryptCfbDecrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    cbShiftIn: SIZE_T,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrcIn: PCBYTE,
    pbDstIn: PBYTE,
    cbDataIn: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_MAX_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;
    const chain: PBYTE = buf[0..SYMCRYPT_MAX_BLOCK_SIZE].ptr;
    const tmp: PBYTE = buf[SYMCRYPT_MAX_BLOCK_SIZE .. 2 * SYMCRYPT_MAX_BLOCK_SIZE].ptr;

    const blockSize: SIZE_T = pBlockCipher.blockSize;
    macros.SYMCRYPT_ASSERT(blockSize <= SYMCRYPT_MAX_BLOCK_SIZE);

    const cbShift: SIZE_T = if (cbShiftIn != 1) blockSize else 1;
    const encryptFunc = pBlockCipher.encryptFunc.?;

    var pbSrc: PCBYTE = pbSrcIn;
    var pbDst: PBYTE = pbDstIn;
    var cbData: SIZE_T = cbDataIn;

    @memcpy(chain[0..blockSize], pbChainingValue[0..blockSize]);
    while (cbData >= cbShift) {
        encryptFunc(pExpandedKey, chain, tmp);

        std.mem.copyForwards(u8, chain[0 .. blockSize - cbShift], chain[cbShift..blockSize]);
        @memcpy(chain[blockSize - cbShift .. blockSize], pbSrc[0..cbShift]);

        SymCryptXorBytes(chain + (blockSize - cbShift), tmp, pbDst, cbShift);

        pbDst += cbShift;
        pbSrc += cbShift;
        cbData -= cbShift;
    }

    @memcpy(pbChainingValue[0..blockSize], chain[0..blockSize]);
}
