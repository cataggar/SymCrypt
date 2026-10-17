//
// hash.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Generic hash engine routines and common state structures ported from lib/hash.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

// ==============================================================================================
// External C Helpers
// ==============================================================================================

pub extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;
pub extern const SymCryptMarvin32DefaultSeed: PCVOID;
pub extern fn SymCryptMarvin32(
    pExpandedSeed: PCVOID,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void;
pub extern const SymCryptTestMsg3: [3]BYTE;
pub extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const wipe_limit: usize = if (types.CPU_X86 or types.CPU_ARM)
    32
else if (types.CPU_AMD64 or types.CPU_ARM64)
    64
else
    0;

pub inline fn SymCryptWipeKnownSize(pbData: PVOID, comptime cbData: usize) void {
    if (cbData > wipe_limit) {
        SymCryptWipe(pbData, cbData);
    } else {
        const pb: [*]u8 = @ptrCast(pbData.?);
        comptime var rem: usize = cbData;
        if ((rem & 1) != 0) {
            rem -= 1;
            macros.FORCE_WRITE8(pb + rem, 0);
        }
        if ((rem & 2) != 0) {
            rem -= 2;
            macros.FORCE_WRITE16(pb + rem, 0);
        }
        if ((rem & 4) != 0) {
            rem -= 4;
            macros.FORCE_WRITE32(pb + rem, 0);
        }
        if ((rem & 8) != 0) {
            rem -= 8;
            macros.FORCE_WRITE64(pb + rem, 0);
        }
        if ((rem & 16) != 0) {
            rem -= 16;
            macros.FORCE_WRITE64(pb + rem, 0);
            macros.FORCE_WRITE64(pb + rem + 8, 0);
        }
        if ((rem & 32) != 0) {
            rem -= 32;
            macros.FORCE_WRITE64(pb + rem, 0);
            macros.FORCE_WRITE64(pb + rem + 8, 0);
            macros.FORCE_WRITE64(pb + rem + 16, 0);
            macros.FORCE_WRITE64(pb + rem + 24, 0);
        }
        if (wipe_limit >= 64 and (rem & 64) != 0) {
            rem -= 64;
            macros.FORCE_WRITE64(pb + rem, 0);
            macros.FORCE_WRITE64(pb + rem + 8, 0);
            macros.FORCE_WRITE64(pb + rem + 16, 0);
            macros.FORCE_WRITE64(pb + rem + 24, 0);
            macros.FORCE_WRITE64(pb + rem + 32, 0);
            macros.FORCE_WRITE64(pb + rem + 40, 0);
            macros.FORCE_WRITE64(pb + rem + 48, 0);
            macros.FORCE_WRITE64(pb + rem + 56, 0);
        }
    }
}

// ==============================================================================================
// Blob Export / Import Constants & Structures (from lib/sc_lib.h)
// ==============================================================================================

pub const SYMCRYPT_BLOB_MAGIC: UINT32 = macros.multiCharConstant("cmys");

pub const SYMCRYPT_BLOB_TYPE = enum(UINT32) {
    SymCryptBlobTypeUnknown = 0,
    SymCryptBlobTypeHashState = 0x100,
    SymCryptBlobTypeMd2State = 0x100 + 1,
    SymCryptBlobTypeMd4State = 0x100 + 2,
    SymCryptBlobTypeMd5State = 0x100 + 3,
    SymCryptBlobTypeSha1State = 0x100 + 4,
    SymCryptBlobTypeSha256State = 0x100 + 5,
    SymCryptBlobTypeSha384State = 0x100 + 6,
    SymCryptBlobTypeSha512State = 0x100 + 7,
    SymCryptBlobTypeSha3_256State = 0x100 + 8,
    SymCryptBlobTypeSha3_384State = 0x100 + 9,
    SymCryptBlobTypeSha3_512State = 0x100 + 10,
    SymCryptBlobTypeSha224State = 0x100 + 11,
    SymCryptBlobTypeSha512_224State = 0x100 + 12,
    SymCryptBlobTypeSha512_256State = 0x100 + 13,
    SymCryptBlobTypeSha3_224State = 0x100 + 14,
    SymCryptBlobTypeShake128State = 0x100 + 15,
    SymCryptBlobTypeShake256State = 0x100 + 16,
    _,
};

pub const SYMCRYPT_BLOB_HEADER = extern struct {
    magic: UINT32 align(1),
    size: UINT32 align(1),
    type: UINT32 align(1),
};

pub const SYMCRYPT_BLOB_TRAILER = extern struct {
    checksum: [8]BYTE,
};

// ==============================================================================================
// Hash State Structures (from inc/symcrypt_internal.h)
// ==============================================================================================

pub const SYMCRYPT_HASH_MAX_RESULT_SIZE: usize = 64;

pub const SYMCRYPT_COMMON_HASH_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [1]BYTE align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_COMMON_HASH_STATE = *SYMCRYPT_COMMON_HASH_STATE;
pub const PCSYMCRYPT_COMMON_HASH_STATE = *const SYMCRYPT_COMMON_HASH_STATE;

pub const SYMCRYPT_MD2_CHAINING_STATE = extern struct {
    C: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    X: [48]BYTE,
};
pub const PSYMCRYPT_MD2_CHAINING_STATE = *SYMCRYPT_MD2_CHAINING_STATE;

pub const SYMCRYPT_MD2_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD2_CHAINING_STATE,
};
pub const PSYMCRYPT_MD2_STATE = *SYMCRYPT_MD2_STATE;
pub const PCSYMCRYPT_MD2_STATE = *const SYMCRYPT_MD2_STATE;

pub const SYMCRYPT_MD4_CHAINING_STATE = extern struct {
    H: [4]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_MD4_CHAINING_STATE = *SYMCRYPT_MD4_CHAINING_STATE;

pub const SYMCRYPT_MD4_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD4_CHAINING_STATE,
};
pub const PSYMCRYPT_MD4_STATE = *SYMCRYPT_MD4_STATE;
pub const PCSYMCRYPT_MD4_STATE = *const SYMCRYPT_MD4_STATE;

pub const SYMCRYPT_MD5_CHAINING_STATE = extern struct {
    H: [4]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_MD5_CHAINING_STATE = *SYMCRYPT_MD5_CHAINING_STATE;

pub const SYMCRYPT_MD5_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MD5_CHAINING_STATE,
};
pub const PSYMCRYPT_MD5_STATE = *SYMCRYPT_MD5_STATE;
pub const PCSYMCRYPT_MD5_STATE = *const SYMCRYPT_MD5_STATE;

pub const SYMCRYPT_SHA1_CHAINING_STATE = extern struct {
    H: [5]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA1_CHAINING_STATE = *SYMCRYPT_SHA1_CHAINING_STATE;

pub const SYMCRYPT_SHA1_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA1_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA1_STATE = *SYMCRYPT_SHA1_STATE;
pub const PCSYMCRYPT_SHA1_STATE = *const SYMCRYPT_SHA1_STATE;

pub const SYMCRYPT_SHA256_CHAINING_STATE = extern struct {
    H: [8]UINT32 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA256_CHAINING_STATE = *SYMCRYPT_SHA256_CHAINING_STATE;

pub const SYMCRYPT_SHA256_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [64]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA256_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA256_STATE = *SYMCRYPT_SHA256_STATE;
pub const PCSYMCRYPT_SHA256_STATE = *const SYMCRYPT_SHA256_STATE;
pub const SYMCRYPT_SHA224_STATE = SYMCRYPT_SHA256_STATE;

pub const SYMCRYPT_SHA512_CHAINING_STATE = extern struct {
    H: [8]UINT64 align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_SHA512_CHAINING_STATE = *SYMCRYPT_SHA512_CHAINING_STATE;

pub const SYMCRYPT_SHA512_STATE = extern struct {
    bytesInBuffer: UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
    dataLengthL: UINT64,
    dataLengthH: UINT64,
    buffer: [128]BYTE align(SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_SHA512_CHAINING_STATE,
};
pub const PSYMCRYPT_SHA512_STATE = *SYMCRYPT_SHA512_STATE;
pub const PCSYMCRYPT_SHA512_STATE = *const SYMCRYPT_SHA512_STATE;
pub const SYMCRYPT_SHA384_STATE = SYMCRYPT_SHA512_STATE;
pub const SYMCRYPT_SHA512_224_STATE = SYMCRYPT_SHA512_STATE;
pub const SYMCRYPT_SHA512_256_STATE = SYMCRYPT_SHA512_STATE;

pub const SYMCRYPT_KECCAK_STATE = extern struct {
    state: [25]UINT64 align(SYMCRYPT_ALIGN_VALUE),
    inputBlockSize: UINT32,
    stateIndex: UINT32,
    paddingValue: UINT8,
    squeezeMode: BOOLEAN,
};

pub const SYMCRYPT_SHA3_STATE = extern struct {
    ks: SYMCRYPT_KECCAK_STATE align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};

pub const SYMCRYPT_HASH_STATE = extern union {
    md2State: SYMCRYPT_MD2_STATE,
    md4State: SYMCRYPT_MD4_STATE,
    md5State: SYMCRYPT_MD5_STATE,
    sha1State: SYMCRYPT_SHA1_STATE,
    sha224State: SYMCRYPT_SHA224_STATE,
    sha256State: SYMCRYPT_SHA256_STATE,
    sha384State: SYMCRYPT_SHA384_STATE,
    sha512State: SYMCRYPT_SHA512_STATE,
    sha512_224State: SYMCRYPT_SHA512_224_STATE,
    sha512_256State: SYMCRYPT_SHA512_256_STATE,
    sha3_224State: SYMCRYPT_SHA3_STATE,
    sha3_256State: SYMCRYPT_SHA3_STATE,
    sha3_384State: SYMCRYPT_SHA3_STATE,
    sha3_512State: SYMCRYPT_SHA3_STATE,
};
pub const PSYMCRYPT_HASH_STATE = *SYMCRYPT_HASH_STATE;
pub const PCSYMCRYPT_HASH_STATE = *const SYMCRYPT_HASH_STATE;

// ==============================================================================================
// Generic Hash Functions (from lib/hash.c)
// ==============================================================================================

pub export fn SymCryptHashAppendInternal(
    pHash: PCSYMCRYPT_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var bytesInBuffer: UINT32 = undefined;
    var freeInBuffer: UINT32 = undefined;
    var tmp: SIZE_T = 0;
    var currPbData = pbData;
    var currCbData = cbData;

    macros.CHECK_MAGIC(pState);

    pState.dataLengthL +%= currCbData;
    if (pState.dataLengthL < currCbData) {
        pState.dataLengthH +%= 1;
    }

    bytesInBuffer = pState.bytesInBuffer;
    const buf: [*]BYTE = @ptrCast(&pState.buffer);
    const chainPtr: PVOID = @ptrCast(@as([*]BYTE, @ptrCast(pState)) + pHash.chainOffset);

    if (bytesInBuffer > 0) {
        macros.ASSERT(pHash.inputBlockSize > bytesInBuffer);

        freeInBuffer = pHash.inputBlockSize - bytesInBuffer;
        if (currCbData < freeInBuffer) {
            // All the data will fit in the buffer.
            // Bulk data processing is skipped and the data will be copied at the end.
        } else {
            @memcpy((buf + bytesInBuffer)[0..freeInBuffer], currPbData[0..freeInBuffer]);
            currPbData += freeInBuffer;
            currCbData -= freeInBuffer;
            pHash.appendBlockFunc.?(chainPtr, buf, pHash.inputBlockSize, &tmp);

            bytesInBuffer = 0;
        }
    }

    if (currCbData >= pHash.inputBlockSize) {
        pHash.appendBlockFunc.?(chainPtr, currPbData, currCbData, &tmp);
        macros.ASSERT(tmp < pHash.inputBlockSize);
        currPbData += currCbData - tmp;
        currCbData = tmp;
    }

    macros.ASSERT(currCbData < pHash.inputBlockSize);

    if (currCbData > 0) {
        @memcpy((buf + bytesInBuffer)[0..currCbData], currPbData[0..currCbData]);
        bytesInBuffer += @intCast(currCbData);
    }

    pState.bytesInBuffer = bytesInBuffer;
}

pub export fn SymCryptHashCommonPaddingMd4Style(
    pHash: PCSYMCRYPT_HASH,
    pState: PSYMCRYPT_COMMON_HASH_STATE,
) callconv(SYMCRYPT_CALL) void {
    var tmp: SIZE_T = 0;
    var bytesInBuffer: SIZE_T = pState.bytesInBuffer;

    macros.CHECK_MAGIC(pState);
    macros.ASSERT(pHash.inputBlockSize == 64);
    macros.ASSERT(bytesInBuffer == @as(SIZE_T, @intCast(pState.dataLengthL & 0x3f)));

    const buf: [*]BYTE = @ptrCast(&pState.buffer);
    const chainPtr: PVOID = @ptrCast(@as([*]BYTE, @ptrCast(pState)) + pHash.chainOffset);

    buf[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    if (bytesInBuffer > 64 - 8) {
        SymCryptWipe(@ptrCast(buf + bytesInBuffer), 64 - bytesInBuffer);
        pHash.appendBlockFunc.?(chainPtr, buf, 64, &tmp);
        macros.ASSERT(tmp == 0);
        bytesInBuffer = 0;
    }

    SymCryptWipe(@ptrCast(buf + bytesInBuffer), 64 - bytesInBuffer);
    macros.STORE_LSBFIRST64(buf + (64 - 8), pState.dataLengthL *% 8);

    pHash.appendBlockFunc.?(chainPtr, buf, 64, &tmp);
}

pub export fn SymCryptHashResultSize(pHash: PCSYMCRYPT_HASH) callconv(SYMCRYPT_CALL) SIZE_T {
    return pHash.resultSize;
}

pub export fn SymCryptHashInputBlockSize(pHash: PCSYMCRYPT_HASH) callconv(SYMCRYPT_CALL) SIZE_T {
    return pHash.inputBlockSize;
}

pub export fn SymCryptHashStateSize(pHash: PCSYMCRYPT_HASH) callconv(SYMCRYPT_CALL) SIZE_T {
    return pHash.stateSize;
}

pub export fn SymCryptHash(
    pHash: PCSYMCRYPT_HASH,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var hashState: SYMCRYPT_HASH_STATE = undefined;

    macros.ASSERT(pHash.stateSize <= @sizeOf(SYMCRYPT_HASH_STATE));
    SymCryptHashInit(pHash, @ptrCast(&hashState));
    SymCryptHashAppend(pHash, @ptrCast(&hashState), pbData, cbData);
    SymCryptHashResult(pHash, @ptrCast(&hashState), pbResult, cbResult);
    SymCryptWipe(@ptrCast(&hashState), pHash.stateSize);
}

pub export fn SymCryptHashInit(
    pHash: PCSYMCRYPT_HASH,
    pState: PVOID,
) callconv(SYMCRYPT_CALL) void {
    pHash.initFunc.?(pState);
}

pub export fn SymCryptHashAppend(
    pHash: PCSYMCRYPT_HASH,
    pState: PVOID,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    pHash.appendFunc.?(pState, pbData, cbData);
}

pub export fn SymCryptHashResult(
    pHash: PCSYMCRYPT_HASH,
    pState: PVOID,
    pbResult: PBYTE,
    cbResult: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = undefined;

    macros.ASSERT(pHash.resultSize <= SYMCRYPT_HASH_MAX_RESULT_SIZE);

    pHash.resultFunc.?(pState, @ptrCast(&buf));
    const copyLen = @min(cbResult, @as(SIZE_T, pHash.resultSize));
    if (copyLen > 0) {
        @memcpy(pbResult[0..copyLen], buf[0..copyLen]);
    }
    SymCryptWipe(@ptrCast(&buf), pHash.resultSize);
}

pub export fn SymCryptHashStateCopy(
    pHash: PCSYMCRYPT_HASH,
    pSrc: PCVOID,
    pDst: PVOID,
) callconv(SYMCRYPT_CALL) void {
    pHash.stateCopyFunc.?(pSrc, pDst);
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_BLOB_HEADER) == 12);
    std.debug.assert(@sizeOf(SYMCRYPT_BLOB_TRAILER) == 8);
}
