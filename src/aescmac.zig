//
// aescmac.zig    Implementation of the AES-CMAC block cipher mode
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
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_MAC = types.SYMCRYPT_MAC;
const PCSYMCRYPT_MAC = types.PCSYMCRYPT_MAC;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

pub const SYMCRYPT_AES_BLOCK_SIZE: usize = 16;
pub const SYMCRYPT_AES_CMAC_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_AES_CMAC_INPUT_BLOCK_SIZE: usize = 16;

pub const SYMCRYPT_AES_EXPANDED_KEY = extern struct {
    RoundKey: [29][4][4]BYTE align(SYMCRYPT_ALIGN_VALUE),
    lastEncRoundKey: *?[4][4]BYTE,
    lastDecRoundKey: *?[4][4]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_AES_EXPANDED_KEY = *SYMCRYPT_AES_EXPANDED_KEY;
pub const PCSYMCRYPT_AES_EXPANDED_KEY = *const SYMCRYPT_AES_EXPANDED_KEY;

pub const SYMCRYPT_AES_CMAC_EXPANDED_KEY = extern struct {
    aesKey: SYMCRYPT_AES_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
    K1: [16]BYTE,
    K2: [16]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_AES_CMAC_EXPANDED_KEY = *SYMCRYPT_AES_CMAC_EXPANDED_KEY;
pub const PCSYMCRYPT_AES_CMAC_EXPANDED_KEY = *const SYMCRYPT_AES_CMAC_EXPANDED_KEY;

pub const SYMCRYPT_AES_CMAC_STATE = extern struct {
    chain: [16]BYTE align(SYMCRYPT_ALIGN_VALUE),
    buf: [16]BYTE,
    bytesInBuf: SIZE_T,
    pKey: PCSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    magic: SIZE_T,
};
pub const PSYMCRYPT_AES_CMAC_STATE = *SYMCRYPT_AES_CMAC_STATE;
pub const PCSYMCRYPT_AES_CMAC_STATE = *const SYMCRYPT_AES_CMAC_STATE;

extern fn SymCryptAesExpandKey(pExpandedKey: PSYMCRYPT_AES_EXPANDED_KEY, pbKey: PCBYTE, cbKey: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptAesKeyCopy(pSrc: PCSYMCRYPT_AES_EXPANDED_KEY, pDst: PSYMCRYPT_AES_EXPANDED_KEY) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptAesEncrypt(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcMac(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbBuf: PBYTE, cbBuf: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg3: [3]BYTE;

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

pub export const SymCryptAesCmacAlgorithm_fast: SYMCRYPT_MAC = .{
    .expandKeyFunc = @ptrCast(&SymCryptAesCmacExpandKey),
    .initFunc = @ptrCast(&SymCryptAesCmacInit),
    .appendFunc = @ptrCast(&SymCryptAesCmacAppend),
    .resultFunc = @ptrCast(&SymCryptAesCmacResult),
    .expandedKeySize = @sizeOf(SYMCRYPT_AES_CMAC_EXPANDED_KEY),
    .stateSize = @sizeOf(SYMCRYPT_AES_CMAC_STATE),
    .resultSize = SYMCRYPT_AES_CMAC_RESULT_SIZE,
    .ppHashAlgorithm = null,
    .outerChainingStateOffset = 0,
};

pub export const SymCryptAesCmacAlgorithm: PCSYMCRYPT_MAC = &SymCryptAesCmacAlgorithm_fast;

pub export fn SymCryptCmacMunge(
    buf: *[SYMCRYPT_AES_BLOCK_SIZE]BYTE,
) callconv(SYMCRYPT_CALL) void {
    var carry: SIZE_T = 0;
    var i: isize = 15;
    while (i >= 0) : (i -= 1) {
        const idx: usize = @intCast(i);
        const tmp: SIZE_T = buf[idx];
        buf[idx] = @truncate(((tmp << 1) | carry) & 0xff);
        carry = tmp >> 7;
    }

    buf[15] ^= @truncate((0 -% carry) & 0x87);
}

pub export fn SymCryptAesCmacExpandKey(
    pExpandedKey: PSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var buf: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    const scError = SymCryptAesExpandKey(&pExpandedKey.aesKey, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    wipeKnownSize(&buf);

    SymCryptAesEncrypt(&pExpandedKey.aesKey, &buf, &buf);

    SymCryptCmacMunge(&buf);
    @memcpy(&pExpandedKey.K1, &buf);
    SymCryptCmacMunge(&buf);
    @memcpy(&pExpandedKey.K2, &buf);

    wipeKnownSize(&buf);

    macros.SYMCRYPT_SET_MAGIC(pExpandedKey);

    return scError;
}

pub export fn SymCryptAesCmacKeyCopy(
    pSrc: PCSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    pDst: PSYMCRYPT_AES_CMAC_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pSrc);
    SymCryptAesKeyCopy(&pSrc.aesKey, &pDst.aesKey);
    @memcpy(&pDst.K1, &pSrc.K1);
    @memcpy(&pDst.K2, &pSrc.K2);
    macros.SYMCRYPT_SET_MAGIC(pDst);
}

pub export fn SymCryptAesCmac(
    pExpandedKey: PSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_AES_CMAC_STATE = undefined;

    SymCryptAesCmacInit(&state, pExpandedKey);
    SymCryptAesCmacAppend(&state, pbData, cbData);
    SymCryptAesCmacResult(&state, pbResult);

    wipeKnownSize(&state);
}

pub export fn SymCryptAesCmacStateCopy(
    pSrc: PCSYMCRYPT_AES_CMAC_STATE,
    pExpandedKey: ?PCSYMCRYPT_AES_CMAC_EXPANDED_KEY,
    pDst: PSYMCRYPT_AES_CMAC_STATE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pSrc);
    pDst.* = pSrc.*;

    if (pExpandedKey) |key| {
        macros.SYMCRYPT_CHECK_MAGIC(key);
        pDst.pKey = key;
    } else {
        macros.SYMCRYPT_CHECK_MAGIC(pSrc.pKey);
        pDst.pKey = pSrc.pKey;
    }

    macros.SYMCRYPT_SET_MAGIC(pDst);
}

pub export fn SymCryptAesCmacInit(
    pState: PSYMCRYPT_AES_CMAC_STATE,
    pExpandedKey: PCSYMCRYPT_AES_CMAC_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    pState.bytesInBuf = 0;
    wipeKnownSize(&pState.chain);
    pState.pKey = pExpandedKey;

    macros.SYMCRYPT_SET_MAGIC(pState);
}

pub export fn SymCryptAesCmacAppend(
    pState: PSYMCRYPT_AES_CMAC_STATE,
    pbDataIn: PCBYTE,
    cbDataIn: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData: PCBYTE = pbDataIn;
    var cbData: SIZE_T = cbDataIn;

    macros.SYMCRYPT_CHECK_MAGIC(pState);

    if (pState.bytesInBuf != 0) {
        const freeInBuf: SIZE_T = SYMCRYPT_AES_BLOCK_SIZE - pState.bytesInBuf;
        macros.SYMCRYPT_ASSERT(freeInBuf < SYMCRYPT_AES_BLOCK_SIZE);

        if (cbData <= freeInBuf) {
            // Do nothing; data will be copied into buf at the end of this function.
        } else {
            @memcpy(pState.buf[pState.bytesInBuf .. pState.bytesInBuf + freeInBuf], pbData[0..freeInBuf]);
            pbData += freeInBuf;
            cbData -= freeInBuf;
            SymCryptAesCbcMac(&pState.pKey.aesKey, &pState.chain, &pState.buf, SYMCRYPT_AES_BLOCK_SIZE);
            pState.bytesInBuf = 0;
        }
    }

    if (cbData > SYMCRYPT_AES_BLOCK_SIZE) {
        const bytesToDo: SIZE_T = (cbData - 1) & ~@as(SIZE_T, SYMCRYPT_AES_BLOCK_SIZE - 1);
        SymCryptAesCbcMac(&pState.pKey.aesKey, &pState.chain, pbData, bytesToDo);
        pbData += bytesToDo;
        cbData -= bytesToDo;
    }

    if (cbData > 0) {
        @memcpy(pState.buf[pState.bytesInBuf .. pState.bytesInBuf + cbData], pbData[0..cbData]);
        pState.bytesInBuf += cbData;
    }
}

pub export fn SymCryptAesCmacResult(
    pState: PSYMCRYPT_AES_CMAC_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pState);

    if (pState.bytesInBuf < SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptWipe(@ptrCast(pState.buf[pState.bytesInBuf + 1 ..].ptr), SYMCRYPT_AES_BLOCK_SIZE - pState.bytesInBuf - 1);
        pState.buf[pState.bytesInBuf] = 0x80;
        SymCryptXorBytes(&pState.buf, &pState.pKey.K2, &pState.buf, SYMCRYPT_AES_BLOCK_SIZE);
    } else {
        SymCryptXorBytes(&pState.buf, &pState.pKey.K1, &pState.buf, SYMCRYPT_AES_BLOCK_SIZE);
    }

    SymCryptAesCbcMac(&pState.pKey.aesKey, &pState.chain, &pState.buf, SYMCRYPT_AES_BLOCK_SIZE);
    @memcpy(pbResult[0..SYMCRYPT_AES_BLOCK_SIZE], &pState.chain);

    pState.bytesInBuf = 0;
    wipeKnownSize(&pState.chain);
    wipeKnownSize(&pState.buf);
}

const aesCmacKat: [SYMCRYPT_AES_CMAC_RESULT_SIZE]BYTE = .{
    0x0a, 0x54, 0xa6, 0xa4, 0x25, 0xd4, 0x84, 0x38, 0xc3, 0xf8, 0xbb, 0xe0, 0x9b, 0xf9, 0x44, 0xcc,
};

pub export fn SymCryptAesCmacSelftest() callconv(SYMCRYPT_CALL) void {
    var xKey: SYMCRYPT_AES_CMAC_EXPANDED_KEY = undefined;
    var res: [SYMCRYPT_AES_CMAC_RESULT_SIZE]BYTE = undefined;

    _ = SymCryptAesCmacExpandKey(&xKey, &SymCryptTestKey32, 16);
    SymCryptAesCmac(&xKey, &SymCryptTestMsg3, SymCryptTestMsg3.len, &res);

    SymCryptInjectError(&res, res.len);
    if (!std.mem.eql(u8, &res, &aesCmacKat)) {
        macros.SymCryptFatal(macros.multiCharConstant("hsh5"));
    }
}
