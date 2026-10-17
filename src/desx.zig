//
// desx.zig   DESX implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const des3 = @import("des3.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NO_ERROR = types.SYMCRYPT_NO_ERROR;
const SYMCRYPT_WRONG_KEY_SIZE = types.SYMCRYPT_WRONG_KEY_SIZE;
const SYMCRYPT_BLOCKCIPHER = types.SYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const SYMCRYPT_DES_EXPANDED_KEY = des3.SYMCRYPT_DES_EXPANDED_KEY;

pub const SYMCRYPT_DESX_BLOCK_SIZE: usize = 8;

pub const SYMCRYPT_DESX_EXPANDED_KEY = extern struct {
    desKey: SYMCRYPT_DES_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
    inputWhitening: [8]BYTE,
    outputWhitening: [8]BYTE,
};
pub const PSYMCRYPT_DESX_EXPANDED_KEY = *SYMCRYPT_DESX_EXPANDED_KEY;
pub const PCSYMCRYPT_DESX_EXPANDED_KEY = *const SYMCRYPT_DESX_EXPANDED_KEY;

extern fn SymCryptXorBytes(
    pbSrc1: PCBYTE,
    pbSrc2: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export const SymCryptDesxBlockCipher_default: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&SymCryptDesxExpandKey),
    .encryptFunc = @ptrCast(&SymCryptDesxEncrypt),
    .decryptFunc = @ptrCast(&SymCryptDesxDecrypt),
    .ecbEncryptFunc = null,
    .ecbDecryptFunc = null,
    .cbcEncryptFunc = null,
    .cbcDecryptFunc = null,
    .cbcMacFunc = null,
    .ctrMsb64Func = null,
    .gcmEncryptPartFunc = null,
    .gcmDecryptPartFunc = null,
    .blockSize = 8,
    .expandedKeySize = @sizeOf(SYMCRYPT_DESX_EXPANDED_KEY),
};

pub export const SymCryptDesxBlockCipher: PCSYMCRYPT_BLOCKCIPHER = &SymCryptDesxBlockCipher_default;

pub export fn SymCryptDesxExpandKey(
    pExpandedKey: PSYMCRYPT_DESX_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbKey != 24) {
        return SYMCRYPT_WRONG_KEY_SIZE;
    }

    _ = des3.SymCryptDesExpandKey(&pExpandedKey.desKey, pbKey, 8);
    @memcpy(&pExpandedKey.inputWhitening, pbKey[8..16]);
    @memcpy(&pExpandedKey.outputWhitening, pbKey[16..24]);

    return SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptDesxEncrypt(
    pExpandedKey: PCSYMCRYPT_DESX_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var buf: [8]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    SymCryptXorBytes(pbSrc, &pExpandedKey.inputWhitening, &buf, 8);
    des3.SymCryptDesEncrypt(&pExpandedKey.desKey, &buf, &buf);
    SymCryptXorBytes(&buf, &pExpandedKey.outputWhitening, pbDst, 8);

    SymCryptWipe(&buf, @sizeOf(@TypeOf(buf)));
}

pub export fn SymCryptDesxDecrypt(
    pExpandedKey: PCSYMCRYPT_DESX_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var buf: [8]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    SymCryptXorBytes(pbSrc, &pExpandedKey.outputWhitening, &buf, 8);
    des3.SymCryptDesDecrypt(&pExpandedKey.desKey, &buf, &buf);
    SymCryptXorBytes(&buf, &pExpandedKey.inputWhitening, pbDst, 8);

    SymCryptWipe(&buf, @sizeOf(@TypeOf(buf)));
}

const desxKnownKey: [24]BYTE = .{
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
};

const desxKnownPlaintext: [8]BYTE = .{
    0xd9, 0xb6, 0xa1, 0x4e, 0xe6, 0x71, 0x4e, 0x17,
};

const desxKnownCiphertext: [8]BYTE = .{
    0x66, 0x77, 0x1f, 0x2a, 0x0c, 0x05, 0x01, 0xca,
};

pub export fn SymCryptDesxSelftest() callconv(SYMCRYPT_CALL) void {
    var key: SYMCRYPT_DESX_EXPANDED_KEY = undefined;
    var buf: [SYMCRYPT_DESX_BLOCK_SIZE]BYTE = undefined;

    if (SymCryptDesxExpandKey(&key, &desxKnownKey, desxKnownKey.len) != SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desx"));
    }

    SymCryptDesxEncrypt(&key, &desxKnownPlaintext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_DESX_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &desxKnownCiphertext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desy"));
    }

    SymCryptDesxDecrypt(&key, &desxKnownCiphertext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_DESX_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &desxKnownPlaintext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desz"));
    }
}
