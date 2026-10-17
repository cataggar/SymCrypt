//
// aes_asm.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// All AES code that calls upon ASM functions.
//

const types = @import("types.zig");

const SIZE_T = types.SIZE_T;
const PCBYTE = types.PCBYTE;
const PBYTE = types.PBYTE;
const PCSYMCRYPT_AES_EXPANDED_KEY = types.PCSYMCRYPT_AES_EXPANDED_KEY;

pub extern fn SymCryptAesEncryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(types.SYMCRYPT_CALL) void;

pub extern fn SymCryptAesDecryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(types.SYMCRYPT_CALL) void;

pub extern fn SymCryptAesCbcEncryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void;

pub extern fn SymCryptAesCbcDecryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void;

pub extern fn SymCryptAesCtrMsb64Asm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void;

pub fn SymCryptAesEcbEncryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var src = pbSrc;
    var dst = pbDst;
    var remaining = cbData;

    while (remaining >= types.SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesEncryptAsm(pExpandedKey, src, dst);
        src += types.SYMCRYPT_AES_BLOCK_SIZE;
        dst += types.SYMCRYPT_AES_BLOCK_SIZE;
        remaining -= types.SYMCRYPT_AES_BLOCK_SIZE;
    }
}

pub fn SymCryptAesEcbDecryptAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var src = pbSrc;
    var dst = pbDst;
    var remaining = cbData;

    while (remaining >= types.SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesDecryptAsm(pExpandedKey, src, dst);
        src += types.SYMCRYPT_AES_BLOCK_SIZE;
        dst += types.SYMCRYPT_AES_BLOCK_SIZE;
        remaining -= types.SYMCRYPT_AES_BLOCK_SIZE;
    }
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM) {
        @export(&SymCryptAesEcbEncryptAsm, .{ .name = "SymCryptAesEcbEncryptAsm" });
        @export(&SymCryptAesEcbDecryptAsm, .{ .name = "SymCryptAesEcbDecryptAsm" });
    }
}
