//
// aes_default.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This is the interface for the default AES implementation.
// On each platform, this is the fastest AES implementation irrespective of code size.
// It uses assembler, XMM, or any other trick.
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_key = @import("aes_key.zig");
const aes_c = @import("aes_c.zig");
const aes_asm = @import("aes_asm.zig");

const SIZE_T = types.SIZE_T;
const BOOL = types.BOOL;
const PCBYTE = types.PCBYTE;
const PBYTE = types.PBYTE;
const PCVOID = types.PCVOID;
const SYMCRYPT_BLOCKCIPHER = types.SYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_AES_EXPANDED_KEY = types.PCSYMCRYPT_AES_EXPANDED_KEY;
const PSYMCRYPT_GCM_STATE = types.PSYMCRYPT_GCM_STATE;
const PSYMCRYPT_GF128_ELEMENT = types.PSYMCRYPT_GF128_ELEMENT;
const PCSYMCRYPT_GF128_ELEMENT = types.PCSYMCRYPT_GF128_ELEMENT;
const PCSYMCRYPT_GHASH_EXPANDED_KEY = types.PCSYMCRYPT_GHASH_EXPANDED_KEY;

extern fn SymCryptAes4SboxXmm(pIn: PCBYTE, pOut: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAes4SboxNeon(pIn: PCBYTE, pOut: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCreateDecryptionRoundKeyXmm(pEncryptionRoundKey: PCBYTE, pDecryptionRoundKey: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCreateDecryptionRoundKeyNeon(pEncryptionRoundKey: PCBYTE, pDecryptionRoundKey: PBYTE) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesEncryptXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesEncryptNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesDecryptXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesDecryptNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesEcbEncryptXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesEcbEncryptNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesCbcEncryptXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcEncryptNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcDecryptXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcDecryptNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcDecryptYmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesCbcMacXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbData: PCBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCbcMacNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbData: PCBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesCtrMsb32Xmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCtrMsb32Neon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCtrMsb64Xmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesCtrMsb64Neon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptCbcEncrypt(pBlockCipher: PCSYMCRYPT_BLOCKCIPHER, pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCbcDecrypt(pBlockCipher: PCSYMCRYPT_BLOCKCIPHER, pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCbcMac(pBlockCipher: PCSYMCRYPT_BLOCKCIPHER, pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbData: PCBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCtrMsb32(pBlockCipher: PCSYMCRYPT_BLOCKCIPHER, pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCtrMsb64(pBlockCipher: PCSYMCRYPT_BLOCKCIPHER, pExpandedKey: PCVOID, pbChainingValue: PBYTE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptGHashAppendData(expandedKey: PCSYMCRYPT_GHASH_EXPANDED_KEY, pState: *types.SYMCRYPT_GF128_ELEMENT, pbData: PCBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptAesGcmEncryptStitchedXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmDecryptStitchedXmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmEncryptStitchedYmm_2048(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmDecryptStitchedYmm_2048(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmEncryptStitchedZmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmDecryptStitchedZmm(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmEncryptStitchedNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptAesGcmDecryptStitchedNeon(pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY, pbChainingValue: PBYTE, expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT, pState: *types.SYMCRYPT_GF128_ELEMENT, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptGcmEncryptPartTwoPass(pState: PSYMCRYPT_GCM_STATE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptGcmDecryptPartTwoPass(pState: PSYMCRYPT_GCM_STATE, pbSrc: PCBYTE, pbDst: PBYTE, cbData: SIZE_T) callconv(types.SYMCRYPT_CALL) void;

pub export const SymCryptAesBlockCipherNoOpt: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&aes_key.SymCryptAesExpandKey),
    .encryptFunc = if (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM)
        @ptrCast(&aes_asm.SymCryptAesEncryptAsm)
    else
        @ptrCast(&aes_c.SymCryptAesEncryptC),
    .decryptFunc = if (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM)
        @ptrCast(&aes_asm.SymCryptAesDecryptAsm)
    else
        @ptrCast(&aes_c.SymCryptAesDecryptC),
    .ecbEncryptFunc = null,
    .ecbDecryptFunc = null,
    .cbcEncryptFunc = null,
    .cbcDecryptFunc = null,
    .cbcMacFunc = null,
    .ctrMsb64Func = null,
    .gcmEncryptPartFunc = null,
    .gcmDecryptPartFunc = null,
    .blockSize = types.SYMCRYPT_AES_BLOCK_SIZE,
    .expandedKeySize = @sizeOf(types.SYMCRYPT_AES_EXPANDED_KEY),
};

pub export fn SymCryptAes4Sbox(
    pIn: PCBYTE,
    pOut: PBYTE,
    UseSimd: BOOL,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime (types.CPU_X86 or types.CPU_AMD64)) {
        if (UseSimd != 0) {
            SymCryptAes4SboxXmm(pIn, pOut);
        } else {
            aes_c.SymCryptAes4SboxC(pIn, pOut);
        }
    } else if (comptime types.CPU_ARM64) {
        if (UseSimd != 0) {
            SymCryptAes4SboxNeon(pIn, pOut);
        } else {
            aes_c.SymCryptAes4SboxC(pIn, pOut);
        }
    } else {
        aes_c.SymCryptAes4SboxC(pIn, pOut);
    }
}

pub export fn SymCryptAesCreateDecryptionRoundKey(
    pEncryptionRoundKey: PCBYTE,
    pDecryptionRoundKey: PBYTE,
    UseSimd: BOOL,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime (types.CPU_X86 or types.CPU_AMD64)) {
        if (UseSimd != 0) {
            SymCryptAesCreateDecryptionRoundKeyXmm(pEncryptionRoundKey, pDecryptionRoundKey);
        } else {
            aes_c.SymCryptAesCreateDecryptionRoundKeyC(pEncryptionRoundKey, pDecryptionRoundKey);
        }
    } else if (comptime types.CPU_ARM64) {
        if (UseSimd != 0) {
            SymCryptAesCreateDecryptionRoundKeyNeon(pEncryptionRoundKey, pDecryptionRoundKey);
        } else {
            aes_c.SymCryptAesCreateDecryptionRoundKeyC(pEncryptionRoundKey, pDecryptionRoundKey);
        }
    } else {
        aes_c.SymCryptAesCreateDecryptionRoundKeyC(pEncryptionRoundKey, pDecryptionRoundKey);
    }
}

pub export fn SymCryptAesEncrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesEncryptXmm(pExpandedKey, pbSrc, pbDst);
        } else {
            aes_asm.SymCryptAesEncryptAsm(pExpandedKey, pbSrc, pbDst);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesEncryptXmm(pExpandedKey, pbSrc, pbDst);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesEncryptAsm(pExpandedKey, pbSrc, pbDst);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesEncryptAsm(pExpandedKey, pbSrc, pbDst);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesEncryptNeon(pExpandedKey, pbSrc, pbDst);
        } else {
            aes_c.SymCryptAesEncryptC(pExpandedKey, pbSrc, pbDst);
        }
    } else {
        aes_c.SymCryptAesEncryptC(pExpandedKey, pbSrc, pbDst);
    }
}

pub export fn SymCryptAesDecrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesDecryptXmm(pExpandedKey, pbSrc, pbDst);
        } else {
            aes_asm.SymCryptAesDecryptAsm(pExpandedKey, pbSrc, pbDst);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesDecryptXmm(pExpandedKey, pbSrc, pbDst);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesDecryptAsm(pExpandedKey, pbSrc, pbDst);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesDecryptAsm(pExpandedKey, pbSrc, pbDst);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesDecryptNeon(pExpandedKey, pbSrc, pbDst);
        } else {
            aes_c.SymCryptAesDecryptC(pExpandedKey, pbSrc, pbDst);
        }
    } else {
        aes_c.SymCryptAesDecryptC(pExpandedKey, pbSrc, pbDst);
    }
}

pub export fn SymCryptAesCbcEncrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesCbcEncryptXmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            aes_asm.SymCryptAesCbcEncryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCbcEncryptXmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesCbcEncryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesCbcEncryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesCbcEncryptNeon(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            SymCryptCbcEncrypt(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else {
        SymCryptCbcEncrypt(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesCbcDecrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE | types.SYMCRYPT_CPU_FEATURE_SAVEYMM_NOFAIL) and
            cbData >= types.CBC_YMM_MINBLOCKS * types.SYMCRYPT_AES_BLOCK_SIZE and
            macros.SymCryptSaveYmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCbcDecryptYmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreYmm(&SaveData);
        } else if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesCbcDecryptXmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            aes_asm.SymCryptAesCbcDecryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCbcDecryptXmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesCbcDecryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesCbcDecryptAsm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesCbcDecryptNeon(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            SymCryptCbcDecrypt(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else {
        SymCryptCbcDecrypt(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesEcbEncrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesEcbEncryptXmm(pExpandedKey, pbSrc, pbDst, cbData);
        } else {
            aes_asm.SymCryptAesEcbEncryptAsm(pExpandedKey, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesEcbEncryptXmm(pExpandedKey, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesEcbEncryptAsm(pExpandedKey, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesEcbEncryptAsm(pExpandedKey, pbSrc, pbDst, cbData);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesEcbEncryptNeon(pExpandedKey, pbSrc, pbDst, cbData);
        } else {
            aes_c.SymCryptAesEcbEncryptC(pExpandedKey, pbSrc, pbDst, cbData);
        }
    } else {
        aes_c.SymCryptAesEcbEncryptC(pExpandedKey, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesEcbDecrypt(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var src = pbSrc;
    var dst = pbDst;
    var remaining = cbData;

    while (remaining >= types.SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesDecrypt(pExpandedKey, src, dst);
        src += types.SYMCRYPT_AES_BLOCK_SIZE;
        dst += types.SYMCRYPT_AES_BLOCK_SIZE;
        remaining -= types.SYMCRYPT_AES_BLOCK_SIZE;
    }
}

pub export fn SymCryptAesCbcMac(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesCbcMacXmm(pExpandedKey, pbChainingValue, pbData, cbData);
        } else {
            macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
            SymCryptCbcMac(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCbcMacXmm(pExpandedKey, pbChainingValue, pbData, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
            SymCryptCbcMac(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData);
        }
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesCbcMacNeon(pExpandedKey, pbChainingValue, pbData, cbData);
        } else {
            macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
            SymCryptCbcMac(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData);
        }
    } else {
        macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptCbcMac(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbData, cbData);
    }
}

pub export fn SymCryptAesCtrMsb32(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesCtrMsb32Xmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
            SymCryptCtrMsb32(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCtrMsb32Xmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
            SymCryptCtrMsb32(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesCtrMsb32Neon(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            SymCryptCtrMsb32(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else {
        macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptCtrMsb32(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesCtrMsb64(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptAesCtrMsb64Xmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            aes_asm.SymCryptAesCtrMsb64Asm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesCtrMsb64Xmm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            aes_asm.SymCryptAesCtrMsb64Asm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM) {
        aes_asm.SymCryptAesCtrMsb64Asm(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptAesCtrMsb64Neon(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        } else {
            SymCryptCtrMsb64(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
        }
    } else {
        macros.SYMCRYPT_ASSERT(SymCryptAesBlockCipherNoOpt.blockSize == types.SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptCtrMsb64(&SymCryptAesBlockCipherNoOpt, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesGcmEncryptPartOnePass(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;
    var bytesToProcess: SIZE_T = undefined;

    macros.SYMCRYPT_ASSERT(@as(SIZE_T, @intCast(pState.cbData & types.SYMCRYPT_GCM_BLOCK_MOD_MASK)) == pState.bytesInMacBlock);
    macros.SYMCRYPT_ASSERT(pState.cbData + cbData <= types.SYMCRYPT_GCM_MAX_DATA_SIZE);
    pState.cbData += cbData;

    if (pState.bytesInMacBlock > 0) {
        bytesToProcess = @min(cbData, types.SYMCRYPT_GCM_BLOCK_SIZE - pState.bytesInMacBlock);
        macros.SymCryptXorBytes(
            pbSrc,
            @ptrCast(&pState.keystreamBlock[pState.bytesInMacBlock]),
            @ptrCast(&pState.macBlock[pState.bytesInMacBlock]),
            bytesToProcess,
        );
        @memcpy(pbDst[0..bytesToProcess], pState.macBlock[pState.bytesInMacBlock .. pState.bytesInMacBlock + bytesToProcess]);
        pbSrc += bytesToProcess;
        pbDst += bytesToProcess;
        cbData -= bytesToProcess;
        pState.bytesInMacBlock += bytesToProcess;

        if (pState.bytesInMacBlock == types.SYMCRYPT_GCM_BLOCK_SIZE) {
            SymCryptGHashAppendData(
                &pState.pKey.ghashKey,
                &pState.ghashState,
                &pState.macBlock,
                types.SYMCRYPT_GCM_BLOCK_SIZE,
            );
            pState.bytesInMacBlock = 0;
        }
    }

    if (cbData >= types.SYMCRYPT_GCM_BLOCK_SIZE) {
        bytesToProcess = cbData & types.SYMCRYPT_GCM_BLOCK_ROUND_MASK;
        macros.SYMCRYPT_ASSERT(pState.pKey.pBlockCipher.blockSize == types.SYMCRYPT_GCM_BLOCK_SIZE);

        if (comptime types.CPU_AMD64) {
            var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
            if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_512_CODE | types.SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL) and
                (bytesToProcess >= types.GCM_ZMM_ENCRYPT_MINBLOCKS * types.SYMCRYPT_GCM_BLOCK_SIZE) and
                macros.SymCryptSaveZmm(&SaveData) == .SYMCRYPT_NO_ERROR)
            {
                SymCryptAesGcmEncryptStitchedZmm(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
                macros.SymCryptRestoreZmm(&SaveData);
            } else if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE) and
                (bytesToProcess >= types.GCM_YMM_MINBLOCKS * types.SYMCRYPT_GCM_BLOCK_SIZE) and
                macros.SymCryptSaveYmm(&SaveData) == .SYMCRYPT_NO_ERROR)
            {
                SymCryptAesGcmEncryptStitchedYmm_2048(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
                macros.SymCryptRestoreYmm(&SaveData);
            } else {
                SymCryptAesGcmEncryptStitchedXmm(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
            }
        } else if (comptime types.CPU_X86) {
            SymCryptAesGcmEncryptStitchedXmm(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                @ptrCast(@alignCast(&pState.pKey.ghashKey.tableSpace[pState.pKey.ghashKey.tableOffset])),
                &pState.ghashState,
                pbSrc,
                pbDst,
                bytesToProcess,
            );
        } else if (comptime types.CPU_ARM64) {
            SymCryptAesGcmEncryptStitchedNeon(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                @ptrCast(&pState.pKey.ghashKey.table),
                &pState.ghashState,
                pbSrc,
                pbDst,
                bytesToProcess,
            );
        } else {
            SymCryptAesCtrMsb32(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                pbSrc,
                pbDst,
                cbData,
            );
            SymCryptGHashAppendData(
                &pState.pKey.ghashKey,
                &pState.ghashState,
                pbDst,
                cbData,
            );
        }

        pbSrc += bytesToProcess;
        pbDst += bytesToProcess;
        cbData -= bytesToProcess;
    }

    if (cbData > 0) {
        macros.SymCryptWipeKnownSize(&pState.keystreamBlock, types.SYMCRYPT_GCM_BLOCK_SIZE);

        macros.SYMCRYPT_ASSERT(pState.pKey.pBlockCipher.blockSize == types.SYMCRYPT_GCM_BLOCK_SIZE);
        SymCryptAesCtrMsb32(
            &pState.pKey.blockcipherKey.aes,
            &pState.counterBlock,
            &pState.keystreamBlock,
            &pState.keystreamBlock,
            types.SYMCRYPT_GCM_BLOCK_SIZE,
        );

        macros.SymCryptXorBytes(&pState.keystreamBlock, pbSrc, &pState.macBlock, cbData);
        @memcpy(pbDst[0..cbData], pState.macBlock[0..cbData]);
        pState.bytesInMacBlock = cbData;
    }
}

pub export fn SymCryptAesGcmDecryptPartOnePass(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;
    var bytesToProcess: SIZE_T = undefined;

    macros.SYMCRYPT_ASSERT(@as(SIZE_T, @intCast(pState.cbData & types.SYMCRYPT_GCM_BLOCK_MOD_MASK)) == pState.bytesInMacBlock);
    macros.SYMCRYPT_ASSERT(pState.cbData + cbData <= types.SYMCRYPT_GCM_MAX_DATA_SIZE);
    pState.cbData += cbData;

    if (pState.bytesInMacBlock > 0) {
        bytesToProcess = @min(cbData, types.SYMCRYPT_GCM_BLOCK_SIZE - pState.bytesInMacBlock);
        @memcpy(pState.macBlock[pState.bytesInMacBlock .. pState.bytesInMacBlock + bytesToProcess], pbSrc[0..bytesToProcess]);
        macros.SymCryptXorBytes(
            @ptrCast(&pState.keystreamBlock[pState.bytesInMacBlock]),
            @ptrCast(&pState.macBlock[pState.bytesInMacBlock]),
            pbDst,
            bytesToProcess,
        );

        pbSrc += bytesToProcess;
        pbDst += bytesToProcess;
        cbData -= bytesToProcess;
        pState.bytesInMacBlock += bytesToProcess;

        if (pState.bytesInMacBlock == types.SYMCRYPT_GCM_BLOCK_SIZE) {
            SymCryptGHashAppendData(
                &pState.pKey.ghashKey,
                &pState.ghashState,
                &pState.macBlock,
                types.SYMCRYPT_GCM_BLOCK_SIZE,
            );
            pState.bytesInMacBlock = 0;
        }
    }

    if (cbData >= types.SYMCRYPT_GCM_BLOCK_SIZE) {
        bytesToProcess = cbData & types.SYMCRYPT_GCM_BLOCK_ROUND_MASK;
        macros.SYMCRYPT_ASSERT(pState.pKey.pBlockCipher.blockSize == types.SYMCRYPT_GCM_BLOCK_SIZE);

        if (comptime types.CPU_AMD64) {
            var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
            if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_512_CODE | types.SYMCRYPT_CPU_FEATURE_SAVEZMM_NOFAIL) and
                (bytesToProcess >= types.GCM_ZMM_DECRYPT_MINBLOCKS * types.SYMCRYPT_GCM_BLOCK_SIZE) and
                macros.SymCryptSaveZmm(&SaveData) == .SYMCRYPT_NO_ERROR)
            {
                SymCryptAesGcmDecryptStitchedZmm(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
                macros.SymCryptRestoreZmm(&SaveData);
            } else if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE) and
                (bytesToProcess >= types.GCM_YMM_MINBLOCKS * types.SYMCRYPT_GCM_BLOCK_SIZE) and
                macros.SymCryptSaveYmm(&SaveData) == .SYMCRYPT_NO_ERROR)
            {
                SymCryptAesGcmDecryptStitchedYmm_2048(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
                macros.SymCryptRestoreYmm(&SaveData);
            } else {
                SymCryptAesGcmDecryptStitchedXmm(
                    &pState.pKey.blockcipherKey.aes,
                    &pState.counterBlock,
                    @ptrCast(&pState.pKey.ghashKey.table),
                    &pState.ghashState,
                    pbSrc,
                    pbDst,
                    bytesToProcess,
                );
            }
        } else if (comptime types.CPU_X86) {
            SymCryptAesGcmDecryptStitchedXmm(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                @ptrCast(@alignCast(&pState.pKey.ghashKey.tableSpace[pState.pKey.ghashKey.tableOffset])),
                &pState.ghashState,
                pbSrc,
                pbDst,
                bytesToProcess,
            );
        } else if (comptime types.CPU_ARM64) {
            SymCryptAesGcmDecryptStitchedNeon(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                @ptrCast(&pState.pKey.ghashKey.table),
                &pState.ghashState,
                pbSrc,
                pbDst,
                bytesToProcess,
            );
        } else {
            SymCryptGHashAppendData(
                &pState.pKey.ghashKey,
                &pState.ghashState,
                pbSrc,
                cbData,
            );
            SymCryptAesCtrMsb32(
                &pState.pKey.blockcipherKey.aes,
                &pState.counterBlock,
                pbSrc,
                pbDst,
                cbData,
            );
        }

        pbSrc += bytesToProcess;
        pbDst += bytesToProcess;
        cbData -= bytesToProcess;
    }

    if (cbData > 0) {
        macros.SymCryptWipeKnownSize(&pState.keystreamBlock, types.SYMCRYPT_GCM_BLOCK_SIZE);

        macros.SYMCRYPT_ASSERT(pState.pKey.pBlockCipher.blockSize == types.SYMCRYPT_GCM_BLOCK_SIZE);
        SymCryptAesCtrMsb32(
            &pState.pKey.blockcipherKey.aes,
            &pState.counterBlock,
            &pState.keystreamBlock,
            &pState.keystreamBlock,
            types.SYMCRYPT_GCM_BLOCK_SIZE,
        );

        @memcpy(pState.macBlock[0..cbData], pbSrc[0..cbData]);
        macros.SymCryptXorBytes(
            &pState.keystreamBlock,
            &pState.macBlock,
            pbDst,
            cbData,
        );

        pState.bytesInMacBlock = cbData;
    }
}

pub export fn SymCryptAesGcmEncryptPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_PCLMULQDQ_CODE)) {
            SymCryptAesGcmEncryptPartOnePass(pState, pbSrc, pbDst, cbData);
        } else {
            SymCryptGcmEncryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_PCLMULQDQ_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesGcmEncryptPartOnePass(pState, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            SymCryptGcmEncryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES | types.SYMCRYPT_CPU_FEATURE_NEON_PMULL)) {
            SymCryptAesGcmEncryptPartOnePass(pState, pbSrc, pbDst, cbData);
        } else {
            SymCryptGcmEncryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else {
        SymCryptGcmEncryptPartTwoPass(pState, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptAesGcmDecryptPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_PCLMULQDQ_CODE)) {
            SymCryptAesGcmDecryptPartOnePass(pState, pbSrc, pbDst, cbData);
        } else {
            SymCryptGcmDecryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_PCLMULQDQ_CODE) and
            macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptAesGcmDecryptPartOnePass(pState, pbSrc, pbDst, cbData);
            macros.SymCryptRestoreXmm(&SaveData);
        } else {
            SymCryptGcmDecryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES | types.SYMCRYPT_CPU_FEATURE_NEON_PMULL)) {
            SymCryptAesGcmDecryptPartOnePass(pState, pbSrc, pbDst, cbData);
        } else {
            SymCryptGcmDecryptPartTwoPass(pState, pbSrc, pbDst, cbData);
        }
    } else {
        SymCryptGcmDecryptPartTwoPass(pState, pbSrc, pbDst, cbData);
    }
}
