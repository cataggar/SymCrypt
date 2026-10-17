//
// aes_default_bc.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// The default AES block cipher description.
// Kept in a separate file to avoid linking the AES code into every binary that uses it.
//

const types = @import("types.zig");
const aes_key = @import("aes_key.zig");
const aes_default = @import("aes_default.zig");

const SYMCRYPT_BLOCKCIPHER = types.SYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;

pub export const SymCryptAesBlockCipher_Fast: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&aes_key.SymCryptAesExpandKey),
    .encryptFunc = @ptrCast(&aes_default.SymCryptAesEncrypt),
    .decryptFunc = @ptrCast(&aes_default.SymCryptAesDecrypt),
    .ecbEncryptFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesEcbEncrypt)
    else
        null,
    .ecbDecryptFunc = if (types.CPU_X86 or types.CPU_AMD64)
        @ptrCast(&aes_default.SymCryptAesEcbDecrypt)
    else
        null,
    .cbcEncryptFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesCbcEncrypt)
    else
        null,
    .cbcDecryptFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesCbcDecrypt)
    else
        null,
    .cbcMacFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesCbcMac)
    else
        null,
    .ctrMsb64Func = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesCtrMsb64)
    else
        null,
    .gcmEncryptPartFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesGcmEncryptPart)
    else
        null,
    .gcmDecryptPartFunc = if (types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64)
        @ptrCast(&aes_default.SymCryptAesGcmDecryptPart)
    else
        null,
    .blockSize = types.SYMCRYPT_AES_BLOCK_SIZE,
    .expandedKeySize = @sizeOf(types.SYMCRYPT_AES_EXPANDED_KEY),
};

pub export const SymCryptAesBlockCipher: PCSYMCRYPT_BLOCKCIPHER = &SymCryptAesBlockCipher_Fast;
