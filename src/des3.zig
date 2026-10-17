//
// des3.zig Routines for DES and 3DES
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const des_tables = @import("des_tables.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NO_ERROR = types.SYMCRYPT_NO_ERROR;
const SYMCRYPT_WRONG_KEY_SIZE = types.SYMCRYPT_WRONG_KEY_SIZE;
const SYMCRYPT_BLOCKCIPHER = types.SYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;

pub const SYMCRYPT_3DES_BLOCK_SIZE: usize = 8;
pub const SYMCRYPT_DES_BLOCK_SIZE: usize = 8;

pub const SYMCRYPT_3DES_EXPANDED_KEY = extern struct {
    roundKey: [3][16][2]UINT32 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};
pub const PSYMCRYPT_3DES_EXPANDED_KEY = *SYMCRYPT_3DES_EXPANDED_KEY;
pub const PCSYMCRYPT_3DES_EXPANDED_KEY = *const SYMCRYPT_3DES_EXPANDED_KEY;

pub const SYMCRYPT_DES_EXPANDED_KEY = extern struct {
    threeDes: SYMCRYPT_3DES_EXPANDED_KEY align(SYMCRYPT_ALIGN_VALUE),
};
pub const PSYMCRYPT_DES_EXPANDED_KEY = *SYMCRYPT_DES_EXPANDED_KEY;
pub const PCSYMCRYPT_DES_EXPANDED_KEY = *const SYMCRYPT_DES_EXPANDED_KEY;

extern fn SymCryptCbcEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptCbcDecrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export const SymCrypt3DesBlockCipher_default: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&SymCrypt3DesExpandKey),
    .encryptFunc = @ptrCast(&SymCrypt3DesEncrypt),
    .decryptFunc = @ptrCast(&SymCrypt3DesDecrypt),
    .ecbEncryptFunc = null,
    .ecbDecryptFunc = null,
    .cbcEncryptFunc = null,
    .cbcDecryptFunc = null,
    .cbcMacFunc = null,
    .ctrMsb64Func = null,
    .gcmEncryptPartFunc = null,
    .gcmDecryptPartFunc = null,
    .blockSize = 8,
    .expandedKeySize = @sizeOf(SYMCRYPT_3DES_EXPANDED_KEY),
};

pub export const SymCryptDesBlockCipher_default: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&SymCryptDesExpandKey),
    .encryptFunc = @ptrCast(&SymCryptDesEncrypt),
    .decryptFunc = @ptrCast(&SymCryptDesDecrypt),
    .ecbEncryptFunc = null,
    .ecbDecryptFunc = null,
    .cbcEncryptFunc = null,
    .cbcDecryptFunc = null,
    .cbcMacFunc = null,
    .ctrMsb64Func = null,
    .gcmEncryptPartFunc = null,
    .gcmDecryptPartFunc = null,
    .blockSize = 8,
    .expandedKeySize = @sizeOf(SYMCRYPT_DES_EXPANDED_KEY),
};

pub export const SymCrypt3DesBlockCipher: PCSYMCRYPT_BLOCKCIPHER = &SymCrypt3DesBlockCipher_default;
pub export const SymCryptDesBlockCipher: PCSYMCRYPT_BLOCKCIPHER = &SymCryptDesBlockCipher_default;

inline fn swapBitsWithinUint32(value: *UINT32, comptime shift: u5, mask: UINT32) void {
    const tmp: UINT32 = (value.* ^ (value.* >> shift)) & mask;
    value.* = value.* ^ tmp ^ (tmp << shift);
}

inline fn swapBitsBetweenUint32(v1: *UINT32, v2: *UINT32, comptime shift: u5, mask: UINT32) void {
    const tmp: UINT32 = (v1.* ^ (v2.* >> shift)) & mask;
    v1.* ^= tmp;
    v2.* ^= (tmp << shift);
}

const SymCryptDesDoubleShift: [16]BYTE = .{ 0, 0, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 0 };

pub export fn SymCryptDesExpandKey(
    pExpandedKey: PSYMCRYPT_DES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbKey != 8) {
        return SYMCRYPT_WRONG_KEY_SIZE;
    }
    return SymCrypt3DesExpandKey(&pExpandedKey.threeDes, pbKey, cbKey);
}

pub export fn SymCryptDesEncrypt(
    pExpandedKey: PCSYMCRYPT_DES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCrypt3DesEncrypt(&pExpandedKey.threeDes, pbSrc, pbDst);
}

pub export fn SymCryptDesDecrypt(
    pExpandedKey: PCSYMCRYPT_DES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCrypt3DesDecrypt(&pExpandedKey.threeDes, pbSrc, pbDst);
}

pub export fn SymCrypt3DesCbcEncrypt(
    pExpandedKey: PCSYMCRYPT_3DES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_3DES_BLOCK_SIZE);
    SymCryptCbcEncrypt(SymCrypt3DesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

pub export fn SymCrypt3DesCbcDecrypt(
    pExpandedKey: PCSYMCRYPT_3DES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(SymCrypt3DesBlockCipher.blockSize == SYMCRYPT_3DES_BLOCK_SIZE);
    SymCryptCbcDecrypt(SymCrypt3DesBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
}

pub export fn SymCryptDesExpandSingleKey(
    expandedKeyTable: *[16][2]UINT32,
    pKey: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    var Cr: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pKey);
    var Dr: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pKey + 4);

    swapBitsBetweenUint32(&Cr, &Dr, 4, 0x0f0f0f0f);
    swapBitsWithinUint32(&Dr, 18, 0x00003333);
    swapBitsWithinUint32(&Cr, 18, 0x00003333);
    swapBitsBetweenUint32(&Cr, &Dr, 1, 0x55555555);
    swapBitsBetweenUint32(&Dr, &Cr, 8, 0x00ff00ff);
    swapBitsBetweenUint32(&Cr, &Dr, 1, 0x55555555);
    swapBitsWithinUint32(&Dr, 16, 0xff);

    Dr = (Dr & 0x00ffffff) | ((Cr & 0xf0000000) >> 4);
    Cr = (Cr & 0x0fffffff);

    var r: usize = 0;
    while (r < 16) : (r += 1) {
        if (SymCryptDesDoubleShift[r] != 0) {
            Cr = (Cr >> 2) | (Cr << 26);
            Dr = (Dr >> 2) | (Dr << 26);
        } else {
            Cr = (Cr >> 1) | (Cr << 27);
            Dr = (Dr >> 1) | (Dr << 27);
        }

        Cr &= 0x0fffffff;
        Dr &= 0x0fffffff;

        const K1: UINT32 =
            des_tables.SymCryptDesKeySelect[0][(Cr) & 0x3f] |
            des_tables.SymCryptDesKeySelect[1][((Cr >> 6) & 0x03) | ((Cr >> 7) & 0x3c)] |
            des_tables.SymCryptDesKeySelect[2][((Cr >> 13) & 0x0f) | ((Cr >> 14) & 0x30)] |
            des_tables.SymCryptDesKeySelect[3][((Cr >> 20) & 0x01) | ((Cr >> 21) & 0x06) | ((Cr >> 22) & 0x38)];

        const K2: UINT32 =
            des_tables.SymCryptDesKeySelect[4][(Dr) & 0x3f] |
            des_tables.SymCryptDesKeySelect[5][((Dr >> 7) & 0x03) | ((Dr >> 8) & 0x3c)] |
            des_tables.SymCryptDesKeySelect[6][(Dr >> 15) & 0x3f] |
            des_tables.SymCryptDesKeySelect[7][((Dr >> 21) & 0x0f) | ((Dr >> 22) & 0x30)];

        const tmp0: UINT32 = (K2 << 16) | (K1 & 0x0000ffff);
        expandedKeyTable[r][0] = macros.ROL32(tmp0, 2);

        const tmp1: UINT32 = (K1 >> 16) | (K2 & 0xffff0000);
        expandedKeyTable[r][1] = macros.ROL32(tmp1, 6);
    }
}

pub export fn SymCrypt3DesExpandKey(
    pExpandedKey: PSYMCRYPT_3DES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var keyIndex: SIZE_T = 0;

    if (cbKey != 8 and cbKey != 16 and cbKey != 24) {
        return SYMCRYPT_WRONG_KEY_SIZE;
    }

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        macros.SYMCRYPT_ASSERT(keyIndex <= cbKey - 8);
        SymCryptDesExpandSingleKey(&pExpandedKey.roundKey[i], pbKey + keyIndex);
        keyIndex = (keyIndex + 8) % cbKey;
    }

    macros.SYMCRYPT_SET_MAGIC(pExpandedKey);

    return SYMCRYPT_NO_ERROR;
}

inline fn roundF(L: *UINT32, R: UINT32, keyptr: *const [2]UINT32) void {
    const Ta: UINT32 = keyptr[0] ^ R;
    const Tb: UINT32 = macros.ROR32(keyptr[1] ^ R, 4);

    L.* ^= des_tables.SymCryptDesSpbox[0][(Ta >> 2) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[1][(Tb >> 2) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[2][(Ta >> 10) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[3][(Tb >> 10) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[4][(Ta >> 18) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[5][(Tb >> 18) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[6][(Ta >> 26) & 0x3f];
    L.* ^= des_tables.SymCryptDesSpbox[7][(Tb >> 26) & 0x3f];
}

pub export fn SymCrypt3DesEncrypt(
    pExpandedKey: PCSYMCRYPT_3DES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var R: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pbSrc);
    var L: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pbSrc + 4);
    var Ta: UINT32 = undefined;

    R = macros.ROL32(R, 4);
    Ta = (L ^ R) & 0xf0f0f0f0;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROL32(L, 20);
    Ta = (L ^ R) & 0xfff0000f;
    R ^= Ta;
    L ^= Ta;

    L = macros.ROL32(L, 14);
    Ta = (L ^ R) & 0x33333333;
    R ^= Ta;
    L ^= Ta;

    R = macros.ROL32(R, 22);
    Ta = (L ^ R) & 0x03fc03fc;
    R ^= Ta;
    L ^= Ta;

    R = macros.ROL32(R, 9);
    Ta = (L ^ R) & 0xaaaaaaaa;
    R ^= Ta;
    L ^= Ta;

    L = macros.ROL32(L, 1);

    // First: encryption
    {
        var r: usize = 0;
        while (r < 16) : (r += 2) {
            roundF(&L, R, &pExpandedKey.roundKey[0][r]);
            roundF(&R, L, &pExpandedKey.roundKey[0][r + 1]);
        }
    }

    // Second: decryption
    {
        var r: isize = 14;
        while (r >= 0) : (r -= 2) {
            const idx: usize = @intCast(r);
            roundF(&R, L, &pExpandedKey.roundKey[1][idx + 1]);
            roundF(&L, R, &pExpandedKey.roundKey[1][idx]);
        }
    }

    // Third: encryption
    {
        var r: usize = 0;
        while (r < 16) : (r += 2) {
            roundF(&L, R, &pExpandedKey.roundKey[2][r]);
            roundF(&R, L, &pExpandedKey.roundKey[2][r + 1]);
        }
    }

    R = macros.ROR32(R, 1);
    Ta = (L ^ R) & 0xaaaaaaaa;
    R ^= Ta;
    L ^= Ta;

    L = macros.ROR32(L, 9);
    Ta = (L ^ R) & 0x03fc03fc;
    R ^= Ta;
    L ^= Ta;

    L = macros.ROR32(L, 22);
    Ta = (L ^ R) & 0x33333333;
    R ^= Ta;
    L ^= Ta;

    R = macros.ROR32(R, 14);
    Ta = (L ^ R) & 0xfff0000f;
    R ^= Ta;
    L ^= Ta;

    R = macros.ROR32(R, 20);
    Ta = (L ^ R) & 0xf0f0f0f0;
    R ^= Ta;
    L ^= Ta;

    L = macros.ROR32(L, 4);

    macros.SYMCRYPT_STORE_LSBFIRST32(pbDst, L);
    macros.SYMCRYPT_STORE_LSBFIRST32(pbDst + 4, R);
}

pub export fn SymCrypt3DesDecrypt(
    pExpandedKey: PCSYMCRYPT_3DES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var R: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pbSrc);
    var L: UINT32 = macros.SYMCRYPT_LOAD_LSBFIRST32(pbSrc + 4);
    var Ta: UINT32 = undefined;

    R = macros.ROL32(R, 4);
    Ta = (L ^ R) & 0xf0f0f0f0;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROL32(L, 20);
    Ta = (L ^ R) & 0xfff0000f;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROL32(L, 14);
    Ta = (L ^ R) & 0x33333333;
    L ^= Ta;
    R ^= Ta;

    R = macros.ROL32(R, 22);
    Ta = (L ^ R) & 0x03fc03fc;
    L ^= Ta;
    R ^= Ta;

    R = macros.ROL32(R, 9);
    Ta = (L ^ R) & 0xaaaaaaaa;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROL32(L, 1);

    // Decrypt with key 2
    {
        var r: isize = 14;
        while (r >= 0) : (r -= 2) {
            const idx: usize = @intCast(r);
            roundF(&L, R, &pExpandedKey.roundKey[2][idx + 1]);
            roundF(&R, L, &pExpandedKey.roundKey[2][idx]);
        }
    }

    // Encrypt with key 1
    {
        var r: usize = 0;
        while (r < 16) : (r += 2) {
            roundF(&R, L, &pExpandedKey.roundKey[1][r]);
            roundF(&L, R, &pExpandedKey.roundKey[1][r + 1]);
        }
    }

    // Decrypt with key 0
    {
        var r: isize = 14;
        while (r >= 0) : (r -= 2) {
            const idx: usize = @intCast(r);
            roundF(&L, R, &pExpandedKey.roundKey[0][idx + 1]);
            roundF(&R, L, &pExpandedKey.roundKey[0][idx]);
        }
    }

    // Inverse permutation, also from Hoey via Outerbridge and Schneier
    R = macros.ROR32(R, 1);
    Ta = (L ^ R) & 0xaaaaaaaa;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROR32(L, 9);
    Ta = (L ^ R) & 0x03fc03fc;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROR32(L, 22);
    Ta = (L ^ R) & 0x33333333;
    L ^= Ta;
    R ^= Ta;

    R = macros.ROR32(R, 14);
    Ta = (L ^ R) & 0xfff0000f;
    L ^= Ta;
    R ^= Ta;

    R = macros.ROR32(R, 20);
    Ta = (L ^ R) & 0xf0f0f0f0;
    L ^= Ta;
    R ^= Ta;

    L = macros.ROR32(L, 4);

    macros.SYMCRYPT_STORE_LSBFIRST32(pbDst, L);
    macros.SYMCRYPT_STORE_LSBFIRST32(pbDst + 4, R);
}

pub export fn SymCryptDesSetOddParity(
    pbData: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var i: SIZE_T = 0;
    while (i < cbData) : (i += 1) {
        const b: BYTE = pbData[i];
        var t: BYTE = b ^ (b >> 4);
        t ^= t >> 2;
        t ^= t >> 1;
        pbData[i] = b ^ (t & 1) ^ 1;
    }
}

const SP800_67Key: [24]BYTE = .{
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
    0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
    0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
};

const des3KnownPlaintext: [8]BYTE = .{
    0x4E, 0x6F, 0x77, 0x20, 0x69, 0x73, 0x20, 0x74,
};

const des3KnownCiphertext: [8]BYTE = .{
    0x31, 0x4F, 0x83, 0x27, 0xFA, 0x7A, 0x09, 0xA8,
};

const desKnownCiphertext: [8]BYTE = .{
    0x3F, 0xA4, 0x0E, 0x8A, 0x98, 0x4D, 0x48, 0x15,
};

pub export fn SymCryptDesSelftest() callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_DES_BLOCK_SIZE]BYTE = undefined;
    var key: SYMCRYPT_DES_EXPANDED_KEY = undefined;

    if (SymCryptDesExpandKey(&key, &SP800_67Key, 8) != SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desa"));
    }

    SymCryptDesEncrypt(&key, &des3KnownPlaintext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_DES_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &desKnownCiphertext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desb"));
    }

    SymCryptDesDecrypt(&key, &desKnownCiphertext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_DES_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &des3KnownPlaintext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("desc"));
    }
}

pub export fn SymCrypt3DesSelftest() callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_3DES_BLOCK_SIZE]BYTE = undefined;
    var key: SYMCRYPT_3DES_EXPANDED_KEY = undefined;

    if (SymCrypt3DesExpandKey(&key, &SP800_67Key, 24) != SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("des3"));
    }

    SymCrypt3DesEncrypt(&key, &des3KnownPlaintext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_3DES_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &des3KnownCiphertext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("des4"));
    }

    SymCrypt3DesDecrypt(&key, &des3KnownCiphertext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_3DES_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &des3KnownPlaintext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("des5"));
    }
}
