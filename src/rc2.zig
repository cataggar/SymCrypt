//
// rc2.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement RC2 from RFC 2268.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT16 = types.UINT16;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NO_ERROR = types.SYMCRYPT_NO_ERROR;
const SYMCRYPT_WRONG_KEY_SIZE = types.SYMCRYPT_WRONG_KEY_SIZE;
const SYMCRYPT_BLOCKCIPHER = types.SYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;

pub const SYMCRYPT_RC2_BLOCK_SIZE: usize = 8;

pub const SYMCRYPT_RC2_EXPANDED_KEY = extern struct {
    K: [64]UINT16 align(SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};
pub const PSYMCRYPT_RC2_EXPANDED_KEY = *SYMCRYPT_RC2_EXPANDED_KEY;
pub const PCSYMCRYPT_RC2_EXPANDED_KEY = *const SYMCRYPT_RC2_EXPANDED_KEY;

extern const SymCryptTestKey32: [32]BYTE;
extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export const SymCryptRc2BlockCipher_default: SYMCRYPT_BLOCKCIPHER = .{
    .expandKeyFunc = @ptrCast(&SymCryptRc2ExpandKey),
    .encryptFunc = @ptrCast(&SymCryptRc2Encrypt),
    .decryptFunc = @ptrCast(&SymCryptRc2Decrypt),
    .ecbEncryptFunc = null,
    .ecbDecryptFunc = null,
    .cbcEncryptFunc = null,
    .cbcDecryptFunc = null,
    .cbcMacFunc = null,
    .ctrMsb64Func = null,
    .gcmEncryptPartFunc = null,
    .gcmDecryptPartFunc = null,
    .blockSize = 8,
    .expandedKeySize = @sizeOf(SYMCRYPT_RC2_EXPANDED_KEY),
};

pub export const SymCryptRc2BlockCipher: PCSYMCRYPT_BLOCKCIPHER = &SymCryptRc2BlockCipher_default;

const PITABLE: [256]BYTE = .{
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
};

pub export fn SymCryptRc2ExpandKeyEx(
    pExpandedKey: PSYMCRYPT_RC2_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    effectiveKeySizeInBits: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var L: [128]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_SET_MAGIC(pExpandedKey);

    if (cbKey < 1 or cbKey > 128 or effectiveKeySizeInBits < 9 or effectiveKeySizeInBits > 8 * 128) {
        return SYMCRYPT_WRONG_KEY_SIZE;
    }

    const T: usize = cbKey;
    const T1: UINT32 = effectiveKeySizeInBits;
    const T8: usize = @intCast((T1 + 7) / 8);

    const shift_amt: u5 = @intCast(8 + T1 - @as(UINT32, @intCast(8 * T8)));
    const TM: BYTE = @truncate((@as(u32, 1) << shift_amt) - 1);

    @memcpy(L[0..T], pbKey[0..T]);

    var i: usize = T;
    while (i <= 127) : (i += 1) {
        L[i] = PITABLE[L[i - 1] +% L[i - T]];
    }

    L[128 - T8] = PITABLE[L[128 - T8] & TM];

    var j: isize = @as(isize, @intCast(127 - T8));
    while (j >= 0) : (j -= 1) {
        const idx: usize = @intCast(j);
        L[idx] = PITABLE[L[idx + 1] ^ L[idx + T8]];
    }

    var k: usize = 0;
    while (k < 64) : (k += 1) {
        pExpandedKey.K[k] = macros.SYMCRYPT_LOAD_LSBFIRST16(L[2 * k ..].ptr);
    }

    SymCryptWipe(&L, @sizeOf(@TypeOf(L)));

    return SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRc2ExpandKey(
    pExpandedKey: PSYMCRYPT_RC2_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptRc2ExpandKeyEx(pExpandedKey, pbKey, cbKey, @truncate(8 *% cbKey));
}

inline fn mixRound(R0: *UINT16, R1: *UINT16, R2: *UINT16, R3: *UINT16, K: *const [64]UINT16, comptime n: usize) void {
    R0.* = R0.* +% K[4 * n] +% (R3.* & R2.*) +% (~R3.* & R1.*);
    R0.* = macros.ROL16(R0.*, 1);
    R1.* = R1.* +% K[4 * n + 1] +% (R0.* & R3.*) +% (~R0.* & R2.*);
    R1.* = macros.ROL16(R1.*, 2);
    R2.* = R2.* +% K[4 * n + 2] +% (R1.* & R0.*) +% (~R1.* & R3.*);
    R2.* = macros.ROL16(R2.*, 3);
    R3.* = R3.* +% K[4 * n + 3] +% (R2.* & R1.*) +% (~R2.* & R0.*);
    R3.* = macros.ROL16(R3.*, 5);
}

inline fn mashRound(R0: *UINT16, R1: *UINT16, R2: *UINT16, R3: *UINT16, K: *const [64]UINT16) void {
    R0.* = R0.* +% K[R3.* & 63];
    R1.* = R1.* +% K[R0.* & 63];
    R2.* = R2.* +% K[R1.* & 63];
    R3.* = R3.* +% K[R2.* & 63];
}

pub export fn SymCryptRc2Encrypt(
    pExpandedKey: PCSYMCRYPT_RC2_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var R0: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 0);
    var R1: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 2);
    var R2: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 4);
    var R3: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 6);

    const K = &pExpandedKey.K;

    mixRound(&R0, &R1, &R2, &R3, K, 0);
    mixRound(&R0, &R1, &R2, &R3, K, 1);
    mixRound(&R0, &R1, &R2, &R3, K, 2);
    mixRound(&R0, &R1, &R2, &R3, K, 3);
    mixRound(&R0, &R1, &R2, &R3, K, 4);

    mashRound(&R0, &R1, &R2, &R3, K);

    mixRound(&R0, &R1, &R2, &R3, K, 5);
    mixRound(&R0, &R1, &R2, &R3, K, 6);
    mixRound(&R0, &R1, &R2, &R3, K, 7);
    mixRound(&R0, &R1, &R2, &R3, K, 8);
    mixRound(&R0, &R1, &R2, &R3, K, 9);
    mixRound(&R0, &R1, &R2, &R3, K, 10);

    mashRound(&R0, &R1, &R2, &R3, K);

    mixRound(&R0, &R1, &R2, &R3, K, 11);
    mixRound(&R0, &R1, &R2, &R3, K, 12);
    mixRound(&R0, &R1, &R2, &R3, K, 13);
    mixRound(&R0, &R1, &R2, &R3, K, 14);
    mixRound(&R0, &R1, &R2, &R3, K, 15);

    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 0, R0);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 2, R1);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 4, R2);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 6, R3);
}

inline fn rmixRound(R0: *UINT16, R1: *UINT16, R2: *UINT16, R3: *UINT16, K: *const [64]UINT16, comptime n: usize) void {
    R3.* = macros.ROR16(R3.*, 5);
    R3.* = R3.* -% K[4 * n + 3] -% (R2.* & R1.*) -% (~R2.* & R0.*);
    R2.* = macros.ROR16(R2.*, 3);
    R2.* = R2.* -% K[4 * n + 2] -% (R1.* & R0.*) -% (~R1.* & R3.*);
    R1.* = macros.ROR16(R1.*, 2);
    R1.* = R1.* -% K[4 * n + 1] -% (R0.* & R3.*) -% (~R0.* & R2.*);
    R0.* = macros.ROR16(R0.*, 1);
    R0.* = R0.* -% K[4 * n] -% (R3.* & R2.*) -% (~R3.* & R1.*);
}

inline fn rmashRound(R0: *UINT16, R1: *UINT16, R2: *UINT16, R3: *UINT16, K: *const [64]UINT16) void {
    R3.* = R3.* -% K[R2.* & 63];
    R2.* = R2.* -% K[R1.* & 63];
    R1.* = R1.* -% K[R0.* & 63];
    R0.* = R0.* -% K[R3.* & 63];
}

pub export fn SymCryptRc2Decrypt(
    pExpandedKey: PCSYMCRYPT_RC2_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var R0: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 0);
    var R1: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 2);
    var R2: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 4);
    var R3: UINT16 = macros.SYMCRYPT_LOAD_LSBFIRST16(pbSrc + 6);

    const K = &pExpandedKey.K;

    rmixRound(&R0, &R1, &R2, &R3, K, 15);
    rmixRound(&R0, &R1, &R2, &R3, K, 14);
    rmixRound(&R0, &R1, &R2, &R3, K, 13);
    rmixRound(&R0, &R1, &R2, &R3, K, 12);
    rmixRound(&R0, &R1, &R2, &R3, K, 11);

    rmashRound(&R0, &R1, &R2, &R3, K);

    rmixRound(&R0, &R1, &R2, &R3, K, 10);
    rmixRound(&R0, &R1, &R2, &R3, K, 9);
    rmixRound(&R0, &R1, &R2, &R3, K, 8);
    rmixRound(&R0, &R1, &R2, &R3, K, 7);
    rmixRound(&R0, &R1, &R2, &R3, K, 6);
    rmixRound(&R0, &R1, &R2, &R3, K, 5);

    rmashRound(&R0, &R1, &R2, &R3, K);

    rmixRound(&R0, &R1, &R2, &R3, K, 4);
    rmixRound(&R0, &R1, &R2, &R3, K, 3);
    rmixRound(&R0, &R1, &R2, &R3, K, 2);
    rmixRound(&R0, &R1, &R2, &R3, K, 1);
    rmixRound(&R0, &R1, &R2, &R3, K, 0);

    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 0, R0);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 2, R1);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 4, R2);
    macros.SYMCRYPT_STORE_LSBFIRST16(pbDst + 6, R3);
}

const testPlaintext: [8]BYTE = .{ 'P', 'l', 'a', 'i', 'n', 't', 'x', 't' };
const testCiphertext: [8]BYTE = .{
    0x89, 0xe8, 0x5d, 0x1a, 0x98, 0xcd, 0xe5, 0x52,
};

pub export fn SymCryptRc2Selftest() callconv(SYMCRYPT_CALL) void {
    var key: SYMCRYPT_RC2_EXPANDED_KEY = undefined;
    var buf: [SYMCRYPT_RC2_BLOCK_SIZE]BYTE = undefined;

    if (SymCryptRc2ExpandKeyEx(&key, &SymCryptTestKey32, 16, 87) != SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("rc21"));
    }

    SymCryptRc2Encrypt(&key, &testPlaintext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_RC2_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &testCiphertext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("rc22"));
    }

    SymCryptRc2Decrypt(&key, &testCiphertext, &buf);

    SymCryptInjectError(&buf, SYMCRYPT_RC2_BLOCK_SIZE);

    if (!std.mem.eql(u8, &buf, &testPlaintext)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("rc23"));
    }
}
