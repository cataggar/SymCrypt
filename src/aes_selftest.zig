//
// aes_selftest.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Core AES self-test routines
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_key = @import("aes_key.zig");
const aes_default = @import("aes_default.zig");

const BYTE = types.BYTE;
const UINT32 = types.UINT32;

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;

pub export fn SymCryptAesSelftest(maskTestsToRun: UINT32) callconv(types.SYMCRYPT_CALL) void {
    var buf: [types.SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;
    var iv: [types.SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;
    var key: types.SYMCRYPT_AES_EXPANDED_KEY = undefined;

    if (aes_key.SymCryptAesExpandKey(&key, &SymCryptTestKey32, 16) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("aes"));
    }

    if ((maskTestsToRun & types.SYMCRYPT_AES_SELFTEST_BASE) != 0) {
        aes_default.SymCryptAesEncrypt(&key, &SymCryptTestMsg16, &buf);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], aes_key.SymCryptAesNistTestVector128Ciphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }

        aes_default.SymCryptAesDecrypt(&key, &buf, &buf);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], SymCryptTestMsg16[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }
    }

    if ((maskTestsToRun & types.SYMCRYPT_AES_SELFTEST_ECB) != 0) {
        aes_default.SymCryptAesEcbEncrypt(&key, &SymCryptTestMsg16, &buf, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], aes_key.SymCryptAesNistTestVector128Ciphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }

        aes_default.SymCryptAesEcbDecrypt(&key, &buf, &buf, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], SymCryptTestMsg16[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }
    }

    if ((maskTestsToRun & types.SYMCRYPT_AES_SELFTEST_CBC) != 0) {
        @memset(&iv, 0);
        aes_default.SymCryptAesCbcEncrypt(&key, &iv, &SymCryptTestMsg16, &buf, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], aes_key.SymCryptAesNistTestVector128Ciphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }

        @memset(&iv, 0);
        aes_default.SymCryptAesCbcDecrypt(&key, &iv, &buf, &buf, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], SymCryptTestMsg16[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }
    }

    if ((maskTestsToRun & types.SYMCRYPT_AES_SELFTEST_CBCMAC) != 0) {
        @memset(&iv, 0);
        aes_default.SymCryptAesCbcMac(&key, &iv, &SymCryptTestMsg16, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&iv, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, iv[0..types.SYMCRYPT_AES_BLOCK_SIZE], aes_key.SymCryptAesNistTestVector128Ciphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }
    }

    if ((maskTestsToRun & types.SYMCRYPT_AES_SELFTEST_CTR) != 0) {
        iv = SymCryptTestMsg16;
        @memset(&buf, 0);
        aes_default.SymCryptAesCtrMsb64(&key, &iv, &buf, &buf, types.SYMCRYPT_AES_BLOCK_SIZE);

        macros.SymCryptInjectError(&buf, types.SYMCRYPT_AES_BLOCK_SIZE);
        if (!std.mem.eql(u8, buf[0..types.SYMCRYPT_AES_BLOCK_SIZE], aes_key.SymCryptAesNistTestVector128Ciphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE])) {
            macros.SymCryptFatal(macros.multiCharConstant("aes"));
        }
    }
}
