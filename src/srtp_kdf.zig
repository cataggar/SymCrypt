//
// srtp_kdf.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// SRTP-KDF implementation as specified in RFC 3711 Section 4.3.1 and self-test,
// ported from lib/srtp_kdf.c and lib/srtp_kdf_selftest.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hmac = @import("hmac.zig");
const aescmac = @import("aescmac.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const SYMCRYPT_AES_EXPANDED_KEY = aescmac.SYMCRYPT_AES_EXPANDED_KEY;
const PSYMCRYPT_AES_EXPANDED_KEY = aescmac.PSYMCRYPT_AES_EXPANDED_KEY;
const PCSYMCRYPT_AES_EXPANDED_KEY = aescmac.PCSYMCRYPT_AES_EXPANDED_KEY;

pub const SYMCRYPT_SRTP_ENCRYPTION_KEY: BYTE = 0x00;
pub const SYMCRYPT_SRTP_AUTHENTICATION_KEY: BYTE = 0x01;
pub const SYMCRYPT_SRTP_SALTING_KEY: BYTE = 0x02;
pub const SYMCRYPT_SRTCP_ENCRYPTION_KEY: BYTE = 0x03;
pub const SYMCRYPT_SRTCP_AUTHENTICATION_KEY: BYTE = 0x04;
pub const SYMCRYPT_SRTCP_SALTING_KEY: BYTE = 0x05;

pub const SYMCRYPT_SRTP_KDF_SALT_SIZE: usize = 112 / 8;

pub const SYMCRYPT_SRTPKDF_EXPANDED_KEY = extern struct {
    aesExpandedKey: SYMCRYPT_AES_EXPANDED_KEY,
};
pub const PSYMCRYPT_SRTPKDF_EXPANDED_KEY = *SYMCRYPT_SRTPKDF_EXPANDED_KEY;
pub const PCSYMCRYPT_SRTPKDF_EXPANDED_KEY = *const SYMCRYPT_SRTPKDF_EXPANDED_KEY;

extern fn SymCryptAesExpandKeyEncryptOnly(
    pExpandedKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

extern fn SymCryptAesCtrMsb64(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbChainingValue: PBYTE,
    pbSrc: ?PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptSrtpKdfExpandKey(
    pExpandedKey: PSYMCRYPT_SRTPKDF_EXPANDED_KEY,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptAesExpandKeyEncryptOnly(&pExpandedKey.aesExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptSrtpKdfDerive(
    pExpandedKey: PCSYMCRYPT_SRTPKDF_EXPANDED_KEY,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    uKeyDerivationRate: UINT32,
    uIndex: UINT64,
    uIndexWidthIn: UINT32,
    label: BYTE,
    pbOutput: ?PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var X: [16]BYTE = @splat(0);
    var uIndexWidth: UINT32 = uIndexWidthIn;

    if (uIndexWidth == 0) {
        uIndexWidth = 48;
    } else if (uIndexWidth != 32 and uIndexWidth != 48) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbSalt != SYMCRYPT_SRTP_KDF_SALT_SIZE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // uKeyDerivationRate must be zero or 2^i for 0 <= i <= 24.
    if ((uKeyDerivationRate > (1 << 24)) or ((uKeyDerivationRate & (uKeyDerivationRate -% 1)) != 0)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Initialize X to Salt || 0
    @memcpy(X[0..SYMCRYPT_SRTP_KDF_SALT_SIZE], pbSalt.?[0..SYMCRYPT_SRTP_KDF_SALT_SIZE]);

    var kdrShift: u6 = 48;
    if (uKeyDerivationRate != 0) {
        var i: u5 = 0;
        while (i <= 24) : (i += 1) {
            if (uKeyDerivationRate == (@as(UINT32, 1) << i)) {
                kdrShift = i;
                break;
            }
        }
    }

    const r: UINT64 = uIndex >> kdrShift;
    const widthShift: u6 = @intCast(uIndexWidth);
    const key_id: UINT64 = (@as(UINT64, label) << widthShift) | r;

    // XOR key_id into salt
    const pbXorPos: [*]BYTE = X[SYMCRYPT_SRTP_KDF_SALT_SIZE - @sizeOf(UINT64) ..].ptr;
    const uSaltLsb: UINT64 = macros.SYMCRYPT_LOAD_MSBFIRST64(pbXorPos);
    macros.SYMCRYPT_STORE_MSBFIRST64(pbXorPos, uSaltLsb ^ key_id);

    SymCryptWipe(@ptrCast(pbOutput), cbOutput);
    SymCryptAesCtrMsb64(&pExpandedKey.aesExpandedKey, &X, pbOutput, pbOutput, cbOutput & ~@as(SIZE_T, 0xf));

    if ((cbOutput & 0xf) != 0) {
        var lastBlockBytes: [16]BYTE = @splat(0);

        SymCryptAesCtrMsb64(&pExpandedKey.aesExpandedKey, &X, &lastBlockBytes, &lastBlockBytes, 16);

        const rem = cbOutput & 0xf;
        const offset = 16 * (cbOutput / 16);
        @memcpy((pbOutput.? + offset)[0..rem], lastBlockBytes[0..rem]);

        hmac.SymCryptWipeKnownSize(&lastBlockBytes, @sizeOf(@TypeOf(lastBlockBytes)));
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSrtpKdf(
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    uKeyDerivationRate: UINT32,
    uIndex: UINT64,
    uIndexWidth: UINT32,
    label: BYTE,
    pbOutput: ?PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var expandedKey: SYMCRYPT_SRTPKDF_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&expandedKey, @sizeOf(@TypeOf(expandedKey)));

    const scError = SymCryptSrtpKdfExpandKey(&expandedKey, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptSrtpKdfDerive(
        &expandedKey,
        pbSalt,
        cbSalt,
        uKeyDerivationRate,
        uIndex,
        uIndexWidth,
        label,
        pbOutput,
        cbOutput,
    );
}

// ==============================================================================================
// Self-test (ported from lib/srtp_kdf_selftest.c)
// ==============================================================================================

const selftest_pbKey = [_]BYTE{
    0xc4, 0x80, 0x9f, 0x6d, 0x36, 0x98, 0x88, 0x72, 0x8e, 0x26, 0xad, 0xb5, 0x32, 0x12, 0x98, 0x90,
};

const selftest_pbSalt = [_]BYTE{
    0x0e, 0x23, 0x00, 0x6c, 0x6c, 0x04, 0x4f, 0x56, 0x62, 0x40, 0x0e, 0x9d, 0x1b, 0xd6,
};

const selftest_uIndex: UINT64 = 0x487165649cca;
const selftest_uSRTCPIndex: UINT32 = 0x56f3f197;
const selftest_uKeyDerivationRate: UINT32 = 0;
const selftest_label: BYTE = SYMCRYPT_SRTP_ENCRYPTION_KEY;

const selftest_pbResultAes128 = [_]BYTE{
    0xdc, 0x38, 0x21, 0x92, 0xab, 0x65, 0x10, 0x8a, 0x86, 0xb2, 0x59, 0xb6, 0x1b, 0x3a, 0xf4, 0x6f,
};

pub export fn SymCryptSrtpKdfSelfTest() callconv(SYMCRYPT_CALL) void {
    var expandedKey: SYMCRYPT_SRTPKDF_EXPANDED_KEY = undefined;
    var rbResultAes128: [selftest_pbResultAes128.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptSrtpKdfExpandKey(&expandedKey, &selftest_pbKey, selftest_pbKey.len);

    _ = SymCryptSrtpKdfDerive(
        &expandedKey,
        &selftest_pbSalt,
        selftest_pbSalt.len,
        selftest_uKeyDerivationRate,
        if (selftest_label < SYMCRYPT_SRTCP_ENCRYPTION_KEY) selftest_uIndex else selftest_uSRTCPIndex,
        if (selftest_label < SYMCRYPT_SRTCP_ENCRYPTION_KEY) 48 else 32,
        selftest_label,
        &rbResultAes128,
        rbResultAes128.len,
    );

    SymCryptInjectError(&rbResultAes128, rbResultAes128.len);

    if (!std.mem.eql(u8, &rbResultAes128, &selftest_pbResultAes128)) {
        macros.SymCryptFatal(macros.multiCharConstant("srtp"));
    }
}
