//
// ssh_kdf.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// SSH-KDF implementation as specified in RFC 4253 Section 7.2 and self-tests,
// ported from lib/ssh_kdf.c, lib/ssh_kdf_sha256.c, and lib/ssh_kdf_sha512.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hmac = @import("hmac.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;

pub const SYMCRYPT_SSHKDF_IV_CLIENT_TO_SERVER: BYTE = 0x41; // 'A'
pub const SYMCRYPT_SSHKDF_IV_SERVER_TO_CLIENT: BYTE = 0x42; // 'B'
pub const SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER: BYTE = 0x43; // 'C'
pub const SYMCRYPT_SSHKDF_ENCRYPTION_KEY_SERVER_TO_CLIENT: BYTE = 0x44; // 'D'
pub const SYMCRYPT_SSHKDF_INTEGRITY_KEY_CLIENT_TO_SERVER: BYTE = 0x45; // 'E'
pub const SYMCRYPT_SSHKDF_INTEGRITY_KEY_SERVER_TO_CLIENT: BYTE = 0x46; // 'F'

pub const SYMCRYPT_SSHKDF_EXPANDED_KEY = extern struct {
    pHashFunc: PCSYMCRYPT_HASH,
    hashState: hmac.SYMCRYPT_HASH_STATE,
};
pub const PSYMCRYPT_SSHKDF_EXPANDED_KEY = *SYMCRYPT_SSHKDF_EXPANDED_KEY;
pub const PCSYMCRYPT_SSHKDF_EXPANDED_KEY = *const SYMCRYPT_SSHKDF_EXPANDED_KEY;

extern fn SymCryptHashInit(pHash: PCSYMCRYPT_HASH, pState: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashAppend(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbData: ?PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashResult(pHash: PCSYMCRYPT_HASH, pState: PVOID, pbResult: PBYTE, cbResult: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashStateCopy(pHash: PCSYMCRYPT_HASH, pSrc: PCVOID, pDst: PVOID) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptHashResultSize(pHash: PCSYMCRYPT_HASH) callconv(SYMCRYPT_CALL) SIZE_T;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern const SymCryptSha256Algorithm: PCSYMCRYPT_HASH;
extern const SymCryptSha512Algorithm: PCSYMCRYPT_HASH;

pub export fn SymCryptSshKdfExpandKey(
    pExpandedKey: PSYMCRYPT_SSHKDF_EXPANDED_KEY,
    pHashFunc: PCSYMCRYPT_HASH,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    pExpandedKey.pHashFunc = pHashFunc;

    SymCryptHashInit(pHashFunc, &pExpandedKey.hashState);
    SymCryptHashAppend(pHashFunc, &pExpandedKey.hashState, pbKey, cbKey);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSshKdfDerive(
    pExpandedKey: PCSYMCRYPT_SSHKDF_EXPANDED_KEY,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    label: BYTE,
    pbSessionId: ?PCBYTE,
    cbSessionId: SIZE_T,
    pbOutput: ?PBYTE,
    cbOutputIn: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var hashState: hmac.SYMCRYPT_HASH_STATE = undefined;
    var labelByte: BYTE = label;

    const pHashFunc: PCSYMCRYPT_HASH = pExpandedKey.pHashFunc;
    const cbHashResultSize: SIZE_T = SymCryptHashResultSize(pHashFunc);

    var cbOutput: SIZE_T = cbOutputIn;
    var cbGeneratedOutput: SIZE_T = 0;

    while (cbOutput > 0) {
        SymCryptHashStateCopy(pHashFunc, &pExpandedKey.hashState, &hashState);
        SymCryptHashAppend(pHashFunc, &hashState, pbHashValue, cbHashValue); // hashState has (K || H)

        // label and session ID are appended only in the first iteration
        if (cbGeneratedOutput == 0) {
            SymCryptHashAppend(pHashFunc, &hashState, @ptrCast(&labelByte), 1);
            SymCryptHashAppend(pHashFunc, &hashState, pbSessionId, cbSessionId);
        } else {
            // We break the read-once write-once rule here by appending data to a
            // hash computation from pbOutput that was written by SymCryptHashResult()
            // below.
            // Modification of data in pbOutput buffer after it's written and before
            // used again will have uncontrolled disturbances in the hash output and cannot
            // be used to gain knowledge about the secret key.
            SymCryptHashAppend(pHashFunc, &hashState, pbOutput.?, cbGeneratedOutput); // hashState has (K || H || K1 .. Ki)
        }

        SymCryptHashResult(pHashFunc, &hashState, pbOutput.? + cbGeneratedOutput, cbOutput);

        const bytesCopied: SIZE_T = @min(cbOutput, cbHashResultSize);
        cbGeneratedOutput += bytesCopied;
        cbOutput -= bytesCopied;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSshKdf(
    pHashFunc: PCSYMCRYPT_HASH,
    pbKey: ?PCBYTE,
    cbKey: SIZE_T,
    pbHashValue: ?PCBYTE,
    cbHashValue: SIZE_T,
    label: BYTE,
    pbSessionId: ?PCBYTE,
    cbSessionId: SIZE_T,
    pbOutput: ?PBYTE,
    cbOutput: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var expandedKey: SYMCRYPT_SSHKDF_EXPANDED_KEY = undefined;
    defer hmac.SymCryptWipeKnownSize(&expandedKey, @sizeOf(@TypeOf(expandedKey)));

    const scError = SymCryptSshKdfExpandKey(&expandedKey, pHashFunc, pbKey, cbKey);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    return SymCryptSshKdfDerive(
        &expandedKey,
        pbHashValue,
        cbHashValue,
        label,
        pbSessionId,
        cbSessionId,
        pbOutput,
        cbOutput,
    );
}

// ==============================================================================================
// Self-tests (ported from lib/ssh_kdf_sha256.c and lib/ssh_kdf_sha512.c)
// ==============================================================================================

const sha256_pbKey = [_]BYTE{
    0x00, 0x00, 0x00, 0x81, 0x00, 0x87, 0x5c, 0x55, 0x1c, 0xef, 0x52, 0x6a, 0x4a, 0x8b, 0xe1, 0xa7,
    0xdf, 0x27, 0xe9, 0xed, 0x35, 0x4b, 0xac, 0x9a, 0xfb, 0x71, 0xf5, 0x3d, 0xba, 0xe9, 0x05, 0x67,
    0x9d, 0x14, 0xf9, 0xfa, 0xf2, 0x46, 0x9c, 0x53, 0x45, 0x7c, 0xf8, 0x0a, 0x36, 0x6b, 0xe2, 0x78,
    0x96, 0x5b, 0xa6, 0x25, 0x52, 0x76, 0xca, 0x2d, 0x9f, 0x4a, 0x97, 0xd2, 0x71, 0xf7, 0x1e, 0x50,
    0xd8, 0xa9, 0xec, 0x46, 0x25, 0x3a, 0x6a, 0x90, 0x6a, 0xc2, 0xc5, 0xe4, 0xf4, 0x8b, 0x27, 0xa6,
    0x3c, 0xe0, 0x8d, 0x80, 0x39, 0x0a, 0x49, 0x2a, 0xa4, 0x3b, 0xad, 0x9d, 0x88, 0x2c, 0xca, 0xc2,
    0x3d, 0xac, 0x88, 0xbc, 0xad, 0xa4, 0xb4, 0xd4, 0x26, 0xa3, 0x62, 0x08, 0x3d, 0xab, 0x65, 0x69,
    0xc5, 0x4c, 0x22, 0x4d, 0xd2, 0xd8, 0x76, 0x43, 0xaa, 0x22, 0x76, 0x93, 0xe1, 0x41, 0xad, 0x16,
    0x30, 0xce, 0x13, 0x14, 0x4e,
};

const sha256_pbHash = [_]BYTE{
    0x0e, 0x68, 0x3f, 0xc8, 0xa9, 0xed, 0x7c, 0x2f, 0xf0, 0x2d, 0xef, 0x23, 0xb2, 0x74, 0x5e, 0xbc,
    0x99, 0xb2, 0x67, 0xda, 0xa8, 0x6a, 0x4a, 0xa7, 0x69, 0x72, 0x39, 0x08, 0x82, 0x53, 0xf6, 0x42,
};

const sha256_pbSessionId = [_]BYTE{
    0x0e, 0x68, 0x3f, 0xc8, 0xa9, 0xed, 0x7c, 0x2f, 0xf0, 0x2d, 0xef, 0x23, 0xb2, 0x74, 0x5e, 0xbc,
    0x99, 0xb2, 0x67, 0xda, 0xa8, 0x6a, 0x4a, 0xa7, 0x69, 0x72, 0x39, 0x08, 0x82, 0x53, 0xf6, 0x42,
};

const sha256_pbResult = [_]BYTE{
    0x4a, 0x63, 0x14, 0xd2, 0xf7, 0x51, 0x1b, 0xf8, 0x8f, 0xad, 0x39, 0xfb, 0x68, 0x92, 0xf3, 0xf2,
    0x18, 0xca, 0xfd, 0x53, 0x0e, 0x72, 0xfe, 0x43,
};

pub export fn SymCryptSshKdfSha256SelfTest() callconv(SYMCRYPT_CALL) void {
    var expandedKey: SYMCRYPT_SSHKDF_EXPANDED_KEY = undefined;
    var rbResult: [sha256_pbResult.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptSshKdfExpandKey(&expandedKey, SymCryptSha256Algorithm, &sha256_pbKey, sha256_pbKey.len);

    _ = SymCryptSshKdfDerive(
        &expandedKey,
        &sha256_pbHash,
        sha256_pbHash.len,
        SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER,
        &sha256_pbSessionId,
        sha256_pbSessionId.len,
        &rbResult,
        rbResult.len,
    );

    SymCryptInjectError(&rbResult, rbResult.len);

    if (!std.mem.eql(u8, &rbResult, &sha256_pbResult)) {
        macros.SymCryptFatal(macros.multiCharConstant("sshk"));
    }
}

const sha512_pbKey = [_]BYTE{
    0x00, 0x00, 0x00, 0x80, 0x57, 0x53, 0x08, 0xca, 0x39, 0x57, 0x98, 0xbb, 0x21, 0xec, 0x54, 0x38,
    0xc4, 0x6a, 0x88, 0xff, 0xa3, 0xf7, 0xf7, 0x67, 0x1c, 0x06, 0xf9, 0x24, 0xab, 0xf7, 0xc3, 0xcf,
    0xb4, 0x6c, 0x78, 0xc0, 0x25, 0x59, 0x6e, 0x4a, 0xba, 0x50, 0xc3, 0x27, 0x10, 0x89, 0x18, 0x4a,
    0x44, 0x7a, 0x57, 0x1a, 0xbb, 0x7f, 0x4a, 0x1b, 0x1c, 0x41, 0xf5, 0xd5, 0xca, 0x80, 0x62, 0x94,
    0x0d, 0x43, 0x69, 0x77, 0x85, 0x89, 0xfd, 0xe8, 0x1a, 0x71, 0xb2, 0x22, 0x8f, 0x01, 0x8c, 0x4c,
    0x83, 0x6c, 0xf3, 0x89, 0xf8, 0x54, 0xf8, 0x6d, 0xe7, 0x1a, 0x68, 0xb1, 0x69, 0x3f, 0xe8, 0xff,
    0xa1, 0xc5, 0x9c, 0xe7, 0xe9, 0xf9, 0x22, 0x3d, 0xeb, 0xad, 0xa2, 0x56, 0x6d, 0x2b, 0x0e, 0x56,
    0x78, 0xa4, 0x8b, 0xfb, 0x53, 0x0e, 0x7b, 0xee, 0x42, 0xbd, 0x2a, 0xc7, 0x30, 0x4a, 0x0a, 0x5a,
    0xe3, 0x39, 0xa2, 0xcd,
};

const sha512_pbHash = [_]BYTE{
    0xa4, 0x12, 0x5a, 0xa9, 0x89, 0x80, 0x92, 0xca, 0x50, 0xc3, 0xc1, 0x63, 0x1c, 0x03, 0xdc, 0xbc,
    0x9d, 0xf9, 0x5c, 0xeb, 0xb4, 0x09, 0x88, 0x1e, 0x58, 0x01, 0x08, 0xb6, 0xcc, 0x47, 0x04, 0xb7,
    0x6c, 0xc7, 0x7b, 0x87, 0x95, 0xfd, 0x59, 0x40, 0x56, 0x1e, 0x32, 0x24, 0xcc, 0x75, 0x84, 0x85,
    0x18, 0x99, 0x2b, 0xd8, 0xd9, 0xb7, 0x0f, 0xe0, 0xfc, 0x97, 0x7a, 0x47, 0x60, 0x63, 0xc8, 0xbf,
};

const sha512_pbSessionId = [_]BYTE{
    0xa4, 0x12, 0x5a, 0xa9, 0x89, 0x80, 0x92, 0xca, 0x50, 0xc3, 0xc1, 0x63, 0x1c, 0x03, 0xdc, 0xbc,
    0x9d, 0xf9, 0x5c, 0xeb, 0xb4, 0x09, 0x88, 0x1e, 0x58, 0x01, 0x08, 0xb6, 0xcc, 0x47, 0x04, 0xb7,
    0x6c, 0xc7, 0x7b, 0x87, 0x95, 0xfd, 0x59, 0x40, 0x56, 0x1e, 0x32, 0x24, 0xcc, 0x75, 0x84, 0x85,
    0x18, 0x99, 0x2b, 0xd8, 0xd9, 0xb7, 0x0f, 0xe0, 0xfc, 0x97, 0x7a, 0x47, 0x60, 0x63, 0xc8, 0xbf,
};

const sha512_pbResult = [_]BYTE{
    0x7e, 0x4a, 0x72, 0x1f, 0xb7, 0x37, 0x9e, 0xbb, 0x42, 0x33, 0x06, 0x46, 0x4d, 0x57, 0xdb, 0x46,
    0xaf, 0xa3, 0xcc, 0xa1, 0x0a, 0x1d, 0x7f, 0xeb,
};

pub export fn SymCryptSshKdfSha512SelfTest() callconv(SYMCRYPT_CALL) void {
    var expandedKey: SYMCRYPT_SSHKDF_EXPANDED_KEY = undefined;
    var rbResult: [sha512_pbResult.len]BYTE align(SYMCRYPT_ALIGN_VALUE) = undefined;

    _ = SymCryptSshKdfExpandKey(&expandedKey, SymCryptSha512Algorithm, &sha512_pbKey, sha512_pbKey.len);

    _ = SymCryptSshKdfDerive(
        &expandedKey,
        &sha512_pbHash,
        sha512_pbHash.len,
        SYMCRYPT_SSHKDF_ENCRYPTION_KEY_CLIENT_TO_SERVER,
        &sha512_pbSessionId,
        sha512_pbSessionId.len,
        &rbResult,
        rbResult.len,
    );

    SymCryptInjectError(&rbResult, rbResult.len);

    if (!std.mem.eql(u8, &rbResult, &sha512_pbResult)) {
        macros.SymCryptFatal(macros.multiCharConstant("sshk"));
    }
}
