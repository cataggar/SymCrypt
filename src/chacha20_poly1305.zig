//
// chacha20_poly1305.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const poly1305 = @import("poly1305.zig");
const chacha20 = @import("chacha20.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOL = types.BOOL;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

const SYMCRYPT_POLY1305_STATE = poly1305.SYMCRYPT_POLY1305_STATE;
const PSYMCRYPT_POLY1305_STATE = poly1305.PSYMCRYPT_POLY1305_STATE;
const SYMCRYPT_POLY1305_RESULT_SIZE = poly1305.SYMCRYPT_POLY1305_RESULT_SIZE;
const SYMCRYPT_POLY1305_BLOCK_SIZE = poly1305.SYMCRYPT_POLY1305_BLOCK_SIZE;
const SYMCRYPT_POLY1305_KEY_SIZE = poly1305.SYMCRYPT_POLY1305_KEY_SIZE;

const SYMCRYPT_CHACHA20_STATE = chacha20.SYMCRYPT_CHACHA20_STATE;

pub const SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE: u64 = ((@as(u64, 1) << 32) - 1) * 64;

pub export const fcbDataLteMaxDataSizeStatic: BOOL =
    if (@as(u64, types.SIZE_T_MAX) <= SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE) 1 else 0;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptEqual(pbSrc1: PCBYTE, pbSrc2: PCBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) BOOLEAN;

pub export fn SymCryptChaCha20Poly1305ComputeTag(
    pState: PSYMCRYPT_POLY1305_STATE,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_POLY1305_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var partialBlockSize: SIZE_T = 0;

    SymCryptWipe(@ptrCast(&buf[0]), SYMCRYPT_POLY1305_BLOCK_SIZE);

    // Add additional authentication data if needed.
    if (cbAuthData > 0) {
        poly1305.SymCryptPoly1305Append(pState, pbAuthData.?, cbAuthData);

        // Append zeros to make a complete Poly1305 block.
        partialBlockSize = cbAuthData % SYMCRYPT_POLY1305_BLOCK_SIZE;
        if (partialBlockSize > 0) {
            poly1305.SymCryptPoly1305Append(pState, &buf, SYMCRYPT_POLY1305_BLOCK_SIZE - partialBlockSize);
        }
    }

    // Add ciphertext if needed.
    if (cbData > 0) {
        poly1305.SymCryptPoly1305Append(pState, pbData, cbData);

        // Append zeros to make a complete Poly1305 block.
        partialBlockSize = cbData % SYMCRYPT_POLY1305_BLOCK_SIZE;
        if (partialBlockSize > 0) {
            poly1305.SymCryptPoly1305Append(pState, &buf, SYMCRYPT_POLY1305_BLOCK_SIZE - partialBlockSize);
        }
    }

    // Add length of additional authentication data and ciphertext.
    macros.STORE_LSBFIRST64(buf[0..].ptr, @as(UINT64, cbAuthData));
    macros.STORE_LSBFIRST64(buf[8..].ptr, @as(UINT64, cbData));
    poly1305.SymCryptPoly1305Append(pState, &buf, SYMCRYPT_POLY1305_BLOCK_SIZE);
    SymCryptWipe(@ptrCast(&buf[0]), SYMCRYPT_POLY1305_BLOCK_SIZE);

    poly1305.SymCryptPoly1305Result(pState, pbTag);
}

pub export fn SymCryptChaCha20Poly1305Encrypt(
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var status: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var ChaCha20State: SYMCRYPT_CHACHA20_STATE = undefined;
    var Poly1305State: SYMCRYPT_POLY1305_STATE = undefined;
    var key: [SYMCRYPT_POLY1305_KEY_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    defer {
        SymCryptWipe(@ptrCast(&ChaCha20State), @sizeOf(SYMCRYPT_CHACHA20_STATE));
        SymCryptWipe(@ptrCast(&Poly1305State), @sizeOf(SYMCRYPT_POLY1305_STATE));
    }

    if (fcbDataLteMaxDataSizeStatic == 0 and @as(u64, cbData) > SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (cbTag != SYMCRYPT_POLY1305_RESULT_SIZE) {
        return .SYMCRYPT_WRONG_TAG_SIZE;
    }

    status = chacha20.SymCryptChaCha20Init(&ChaCha20State, pbKey, cbKey, pbNonce, cbNonce, 0);
    if (status != .SYMCRYPT_NO_ERROR) {
        return status;
    }

    // Generate the first 32 bytes of keystream.
    SymCryptWipe(@ptrCast(&key[0]), key.len);
    chacha20.SymCryptChaCha20Crypt(&ChaCha20State, &key, &key, key.len);

    // Create the Poly1305 key using the first 32 bytes of the ChaCha20 keystream.
    poly1305.SymCryptPoly1305Init(&Poly1305State, &key);
    SymCryptWipe(@ptrCast(&key[0]), key.len);

    // Encrypt data if needed.
    if (cbData > 0) {
        // Advance the keystream to counter 1 (offset 64) for data encryption.
        chacha20.SymCryptChaCha20SetOffset(&ChaCha20State, 64);
        chacha20.SymCryptChaCha20Crypt(&ChaCha20State, pbSrc, pbDst, cbData);
    }

    SymCryptChaCha20Poly1305ComputeTag(
        &Poly1305State,
        pbAuthData,
        cbAuthData,
        pbDst,
        cbData,
        pbTag,
    );

    return status;
}

pub export fn SymCryptChaCha20Poly1305Decrypt(
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var status: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var ChaCha20State: SYMCRYPT_CHACHA20_STATE = undefined;
    var Poly1305State: SYMCRYPT_POLY1305_STATE = undefined;
    var buf: [SYMCRYPT_POLY1305_RESULT_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var key: [SYMCRYPT_POLY1305_KEY_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    defer {
        SymCryptWipe(@ptrCast(&ChaCha20State), @sizeOf(SYMCRYPT_CHACHA20_STATE));
        SymCryptWipe(@ptrCast(&Poly1305State), @sizeOf(SYMCRYPT_POLY1305_STATE));
    }

    if (fcbDataLteMaxDataSizeStatic == 0 and @as(u64, cbData) > SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (cbTag != SYMCRYPT_POLY1305_RESULT_SIZE) {
        return .SYMCRYPT_WRONG_TAG_SIZE;
    }

    status = chacha20.SymCryptChaCha20Init(&ChaCha20State, pbKey, cbKey, pbNonce, cbNonce, 0);
    if (status != .SYMCRYPT_NO_ERROR) {
        return status;
    }

    // Generate the first 32 bytes of keystream.
    SymCryptWipe(@ptrCast(&key[0]), key.len);
    chacha20.SymCryptChaCha20Crypt(&ChaCha20State, &key, &key, key.len);

    // Create the Poly1305 key using the first 32 bytes of the ChaCha20 keystream.
    poly1305.SymCryptPoly1305Init(&Poly1305State, &key);
    SymCryptWipe(@ptrCast(&key[0]), key.len);

    SymCryptChaCha20Poly1305ComputeTag(
        &Poly1305State,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbData,
        &buf,
    );

    // Validate tag in constant time.
    if (SymCryptEqual(pbTag, &buf, cbTag) == types.FALSE) {
        return .SYMCRYPT_AUTHENTICATION_FAILURE;
    }

    // Decrypt data if needed.
    if (cbData > 0) {
        // Advance the keystream to counter 1 (offset 64) for data decryption.
        chacha20.SymCryptChaCha20SetOffset(&ChaCha20State, 64);
        chacha20.SymCryptChaCha20Crypt(&ChaCha20State, pbSrc, pbDst, cbData);
    }

    return status;
}

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;
extern const SymCryptTestMsg3: [3]BYTE;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const SymCryptChaCha20Poly1305Result = [3 + SYMCRYPT_POLY1305_RESULT_SIZE]BYTE{
    0x5d, 0xba, 0x7b,
    0x80, 0x10, 0xd2,
    0x05, 0x4a, 0xad,
    0x53, 0x1f, 0xa2,
    0xce, 0x83, 0xc1,
    0x66, 0x12, 0x85,
    0x21,
};

pub export fn SymCryptChaCha20Poly1305Selftest() callconv(SYMCRYPT_CALL) void {
    var buf: [3 + SYMCRYPT_POLY1305_RESULT_SIZE]BYTE = undefined;

    if (SymCryptChaCha20Poly1305Encrypt(
        &SymCryptTestKey32,
        SymCryptTestKey32.len,
        &SymCryptTestMsg16,
        12,
        &SymCryptTestMsg16,
        SymCryptTestMsg16.len,
        &SymCryptTestMsg3,
        &buf,
        3,
        buf[3..].ptr,
        SYMCRYPT_POLY1305_RESULT_SIZE,
    ) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("ccp0"));
    }

    SymCryptInjectError(&buf, buf.len);
    if (!std.mem.eql(u8, &buf, &SymCryptChaCha20Poly1305Result)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("ccp1"));
    }

    // Inject error into the ciphertext or tag.
    SymCryptInjectError(&buf, buf.len);

    const err = SymCryptChaCha20Poly1305Decrypt(
        &SymCryptTestKey32,
        SymCryptTestKey32.len,
        &SymCryptTestMsg16,
        12,
        &SymCryptTestMsg16,
        SymCryptTestMsg16.len,
        &buf,
        &buf,
        3,
        buf[3..].ptr,
        SYMCRYPT_POLY1305_RESULT_SIZE,
    );
    SymCryptInjectError(&buf, 3);

    if (err != .SYMCRYPT_NO_ERROR or !std.mem.eql(u8, buf[0..3], &SymCryptTestMsg3)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("ccp2"));
    }
}
