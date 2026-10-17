//
// rc4.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This is a new implementation, NOT based on the existing ones in RSA32.lib.
// The algorithm specification is taken from "ARCFOUR Algorithm" internet
// draft dated July 1999, and from memory.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

pub const SYMCRYPT_RC4_S_TYPE = BYTE;

pub const SYMCRYPT_RC4_STATE = extern struct {
    S: [256]SYMCRYPT_RC4_S_TYPE align(types.SYMCRYPT_ALIGN_VALUE),
    i: BYTE,
    j: BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_RC4_STATE = *SYMCRYPT_RC4_STATE;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptRc4Init(
    pState: PSYMCRYPT_RC4_STATE,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var keyBuf: [256]BYTE = undefined;

    if (cbKey > 256 or cbKey == 0) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    // Make a copy of the key to obey the read-once rule.
    @memcpy(keyBuf[0..cbKey], pbKey[0..cbKey]);

    var i: SIZE_T = 0;
    while (i < 256) : (i += 1) {
        pState.S[i] = @truncate(i);
    }

    var j: SIZE_T = 0;
    var keyIdx: SIZE_T = 0;
    i = 0;
    while (i < 256) : (i += 1) {
        const T: SYMCRYPT_RC4_S_TYPE = pState.S[i];
        j = (j + T + keyBuf[keyIdx]) & 0xff;
        pState.S[i] = pState.S[j];
        pState.S[j] = T;
        keyIdx += 1;
        if (keyIdx == cbKey) {
            keyIdx = 0;
        }
    }

    // We store the i value already incremented for the next byte.
    pState.i = 1;
    pState.j = 0;

    macros.SET_MAGIC(pState);

    SymCryptWipe(@ptrCast(&keyBuf[0]), cbKey);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRc4Crypt(
    pState: PSYMCRYPT_RC4_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var idx: SIZE_T = 0;

    macros.CHECK_MAGIC(pState);

    var i: SIZE_T = pState.i;
    var j: SIZE_T = pState.j;

    while (idx < cbData) : (idx += 1) {
        const Ti: SYMCRYPT_RC4_S_TYPE = pState.S[i];
        j = (j + Ti) & 0xff;
        const Tj: SYMCRYPT_RC4_S_TYPE = pState.S[j];
        pState.S[i] = Tj;
        pState.S[j] = Ti;
        pbDst[idx] = pbSrc[idx] ^ pState.S[(Ti +% Tj) & 0xff];

        i = (i + 1) & 0xff;
    }

    pState.i = @truncate(i);
    pState.j = @truncate(j);
}

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg3: [3]BYTE;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const rc4KatAnswer = [3]BYTE{ 0x71, 0x46, 0x92 };

pub export fn SymCryptRc4Selftest() callconv(SYMCRYPT_CALL) void {
    var buf: [3]BYTE = undefined;
    var state: SYMCRYPT_RC4_STATE = undefined;

    _ = SymCryptRc4Init(&state, &SymCryptTestKey32, SymCryptTestKey32.len);

    SymCryptRc4Crypt(&state, &SymCryptTestMsg3, &buf, buf.len);

    SymCryptInjectError(&buf, buf.len);

    if (!std.mem.eql(u8, &buf, &rc4KatAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("rc4 "));
    }
}
