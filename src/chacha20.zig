//
// chacha20.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

pub const SYMCRYPT_CHACHA20_STATE = extern struct {
    key: [8]UINT32 align(types.SYMCRYPT_ALIGN_VALUE),
    nonce: [3]UINT32,
    offset: UINT64,
    keystreamBufferValid: BOOLEAN,
    keystream: [64]BYTE,
};
pub const PSYMCRYPT_CHACHA20_STATE = *SYMCRYPT_CHACHA20_STATE;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptXorBytes(pbSrc1: PCBYTE, pbSrc2: PCBYTE, pbResult: PBYTE, cbBytes: SIZE_T) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptChaCha20Init(
    pState: PSYMCRYPT_CHACHA20_STATE,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    offset: UINT64,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbKey != 32) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    if (cbNonce != 12) {
        return .SYMCRYPT_WRONG_NONCE_SIZE;
    }

    macros.SymCryptLsbFirstToUint32(pbKey, &pState.key, 8);
    macros.SymCryptLsbFirstToUint32(pbNonce, &pState.nonce, 3);

    SymCryptChaCha20SetOffset(pState, offset);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptChaCha20SetOffset(
    pState: PSYMCRYPT_CHACHA20_STATE,
    offset: UINT64,
) callconv(SYMCRYPT_CALL) void {
    pState.offset = offset;
    pState.keystreamBufferValid = types.FALSE;
}

pub export fn SymCryptChaCha20Crypt(
    pState: PSYMCRYPT_CHACHA20_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;
    const blockOffset: UINT32 = @truncate(pState.offset & 0x3f);
    var nBytes: SIZE_T = 0;

    // If the offset is in the middle of the block, we first crypt until the end
    // of the block
    if (blockOffset != 0) {
        if (pState.keystreamBufferValid == types.FALSE) {
            // Generate a block of key stream
            SymCryptWipe(@ptrCast(&pState.keystream[0]), 64);
            SymCryptChaCha20CryptBlocks(
                pState,
                &pState.keystream,
                &pState.keystream,
                64,
            );
            pState.offset -%= 64; // Don't update the offset yet
        }

        nBytes = 64 - @as(SIZE_T, blockOffset); // # bytes in buffer starting at offset
        if (cbData < nBytes) {
            // We don't use the generated block to the end. The buffer will be valid
            // at the end as the offset won't advance beyond the block.
            nBytes = cbData;
            pState.keystreamBufferValid = types.TRUE;
        } else {
            // We'll use the rest of the generated block. After that the key stream
            // buffer won't be valid as the offset will advance beyond it.
            pState.keystreamBufferValid = types.FALSE;
        }

        SymCryptXorBytes(pbSrc, @ptrCast(&pState.keystream[blockOffset]), pbDst, nBytes);
        pbSrc += nBytes;
        pbDst += nBytes;
        cbData -= nBytes;
        pState.offset +%= nBytes;
    }

    // Here: pbSrc, pbDst, cbData, and pState.offset all in sync
    // and either cbData == 0 or offset is at a block boundary

    if (cbData >= 64) {
        nBytes = cbData & ~@as(SIZE_T, 0x3f);
        SymCryptChaCha20CryptBlocks(pState, pbSrc, pbDst, nBytes);
        pbSrc += nBytes;
        pbDst += nBytes;
        cbData -= nBytes;
    }

    if (cbData > 0) {
        // Generate a block of key stream
        SymCryptWipe(@ptrCast(&pState.keystream[0]), 64);
        SymCryptChaCha20CryptBlocks(
            pState,
            &pState.keystream,
            &pState.keystream,
            64,
        );
        pState.offset -%= 64; // Don't update the offset yet
        pState.keystreamBufferValid = types.TRUE;

        SymCryptXorBytes(pbSrc, &pState.keystream, pbDst, cbData);
        pState.offset +%= cbData;
    }
}

inline fn chachaQuarterRound(a: *UINT32, b: *UINT32, c: *UINT32, d: *UINT32) void {
    a.* +%= b.*;
    d.* ^= a.*;
    d.* = macros.ROL32(d.*, 16);
    c.* +%= d.*;
    b.* ^= c.*;
    b.* = macros.ROL32(b.*, 12);
    a.* +%= b.*;
    d.* ^= a.*;
    d.* = macros.ROL32(d.*, 8);
    c.* +%= d.*;
    b.* ^= c.*;
    b.* = macros.ROL32(b.*, 7);
}

pub export fn SymCryptChaCha20CryptBlocks(
    pState: PSYMCRYPT_CHACHA20_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;
    var counter: UINT32 = @truncate(pState.offset >> 6);

    while (cbData >= 64) {
        var s0: UINT32 = 0x61707865;
        var s1: UINT32 = 0x3320646e;
        var s2: UINT32 = 0x79622d32;
        var s3: UINT32 = 0x6b206574;
        var s4: UINT32 = pState.key[0];
        var s5: UINT32 = pState.key[1];
        var s6: UINT32 = pState.key[2];
        var s7: UINT32 = pState.key[3];
        var s8: UINT32 = pState.key[4];
        var s9: UINT32 = pState.key[5];
        var s10: UINT32 = pState.key[6];
        var s11: UINT32 = pState.key[7];
        var s12: UINT32 = counter;
        var s13: UINT32 = pState.nonce[0];
        var s14: UINT32 = pState.nonce[1];
        var s15: UINT32 = pState.nonce[2];

        var i: usize = 0;
        while (i < 10) : (i += 1) {
            chachaQuarterRound(&s0, &s4, &s8, &s12);
            chachaQuarterRound(&s1, &s5, &s9, &s13);
            chachaQuarterRound(&s2, &s6, &s10, &s14);
            chachaQuarterRound(&s3, &s7, &s11, &s15);

            chachaQuarterRound(&s0, &s5, &s10, &s15);
            chachaQuarterRound(&s1, &s6, &s11, &s12);
            chachaQuarterRound(&s2, &s7, &s8, &s13);
            chachaQuarterRound(&s3, &s4, &s9, &s14);
        }

        s0 +%= 0x61707865;
        s1 +%= 0x3320646e;
        s2 +%= 0x79622d32;
        s3 +%= 0x6b206574;
        s4 +%= pState.key[0];
        s5 +%= pState.key[1];
        s6 +%= pState.key[2];
        s7 +%= pState.key[3];
        s8 +%= pState.key[4];
        s9 +%= pState.key[5];
        s10 +%= pState.key[6];
        s11 +%= pState.key[7];
        s12 +%= counter;
        s13 +%= pState.nonce[0];
        s14 +%= pState.nonce[1];
        s15 +%= pState.nonce[2];

        macros.STORE_LSBFIRST32(pbDst + 0, s0 ^ macros.LOAD_LSBFIRST32(pbSrc + 0));
        macros.STORE_LSBFIRST32(pbDst + 4, s1 ^ macros.LOAD_LSBFIRST32(pbSrc + 4));
        macros.STORE_LSBFIRST32(pbDst + 8, s2 ^ macros.LOAD_LSBFIRST32(pbSrc + 8));
        macros.STORE_LSBFIRST32(pbDst + 12, s3 ^ macros.LOAD_LSBFIRST32(pbSrc + 12));
        macros.STORE_LSBFIRST32(pbDst + 16, s4 ^ macros.LOAD_LSBFIRST32(pbSrc + 16));
        macros.STORE_LSBFIRST32(pbDst + 20, s5 ^ macros.LOAD_LSBFIRST32(pbSrc + 20));
        macros.STORE_LSBFIRST32(pbDst + 24, s6 ^ macros.LOAD_LSBFIRST32(pbSrc + 24));
        macros.STORE_LSBFIRST32(pbDst + 28, s7 ^ macros.LOAD_LSBFIRST32(pbSrc + 28));
        macros.STORE_LSBFIRST32(pbDst + 32, s8 ^ macros.LOAD_LSBFIRST32(pbSrc + 32));
        macros.STORE_LSBFIRST32(pbDst + 36, s9 ^ macros.LOAD_LSBFIRST32(pbSrc + 36));
        macros.STORE_LSBFIRST32(pbDst + 40, s10 ^ macros.LOAD_LSBFIRST32(pbSrc + 40));
        macros.STORE_LSBFIRST32(pbDst + 44, s11 ^ macros.LOAD_LSBFIRST32(pbSrc + 44));
        macros.STORE_LSBFIRST32(pbDst + 48, s12 ^ macros.LOAD_LSBFIRST32(pbSrc + 48));
        macros.STORE_LSBFIRST32(pbDst + 52, s13 ^ macros.LOAD_LSBFIRST32(pbSrc + 52));
        macros.STORE_LSBFIRST32(pbDst + 56, s14 ^ macros.LOAD_LSBFIRST32(pbSrc + 56));
        macros.STORE_LSBFIRST32(pbDst + 60, s15 ^ macros.LOAD_LSBFIRST32(pbSrc + 60));

        counter +%= 1;
        pbSrc += 64;
        pbDst += 64;
        cbData -= 64;
        pState.offset +%= 64;
    }
}

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;
extern const SymCryptTestMsg3: [3]BYTE;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const chacha20KatAnswer = [3]BYTE{ 0xb5, 0xe0, 0x54 };

pub export fn SymCryptChaCha20Selftest() callconv(SYMCRYPT_CALL) void {
    var buf: [3]BYTE = undefined;
    var state: SYMCRYPT_CHACHA20_STATE = undefined;

    _ = SymCryptChaCha20Init(
        &state,
        &SymCryptTestKey32,
        SymCryptTestKey32.len,
        &SymCryptTestMsg16,
        12,
        0,
    );

    SymCryptChaCha20Crypt(&state, &SymCryptTestMsg3, &buf, buf.len);

    SymCryptInjectError(&buf, buf.len);

    if (!std.mem.eql(u8, &buf, &chacha20KatAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("Cha2"));
    }
}
