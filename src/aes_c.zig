//
// aes_c.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// The fast-ish C implementation of the core AES functions
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_tables = @import("aes_tables.zig");
const aes_default = @import("aes_default.zig");

const BYTE = types.BYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PCBYTE = types.PCBYTE;
const PBYTE = types.PBYTE;
const PCSYMCRYPT_AES_EXPANDED_KEY = types.PCSYMCRYPT_AES_EXPANDED_KEY;

const NEED_ALIGN: bool = !(types.CPU_X86 or types.CPU_AMD64 or types.CPU_ARM or types.CPU_ARM64);

inline fn IS_UINT32_ALIGNED(p: anytype) bool {
    return (@intFromPtr(p) & 3) == 0;
}

inline fn readU32(p: anytype) UINT32 {
    return @as(*align(1) const UINT32, @ptrCast(p)).*;
}

inline fn writeU32(p: anytype, val: UINT32) void {
    @as(*align(1) UINT32, @ptrCast(p)).* = val;
}

pub export fn SymCryptAes4SboxC(
    pIn: PCBYTE,
    pOut: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    pOut[0] = aes_tables.SymCryptAesSboxMatrixMult[0][pIn[0]][1];
    pOut[1] = aes_tables.SymCryptAesSboxMatrixMult[0][pIn[1]][1];
    pOut[2] = aes_tables.SymCryptAesSboxMatrixMult[0][pIn[2]][1];
    pOut[3] = aes_tables.SymCryptAesSboxMatrixMult[0][pIn[3]][1];
}

pub export fn SymCryptAesCreateDecryptionRoundKeyC(
    pEncryptionRoundKey: PCBYTE,
    pDecryptionRoundKey: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    var p = pDecryptionRoundKey;
    var q = pEncryptionRoundKey;
    var i: usize = 0;

    while (i < 4) : (i += 1) {
        writeU32(
            p,
            readU32(&aes_tables.SymCryptAesInvMatrixMult[0][q[0]][0]) ^
                readU32(&aes_tables.SymCryptAesInvMatrixMult[1][q[1]][0]) ^
                readU32(&aes_tables.SymCryptAesInvMatrixMult[2][q[2]][0]) ^
                readU32(&aes_tables.SymCryptAesInvMatrixMult[3][q[3]][0]),
        );
        p += 4;
        q += 4;
    }
}

pub export fn SymCryptAesEncryptC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbPlaintext: PCBYTE,
    pbCiphertext: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var state: [4][4]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = .{ .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 } };
    var state2: [4]UINT32 align(types.SYMCRYPT_ALIGN_VALUE) = .{ 0, 0, 0, 0 };

    if (comptime NEED_ALIGN) {
        var alignBuffer: [types.SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
        if (!(IS_UINT32_ALIGNED(pbPlaintext) and IS_UINT32_ALIGNED(pbCiphertext))) {
            @memcpy(alignBuffer[0..types.SYMCRYPT_AES_BLOCK_SIZE], pbPlaintext[0..types.SYMCRYPT_AES_BLOCK_SIZE]);
            aes_default.SymCryptAesEncrypt(pExpandedKey, &alignBuffer, &alignBuffer);
            @memcpy(pbCiphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE], alignBuffer[0..types.SYMCRYPT_AES_BLOCK_SIZE]);
            macros.SymCryptWipeKnownSize(&alignBuffer, @sizeOf(@TypeOf(alignBuffer)));
            return;
        }
    }

    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var keyPtr: [*]const [4][4]BYTE = @ptrCast(&pExpandedKey.RoundKey[0]);
    const keyLimit: [*]const [4][4]BYTE = @ptrCast(&pExpandedKey.lastEncRoundKey[0]);

    writeU32(&state[0][0], readU32(&keyPtr[0][0][0]) ^ readU32(pbPlaintext));
    writeU32(&state[1][0], readU32(&keyPtr[0][1][0]) ^ readU32(pbPlaintext + 4));
    writeU32(&state[2][0], readU32(&keyPtr[0][2][0]) ^ readU32(pbPlaintext + 8));
    writeU32(&state[3][0], readU32(&keyPtr[0][3][0]) ^ readU32(pbPlaintext + 12));

    keyPtr += 1;

    while (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        state2[0] = readU32(&aes_tables.SymCryptAesSboxMatrixMult[0][state[0][0]][0]);
        state2[3] = readU32(&aes_tables.SymCryptAesSboxMatrixMult[1][state[0][1]][0]);
        state2[2] = readU32(&aes_tables.SymCryptAesSboxMatrixMult[2][state[0][2]][0]);
        state2[1] = readU32(&aes_tables.SymCryptAesSboxMatrixMult[3][state[0][3]][0]);

        state2[1] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[0][state[1][0]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[1][state[1][1]][0]);
        state2[3] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[2][state[1][2]][0]);
        state2[2] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[3][state[1][3]][0]);

        state2[2] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[0][state[2][0]][0]);
        state2[1] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[1][state[2][1]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[2][state[2][2]][0]);
        state2[3] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[3][state[2][3]][0]);

        state2[3] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[0][state[3][0]][0]);
        state2[2] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[1][state[3][1]][0]);
        state2[1] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[2][state[3][2]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesSboxMatrixMult[3][state[3][3]][0]);

        writeU32(&state[0][0], readU32(&keyPtr[0][0][0]) ^ state2[0]);
        writeU32(&state[1][0], readU32(&keyPtr[0][1][0]) ^ state2[1]);
        writeU32(&state[2][0], readU32(&keyPtr[0][2][0]) ^ state2[2]);
        writeU32(&state[3][0], readU32(&keyPtr[0][3][0]) ^ state2[3]);

        keyPtr += 1;
    }

    state2[0] = @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[0][0]][1]);
    state2[3] = @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[0][1]][1]) << 8;
    state2[2] = @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[0][2]][1]) << 16;
    state2[1] = @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[0][3]][1]) << 24;

    state2[1] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[1][0]][1]);
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[1][1]][1]) << 8;
    state2[3] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[1][2]][1]) << 16;
    state2[2] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[1][3]][1]) << 24;

    state2[2] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[2][0]][1]);
    state2[1] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[2][1]][1]) << 8;
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[2][2]][1]) << 16;
    state2[3] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[2][3]][1]) << 24;

    state2[3] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[3][0]][1]);
    state2[2] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[3][1]][1]) << 8;
    state2[1] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[3][2]][1]) << 16;
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesSboxMatrixMult[0][state[3][3]][1]) << 24;

    writeU32(pbCiphertext, readU32(&keyPtr[0][0][0]) ^ state2[0]);
    writeU32(pbCiphertext + 4, readU32(&keyPtr[0][1][0]) ^ state2[1]);
    writeU32(pbCiphertext + 8, readU32(&keyPtr[0][2][0]) ^ state2[2]);
    writeU32(pbCiphertext + 12, readU32(&keyPtr[0][3][0]) ^ state2[3]);

    macros.SymCryptWipeKnownSize(&state, @sizeOf(@TypeOf(state)));
    macros.SymCryptWipeKnownSize(&state2, @sizeOf(@TypeOf(state2)));
}

pub export fn SymCryptAesDecryptC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbCiphertext: PCBYTE,
    pbPlaintext: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    @setRuntimeSafety(false);
    var state: [4][4]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = .{ .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 }, .{ 0, 0, 0, 0 } };
    var state2: [4]UINT32 align(types.SYMCRYPT_ALIGN_VALUE) = .{ 0, 0, 0, 0 };

    if (comptime NEED_ALIGN) {
        var alignBuffer: [types.SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
        if (!(IS_UINT32_ALIGNED(pbPlaintext) and IS_UINT32_ALIGNED(pbCiphertext))) {
            @memcpy(alignBuffer[0..types.SYMCRYPT_AES_BLOCK_SIZE], pbCiphertext[0..types.SYMCRYPT_AES_BLOCK_SIZE]);
            aes_default.SymCryptAesDecrypt(pExpandedKey, &alignBuffer, &alignBuffer);
            @memcpy(pbPlaintext[0..types.SYMCRYPT_AES_BLOCK_SIZE], alignBuffer[0..types.SYMCRYPT_AES_BLOCK_SIZE]);
            macros.SymCryptWipeKnownSize(&alignBuffer, @sizeOf(@TypeOf(alignBuffer)));
            return;
        }
    }

    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    var keyPtr: [*]const [4][4]BYTE = @ptrCast(&pExpandedKey.lastEncRoundKey[0]);
    const keyLimit: [*]const [4][4]BYTE = @ptrCast(&pExpandedKey.lastDecRoundKey[0]);

    writeU32(&state[0][0], readU32(&keyPtr[0][0][0]) ^ readU32(pbCiphertext));
    writeU32(&state[1][0], readU32(&keyPtr[0][1][0]) ^ readU32(pbCiphertext + 4));
    writeU32(&state[2][0], readU32(&keyPtr[0][2][0]) ^ readU32(pbCiphertext + 8));
    writeU32(&state[3][0], readU32(&keyPtr[0][3][0]) ^ readU32(pbCiphertext + 12));

    keyPtr += 1;

    while (@intFromPtr(keyPtr) < @intFromPtr(keyLimit)) {
        state2[0] = readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[0][state[0][0]][0]);
        state2[1] = readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[1][state[0][1]][0]);
        state2[2] = readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[2][state[0][2]][0]);
        state2[3] = readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[3][state[0][3]][0]);

        state2[1] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[0][state[1][0]][0]);
        state2[2] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[1][state[1][1]][0]);
        state2[3] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[2][state[1][2]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[3][state[1][3]][0]);

        state2[2] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[0][state[2][0]][0]);
        state2[3] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[1][state[2][1]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[2][state[2][2]][0]);
        state2[1] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[3][state[2][3]][0]);

        state2[3] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[0][state[3][0]][0]);
        state2[0] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[1][state[3][1]][0]);
        state2[1] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[2][state[3][2]][0]);
        state2[2] ^= readU32(&aes_tables.SymCryptAesInvSboxMatrixMult[3][state[3][3]][0]);

        writeU32(&state[0][0], readU32(&keyPtr[0][0][0]) ^ state2[0]);
        writeU32(&state[1][0], readU32(&keyPtr[0][1][0]) ^ state2[1]);
        writeU32(&state[2][0], readU32(&keyPtr[0][2][0]) ^ state2[2]);
        writeU32(&state[3][0], readU32(&keyPtr[0][3][0]) ^ state2[3]);

        keyPtr += 1;
    }

    state2[0] = @as(UINT32, aes_tables.SymCryptAesInvSbox[state[0][0]]);
    state2[1] = @as(UINT32, aes_tables.SymCryptAesInvSbox[state[0][1]]) << 8;
    state2[2] = @as(UINT32, aes_tables.SymCryptAesInvSbox[state[0][2]]) << 16;
    state2[3] = @as(UINT32, aes_tables.SymCryptAesInvSbox[state[0][3]]) << 24;

    state2[1] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[1][0]]);
    state2[2] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[1][1]]) << 8;
    state2[3] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[1][2]]) << 16;
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[1][3]]) << 24;

    state2[2] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[2][0]]);
    state2[3] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[2][1]]) << 8;
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[2][2]]) << 16;
    state2[1] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[2][3]]) << 24;

    state2[3] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[3][0]]);
    state2[0] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[3][1]]) << 8;
    state2[1] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[3][2]]) << 16;
    state2[2] |= @as(UINT32, aes_tables.SymCryptAesInvSbox[state[3][3]]) << 24;

    writeU32(pbPlaintext, readU32(&keyPtr[0][0][0]) ^ state2[0]);
    writeU32(pbPlaintext + 4, readU32(&keyPtr[0][1][0]) ^ state2[1]);
    writeU32(pbPlaintext + 8, readU32(&keyPtr[0][2][0]) ^ state2[2]);
    writeU32(pbPlaintext + 12, readU32(&keyPtr[0][3][0]) ^ state2[3]);

    macros.SymCryptWipeKnownSize(&state, @sizeOf(@TypeOf(state)));
    macros.SymCryptWipeKnownSize(&state2, @sizeOf(@TypeOf(state2)));
}

pub export fn SymCryptAesEcbEncryptC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var src = pbSrc;
    var dst = pbDst;
    var remaining = cbData;

    while (remaining >= types.SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesEncryptC(pExpandedKey, src, dst);
        src += types.SYMCRYPT_AES_BLOCK_SIZE;
        dst += types.SYMCRYPT_AES_BLOCK_SIZE;
        remaining -= types.SYMCRYPT_AES_BLOCK_SIZE;
    }
}

pub export fn SymCryptAesEcbDecryptC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var src = pbSrc;
    var dst = pbDst;
    var remaining = cbData;

    while (remaining >= types.SYMCRYPT_AES_BLOCK_SIZE) {
        SymCryptAesDecryptC(pExpandedKey, src, dst);
        src += types.SYMCRYPT_AES_BLOCK_SIZE;
        dst += types.SYMCRYPT_AES_BLOCK_SIZE;
        remaining -= types.SYMCRYPT_AES_BLOCK_SIZE;
    }
}
