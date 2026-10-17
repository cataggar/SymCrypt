//
// aes_key.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Generic AES key expansion routine
//

const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_default = @import("aes_default.zig");

const BYTE = types.BYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOL = types.BOOL;
const BOOLEAN = types.BOOLEAN;
const PCBYTE = types.PCBYTE;
const PBYTE = types.PBYTE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PSYMCRYPT_AES_EXPANDED_KEY = types.PSYMCRYPT_AES_EXPANDED_KEY;
const PCSYMCRYPT_AES_EXPANDED_KEY = types.PCSYMCRYPT_AES_EXPANDED_KEY;

const g_SymCryptAesRoundConstant = [11]BYTE{
    0, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
};

pub export const SymCryptAesNistTestVector128Ciphertext: [16]BYTE = .{
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
    0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
};

pub export fn SymCryptAesExpandKeyInternal(
    pExpandedKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    fCreateDecryptionKeys: BOOLEAN,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    var nRounds: UINT32 = undefined;
    var p: PBYTE = undefined;
    var q: PBYTE = undefined;
    var i: UINT32 = undefined;
    var t: UINT32 = undefined;

    var UseSimd: BOOL = 0;

    var SaveData: types.SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
    if (comptime types.CPU_X86) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            if (macros.SymCryptSaveXmm(&SaveData) == .SYMCRYPT_NO_ERROR) {
                UseSimd = 1;
            }
        }
    } else if (comptime types.CPU_AMD64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            UseSimd = 1;
        }
    } else if (comptime types.CPU_ARM64) {
        if (macros.CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            UseSimd = 1;
        }
    }
    defer {
        if (comptime types.CPU_X86) {
            if (UseSimd != 0) {
                macros.SymCryptRestoreXmm(&SaveData);
            }
        }
    }

    macros.SYMCRYPT_SET_MAGIC(pExpandedKey);

    switch (cbKey) {
        16 => {
            nRounds = 10;
            pExpandedKey.lastEncRoundKey = @ptrCast(&pExpandedKey.RoundKey[nRounds]);
            pExpandedKey.lastDecRoundKey = @ptrCast(&pExpandedKey.RoundKey[2 * nRounds]);

            @memcpy(@as([*]BYTE, @ptrCast(&pExpandedKey.RoundKey[0]))[0..16], pbKey[0..16]);

            p = @ptrCast(&pExpandedKey.RoundKey[1]);

            i = 1;
            while (i <= nRounds) : (i += 1) {
                aes_default.SymCryptAes4Sbox(p - 4, p, UseSimd);
                t = macros.ROR32(macros.SYMCRYPT_LOAD_LSBFIRST32(p), 8) ^
                    macros.SYMCRYPT_LOAD_LSBFIRST32(p - 16) ^
                    g_SymCryptAesRoundConstant[i];
                macros.SYMCRYPT_STORE_LSBFIRST32(p, t);

                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 4))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 12))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 8))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 4))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 8))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 12))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 8))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 4))).*;

                p += 16;
            }
        },
        24 => {
            nRounds = 12;
            pExpandedKey.lastEncRoundKey = @ptrCast(&pExpandedKey.RoundKey[nRounds]);
            pExpandedKey.lastDecRoundKey = @ptrCast(&pExpandedKey.RoundKey[2 * nRounds]);

            @memcpy(@as([*]BYTE, @ptrCast(&pExpandedKey.RoundKey[0]))[0..24], pbKey[0..24]);

            p = @as(PBYTE, @ptrCast(&pExpandedKey.RoundKey[0])) + 24;

            i = 1;
            while (i <= 8) : (i += 1) {
                aes_default.SymCryptAes4Sbox(p - 4, p, UseSimd);
                t = macros.ROR32(macros.SYMCRYPT_LOAD_LSBFIRST32(p), 8) ^
                    macros.SYMCRYPT_LOAD_LSBFIRST32(p - 24) ^
                    g_SymCryptAesRoundConstant[i];
                macros.SYMCRYPT_STORE_LSBFIRST32(p, t);

                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 4))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 20))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 8))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 4))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 16))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 12))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 8))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 12))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 16))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 12))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 8))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 20))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 16))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 4))).*;

                p += 24;
            }
        },
        32 => {
            nRounds = 14;
            pExpandedKey.lastEncRoundKey = @ptrCast(&pExpandedKey.RoundKey[nRounds]);
            pExpandedKey.lastDecRoundKey = @ptrCast(&pExpandedKey.RoundKey[2 * nRounds]);

            @memcpy(@as([*]BYTE, @ptrCast(&pExpandedKey.RoundKey[0]))[0..32], pbKey[0..32]);

            p = @as(PBYTE, @ptrCast(&pExpandedKey.RoundKey[0])) + 32;

            i = 1;
            while (i <= 6) : (i += 1) {
                aes_default.SymCryptAes4Sbox(p - 4, p, UseSimd);
                t = macros.ROR32(macros.SYMCRYPT_LOAD_LSBFIRST32(p), 8) ^
                    macros.SYMCRYPT_LOAD_LSBFIRST32(p - 32) ^
                    g_SymCryptAesRoundConstant[i];
                macros.SYMCRYPT_STORE_LSBFIRST32(p, t);

                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 4))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 28))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 8))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 4))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 24))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 12))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 8))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 20))).*;

                aes_default.SymCryptAes4Sbox(p + 12, p + 16, UseSimd);
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 16))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 16))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 16))).*;

                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 20))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 16))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 12))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 24))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 20))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 8))).*;
                @as(*align(4) UINT32, @ptrCast(@alignCast(p + 28))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 24))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 4))).*;

                p += 32;
            }

            aes_default.SymCryptAes4Sbox(p - 4, p, UseSimd);
            t = macros.ROR32(macros.SYMCRYPT_LOAD_LSBFIRST32(p), 8) ^
                macros.SYMCRYPT_LOAD_LSBFIRST32(p - 32) ^
                g_SymCryptAesRoundConstant[i];
            macros.SYMCRYPT_STORE_LSBFIRST32(p, t);

            @as(*align(4) UINT32, @ptrCast(@alignCast(p + 4))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 28))).*;
            @as(*align(4) UINT32, @ptrCast(@alignCast(p + 8))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 4))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 24))).*;
            @as(*align(4) UINT32, @ptrCast(@alignCast(p + 12))).* = @as(*align(4) const UINT32, @ptrCast(@alignCast(p + 8))).* ^ @as(*align(4) const UINT32, @ptrCast(@alignCast(p - 20))).*;
        },
        else => {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        },
    }

    if (fCreateDecryptionKeys != 0) {
        p = @ptrCast(&pExpandedKey.RoundKey[0][0][0]);
        q = @ptrCast(pExpandedKey.lastDecRoundKey);

        @memcpy(q[0..types.SYMCRYPT_AES_BLOCK_SIZE], p[0..types.SYMCRYPT_AES_BLOCK_SIZE]);
        p += 16;
        q -= 16;

        while (@intFromPtr(p) < @intFromPtr(pExpandedKey.lastEncRoundKey)) {
            aes_default.SymCryptAesCreateDecryptionRoundKey(p, q, UseSimd);
            q -= 16;
            p += 16;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptAesExpandKey(
    pExpandedKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptAesExpandKeyInternal(pExpandedKey, pbKey, cbKey, types.TRUE);
}

pub export fn SymCryptAesExpandKeyEncryptOnly(
    pExpandedKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptAesExpandKeyInternal(pExpandedKey, pbKey, cbKey, types.FALSE);
}

pub export fn SymCryptAesKeyCopy(
    pSrc: PCSYMCRYPT_AES_EXPANDED_KEY,
    pDst: PSYMCRYPT_AES_EXPANDED_KEY,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pSrc);

    pDst.* = pSrc.*;
    pDst.lastEncRoundKey = @ptrFromInt(@intFromPtr(&pDst.RoundKey[0]) + (@intFromPtr(pSrc.lastEncRoundKey) - @intFromPtr(&pSrc.RoundKey[0])));
    pDst.lastDecRoundKey = @ptrFromInt(@intFromPtr(&pDst.RoundKey[0]) + (@intFromPtr(pSrc.lastDecRoundKey) - @intFromPtr(&pSrc.RoundKey[0])));

    macros.SYMCRYPT_SET_MAGIC(pDst);
}
