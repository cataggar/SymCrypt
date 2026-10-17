//
// xtsaes.zig
// XTS-AES implementation (ports lib/xtsaes.c and lib/xtsaes_pattern.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const equal = @import("equal.zig");
const aes_key = @import("aes_key.zig");
const aes_c = @import("aes_c.zig");
const aes_asm = @import("aes_asm.zig");
const aes_default = @import("aes_default.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const PCVOID = types.PCVOID;
const BOOLEAN = types.BOOLEAN;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_AES_BLOCK_SIZE = types.SYMCRYPT_AES_BLOCK_SIZE;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const PCSYMCRYPT_AES_EXPANDED_KEY = types.PCSYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_XTS_AES_EXPANDED_KEY = types.SYMCRYPT_XTS_AES_EXPANDED_KEY;
const PSYMCRYPT_XTS_AES_EXPANDED_KEY = types.PSYMCRYPT_XTS_AES_EXPANDED_KEY;
const PCSYMCRYPT_XTS_AES_EXPANDED_KEY = types.PCSYMCRYPT_XTS_AES_EXPANDED_KEY;
const SYMCRYPT_EXTENDED_SAVE_DATA = types.SYMCRYPT_EXTENDED_SAVE_DATA;

const N_PARALLEL_TWEAKS: usize = 16;

extern fn SymCryptAesEcbEncryptXmm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptAesEcbEncryptNeon(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesEncryptDataUnitXmm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbScratch: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesDecryptDataUnitXmm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbScratch: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesEncryptDataUnitYmm_2048(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbScratch: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesDecryptDataUnitYmm_2048(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbScratch: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesEncryptDataUnitNeon(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptXtsAesDecryptDataUnitNeon(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void;

pub export fn SymCryptXtsAesExpandKey(
    pExpandedKey: PSYMCRYPT_XTS_AES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const halfKeySize: SIZE_T = cbKey / 2;

    var scError = aes_key.SymCryptAesExpandKey(&pExpandedKey.key1, pbKey, halfKeySize);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Pass the 'rest' of the key to the second one. This catches errors such as
    // an attempt to pass a 33 byte key.
    // halfKeySize = 16, which is valid, but this expansion gets a 17-byte key which will fail.
    // Key2 is only used for tweak encryption, so we can use the EncryptOnly key expansion.
    scError = aes_key.SymCryptAesExpandKeyEncryptOnly(
        &pExpandedKey.key2,
        pbKey + halfKeySize,
        cbKey - halfKeySize,
    );
    return scError;
}

pub export fn SymCryptXtsAesExpandKeyEx(
    pExpandedKey: PSYMCRYPT_XTS_AES_EXPANDED_KEY,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if ((flags & types.SYMCRYPT_FLAG_KEY_NO_FIPS) == 0) {
        // FIPS IG C.I enforces that the two AES keys internally used in XTS-AES are non-equal
        if (cbKey > 64) {
            return .SYMCRYPT_WRONG_KEY_SIZE;
        }
        if (equal.SymCryptEqual(pbKey, pbKey + (cbKey / 2), cbKey / 2) != 0) {
            return .SYMCRYPT_FIPS_FAILURE;
        }
    }

    return SymCryptXtsAesExpandKey(pExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptXtsAesKeyCopy(
    pSrc: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    pDst: PSYMCRYPT_XTS_AES_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    aes_key.SymCryptAesKeyCopy(&pSrc.key1, &pDst.key1);
    aes_key.SymCryptAesKeyCopy(&pSrc.key2, &pDst.key2);
}

const XtsImplVariant = enum {
    c_enc,
    c_dec,
    asm_enc,
    asm_dec,
    neon_enc,
    neon_dec,
    xmm_enc,
    xmm_dec,
    ymm_enc,
    ymm_dec,
};

inline fn xtsAesInternalPattern(
    comptime variant: XtsImplVariant,
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
    bOverflow: BOOLEAN,
) void {
    const needsExtraScratch = (variant == .xmm_enc or variant == .xmm_dec or variant == .ymm_enc or variant == .ymm_dec);
    const scratchBytes = if (needsExtraScratch)
        (N_PARALLEL_TWEAKS + 16) * SYMCRYPT_AES_BLOCK_SIZE
    else
        N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE;
    const scratchAlign = if (needsExtraScratch) 16 else types.SYMCRYPT_ALIGN_VALUE;

    var localScratch: [scratchBytes]BYTE align(scratchAlign) = undefined;
    const tweakBuf: PBYTE = @ptrCast(&localScratch[0]);

    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;

    var tweakLow64: UINT64 = macros.SYMCRYPT_LOAD_LSBFIRST64(pbTweak);
    var tweakHigh64: UINT64 = macros.SYMCRYPT_LOAD_LSBFIRST64(pbTweak + 8);

    macros.SYMCRYPT_ASSERT(cbData % cbDataUnit == 0);

    while (cbData >= cbDataUnit) {
        var tweakBytes: SIZE_T = 0;
        const previousTweakLow64: UINT64 = tweakLow64;

        while (true) {
            macros.SYMCRYPT_STORE_LSBFIRST64(tweakBuf + tweakBytes, tweakLow64);
            macros.SYMCRYPT_STORE_LSBFIRST64(tweakBuf + tweakBytes + 8, tweakHigh64);
            tweakLow64 +%= 1;
            cbData -= cbDataUnit;
            tweakBytes += SYMCRYPT_AES_BLOCK_SIZE;
            if (!(cbData >= cbDataUnit and tweakBytes < SYMCRYPT_AES_BLOCK_SIZE * N_PARALLEL_TWEAKS)) {
                break;
            }
        }

        if (bOverflow != 0 and previousTweakLow64 > tweakLow64) {
            macros.SYMCRYPT_ASSERT(tweakLow64 < N_PARALLEL_TWEAKS);
            tweakHigh64 +%= 1;
            var idx: SIZE_T = 0;
            while (idx < tweakLow64) : (idx += 1) {
                macros.SYMCRYPT_STORE_LSBFIRST64(tweakBuf + (tweakBytes - (16 * idx) - 8), tweakHigh64);
            }
        }

        switch (variant) {
            .c_enc, .c_dec => aes_c.SymCryptAesEcbEncryptC(&pExpandedKey.key2, tweakBuf, tweakBuf, tweakBytes),
            .asm_enc, .asm_dec => aes_asm.SymCryptAesEcbEncryptAsm(&pExpandedKey.key2, tweakBuf, tweakBuf, tweakBytes),
            .neon_enc, .neon_dec => SymCryptAesEcbEncryptNeon(&pExpandedKey.key2, tweakBuf, tweakBuf, tweakBytes),
            .xmm_enc, .xmm_dec, .ymm_enc, .ymm_dec => SymCryptAesEcbEncryptXmm(&pExpandedKey.key2, tweakBuf, tweakBuf, tweakBytes),
        }

        var i: SIZE_T = 0;
        while (i < tweakBytes) : (i += SYMCRYPT_AES_BLOCK_SIZE) {
            switch (variant) {
                .c_enc => SymCryptXtsAesEncryptDataUnitC(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .c_dec => SymCryptXtsAesDecryptDataUnitC(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .asm_enc => SymCryptXtsAesEncryptDataUnitAsm(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .asm_dec => SymCryptXtsAesDecryptDataUnitAsm(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .neon_enc => SymCryptXtsAesEncryptDataUnitNeon(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .neon_dec => SymCryptXtsAesDecryptDataUnitNeon(&pExpandedKey.key1, tweakBuf + i, pbSrc, pbDst, cbDataUnit),
                .xmm_enc => SymCryptXtsAesEncryptDataUnitXmm(
                    &pExpandedKey.key1,
                    tweakBuf + i,
                    @ptrCast(&localScratch[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE]),
                    pbSrc,
                    pbDst,
                    cbDataUnit,
                ),
                .xmm_dec => SymCryptXtsAesDecryptDataUnitXmm(
                    &pExpandedKey.key1,
                    tweakBuf + i,
                    @ptrCast(&localScratch[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE]),
                    pbSrc,
                    pbDst,
                    cbDataUnit,
                ),
                .ymm_enc => SymCryptXtsAesEncryptDataUnitYmm_2048(
                    &pExpandedKey.key1,
                    tweakBuf + i,
                    @ptrCast(&localScratch[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE]),
                    pbSrc,
                    pbDst,
                    cbDataUnit,
                ),
                .ymm_dec => SymCryptXtsAesDecryptDataUnitYmm_2048(
                    &pExpandedKey.key1,
                    tweakBuf + i,
                    @ptrCast(&localScratch[N_PARALLEL_TWEAKS * SYMCRYPT_AES_BLOCK_SIZE]),
                    pbSrc,
                    pbDst,
                    cbDataUnit,
                ),
            }
            pbSrc += cbDataUnit;
            pbDst += cbDataUnit;
        }
    }

    macros.SymCryptWipeKnownSize(@ptrCast(&localScratch[0]), @sizeOf(@TypeOf(localScratch)));
}

pub export fn SymCryptXtsAesEncryptInternalC(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.c_enc, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub export fn SymCryptXtsAesDecryptInternalC(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.c_dec, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesEncryptInternalAsm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.asm_enc, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesDecryptInternalAsm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.asm_dec, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesEncryptInternalNeon(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.neon_enc, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesDecryptInternalNeon(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.neon_dec, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesEncryptInternalXmm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.xmm_enc, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesDecryptInternalXmm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.xmm_dec, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesEncryptInternalYmm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.ymm_enc, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

pub fn SymCryptXtsAesDecryptInternalYmm(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    xtsAesInternalPattern(.ymm_dec, pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
}

comptime {
    if (types.CPU_AMD64 or types.CPU_X86 or types.CPU_ARM) {
        @export(&SymCryptXtsAesEncryptInternalAsm, .{ .name = "SymCryptXtsAesEncryptInternalAsm" });
        @export(&SymCryptXtsAesDecryptInternalAsm, .{ .name = "SymCryptXtsAesDecryptInternalAsm" });
    }
    if (types.CPU_ARM64) {
        @export(&SymCryptXtsAesEncryptInternalNeon, .{ .name = "SymCryptXtsAesEncryptInternalNeon" });
        @export(&SymCryptXtsAesDecryptInternalNeon, .{ .name = "SymCryptXtsAesDecryptInternalNeon" });
    }
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptXtsAesEncryptInternalXmm, .{ .name = "SymCryptXtsAesEncryptInternalXmm" });
        @export(&SymCryptXtsAesDecryptInternalXmm, .{ .name = "SymCryptXtsAesDecryptInternalXmm" });
        @export(&SymCryptXtsAesEncryptInternalYmm, .{ .name = "SymCryptXtsAesEncryptInternalYmm" });
        @export(&SymCryptXtsAesDecryptInternalYmm, .{ .name = "SymCryptXtsAesDecryptInternalYmm" });
    }
}

pub export fn SymCryptXtsAesEncryptInternal(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE) and
            macros.SymCryptSaveYmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptXtsAesEncryptInternalYmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
            macros.SymCryptRestoreYmm(&saveData);
        } else if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptXtsAesEncryptInternalXmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        } else {
            SymCryptXtsAesEncryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else if (comptime types.CPU_X86) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptXtsAesEncryptInternalXmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
            macros.SymCryptRestoreXmm(&saveData);
        } else {
            SymCryptXtsAesEncryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else if (comptime types.CPU_ARM) {
        SymCryptXtsAesEncryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
    } else if (comptime types.CPU_ARM64) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptXtsAesEncryptInternalNeon(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        } else {
            SymCryptXtsAesEncryptInternalC(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else {
        SymCryptXtsAesEncryptInternalC(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
    }
}

pub export fn SymCryptXtsAesEncrypt(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    tweak: UINT64,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var fullTweak: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_ASSERT(cbData % cbDataUnit == 0);

    if (cbDataUnit < SYMCRYPT_AES_BLOCK_SIZE) {
        return;
    }

    macros.SYMCRYPT_STORE_LSBFIRST64(@ptrCast(&fullTweak[0]), tweak);
    macros.SYMCRYPT_STORE_LSBFIRST64(@ptrCast(&fullTweak[8]), 0);

    SymCryptXtsAesEncryptInternal(pExpandedKey, cbDataUnit, @ptrCast(&fullTweak[0]), pbSrc, pbDst, cbData, types.FALSE);
}

pub export fn SymCryptXtsAesEncryptWith128bTweak(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (cbDataUnit < SYMCRYPT_AES_BLOCK_SIZE) {
        return;
    }

    SymCryptXtsAesEncryptInternal(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, types.TRUE);
}

pub export fn SymCryptXtsAesDecryptInternal(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    bOverflow: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_AMD64) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_VAES_256_CODE) and
            macros.SymCryptSaveYmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptXtsAesDecryptInternalYmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
            macros.SymCryptRestoreYmm(&saveData);
        } else if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE)) {
            SymCryptXtsAesDecryptInternalXmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        } else {
            SymCryptXtsAesDecryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else if (comptime types.CPU_X86) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_AESNI_CODE) and
            macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptXtsAesDecryptInternalXmm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
            macros.SymCryptRestoreXmm(&saveData);
        } else {
            SymCryptXtsAesDecryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else if (comptime types.CPU_ARM) {
        SymCryptXtsAesDecryptInternalAsm(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
    } else if (comptime types.CPU_ARM64) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_AES)) {
            SymCryptXtsAesDecryptInternalNeon(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        } else {
            SymCryptXtsAesDecryptInternalC(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
        }
    } else {
        SymCryptXtsAesDecryptInternalC(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, bOverflow);
    }
}

pub export fn SymCryptXtsAesDecrypt(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    tweak: UINT64,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var fullTweak: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_ASSERT(cbData % cbDataUnit == 0);

    if (cbDataUnit < SYMCRYPT_AES_BLOCK_SIZE) {
        return;
    }

    macros.SYMCRYPT_STORE_LSBFIRST64(@ptrCast(&fullTweak[0]), tweak);
    macros.SYMCRYPT_STORE_LSBFIRST64(@ptrCast(&fullTweak[8]), 0);

    SymCryptXtsAesDecryptInternal(pExpandedKey, cbDataUnit, @ptrCast(&fullTweak[0]), pbSrc, pbDst, cbData, types.FALSE);
}

pub export fn SymCryptXtsAesDecryptWith128bTweak(
    pExpandedKey: PCSYMCRYPT_XTS_AES_EXPANDED_KEY,
    cbDataUnit: SIZE_T,
    pbTweak: PCBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (cbDataUnit < SYMCRYPT_AES_BLOCK_SIZE) {
        return;
    }

    SymCryptXtsAesDecryptInternal(pExpandedKey, cbDataUnit, pbTweak, pbSrc, pbDst, cbData, types.TRUE);
}

pub export fn SymCryptXtsUpdateTweak(buf: PBYTE) callconv(SYMCRYPT_CALL) void {
    const b0: UINT64 = macros.SYMCRYPT_LOAD_LSBFIRST64(buf);
    const b1: UINT64 = macros.SYMCRYPT_LOAD_LSBFIRST64(buf + 8);

    const feedback: UINT64 = (0 -% (b1 >> 63)) & 135;

    const r0: UINT64 = (b0 << 1) ^ feedback;
    const r1: UINT64 = (b1 << 1) | (b0 >> 63);

    macros.SYMCRYPT_STORE_LSBFIRST64(buf, r0);
    macros.SYMCRYPT_STORE_LSBFIRST64(buf + 8, r1);
}

pub export fn SymCryptXtsEncryptDataUnit(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbTweakBlock: PBYTE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;

    while (cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
        pBlockCipher.encryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
        macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), pbDst, SYMCRYPT_AES_BLOCK_SIZE);

        macros.SYMCRYPT_ASSERT(pBlockCipher.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptXtsUpdateTweak(pbTweakBlock);

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbData > SYMCRYPT_AES_BLOCK_SIZE) {
        // Ciphertext stealing encryption
        // Encrypt penultimate plaintext block into buf
        macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
        pBlockCipher.encryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
        macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);

        cbData -= SYMCRYPT_AES_BLOCK_SIZE;

        // Copy buf to buf[SYMCRYPT_AES_BLOCK_SIZE]
        @memcpy(buf[SYMCRYPT_AES_BLOCK_SIZE..][0..SYMCRYPT_AES_BLOCK_SIZE], buf[0..SYMCRYPT_AES_BLOCK_SIZE]);
        // Copy final plaintext bytes to prefix of buf - we must read before writing to support in-place encryption
        @memcpy(buf[0..cbData], (pbSrc + SYMCRYPT_AES_BLOCK_SIZE)[0..cbData]);
        // Copy prefix of buf[SYMCRYPT_AES_BLOCK_SIZE] to the right place in the destination buffer
        @memcpy((pbDst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbData], buf[SYMCRYPT_AES_BLOCK_SIZE..][0..cbData]);

        // Do final tweak update
        SymCryptXtsUpdateTweak(pbTweakBlock);

        // Set pbSrc correctly to share code with non-ciphertext stealing case
        pbSrc = @ptrCast(&buf[0]);
    }

    // Final full block encryption
    macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
    pBlockCipher.encryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
    macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), pbDst, SYMCRYPT_AES_BLOCK_SIZE);

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
}

pub export fn SymCryptXtsDecryptDataUnit(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbTweakBlock_in: PBYTE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;
    var tweakBuf: [SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;
    var pbTweakBlock = pbTweakBlock_in;
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;

    while (cbData >= 2 * SYMCRYPT_AES_BLOCK_SIZE) {
        macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
        pBlockCipher.decryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
        macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), pbDst, SYMCRYPT_AES_BLOCK_SIZE);

        macros.SYMCRYPT_ASSERT(pBlockCipher.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptXtsUpdateTweak(pbTweakBlock);

        pbSrc += SYMCRYPT_AES_BLOCK_SIZE;
        pbDst += SYMCRYPT_AES_BLOCK_SIZE;
        cbData -= SYMCRYPT_AES_BLOCK_SIZE;
    }

    if (cbData > SYMCRYPT_AES_BLOCK_SIZE) {
        // Ciphertext stealing decryption
        // Save penultimate value of tweak to tweakBuf
        @memcpy(tweakBuf[0..SYMCRYPT_AES_BLOCK_SIZE], pbTweakBlock[0..SYMCRYPT_AES_BLOCK_SIZE]);

        // Do final tweak update
        SymCryptXtsUpdateTweak(pbTweakBlock);

        // Decrypt penultimate ciphertext block into buf
        macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
        pBlockCipher.decryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
        macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);

        cbData -= SYMCRYPT_AES_BLOCK_SIZE;

        // Copy buf to buf[SYMCRYPT_AES_BLOCK_SIZE]
        @memcpy(buf[SYMCRYPT_AES_BLOCK_SIZE..][0..SYMCRYPT_AES_BLOCK_SIZE], buf[0..SYMCRYPT_AES_BLOCK_SIZE]);
        // Copy final ciphertext bytes to prefix of buf - we must read before writing to support in-place decryption
        @memcpy(buf[0..cbData], (pbSrc + SYMCRYPT_AES_BLOCK_SIZE)[0..cbData]);
        // Copy prefix of buf[SYMCRYPT_AES_BLOCK_SIZE] to the right place in the destination buffer
        @memcpy((pbDst + SYMCRYPT_AES_BLOCK_SIZE)[0..cbData], buf[SYMCRYPT_AES_BLOCK_SIZE..][0..cbData]);

        // Set pbSrc and pbTweakBlock correctly to share code with non-ciphertext stealing case
        pbSrc = @ptrCast(&buf[0]);
        pbTweakBlock = @ptrCast(&tweakBuf[0]);
    }

    // Final full block decryption
    macros.SymCryptXorBytes(pbTweakBlock, pbSrc, @ptrCast(&buf[0]), SYMCRYPT_AES_BLOCK_SIZE);
    pBlockCipher.decryptFunc.?(pExpandedKey, @ptrCast(&buf[0]), @ptrCast(&buf[0]));
    macros.SymCryptXorBytes(pbTweakBlock, @ptrCast(&buf[0]), pbDst, SYMCRYPT_AES_BLOCK_SIZE);

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    macros.SymCryptWipeKnownSize(@ptrCast(&tweakBuf[0]), @sizeOf(@TypeOf(tweakBuf)));
}

pub export fn SymCryptXtsAesEncryptDataUnitAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(aes_default.SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
    SymCryptXtsEncryptDataUnit(
        &aes_default.SymCryptAesBlockCipherNoOpt,
        @ptrCast(pExpandedKey),
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData,
    );
}

pub export fn SymCryptXtsAesDecryptDataUnitAsm(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(aes_default.SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
    SymCryptXtsDecryptDataUnit(
        &aes_default.SymCryptAesBlockCipherNoOpt,
        @ptrCast(pExpandedKey),
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData,
    );
}

pub export fn SymCryptXtsAesEncryptDataUnitC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(aes_default.SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
    SymCryptXtsEncryptDataUnit(
        &aes_default.SymCryptAesBlockCipherNoOpt,
        @ptrCast(pExpandedKey),
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData,
    );
}

pub export fn SymCryptXtsAesDecryptDataUnitC(
    pExpandedKey: PCSYMCRYPT_AES_EXPANDED_KEY,
    pbTweakBlock: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(aes_default.SymCryptAesBlockCipherNoOpt.blockSize == SYMCRYPT_AES_BLOCK_SIZE);
    SymCryptXtsDecryptDataUnit(
        &aes_default.SymCryptAesBlockCipherNoOpt,
        @ptrCast(pExpandedKey),
        pbTweakBlock,
        pbSrc,
        pbDst,
        cbData,
    );
}

const SymCryptXtsAesCiphertext = [32]BYTE{
    0xef, 0xe5, 0x8b, 0x1a, 0x0b, 0xaf, 0xc1, 0x08,
    0xe9, 0xb7, 0x74, 0x1c, 0xcb, 0xdc, 0xf8, 0x53,
    0x4f, 0x90, 0x55, 0x32, 0x53, 0xf6, 0x18, 0xd2,
    0x34, 0xd5, 0xf2, 0x29, 0xf6, 0x4f, 0xd3, 0x8c,
};

pub export fn SymCryptXtsAesSelftest() callconv(SYMCRYPT_CALL) void {
    var key: SYMCRYPT_XTS_AES_EXPANDED_KEY = undefined;
    var buf: [32]BYTE = undefined;
    var plaintext: [32]BYTE = undefined;

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    buf[0] = 1;

    if (SymCryptXtsAesExpandKeyEx(&key, @ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)), 0) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("xtsa"));
    }

    SymCryptXtsAesEncrypt(&key, @sizeOf(@TypeOf(buf)), 0, @ptrCast(&buf[0]), @ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));

    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    if (std.mem.eql(u8, &buf, &SymCryptXtsAesCiphertext) == false) {
        macros.SymCryptFatal(macros.multiCharConstant("xtsa"));
    }

    SymCryptXtsAesDecrypt(&key, @sizeOf(@TypeOf(buf)), 0, @ptrCast(&buf[0]), @ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));

    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));

    macros.SymCryptWipeKnownSize(@ptrCast(&plaintext[0]), @sizeOf(@TypeOf(plaintext)));
    plaintext[0] = 1;
    if (std.mem.eql(u8, &buf, &plaintext) == false) {
        macros.SymCryptFatal(macros.multiCharConstant("xtsa"));
    }
}
