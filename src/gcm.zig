//
// gcm.zig
// Galois/Counter Mode (GCM) implementation (ports lib/gcm.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const equal = @import("equal.zig");
const blockciphermodes = @import("blockciphermodes.zig");
const aes_key = @import("aes_key.zig");
const aes_default = @import("aes_default.zig");
const aes_default_bc = @import("aes_default_bc.zig");
const ghash = @import("ghash.zig");
const selftest = @import("selftest.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const PVOID = types.PVOID;
const PCVOID = types.PCVOID;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const SYMCRYPT_GCM_BLOCK_SIZE = types.SYMCRYPT_GCM_BLOCK_SIZE;
const SYMCRYPT_GCM_MAX_KEY_SIZE = types.SYMCRYPT_GCM_MAX_KEY_SIZE;
const SYMCRYPT_GCM_MAX_DATA_SIZE = types.SYMCRYPT_GCM_MAX_DATA_SIZE;
const SYMCRYPT_GCM_BLOCK_MOD_MASK = types.SYMCRYPT_GCM_BLOCK_MOD_MASK;
const SYMCRYPT_GCM_BLOCK_ROUND_MASK = types.SYMCRYPT_GCM_BLOCK_ROUND_MASK;
const SYMCRYPT_GF128_BLOCK_SIZE = types.SYMCRYPT_GF128_BLOCK_SIZE;
const SYMCRYPT_GF128_ELEMENT = types.SYMCRYPT_GF128_ELEMENT;
const SYMCRYPT_GCM_EXPANDED_KEY = types.SYMCRYPT_GCM_EXPANDED_KEY;
const PSYMCRYPT_GCM_EXPANDED_KEY = types.PSYMCRYPT_GCM_EXPANDED_KEY;
const PCSYMCRYPT_GCM_EXPANDED_KEY = types.PCSYMCRYPT_GCM_EXPANDED_KEY;
const SYMCRYPT_GCM_STATE = types.SYMCRYPT_GCM_STATE;
const PSYMCRYPT_GCM_STATE = types.PSYMCRYPT_GCM_STATE;
const PCSYMCRYPT_GCM_STATE = types.PCSYMCRYPT_GCM_STATE;

const SYMCRYPT_GCM_MIN_TAG_SIZE: SIZE_T = 12;
const SYMCRYPT_GCM_MAX_TAG_SIZE: SIZE_T = 16;

inline fn blockCipherExpandKey(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PVOID,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) SYMCRYPT_ERROR {
    if (pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        return aes_key.SymCryptAesExpandKey(@ptrCast(@alignCast(pExpandedKey)), pbKey, cbKey);
    } else {
        return pBlockCipher.expandKeyFunc.?(pExpandedKey, pbKey, cbKey);
    }
}

inline fn blockCipherEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
) void {
    if (pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesEncrypt(@ptrCast(@alignCast(pExpandedKey)), pbSrc, pbDst);
    } else {
        pBlockCipher.encryptFunc.?(pExpandedKey, pbSrc, pbDst);
    }
}

inline fn blockCipherCtrMsb32(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) void {
    if (pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesCtrMsb32(@ptrCast(@alignCast(pExpandedKey)), pbChainingValue, pbSrc, pbDst, cbData);
    } else {
        blockciphermodes.SymCryptCtrMsb32(pBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptGcmValidateParameters(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    cbNonce: SIZE_T,
    cbAssociatedData: UINT64,
    cbData: UINT64,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (pBlockCipher.blockSize != SYMCRYPT_GCM_BLOCK_SIZE) {
        return .SYMCRYPT_WRONG_BLOCK_SIZE;
    }

    if (cbNonce < 1) {
        return .SYMCRYPT_WRONG_NONCE_SIZE;
    }

    if ((cbAssociatedData >> 61) > 0) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (cbData > SYMCRYPT_GCM_MAX_DATA_SIZE) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (cbTag < SYMCRYPT_GCM_MIN_TAG_SIZE or cbTag > SYMCRYPT_GCM_MAX_TAG_SIZE) {
        return .SYMCRYPT_WRONG_TAG_SIZE;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptGcmAddMacData(
    pState: PSYMCRYPT_GCM_STATE,
    pbData_in: ?PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var cbData = cbData_in;
    if (cbData == 0) {
        return;
    }
    var pbData = pbData_in.?;

    if (pState.bytesInMacBlock > 0) {
        const nBytes: SIZE_T = @min(cbData, SYMCRYPT_GCM_BLOCK_SIZE - pState.bytesInMacBlock);
        @memcpy(pState.macBlock[pState.bytesInMacBlock..][0..nBytes], pbData[0..nBytes]);
        pbData += nBytes;
        cbData -= nBytes;
        pState.bytesInMacBlock += nBytes;
        if (pState.bytesInMacBlock == SYMCRYPT_GCM_BLOCK_SIZE) {
            ghash.SymCryptGHashAppendData(
                &pState.pKey.ghashKey,
                &pState.ghashState,
                @ptrCast(&pState.macBlock[0]),
                SYMCRYPT_GCM_BLOCK_SIZE,
            );
            pState.bytesInMacBlock = 0;
        }
    }

    if (cbData >= SYMCRYPT_GCM_BLOCK_SIZE) {
        const bytesToDo: SIZE_T = cbData & SYMCRYPT_GCM_BLOCK_ROUND_MASK;
        ghash.SymCryptGHashAppendData(&pState.pKey.ghashKey, &pState.ghashState, pbData, bytesToDo);
        pbData += bytesToDo;
        cbData -= bytesToDo;
    }

    if (cbData > 0) {
        @memcpy(pState.macBlock[0..cbData], pbData[0..cbData]);
        pState.bytesInMacBlock = cbData;
    }
}

pub export fn SymCryptGcmPadMacData(pState: PSYMCRYPT_GCM_STATE) callconv(SYMCRYPT_CALL) void {
    if (pState.bytesInMacBlock > 0) {
        libmain.SymCryptWipe(
            @ptrCast(&pState.macBlock[pState.bytesInMacBlock]),
            SYMCRYPT_GCM_BLOCK_SIZE - pState.bytesInMacBlock,
        );
        ghash.SymCryptGHashAppendData(
            &pState.pKey.ghashKey,
            &pState.ghashState,
            @ptrCast(&pState.macBlock[0]),
            SYMCRYPT_GCM_BLOCK_SIZE,
        );
        pState.bytesInMacBlock = 0;
    }
}

pub export fn SymCryptGcmEncryptDecryptPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbData = cbData_in;

    const usedKeystreamBytes: SIZE_T = @as(SIZE_T, @truncate(pState.cbData)) & SYMCRYPT_GCM_BLOCK_MOD_MASK;
    pState.cbData += cbData;
    if (pState.cbData > SYMCRYPT_GCM_MAX_DATA_SIZE) {
        macros.SymCryptFatal(macros.multiCharConstant("gcmd"));
    }

    if (usedKeystreamBytes > 0) {
        const nBytes: SIZE_T = @min(cbData, SYMCRYPT_GCM_BLOCK_SIZE - usedKeystreamBytes);
        macros.SymCryptXorBytes(pbSrc, @ptrCast(&pState.keystreamBlock[usedKeystreamBytes]), pbDst, nBytes);
        pbSrc += nBytes;
        pbDst += nBytes;
        cbData -= nBytes;
    }

    if (cbData >= SYMCRYPT_GCM_BLOCK_SIZE) {
        const bytesToDo: SIZE_T = cbData & SYMCRYPT_GCM_BLOCK_ROUND_MASK;
        blockCipherCtrMsb32(
            pState.pKey.pBlockCipher,
            @ptrCast(&pState.pKey.blockcipherKey),
            @ptrCast(&pState.counterBlock[0]),
            pbSrc,
            pbDst,
            bytesToDo,
        );
        pbSrc += bytesToDo;
        pbDst += bytesToDo;
        cbData -= bytesToDo;
    }

    if (cbData > 0) {
        macros.SymCryptWipeKnownSize(@ptrCast(&pState.keystreamBlock[0]), SYMCRYPT_GCM_BLOCK_SIZE);
        blockCipherCtrMsb32(
            pState.pKey.pBlockCipher,
            @ptrCast(&pState.pKey.blockcipherKey),
            @ptrCast(&pState.counterBlock[0]),
            @ptrCast(&pState.keystreamBlock[0]),
            @ptrCast(&pState.keystreamBlock[0]),
            SYMCRYPT_GCM_BLOCK_SIZE,
        );
        macros.SymCryptXorBytes(pbSrc, @ptrCast(&pState.keystreamBlock[0]), pbDst, cbData);
    }
}

inline fn SymCryptGcmResetCounterBlock(pState: PSYMCRYPT_GCM_STATE) void {
    const blocksProcessed: UINT32 = @truncate((pState.cbData + SYMCRYPT_GCM_BLOCK_SIZE - 1) / SYMCRYPT_GCM_BLOCK_SIZE);
    const preCounter32: UINT32 = macros.SYMCRYPT_LOAD_MSBFIRST32(@ptrCast(&pState.counterBlock[12])) -% blocksProcessed -% 1;
    macros.SYMCRYPT_STORE_MSBFIRST32(@ptrCast(&pState.counterBlock[12]), preCounter32);
}

pub export fn SymCryptGcmComputeTag(
    pState: PSYMCRYPT_GCM_STATE,
    pbTag: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var buf: [2 * SYMCRYPT_GCM_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&buf[16]), pState.cbAuthData * 8);
    macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&buf[24]), pState.cbData * 8);

    if (pState.bytesInMacBlock > 0) {
        macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), SYMCRYPT_GCM_BLOCK_SIZE);
        @memcpy(buf[0..pState.bytesInMacBlock], pState.macBlock[0..pState.bytesInMacBlock]);

        ghash.SymCryptGHashAppendData(
            &pState.pKey.ghashKey,
            &pState.ghashState,
            @ptrCast(&buf[0]),
            2 * SYMCRYPT_GCM_BLOCK_SIZE,
        );
    } else {
        ghash.SymCryptGHashAppendData(
            &pState.pKey.ghashKey,
            &pState.ghashState,
            @ptrCast(&buf[16]),
            SYMCRYPT_GCM_BLOCK_SIZE,
        );
    }

    SymCryptGcmResetCounterBlock(pState);

    macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&buf[0]), pState.ghashState.ull[1]);
    macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&buf[8]), pState.ghashState.ull[0]);

    macros.SYMCRYPT_ASSERT(pState.pKey.pBlockCipher.blockSize == SYMCRYPT_GCM_BLOCK_SIZE);
    blockCipherCtrMsb32(
        pState.pKey.pBlockCipher,
        @ptrCast(&pState.pKey.blockcipherKey),
        @ptrCast(&pState.counterBlock[0]),
        @ptrCast(&buf[0]),
        pbTag,
        SYMCRYPT_GCM_BLOCK_SIZE,
    );

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
}

pub export fn SymCryptGcmExpandKey(
    expandedKey: PSYMCRYPT_GCM_EXPANDED_KEY,
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pbKey: PCBYTE,
    cbKey: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var H: [SYMCRYPT_GCM_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var status: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (cbKey > SYMCRYPT_GCM_MAX_KEY_SIZE) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    // Perform the BlockCipher key expansion first so that works if the output makes things overlap
    expandedKey.pBlockCipher = pBlockCipher;
    status = blockCipherExpandKey(pBlockCipher, @ptrCast(&expandedKey.blockcipherKey), pbKey, cbKey);

    if (status == .SYMCRYPT_NO_ERROR) {
        expandedKey.cbKey = cbKey;
        @memcpy(expandedKey.abKey[0..cbKey], pbKey[0..cbKey]);

        macros.SymCryptWipeKnownSize(@ptrCast(&H[0]), @sizeOf(@TypeOf(H)));
        blockCipherEncrypt(pBlockCipher, @ptrCast(&expandedKey.blockcipherKey), @ptrCast(&H[0]), @ptrCast(&H[0]));

        ghash.SymCryptGHashExpandKey(&expandedKey.ghashKey, @ptrCast(&H[0]));

        macros.SymCryptWipeKnownSize(@ptrCast(&H[0]), @sizeOf(@TypeOf(H)));

        macros.SYMCRYPT_SET_MAGIC(expandedKey);
    }

    return status;
}

pub export fn SymCryptGcmKeyCopy(
    pSrc: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pDst: PSYMCRYPT_GCM_EXPANDED_KEY,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pSrc);

    const status = SymCryptGcmExpandKey(pDst, pSrc.pBlockCipher, @ptrCast(&pSrc.abKey[0]), pSrc.cbKey);
    macros.SYMCRYPT_ASSERT(status == .SYMCRYPT_NO_ERROR);
}

pub export fn SymCryptGcmSetNonce(
    pState: PSYMCRYPT_GCM_STATE,
    pbNonce_in: PCBYTE,
    cbNonce_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    const pKey = pState.pKey;

    if (cbNonce_in == 12) {
        @memcpy(pState.counterBlock[0..12], pbNonce_in[0..12]);
        macros.SYMCRYPT_STORE_MSBFIRST32(@ptrCast(&pState.counterBlock[12]), 1);
    } else {
        var pbNonce = pbNonce_in;
        var cbNonce = cbNonce_in;
        var ghashState: SYMCRYPT_GF128_ELEMENT = std.mem.zeroes(SYMCRYPT_GF128_ELEMENT);

        const nBytes: SIZE_T = cbNonce & SYMCRYPT_GCM_BLOCK_ROUND_MASK;
        ghash.SymCryptGHashAppendData(&pKey.ghashKey, &ghashState, pbNonce, nBytes);

        // We use pState->counterBlock as an aligned temporary buffer of size SYMCRYPT_GCM_BLOCK_SIZE.
        pbNonce += nBytes;
        cbNonce -= nBytes;
        if (cbNonce > 0) {
            @memcpy(pState.counterBlock[0..cbNonce], pbNonce[0..cbNonce]);
            libmain.SymCryptWipe(@ptrCast(&pState.counterBlock[cbNonce]), SYMCRYPT_GCM_BLOCK_SIZE - cbNonce);
            ghash.SymCryptGHashAppendData(
                &pKey.ghashKey,
                &ghashState,
                @ptrCast(&pState.counterBlock[0]),
                SYMCRYPT_GCM_BLOCK_SIZE,
            );
        }
        macros.SymCryptWipeKnownSize(@ptrCast(&pState.counterBlock[0]), 8);
        macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&pState.counterBlock[8]), @as(UINT64, cbNonce_in) * 8);
        ghash.SymCryptGHashAppendData(
            &pKey.ghashKey,
            &ghashState,
            @ptrCast(&pState.counterBlock[0]),
            SYMCRYPT_GCM_BLOCK_SIZE,
        );

        ghash.SymCryptGHashResult(&ghashState, @ptrCast(&pState.counterBlock[0]));

        macros.SymCryptWipeKnownSize(@ptrCast(&ghashState), @sizeOf(@TypeOf(ghashState)));
    }

    // Increment the counter block integer by 1
    macros.SYMCRYPT_STORE_MSBFIRST32(
        @ptrCast(&pState.counterBlock[12]),
        macros.SYMCRYPT_LOAD_MSBFIRST32(@ptrCast(&pState.counterBlock[12])) +% 1,
    );
}

pub export fn SymCryptGcmInit(
    pState: PSYMCRYPT_GCM_STATE,
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pExpandedKey);

    pState.pKey = pExpandedKey;
    pState.cbData = 0;
    pState.cbAuthData = 0;
    pState.bytesInMacBlock = 0;

    pState.ghashState = std.mem.zeroes(SYMCRYPT_GF128_ELEMENT);

    SymCryptGcmSetNonce(pState, pbNonce, cbNonce);

    macros.SYMCRYPT_SET_MAGIC(pState);
}

pub export fn SymCryptGcmStateCopy(
    pSrc: PCSYMCRYPT_GCM_STATE,
    pExpandedKeyCopy: ?PCSYMCRYPT_GCM_EXPANDED_KEY,
    pDst: PSYMCRYPT_GCM_STATE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pSrc);

    pDst.* = pSrc.*;
    if (pExpandedKeyCopy) |keyCopy| {
        pDst.pKey = keyCopy;
    }

    macros.SYMCRYPT_SET_MAGIC(pDst);
}

pub export fn SymCryptGcmAuthPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pState);
    macros.SYMCRYPT_ASSERT(pState.cbData == 0);

    SymCryptGcmAddMacData(pState, pbAuthData, cbAuthData);
    pState.cbAuthData += cbAuthData;
}

pub export fn SymCryptGcmEncryptPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (pState.cbData == 0) {
        SymCryptGcmPadMacData(pState);
    }

    if (pState.pKey.pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesGcmEncryptPart(pState, pbSrc, pbDst, cbData);
        macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock <= 15);
    } else if (pState.pKey.pBlockCipher.gcmEncryptPartFunc) |f| {
        f(@ptrCast(pState), pbSrc, pbDst, cbData);
        macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock <= 15);
    } else {
        SymCryptGcmEncryptPartTwoPass(pState, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptGcmEncryptPartTwoPass(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    // Do the actual encryption, note that this updates pState->cbData for us
    SymCryptGcmEncryptDecryptPart(pState, pbSrc, pbDst, cbData);

    // Note that it is okay to pass pbDst because we are done reading from pbSrc
    // if pbSrc == pbDst.
    SymCryptGcmAddMacData(pState, pbDst, cbData);
}

pub export fn SymCryptGcmDecryptPart(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (pState.cbData == 0) {
        SymCryptGcmPadMacData(pState);
    }

    if (pState.pKey.pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesGcmDecryptPart(pState, pbSrc, pbDst, cbData);
        macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock <= 15);
    } else if (pState.pKey.pBlockCipher.gcmDecryptPartFunc) |f| {
        f(@ptrCast(pState), pbSrc, pbDst, cbData);
        macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock <= 15);
    } else {
        SymCryptGcmDecryptPartTwoPass(pState, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptGcmDecryptPartTwoPass(
    pState: PSYMCRYPT_GCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    SymCryptGcmAddMacData(pState, pbSrc, cbData);

    // Do the actual decryption, note that this updates pState->cbData for us
    // We do the decryption after the GHash capability in case pbSrc == pbDst
    SymCryptGcmEncryptDecryptPart(pState, pbSrc, pbDst, cbData);
}

pub export fn SymCryptGcmEncryptFinal(
    pState: PSYMCRYPT_GCM_STATE,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var buf: [SYMCRYPT_GCM_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_ASSERT(cbTag >= SYMCRYPT_GCM_MIN_TAG_SIZE and cbTag <= SYMCRYPT_GCM_MAX_TAG_SIZE);

    SymCryptGcmComputeTag(pState, @ptrCast(&buf[0]));
    @memcpy(pbTag[0..cbTag], buf[0..cbTag]);

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    macros.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_GCM_STATE));
    macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock == 0);
}

pub export fn SymCryptGcmDecryptFinal(
    pState: PSYMCRYPT_GCM_STATE,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var buf: [SYMCRYPT_GCM_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var status: SYMCRYPT_ERROR = undefined;

    macros.SYMCRYPT_ASSERT(cbTag >= SYMCRYPT_GCM_MIN_TAG_SIZE and cbTag <= SYMCRYPT_GCM_MAX_TAG_SIZE);

    SymCryptGcmComputeTag(pState, @ptrCast(&buf[0]));

    if (equal.SymCryptEqual(pbTag, @ptrCast(&buf[0]), cbTag) == 0) {
        status = .SYMCRYPT_AUTHENTICATION_FAILURE;
    } else {
        status = .SYMCRYPT_NO_ERROR;
    }

    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    macros.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_GCM_STATE));
    macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock == 0);

    return status;
}

pub export fn SymCryptGcmEncrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_GCM_STATE = undefined;

    SymCryptGcmInit(&state, pExpandedKey, pbNonce, cbNonce);
    SymCryptGcmAuthPart(&state, pbAuthData, cbAuthData);
    SymCryptGcmEncryptPart(&state, pbSrc, pbDst, cbData);
    SymCryptGcmEncryptFinal(&state, pbTag, cbTag);
}

pub export fn SymCryptGcmDecrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
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
    var state: SYMCRYPT_GCM_STATE = undefined;

    SymCryptGcmInit(&state, pExpandedKey, pbNonce, cbNonce);
    SymCryptGcmAuthPart(&state, pbAuthData, cbAuthData);
    SymCryptGcmDecryptPart(&state, pbSrc, pbDst, cbData);
    const status = SymCryptGcmDecryptFinal(&state, pbTag, cbTag);
    if (status != .SYMCRYPT_NO_ERROR) {
        libmain.SymCryptWipe(pbDst, cbData);
    }
    return status;
}

const SymCryptGcmSelftestResult = [3 + SYMCRYPT_GCM_BLOCK_SIZE]BYTE{
    0xa5, 0x4c, 0x60,
    0x80, 0xb0, 0x48,
    0x6d, 0x03, 0x9f,
    0xea, 0xc3, 0x3c,
    0x28, 0x96, 0x3f,
    0x99, 0x8a, 0x77,
    0x43,
};

pub export fn SymCryptGcmSelftest() callconv(SYMCRYPT_CALL) void {
    var buf: [3 + SYMCRYPT_GCM_BLOCK_SIZE]BYTE = undefined;
    var key: SYMCRYPT_GCM_EXPANDED_KEY = undefined;
    var err: SYMCRYPT_ERROR = undefined;

    if (SymCryptGcmExpandKey(
        &key,
        &aes_default_bc.SymCryptAesBlockCipher_Fast,
        @ptrCast(&selftest.SymCryptTestKey32[0]),
        16,
    ) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("gcm0"));
    }

    SymCryptGcmEncrypt(
        &key,
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        12,
        null,
        0,
        @ptrCast(&selftest.SymCryptTestMsg3[0]),
        @ptrCast(&buf[0]),
        3,
        @ptrCast(&buf[3]),
        SYMCRYPT_GCM_BLOCK_SIZE,
    );

    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    if (!std.mem.eql(u8, &buf, &SymCryptGcmSelftestResult)) {
        macros.SymCryptFatal(macros.multiCharConstant("gcm1"));
    }

    // inject error into the ciphertext or tag
    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));

    err = SymCryptGcmDecrypt(
        &key,
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        12,
        null,
        0,
        @ptrCast(&buf[0]),
        @ptrCast(&buf[0]),
        3,
        @ptrCast(&buf[3]),
        SYMCRYPT_GCM_BLOCK_SIZE,
    );

    macros.SymCryptInjectError(@ptrCast(&buf[0]), 3);
    if (err != .SYMCRYPT_NO_ERROR or !std.mem.eql(u8, buf[0..3], &selftest.SymCryptTestMsg3)) {
        macros.SymCryptFatal(macros.multiCharConstant("gcm2"));
    }

    macros.SymCryptWipeKnownSize(@ptrCast(&key), @sizeOf(@TypeOf(key)));
    macros.SymCryptWipeKnownSize(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
}
