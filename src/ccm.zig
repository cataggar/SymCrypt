//
// ccm.zig
// Counter with CBC-MAC (CCM) implementation (ports lib/ccm.c)
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
const selftest = @import("selftest.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const PCVOID = types.PCVOID;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const PCSYMCRYPT_BLOCKCIPHER = types.PCSYMCRYPT_BLOCKCIPHER;
const SYMCRYPT_CCM_BLOCK_SIZE = types.SYMCRYPT_CCM_BLOCK_SIZE;
const SYMCRYPT_CCM_STATE = types.SYMCRYPT_CCM_STATE;
const PSYMCRYPT_CCM_STATE = types.PSYMCRYPT_CCM_STATE;
const SYMCRYPT_AES_EXPANDED_KEY = types.SYMCRYPT_AES_EXPANDED_KEY;

const CCM_MIN_NONCE_SIZE: SIZE_T = 7;
const CCM_MAX_NONCE_SIZE: SIZE_T = 13;
const CCM_MIN_TAG_SIZE: SIZE_T = 4;
const CCM_MAX_TAG_SIZE: SIZE_T = 16;

const AUTHDATA_16BIT_LIMIT: UINT64 = (1 << 16) - (1 << 8);
const AUTHDATA_32BIT_LIMIT: UINT64 = @as(UINT64, 1) << 32;

const CCM_BLOCK_MOD_MASK: SIZE_T = SYMCRYPT_CCM_BLOCK_SIZE - 1;
const CCM_BLOCK_ROUND_MASK: SIZE_T = ~CCM_BLOCK_MOD_MASK;

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

inline fn blockCipherCbcMac(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) void {
    if (pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesCbcMac(@ptrCast(@alignCast(pExpandedKey)), pbChainingValue, pbData, cbData);
    } else if (pBlockCipher.cbcMacFunc) |f| {
        f(pExpandedKey, pbChainingValue, pbData, cbData);
    } else {
        blockciphermodes.SymCryptCbcMac(pBlockCipher, pExpandedKey, pbChainingValue, pbData, cbData);
    }
}

inline fn blockCipherCtrMsb64(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbChainingValue: PBYTE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) void {
    if (pBlockCipher == &aes_default_bc.SymCryptAesBlockCipher_Fast) {
        aes_default.SymCryptAesCtrMsb64(@ptrCast(@alignCast(pExpandedKey)), pbChainingValue, pbSrc, pbDst, cbData);
    } else if (pBlockCipher.ctrMsb64Func) |f| {
        f(pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    } else {
        blockciphermodes.SymCryptCtrMsb64(pBlockCipher, pExpandedKey, pbChainingValue, pbSrc, pbDst, cbData);
    }
}

pub export fn SymCryptCcmValidateParameters(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    cbNonce: SIZE_T,
    cbAssociatedData: SIZE_T,
    cbData: UINT64,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = cbAssociatedData;

    if (pBlockCipher.blockSize != SYMCRYPT_CCM_BLOCK_SIZE) {
        return .SYMCRYPT_WRONG_BLOCK_SIZE;
    }

    if (cbNonce < CCM_MIN_NONCE_SIZE or cbNonce > CCM_MAX_NONCE_SIZE) {
        return .SYMCRYPT_WRONG_NONCE_SIZE;
    }

    const cbCounter: SIZE_T = SYMCRYPT_CCM_BLOCK_SIZE - cbNonce - 1;

    if (cbCounter < @sizeOf(UINT64) and cbData >= (@as(UINT64, 1) << @intCast(8 * cbCounter))) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (cbTag < CCM_MIN_TAG_SIZE or
        cbTag > CCM_MAX_TAG_SIZE or
        (cbTag & 1) == 1)
    {
        return .SYMCRYPT_WRONG_TAG_SIZE;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptCcmEncryptDecryptPart(
    pState: PSYMCRYPT_CCM_STATE,
    pbSrc_in: PCBYTE,
    pbDst_in: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbSrc = pbSrc_in;
    var pbDst = pbDst_in;
    var cbToDo = cbData;

    while ((pState.bytesProcessed & CCM_BLOCK_MOD_MASK) != 0 and cbToDo > 0) {
        const idx: SIZE_T = @as(SIZE_T, @truncate(pState.bytesProcessed)) & CCM_BLOCK_MOD_MASK;
        pbDst[0] = pbSrc[0] ^ pState.keystreamBlock[idx];
        pbDst += 1;
        pbSrc += 1;
        cbToDo -= 1;
        pState.bytesProcessed += 1;
    }

    if (cbToDo >= SYMCRYPT_CCM_BLOCK_SIZE) {
        const bytesToProcess: SIZE_T = cbToDo & CCM_BLOCK_ROUND_MASK;
        macros.SYMCRYPT_ASSERT(bytesToProcess <= cbToDo);
        macros.SYMCRYPT_ASSERT(pState.pBlockCipher.blockSize == SYMCRYPT_CCM_BLOCK_SIZE);

        blockCipherCtrMsb64(
            pState.pBlockCipher,
            pState.pExpandedKey,
            @ptrCast(&pState.counterBlock[0]),
            pbSrc,
            pbDst,
            bytesToProcess,
        );
        pbSrc += bytesToProcess;
        pbDst += bytesToProcess;
        pState.bytesProcessed += bytesToProcess;
        cbToDo -= bytesToProcess;
    }

    if (cbToDo > 0) {
        macros.SymCryptWipeKnownSize(@ptrCast(&pState.keystreamBlock[0]), SYMCRYPT_CCM_BLOCK_SIZE);
        macros.SYMCRYPT_ASSERT(pState.pBlockCipher.blockSize == SYMCRYPT_CCM_BLOCK_SIZE);

        blockCipherCtrMsb64(
            pState.pBlockCipher,
            pState.pExpandedKey,
            @ptrCast(&pState.counterBlock[0]),
            @ptrCast(&pState.keystreamBlock[0]),
            @ptrCast(&pState.keystreamBlock[0]),
            SYMCRYPT_CCM_BLOCK_SIZE,
        );
        while (cbToDo > 0) {
            const idx: SIZE_T = @as(SIZE_T, @truncate(pState.bytesProcessed)) & CCM_BLOCK_MOD_MASK;
            pbDst[0] = pbSrc[0] ^ pState.keystreamBlock[idx];
            pbDst += 1;
            pbSrc += 1;
            cbToDo -= 1;
            pState.bytesProcessed += 1;
        }
    }
}

pub export fn SymCryptCcmAddMacData(
    pState: PSYMCRYPT_CCM_STATE,
    pbData_in: ?PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var cbData = cbData_in;
    if (cbData == 0) {
        return;
    }
    var pbData = pbData_in.?;

    if (pState.bytesInMacBlock > 0) {
        const bytesToProcess: SIZE_T = @min(cbData, SYMCRYPT_CCM_BLOCK_SIZE - pState.bytesInMacBlock);
        macros.SymCryptXorBytes(
            @ptrCast(&pState.macBlock[pState.bytesInMacBlock]),
            pbData,
            @ptrCast(&pState.macBlock[pState.bytesInMacBlock]),
            bytesToProcess,
        );
        pbData += bytesToProcess;
        cbData -= bytesToProcess;
        pState.bytesInMacBlock += bytesToProcess;

        if (pState.bytesInMacBlock == SYMCRYPT_CCM_BLOCK_SIZE) {
            blockCipherEncrypt(
                pState.pBlockCipher,
                pState.pExpandedKey,
                @ptrCast(&pState.macBlock[0]),
                @ptrCast(&pState.macBlock[0]),
            );
            pState.bytesInMacBlock = 0;
        }
    }

    if (cbData >= SYMCRYPT_CCM_BLOCK_SIZE) {
        const bytesToProcess: SIZE_T = cbData & CCM_BLOCK_ROUND_MASK;
        macros.SYMCRYPT_ASSERT(pState.pBlockCipher.blockSize == SYMCRYPT_CCM_BLOCK_SIZE);

        blockCipherCbcMac(
            pState.pBlockCipher,
            pState.pExpandedKey,
            @ptrCast(&pState.macBlock[0]),
            pbData,
            bytesToProcess,
        );
        pbData += bytesToProcess;
        cbData -= bytesToProcess;
    }

    if (cbData > 0) {
        macros.SymCryptXorBytes(@ptrCast(&pState.macBlock[0]), pbData, @ptrCast(&pState.macBlock[0]), cbData);
        pState.bytesInMacBlock = cbData;
    }
}

pub export fn SymCryptCcmPadMacData(pState: PSYMCRYPT_CCM_STATE) callconv(SYMCRYPT_CALL) void {
    if (pState.bytesInMacBlock > 0) {
        blockCipherEncrypt(
            pState.pBlockCipher,
            pState.pExpandedKey,
            @ptrCast(&pState.macBlock[0]),
            @ptrCast(&pState.macBlock[0]),
        );
        pState.bytesInMacBlock = 0;
    }
}

pub export fn SymCryptCcmEncrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
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
    var state: SYMCRYPT_CCM_STATE = undefined;

    SymCryptCcmInit(
        &state,
        pBlockCipher,
        pExpandedKey,
        pbNonce,
        cbNonce,
        pbAuthData,
        cbAuthData,
        cbData,
        cbTag,
    );

    SymCryptCcmEncryptPart(&state, pbSrc, pbDst, cbData);

    SymCryptCcmEncryptFinal(&state, pbTag, cbTag);
}

pub export fn SymCryptCcmDecrypt(
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
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
    var state: SYMCRYPT_CCM_STATE = undefined;

    SymCryptCcmInit(
        &state,
        pBlockCipher,
        pExpandedKey,
        pbNonce,
        cbNonce,
        pbAuthData,
        cbAuthData,
        cbData,
        cbTag,
    );

    SymCryptCcmDecryptPart(&state, pbSrc, pbDst, cbData);

    const status = SymCryptCcmDecryptFinal(&state, pbTag, cbTag);
    if (status != .SYMCRYPT_NO_ERROR) {
        libmain.SymCryptWipe(pbDst, cbData);
    }

    return status;
}

pub export fn SymCryptCcmInit(
    pState: PSYMCRYPT_CCM_STATE,
    pBlockCipher: PCSYMCRYPT_BLOCKCIPHER,
    pExpandedKey: PCVOID,
    pbNonce: PCBYTE,
    cbNonce_in: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    cbData: UINT64,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var tmpBuf: [SYMCRYPT_CCM_BLOCK_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipeKnownSize(&tmpBuf, @sizeOf(@TypeOf(tmpBuf)));

    macros.SYMCRYPT_SET_MAGIC(pState);

    macros.SYMCRYPT_ASSERT(
        SymCryptCcmValidateParameters(pBlockCipher, cbNonce_in, cbAuthData, cbData, cbTag) == .SYMCRYPT_NO_ERROR,
    );

    const cbNonce: SIZE_T = cbNonce_in & (SYMCRYPT_CCM_BLOCK_SIZE - 1);
    const cbCounter: SIZE_T = SYMCRYPT_CCM_BLOCK_SIZE - 1 - cbNonce;

    pState.pBlockCipher = pBlockCipher;
    pState.pExpandedKey = pExpandedKey;
    pState.cbNonce = cbNonce;
    pState.cbData = cbData;
    pState.cbTag = cbTag;
    pState.cbCounter = cbCounter;
    pState.bytesProcessed = 0;
    pState.bytesInMacBlock = 0;

    var flags: BYTE = @truncate(pState.cbCounter - 1);
    flags |= @as(BYTE, @truncate((cbTag - 2) / 2)) << 3;
    if (cbAuthData > 0) {
        flags |= (1 << 6);
    }

    pState.macBlock[0] = flags;
    @memcpy(pState.macBlock[1..][0..cbNonce], pbNonce[0..cbNonce]);
    macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&tmpBuf[0]), cbData);
    @memcpy(pState.macBlock[1 + cbNonce ..][0..cbCounter], tmpBuf[8 - cbCounter .. 8]);

    macros.SymCryptWipeKnownSize(@ptrCast(&pState.counterBlock[0]), SYMCRYPT_CCM_BLOCK_SIZE);
    pState.counterBlock[0] = flags & 0x7;
    @memcpy(pState.counterBlock[1..][0..cbNonce], pState.macBlock[1..][0..cbNonce]);
    pState.counterBlock[SYMCRYPT_CCM_BLOCK_SIZE - 1] = 1;

    blockCipherEncrypt(pBlockCipher, pExpandedKey, @ptrCast(&pState.macBlock[0]), @ptrCast(&pState.macBlock[0]));

    if (cbAuthData == 0) {
        // nothing needs to be done
    } else if (cbAuthData < AUTHDATA_16BIT_LIMIT) {
        macros.SYMCRYPT_STORE_MSBFIRST16(@ptrCast(&tmpBuf[0]), @truncate(cbAuthData));
        SymCryptCcmAddMacData(pState, @ptrCast(&tmpBuf[0]), 2);
    } else if (@as(UINT64, cbAuthData) < AUTHDATA_32BIT_LIMIT) {
        tmpBuf[0] = 0xff;
        tmpBuf[1] = 0xfe;
        macros.SYMCRYPT_STORE_MSBFIRST32(@ptrCast(&tmpBuf[2]), @truncate(cbAuthData));
        SymCryptCcmAddMacData(pState, @ptrCast(&tmpBuf[0]), 6);
    } else {
        tmpBuf[0] = 0xff;
        tmpBuf[1] = 0xff;
        macros.SYMCRYPT_STORE_MSBFIRST64(@ptrCast(&tmpBuf[2]), cbAuthData);
        SymCryptCcmAddMacData(pState, @ptrCast(&tmpBuf[0]), 10);
    }

    SymCryptCcmAddMacData(pState, pbAuthData, cbAuthData);
    SymCryptCcmPadMacData(pState);
}

pub export fn SymCryptCcmEncryptPart(
    pState: PSYMCRYPT_CCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pState);

    const bytesProcessedAfterThisCall: UINT64 = cbData +% pState.bytesProcessed;
    macros.SYMCRYPT_ASSERT(bytesProcessedAfterThisCall >= cbData and bytesProcessedAfterThisCall <= pState.cbData);

    SymCryptCcmAddMacData(pState, pbSrc, cbData);
    SymCryptCcmEncryptDecryptPart(pState, pbSrc, pbDst, cbData);
}

pub export fn SymCryptCcmEncryptFinal(
    pState: PSYMCRYPT_CCM_STATE,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pState);
    macros.SYMCRYPT_ASSERT(cbTag == pState.cbTag and pState.bytesProcessed == pState.cbData);

    SymCryptCcmPadMacData(pState);

    libmain.SymCryptWipe(@ptrCast(&pState.counterBlock[1 + pState.cbNonce]), pState.cbCounter);
    pState.bytesProcessed = 0;

    SymCryptCcmEncryptDecryptPart(
        pState,
        @ptrCast(&pState.macBlock[0]),
        @ptrCast(&pState.macBlock[0]),
        SYMCRYPT_CCM_BLOCK_SIZE,
    );

    @memcpy(pbTag[0..cbTag], pState.macBlock[0..cbTag]);

    macros.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_CCM_STATE));
    macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock == 0);
}

pub export fn SymCryptCcmDecryptPart(
    pState: PSYMCRYPT_CCM_STATE,
    pbSrc: PCBYTE,
    pbDst: PBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pState);

    const bytesProcessedAfterThisCall: UINT64 = cbData +% pState.bytesProcessed;
    macros.SYMCRYPT_ASSERT(bytesProcessedAfterThisCall >= cbData and bytesProcessedAfterThisCall <= pState.cbData);

    SymCryptCcmEncryptDecryptPart(pState, pbSrc, pbDst, cbData);
    SymCryptCcmAddMacData(pState, pbDst, cbData);
}

pub export fn SymCryptCcmDecryptFinal(
    pState: PSYMCRYPT_CCM_STATE,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var status: SYMCRYPT_ERROR = undefined;

    macros.SYMCRYPT_CHECK_MAGIC(pState);
    macros.SYMCRYPT_ASSERT(cbTag == pState.cbTag and pState.bytesProcessed == pState.cbData);

    SymCryptCcmPadMacData(pState);

    libmain.SymCryptWipe(@ptrCast(&pState.counterBlock[1 + pState.cbNonce]), pState.cbCounter);
    pState.bytesProcessed = 0;

    SymCryptCcmEncryptDecryptPart(
        pState,
        @ptrCast(&pState.macBlock[0]),
        @ptrCast(&pState.macBlock[0]),
        SYMCRYPT_CCM_BLOCK_SIZE,
    );

    if (equal.SymCryptEqual(pbTag, @ptrCast(&pState.macBlock[0]), cbTag) == 0) {
        status = .SYMCRYPT_AUTHENTICATION_FAILURE;
    } else {
        status = .SYMCRYPT_NO_ERROR;
    }

    macros.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_CCM_STATE));
    macros.SYMCRYPT_ASSERT(pState.bytesInMacBlock == 0);

    return status;
}

const SymCryptCcmSelftestResult = [3 + SYMCRYPT_CCM_BLOCK_SIZE]BYTE{
    0x42, 0xd7, 0xda,
    0x3d, 0x9e, 0x95,
    0x82, 0x29, 0x3c,
    0x10, 0x9c, 0xa3,
    0x39, 0x31, 0x3f,
    0x18, 0xf3, 0x10,
    0xf6,
};

pub export fn SymCryptCcmSelftest() callconv(SYMCRYPT_CALL) void {
    var buf: [3 + SYMCRYPT_CCM_BLOCK_SIZE]BYTE = undefined;
    var key: SYMCRYPT_AES_EXPANDED_KEY = undefined;
    var err: SYMCRYPT_ERROR = undefined;

    if (aes_key.SymCryptAesExpandKey(&key, @ptrCast(&selftest.SymCryptTestKey32[0]), 16) != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("ccm0"));
    }

    SymCryptCcmEncrypt(
        &aes_default_bc.SymCryptAesBlockCipher_Fast,
        @ptrCast(&key),
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        12,
        null,
        0,
        @ptrCast(&selftest.SymCryptTestMsg3[0]),
        @ptrCast(&buf[0]),
        3,
        @ptrCast(&buf[3]),
        SYMCRYPT_CCM_BLOCK_SIZE,
    );

    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));
    if (!std.mem.eql(u8, &buf, &SymCryptCcmSelftestResult)) {
        macros.SymCryptFatal(macros.multiCharConstant("ccm1"));
    }

    // inject error into the ciphertext or tag
    macros.SymCryptInjectError(@ptrCast(&buf[0]), @sizeOf(@TypeOf(buf)));

    err = SymCryptCcmDecrypt(
        &aes_default_bc.SymCryptAesBlockCipher_Fast,
        @ptrCast(&key),
        @ptrCast(&selftest.SymCryptTestKey32[16]),
        12,
        null,
        0,
        @ptrCast(&buf[0]),
        @ptrCast(&buf[0]),
        3,
        @ptrCast(&buf[3]),
        SYMCRYPT_CCM_BLOCK_SIZE,
    );

    macros.SymCryptInjectError(@ptrCast(&buf[0]), 3);
    if (err != .SYMCRYPT_NO_ERROR or !std.mem.eql(u8, buf[0..3], &selftest.SymCryptTestMsg3)) {
        macros.SymCryptFatal(macros.multiCharConstant("ccm2"));
    }
}
