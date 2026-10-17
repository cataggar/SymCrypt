//
// aes_ctr_drbg.zig   code for SP 800-90 AES-CTR-DRBG implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const aes_key = @import("aes_key.zig");
const aes_default = @import("aes_default.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_AES_EXPANDED_KEY = types.SYMCRYPT_AES_EXPANDED_KEY;
const PSYMCRYPT_AES_EXPANDED_KEY = types.PSYMCRYPT_AES_EXPANDED_KEY;
const SYMCRYPT_RNG_AES_STATE = types.SYMCRYPT_RNG_AES_STATE;
const PSYMCRYPT_RNG_AES_STATE = types.PSYMCRYPT_RNG_AES_STATE;
const PSYMCRYPT_RNG_AES_FIPS140_2_STATE = types.PSYMCRYPT_RNG_AES_FIPS140_2_STATE;

const SYMCRYPT_AES_BLOCK_SIZE = types.SYMCRYPT_AES_BLOCK_SIZE;
const SYMCRYPT_RNG_AES_MIN_INSTANTIATE_SIZE = types.SYMCRYPT_RNG_AES_MIN_INSTANTIATE_SIZE;
const SYMCRYPT_RNG_AES_MIN_RESEED_SIZE = types.SYMCRYPT_RNG_AES_MIN_RESEED_SIZE;
const SYMCRYPT_RNG_AES_MAX_SEED_SIZE = types.SYMCRYPT_RNG_AES_MAX_SEED_SIZE;
const SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE = types.SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE;

const SYMCRYPT_RNG_AES_KEY_SIZE: usize = 32;
const SYMCRYPT_RNG_AES_KEY_AND_V_SIZE: usize = 32 + 16;
const SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE: usize = 1 << 16;
const SYMCRYPT_RNG_AES_MAX_REQUESTS_PER_RESEED: UINT64 = @as(UINT64, 1) << 48;

pub export fn SymCryptRngAesBcc(
    pKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pcbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    //
    // Length of input should always be multiple of the AES block size
    //
    macros.SYMCRYPT_ASSERT(cbData % SYMCRYPT_AES_BLOCK_SIZE == 0);

    macros.SymCryptWipe(pbResult, SYMCRYPT_AES_BLOCK_SIZE);

    aes_default.SymCryptAesCbcMac(pKey, pbResult, pcbData, cbData);
}

pub export fn SymCryptRngAesDf(
    pcbData: PCBYTE,
    cbData: SIZE_T,
    pbSeed: PBYTE,
) callconv(types.SYMCRYPT_CALL) void {
    // maximal input length + IV + padding
    var buf: [SYMCRYPT_RNG_AES_MAX_SEED_SIZE + 3 * SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var temp: [SYMCRYPT_RNG_AES_KEY_AND_V_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var aesKey: SYMCRYPT_AES_EXPANDED_KEY = undefined;

    comptime {
        std.debug.assert(@sizeOf(@TypeOf(temp)) % SYMCRYPT_AES_BLOCK_SIZE == 0);
    }

    //
    // See SP800-90 section 10.4.2
    //
    // Our buf contains the following data:
    // - 16 bytes IV
    // - 4 bytes L
    // - 4 bytes N
    // - up to SEEDLEN bytes input data
    // - 1 byte 0x80
    // - zeroes to fill to a multiple of 16
    //

    macros.SYMCRYPT_ASSERT(cbData >= SYMCRYPT_RNG_AES_MIN_RESEED_SIZE and
        cbData <= SYMCRYPT_RNG_AES_MAX_SEED_SIZE);

    //
    // Initialize the entire buf to zero
    //
    macros.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));

    //
    // build the string S in buf[16...]
    //
    var offset: SIZE_T = SYMCRYPT_AES_BLOCK_SIZE;

    //
    // Set L; SP800-90 isn't clear, but we'll use MSB first as that is what is used elsewhere.
    //
    macros.SYMCRYPT_STORE_MSBFIRST32(buf[offset..].ptr, @intCast(cbData));
    offset += 4;

    //
    // Set N
    //
    macros.SYMCRYPT_STORE_MSBFIRST32(buf[offset..].ptr, SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE);
    offset += 4;

    //
    // Set input_string
    //
    @memcpy(buf[offset .. offset + cbData], pcbData[0..cbData]);
    offset += cbData;

    //
    // set padding
    //
    buf[offset] = 0x80;
    offset += 1;

    while (offset % SYMCRYPT_AES_BLOCK_SIZE != 0) {
        buf[offset] = 0;
        offset += 1;
    }

    const lenIvS: SIZE_T = offset; // Length of IV & S together

    //
    // Set up the initial key
    //
    var i: SIZE_T = 0;
    while (i < SYMCRYPT_RNG_AES_KEY_SIZE) : (i += 1) {
        temp[i] = @intCast(i);
    }
    _ = aes_key.SymCryptAesExpandKeyEncryptOnly(&aesKey, &temp, SYMCRYPT_RNG_AES_KEY_SIZE);

    //
    // Produce the 'temp' intermediate result.
    //
    i = 0;
    while (i < SYMCRYPT_RNG_AES_KEY_AND_V_SIZE / SYMCRYPT_AES_BLOCK_SIZE) : (i += 1) {
        //
        // Update the IV with the right i value.
        // i is only 0-2, so we only have to set a single byte
        //
        buf[3] = @intCast(i);

        //
        // Now we perform the BCC function, which is just CbcMac
        // BCC(K,(IV||S))
        SymCryptRngAesBcc(&aesKey, &buf, lenIvS, temp[i * SYMCRYPT_AES_BLOCK_SIZE ..].ptr);
    }

    //
    // Second phase, produce the actual output
    //
    _ = aes_key.SymCryptAesExpandKeyEncryptOnly(&aesKey, &temp, SYMCRYPT_RNG_AES_KEY_SIZE);
    const pX: PBYTE = temp[SYMCRYPT_RNG_AES_KEY_SIZE..].ptr;

    i = 0;
    while (i < SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE) : (i += SYMCRYPT_AES_BLOCK_SIZE) {
        aes_default.SymCryptAesEncrypt(&aesKey, pX, pX);
        @memcpy(pbSeed[i .. i + SYMCRYPT_AES_BLOCK_SIZE], pX[0..SYMCRYPT_AES_BLOCK_SIZE]);
    }

    macros.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));
    macros.SymCryptWipeKnownSize(&temp, @sizeOf(@TypeOf(temp)));
    macros.SymCryptWipeKnownSize(&aesKey, @sizeOf(SYMCRYPT_AES_EXPANDED_KEY));
}

pub export fn SymCryptRngAesGenerateBlocks(
    pAesKey: PSYMCRYPT_AES_EXPANDED_KEY,
    pV: PBYTE,
    pbRandomInput: PBYTE,
    cbRandomInput: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var pbRandom = pbRandomInput;
    var cbRandom = cbRandomInput;

    //
    // cbRandom must be a multiple of BLOCK_LEN and > 0.
    //
    macros.SYMCRYPT_ASSERT((cbRandom & (SYMCRYPT_AES_BLOCK_SIZE - 1)) == 0);

    var cBlocks: SIZE_T = cbRandom / SYMCRYPT_AES_BLOCK_SIZE;

    //
    // We violate the write-once rule here by wiping the output buffer and then
    // filling it with the CTR-mode encryption.
    // This is safe because the caller only learns the proper output anyway.
    //
    macros.SymCryptWipe(pbRandom, cbRandom);

    const MAX_CTRMSB64_BLOCKS: UINT64 = if (types.DEBUG) (1 << 3) else (1 << 10);

    //
    // This loop is a little complicated because we need to pre-increment the 128-bit value V
    // and the SymCryptAesCtrMsb64 function does a 64-bit post-increment.
    //
    while (cBlocks != 0) {
        // Increment V
        var v: UINT64 = macros.SYMCRYPT_LOAD_MSBFIRST64(pV + 8) +% 1;
        macros.SYMCRYPT_STORE_MSBFIRST64(pV + 8, v);
        macros.SYMCRYPT_STORE_MSBFIRST64(pV, macros.SYMCRYPT_LOAD_MSBFIRST64(pV) +% @intFromBool(v == 0));

        //
        // 1 + (~v & mask) is the value you can add to v so that the mask bits of the sum
        // end up to be zero. It is in the range 1 .. mask+1
        //
        const maxBlocks: SIZE_T = @intCast(1 + ((~v) & (MAX_CTRMSB64_BLOCKS - 1)));
        const blocksToDo: SIZE_T = @min(cBlocks, maxBlocks);

        const bytesToDo: SIZE_T = blocksToDo * SYMCRYPT_AES_BLOCK_SIZE;
        macros.SYMCRYPT_ASSERT(bytesToDo <= cbRandom);
        aes_default.SymCryptAesCtrMsb64(pAesKey, pV, pbRandom, pbRandom, bytesToDo);
        pbRandom += bytesToDo;
        cbRandom -= bytesToDo;
        cBlocks -= blocksToDo;

        //
        // Post-decrement the V block to compensate for the post-increment of the Msb64 function
        //
        v +%= blocksToDo - 1;
        macros.SYMCRYPT_ASSERT(v != 0);

        macros.SYMCRYPT_STORE_MSBFIRST64(pV + 8, v);
        // No need to carry to the first half of V here, it cannot happen
    }
}

inline fn SymCryptRngAesAreBlocksIdentical(
    pSrc1: PCBYTE,
    pSrc2: PCBYTE,
) SIZE_T {
    const p1: [*]align(1) const SIZE_T = @ptrCast(pSrc1);
    const p2: [*]align(1) const SIZE_T = @ptrCast(pSrc2);

    var tmp: SIZE_T = 0;
    if (comptime (types.CPU_X86 or types.CPU_ARM)) {
        comptime std.debug.assert(@sizeOf(SIZE_T) == 4);
        tmp = (p1[0] ^ p2[0]) | (p1[1] ^ p2[1]) | (p1[2] ^ p2[2]) | (p1[3] ^ p2[3]);
    } else if (comptime (types.CPU_AMD64 or types.CPU_ARM64)) {
        comptime std.debug.assert(@sizeOf(SIZE_T) == 8);
        tmp = (p1[0] ^ p2[0]) | (p1[1] ^ p2[1]);
    } else {
        comptime std.debug.assert(16 % @sizeOf(SIZE_T) == 0);
        inline for (0..16 / @sizeOf(SIZE_T)) |i| {
            tmp |= p1[i] ^ p2[i];
        }
    }

    return @intFromBool(tmp == 0);
}

pub export fn SymCryptRngAesCheckBlocksNotIdentical(
    pbPreviousBlock: PBYTE,
    pcbData: PCBYTE,
    cbData: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(((cbData & 15) == 0) and cbData > 0);

    var identical: SIZE_T = SymCryptRngAesAreBlocksIdentical(pbPreviousBlock, pcbData);

    var i: SIZE_T = SYMCRYPT_AES_BLOCK_SIZE;
    while (i < cbData) : (i += SYMCRYPT_AES_BLOCK_SIZE) {
        macros.SYMCRYPT_ASSERT(cbData >= i + SYMCRYPT_AES_BLOCK_SIZE);
        identical |= SymCryptRngAesAreBlocksIdentical(pcbData + i - SYMCRYPT_AES_BLOCK_SIZE, pcbData + i);
    }

    @memcpy(pbPreviousBlock[0..SYMCRYPT_AES_BLOCK_SIZE], (pcbData + cbData - SYMCRYPT_AES_BLOCK_SIZE)[0..SYMCRYPT_AES_BLOCK_SIZE]);

    if (identical != 0) {
        macros.SymCryptFatal(macros.multiCharConstant("acdi"));
    }
}

pub export fn SymCryptRngAesUpdate(
    pState: PSYMCRYPT_RNG_AES_STATE,
    pbProvidedData: ?PCBYTE,
    pAesKey: ?PSYMCRYPT_AES_EXPANDED_KEY,
) callconv(types.SYMCRYPT_CALL) void {
    var aesKey: SYMCRYPT_AES_EXPANDED_KEY = undefined;
    var pKey: PSYMCRYPT_AES_EXPANDED_KEY = undefined;
    var buf: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    if (pAesKey) |existingKey| {
        pKey = existingKey;
    } else {
        _ = aes_key.SymCryptAesExpandKeyEncryptOnly(&aesKey, &pState.keyAndV, SYMCRYPT_RNG_AES_KEY_SIZE);
        pKey = &aesKey;
    }

    //
    // Copy the V value so that we can overwrite it safely.
    //
    @memcpy(&buf, pState.keyAndV[SYMCRYPT_RNG_AES_KEY_SIZE .. SYMCRYPT_RNG_AES_KEY_SIZE + SYMCRYPT_AES_BLOCK_SIZE]);

    SymCryptRngAesGenerateBlocks(
        pKey,
        &buf,
        &pState.keyAndV,
        @sizeOf(@TypeOf(pState.keyAndV)),
    );

    if (pbProvidedData) |provided| {
        // XOR provided data in
        macros.SymCryptXorBytes(&pState.keyAndV, provided, &pState.keyAndV, SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE);
    }

    macros.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));

    //
    // Only wipe the key if necessary.
    //
    if (pKey == &aesKey) {
        macros.SymCryptWipeKnownSize(&aesKey, @sizeOf(SYMCRYPT_AES_EXPANDED_KEY));
    }
}

pub export fn SymCryptRngAesGenerateSmall(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
    pbRandomInput: PBYTE,
    cbRandomInput: SIZE_T,
    pbAdditionalInputOpt: ?PCBYTE,
    cbAdditionalInput: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbRandom = pbRandomInput;
    var cbRandom = cbRandomInput;
    var pbAdditionalInput = pbAdditionalInputOpt;

    var aesKey: SYMCRYPT_AES_EXPANDED_KEY = undefined;
    var buf: [SYMCRYPT_AES_BLOCK_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var abSeed: [SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    //
    // SP 800-90 9.3.1 requires a check on the length of the request.
    //
    if (cbRandom > SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    if (pRngState.requestCounter > SYMCRYPT_RNG_AES_MAX_REQUESTS_PER_RESEED) {
        return .SYMCRYPT_FIPS_FAILURE;
    }

    if (pbAdditionalInput) |addInput| {
        // Update additional input using Derivation function
        SymCryptRngAesDf(addInput, cbAdditionalInput, &abSeed);
        pbAdditionalInput = &abSeed;

        // Update state with modified additional input
        SymCryptRngAesUpdate(pRngState, pbAdditionalInput, null);
    }

    _ = aes_key.SymCryptAesExpandKeyEncryptOnly(&aesKey, &pRngState.keyAndV, SYMCRYPT_RNG_AES_KEY_SIZE);

    if (cbRandom >= SYMCRYPT_AES_BLOCK_SIZE) {
        const wholeBlocks: SIZE_T = cbRandom & ~(SYMCRYPT_AES_BLOCK_SIZE - 1);
        SymCryptRngAesGenerateBlocks(
            &aesKey,
            pRngState.keyAndV[SYMCRYPT_RNG_AES_KEY_SIZE..].ptr,
            pbRandom,
            wholeBlocks,
        );
        if (pRngState.fips140_2Check != 0) {
            SymCryptRngAesCheckBlocksNotIdentical(&pRngState.previousBlock, pbRandom, wholeBlocks);
        }
        pbRandom += wholeBlocks;
        cbRandom -= wholeBlocks;
    }

    if (cbRandom > 0) {
        macros.SYMCRYPT_ASSERT(cbRandom < SYMCRYPT_AES_BLOCK_SIZE);
        SymCryptRngAesGenerateBlocks(
            &aesKey,
            pRngState.keyAndV[SYMCRYPT_RNG_AES_KEY_SIZE..].ptr,
            &buf,
            @sizeOf(@TypeOf(buf)),
        );
        if (pRngState.fips140_2Check != 0) {
            SymCryptRngAesCheckBlocksNotIdentical(&pRngState.previousBlock, &buf, @sizeOf(@TypeOf(buf)));
        }

        @memcpy(pbRandom[0..cbRandom], buf[0..cbRandom]);
        macros.SymCryptWipeKnownSize(&buf, @sizeOf(@TypeOf(buf)));
    }

    SymCryptRngAesUpdate(pRngState, pbAdditionalInput, &aesKey);

    pRngState.requestCounter += 1;

    macros.SymCryptWipeKnownSize(&aesKey, @sizeOf(SYMCRYPT_AES_EXPANDED_KEY));
    macros.SymCryptWipeKnownSize(&abSeed, @sizeOf(@TypeOf(abSeed)));

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRngAesInstantiate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
    pcbSeedMaterial: ?PCBYTE,
    cbSeedMaterial: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    @setRuntimeSafety(false);
    if (cbSeedMaterial < SYMCRYPT_RNG_AES_MIN_INSTANTIATE_SIZE) {
        return .SYMCRYPT_EXTERNAL_FAILURE;
    }

    macros.SymCryptWipeKnownSize(pRngState, @sizeOf(SYMCRYPT_RNG_AES_STATE));

    macros.SYMCRYPT_SET_MAGIC(pRngState);

    return SymCryptRngAesReseed(pRngState, pcbSeedMaterial, cbSeedMaterial);
}

pub export fn SymCryptRngAesGenerate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
    pbRandomInput: PBYTE,
    cbRandomInput: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    var pbRandom = pbRandomInput;
    var cbRandom = cbRandomInput;
    var scError: SYMCRYPT_ERROR = undefined;

    macros.SYMCRYPT_CHECK_MAGIC(pRngState);

    while (cbRandom > SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE) {
        scError = SymCryptRngAesGenerateSmall(pRngState, pbRandom, SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE, null, 0);
        if (scError != .SYMCRYPT_NO_ERROR) {
            macros.SymCryptFatal(macros.multiCharConstant("acdx"));
        }
        pbRandom += SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE;
        cbRandom -= SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE;
    }

    if (cbRandom > 0) {
        scError = SymCryptRngAesGenerateSmall(pRngState, pbRandom, cbRandom, null, 0);
        if (scError != .SYMCRYPT_NO_ERROR) {
            macros.SymCryptFatal(macros.multiCharConstant("acdx"));
        }
    }
}

pub export fn SymCryptRngAesReseed(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
    pcbSeedMaterial: ?PCBYTE,
    cbSeedMaterial: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var abSeed: [SYMCRYPT_RNG_AES_INTERNAL_SEED_SIZE]BYTE align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.SYMCRYPT_CHECK_MAGIC(pRngState);

    if (cbSeedMaterial < SYMCRYPT_RNG_AES_MIN_RESEED_SIZE or
        cbSeedMaterial > SYMCRYPT_RNG_AES_MAX_SEED_SIZE)
    {
        return .SYMCRYPT_EXTERNAL_FAILURE;
    }

    SymCryptRngAesDf(pcbSeedMaterial.?, cbSeedMaterial, &abSeed);

    SymCryptRngAesUpdate(pRngState, &abSeed, null);

    pRngState.requestCounter = 1;

    macros.SymCryptWipeKnownSize(&abSeed, @sizeOf(@TypeOf(abSeed)));

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRngAesUninstantiate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SymCryptWipeKnownSize(pRngState, @sizeOf(SYMCRYPT_RNG_AES_STATE));
}

////////////////////////////////////////////////////////////////////////////
// Self test

const g_abInstantiateEntropyInputPlusNonce = [_]BYTE{
    // Entropy input
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,

    // Nonce
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
};

const g_abReseedEntropy = [_]BYTE{
    0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
    0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D, 0x8E, 0x8F,
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
    0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F,
    0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
    0xA8, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF,
};

const g_abOutput1 = [32]BYTE{
    0xD1, 0xE9, 0xC7, 0x37, 0xB6, 0xEB, 0xAE, 0xD7,
    0x65, 0xA0, 0xD4, 0xE4, 0xC6, 0xEA, 0xEB, 0xE2,
    0x67, 0xF5, 0xE9, 0x19, 0x36, 0x80, 0xFD, 0xFF,
    0xA6, 0x2F, 0x48, 0x65, 0xB3, 0xF0, 0x09, 0xEC,
};

const g_expectedStateAfterInstantiate = [SYMCRYPT_RNG_AES_KEY_AND_V_SIZE]BYTE{
    // key
    0x8C, 0x10, 0xB6, 0x58, 0x44, 0x0C, 0x71, 0x35,
    0x64, 0x9D, 0xC7, 0x7B, 0xE6, 0xE5, 0x75, 0xCE,
    0x87, 0xE7, 0x48, 0x90, 0x83, 0x9B, 0x89, 0x59,
    0x14, 0x17, 0xAF, 0xAD, 0x14, 0xB2, 0x26, 0xD5,
    // V
    0xB4, 0x03, 0x6B, 0x1D, 0xBA, 0x04, 0x3A, 0xE6,
    0x55, 0xAC, 0xD6, 0x46, 0xEC, 0x5A, 0xD3, 0x5C,
};

const g_expectedStateAfterReseed = [SYMCRYPT_RNG_AES_KEY_AND_V_SIZE]BYTE{
    // key
    0x17, 0x98, 0xC0, 0xDF, 0x09, 0x69, 0x6A, 0x46,
    0x19, 0x46, 0xFE, 0x6D, 0x68, 0x7D, 0x8C, 0xC8,
    0x3F, 0xEE, 0xF1, 0x22, 0xF3, 0xBB, 0xC5, 0xF2,
    0x9D, 0xAC, 0x85, 0x10, 0xF3, 0x4A, 0xF0, 0x15,
    // V
    0x0B, 0xF3, 0x34, 0x4D, 0xF5, 0x29, 0x27, 0x6B,
    0x0D, 0x5B, 0xBC, 0x83, 0x9B, 0xD3, 0x65, 0x6A,
};

const g_expectedStateAfterGenerate = [SYMCRYPT_RNG_AES_KEY_AND_V_SIZE]BYTE{
    // key
    0x28, 0xbc, 0x65, 0xa8, 0x6a, 0xb7, 0xc7, 0x4e, 0xdf, 0x4b, 0xb8, 0x72, 0x87, 0xd3, 0x4f, 0xbb,
    0x8d, 0x6f, 0x16, 0xd7, 0xb9, 0x1b, 0x6a, 0xbb, 0xee, 0x7b, 0x88, 0x86, 0x5b, 0x0f, 0xc7, 0xbd,
    // V
    0xb7, 0x46, 0x11, 0xf3, 0x92, 0x95, 0xa6, 0x25, 0x7c, 0x39, 0x98, 0x4c, 0x9c, 0x09, 0x9b, 0x30,
};

pub export fn SymCryptRngAesTestInstantiate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    var scError = SymCryptRngAesInstantiate(pRngState, null, 327);
    if (scError == .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("aci1"));
    }

    scError = SymCryptRngAesInstantiate(
        pRngState,
        &g_abInstantiateEntropyInputPlusNonce,
        g_abInstantiateEntropyInputPlusNonce.len,
    );

    macros.SymCryptInjectError(&pRngState.keyAndV, SYMCRYPT_RNG_AES_KEY_AND_V_SIZE);

    if (scError != .SYMCRYPT_NO_ERROR or
        !std.mem.eql(u8, &pRngState.keyAndV, &g_expectedStateAfterInstantiate))
    {
        macros.SymCryptFatal(macros.multiCharConstant("aci2"));
    }
}

pub export fn SymCryptRngAesTestReseed(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    macros.SYMCRYPT_SET_MAGIC(pRngState);
    @memcpy(&pRngState.keyAndV, &g_expectedStateAfterInstantiate);
    pRngState.requestCounter = 7;
    pRngState.fips140_2Check = types.FALSE;

    var scError = SymCryptRngAesReseed(pRngState, null, 597);
    if (scError == .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("acr1"));
    }

    scError = SymCryptRngAesReseed(pRngState, &g_abReseedEntropy, g_abReseedEntropy.len);

    macros.SymCryptInjectError(&pRngState.keyAndV, SYMCRYPT_RNG_AES_KEY_AND_V_SIZE);

    if (scError != .SYMCRYPT_NO_ERROR or
        !std.mem.eql(u8, &pRngState.keyAndV, &g_expectedStateAfterReseed))
    {
        macros.SymCryptFatal(macros.multiCharConstant("acr2"));
    }
}

pub export fn SymCryptRngAesTestGenerate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    var abOutput: [2 * SYMCRYPT_AES_BLOCK_SIZE]BYTE = undefined;

    macros.SYMCRYPT_SET_MAGIC(pRngState);
    @memcpy(&pRngState.keyAndV, &g_expectedStateAfterReseed);
    pRngState.requestCounter = 7;
    pRngState.fips140_2Check = types.FALSE;

    pRngState.requestCounter = SYMCRYPT_RNG_AES_MAX_REQUESTS_PER_RESEED + 1;
    var scError = SymCryptRngAesGenerateSmall(pRngState, &abOutput, g_abOutput1.len, null, 0);

    if (scError == .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("acg1"));
    }
    pRngState.requestCounter = 7;

    scError = SymCryptRngAesGenerateSmall(pRngState, &abOutput, SYMCRYPT_RNG_AES_MAX_REQUEST_SIZE + 1, null, 0);

    if (scError == .SYMCRYPT_NO_ERROR) {
        macros.SymCryptFatal(macros.multiCharConstant("acg2"));
    }

    scError = SymCryptRngAesGenerateSmall(pRngState, &abOutput, g_abOutput1.len, null, 0);

    macros.SymCryptInjectError(&abOutput, @sizeOf(@TypeOf(abOutput)));

    if (scError != .SYMCRYPT_NO_ERROR or !std.mem.eql(u8, &abOutput, &g_abOutput1)) {
        macros.SymCryptFatal(macros.multiCharConstant("acg3"));
    }

    macros.SymCryptInjectError(&pRngState.keyAndV, SYMCRYPT_RNG_AES_KEY_AND_V_SIZE);

    if (!std.mem.eql(u8, &pRngState.keyAndV, &g_expectedStateAfterGenerate)) {
        macros.SymCryptFatal(macros.multiCharConstant("acg4"));
    }
}

pub export fn SymCryptRngAesTestUninstantiate(
    pRngState: PSYMCRYPT_RNG_AES_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    const p: [*]const SIZE_T = @ptrCast(@alignCast(pRngState));

    comptime {
        std.debug.assert(@sizeOf(SYMCRYPT_RNG_AES_STATE) % @sizeOf(SIZE_T) == 0);
    }

    macros.SYMCRYPT_CHECK_MAGIC(pRngState);

    SymCryptRngAesUninstantiate(pRngState);

    var t: SIZE_T = 0;
    var i: SIZE_T = 0;
    while (i < @sizeOf(SYMCRYPT_RNG_AES_STATE) / @sizeOf(SIZE_T)) : (i += 1) {
        t |= p[i];
    }

    if (t != 0) {
        macros.SymCryptFatal(macros.multiCharConstant("acdu"));
    }
}

pub export fn SymCryptRngAesInstantiateSelftest() callconv(types.SYMCRYPT_CALL) void {
    var rng: SYMCRYPT_RNG_AES_STATE = undefined;

    SymCryptRngAesTestInstantiate(&rng);

    //
    // Uninstantiate has to be tested whenever another function is tested.
    //
    SymCryptRngAesTestUninstantiate(&rng);
}

pub export fn SymCryptRngAesReseedSelftest() callconv(types.SYMCRYPT_CALL) void {
    var rng: SYMCRYPT_RNG_AES_STATE = undefined;

    SymCryptRngAesTestReseed(&rng);

    //
    // Uninstantiate has to be tested whenever another function is tested.
    //
    SymCryptRngAesTestUninstantiate(&rng);
}

pub export fn SymCryptRngAesGenerateSelftest() callconv(types.SYMCRYPT_CALL) void {
    var rng: SYMCRYPT_RNG_AES_STATE = undefined;

    SymCryptRngAesTestGenerate(&rng);

    //
    // Uninstantiate has to be tested whenever another function is tested.
    //
    SymCryptRngAesTestUninstantiate(&rng);
}

///////////////////////////////////////////////////////////////////
// AES-CTR_DRGB with FIPS 140-2 continuous self-test
//

pub export fn SymCryptRngAesFips140_2Instantiate(
    pRngState: PSYMCRYPT_RNG_AES_FIPS140_2_STATE,
    pcbSeedMaterial: ?PCBYTE,
    cbSeedMaterial: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const scError = SymCryptRngAesInstantiate(&pRngState.rng, pcbSeedMaterial, cbSeedMaterial);

    if (scError == .SYMCRYPT_NO_ERROR) {
        //
        // Generate the first block of output and store it so that we can compare future blocks.
        //
        SymCryptRngAesGenerate(&pRngState.rng, &pRngState.rng.previousBlock, @sizeOf(@TypeOf(pRngState.rng.previousBlock)));
        pRngState.rng.fips140_2Check = types.TRUE;
    }

    return scError;
}

pub export fn SymCryptRngAesFips140_2Generate(
    pRngState: PSYMCRYPT_RNG_AES_FIPS140_2_STATE,
    pbRandom: PBYTE,
    cbRandom: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void {
    SymCryptRngAesGenerate(&pRngState.rng, pbRandom, cbRandom);
}

pub export fn SymCryptRngAesFips140_2Reseed(
    pRngState: PSYMCRYPT_RNG_AES_FIPS140_2_STATE,
    pcbSeedMaterial: ?PCBYTE,
    cbSeedMaterial: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptRngAesReseed(&pRngState.rng, pcbSeedMaterial, cbSeedMaterial);
}

pub export fn SymCryptRngAesFips140_2Uninstantiate(
    pRngState: PSYMCRYPT_RNG_AES_FIPS140_2_STATE,
) callconv(types.SYMCRYPT_CALL) void {
    SymCryptRngAesUninstantiate(&pRngState.rng);
}
