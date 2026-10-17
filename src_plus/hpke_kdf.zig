//
// hpke_kdf.zig
//
// HPKE KDF primitives and the key-schedule support that composes them:
// LabeledExtract/LabeledExpand (two-stage HKDF) and the OneStage SHAKE-backed
// equivalent, plus suite_id construction, CombineSecrets_{One,Two}Stage, and
// SecretExport.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");

const BYTE = internal.BYTE;
const PBYTE = internal.PBYTE;
const PCBYTE = internal.PCBYTE;
const UINT16 = internal.UINT16;
const SIZE_T = internal.SIZE_T;
const BOOLEAN = internal.BOOLEAN;
const SYMCRYPT_CALL = internal.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = internal.SYMCRYPT_ERROR;
const SYMCRYPT_HPKE_KDF_ID = internal.SYMCRYPT_HPKE_KDF_ID;
const PSYMCRYPT_HPKECONTEXT = internal.PSYMCRYPT_HPKECONTEXT;
const PCSYMCRYPT_HPKECONTEXT = internal.PCSYMCRYPT_HPKECONTEXT;
const PCSYMCRYPT_MAC = internal.PCSYMCRYPT_MAC;

fn SymCryptHpkeHkdfMacFromId(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
) ?PCSYMCRYPT_MAC {
    return switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256 => internal.SymCryptGetMacAlgorithm(.SYMCRYPT_MAC_ID_HMAC_SHA256),
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384 => internal.SymCryptGetMacAlgorithm(.SYMCRYPT_MAC_ID_HMAC_SHA384),
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512 => internal.SymCryptGetMacAlgorithm(.SYMCRYPT_MAC_ID_HMAC_SHA512),
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return null;
        },
    };
}

//
// Get the hash output size (Nh) for the KDF from its ID.
//
pub export fn SymCryptHpkeKdfOutputSizeFromId(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
) callconv(SYMCRYPT_CALL) UINT16 {
    return switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256 => 32,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384 => 48,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512 => 64,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128 => 32,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256 => 64,
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return 0;
        },
    };
}

pub export fn SymCryptHpkeBuildKemSuiteId(
    kemId: UINT16,
    pbSuiteId: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    // suite_id = "KEM" || I2OSP(kem_id, 2)
    @memcpy(pbSuiteId[0..3], "KEM");
    internal.SYMCRYPT_STORE_MSBFIRST16(pbSuiteId[3..5], kemId);
}

fn SymCryptHpkeBuildHpkeSuiteId(
    kemId: UINT16,
    kdfId: UINT16,
    aeadId: UINT16,
    pbSuiteId: *[internal.SYMCRYPT_HPKE_SUITE_ID_SIZE]BYTE,
) void {
    // suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
    @memcpy(pbSuiteId[0..4], "HPKE");
    internal.SYMCRYPT_STORE_MSBFIRST16(pbSuiteId[4..6], kemId);
    internal.SYMCRYPT_STORE_MSBFIRST16(pbSuiteId[6..8], kdfId);
    internal.SYMCRYPT_STORE_MSBFIRST16(pbSuiteId[8..10], aeadId);
}

//
// LabeledExtract / LabeledExpand: two-stage HKDF wrappers. SHAKE-based KDFs
// use the OneStage path below.
//
//   Longest current label is "shared_secret" (13 chars).
//
const SYMCRYPT_HPKE_MAX_LABEL_SIZE: usize = 13;

//
// labeled_ikm = "HPKE-v1" || suite_id || label || ikm
// Maximum: version(7) + suite_id(10) + label(13) + ikm(128) = 158
//
const SYMCRYPT_HPKE_LABELED_IKM_MAX: usize =
    internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE +
    internal.SYMCRYPT_HPKE_SUITE_ID_SIZE +
    SYMCRYPT_HPKE_MAX_LABEL_SIZE +
    internal.SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE;

pub export fn SymCryptHpkeLabeledExtract(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pbSuiteId: PCBYTE,
    cbSuiteId: SIZE_T,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    pbLabel: PCBYTE,
    cbLabel: SIZE_T,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbPrk: PBYTE,
    cbPrk: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var labeledIkm: [SYMCRYPT_HPKE_LABELED_IKM_MAX]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&labeledIkm), labeledIkm.len);

    if (cbIkm > internal.SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    internal.SYMCRYPT_ASSERT(cbSuiteId <= internal.SYMCRYPT_HPKE_SUITE_ID_SIZE);
    internal.SYMCRYPT_ASSERT(cbLabel <= SYMCRYPT_HPKE_MAX_LABEL_SIZE);

    //
    // Build labeled_ikm = "HPKE-v1" || suite_id || label || ikm
    //
    var offset: SIZE_T = 0;

    @memcpy(labeledIkm[offset .. offset + internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE], internal.SYMCRYPT_HPKE_VERSION_LABEL);
    offset += internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE;

    @memcpy(labeledIkm[offset .. offset + cbSuiteId], pbSuiteId[0..cbSuiteId]);
    offset += cbSuiteId;

    @memcpy(labeledIkm[offset .. offset + cbLabel], pbLabel[0..cbLabel]);
    offset += cbLabel;

    if (cbIkm > 0) {
        @memcpy(labeledIkm[offset .. offset + cbIkm], pbIkm.?[0..cbIkm]);
        offset += cbIkm;
    }

    const cbLabeledIkm: SIZE_T = offset;
    internal.SYMCRYPT_ASSERT(cbLabeledIkm <= labeledIkm.len);

    //
    // Extract(salt, labeled_ikm) via SymCrypt HKDF API.
    // When pbSalt is NULL and cbSalt is 0, SymCryptHkdfExtractPrk
    // uses a string of zeroes of length HashLen per the HMAC specification.
    //
    scError = internal.SymCryptHkdfExtractPrk(
        SymCryptHpkeHkdfMacFromId(kdfId).?,
        &labeledIkm,
        cbLabeledIkm,
        pbSalt,
        cbSalt,
        pbPrk,
        cbPrk,
    );

    return scError;
}

//
// labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
// Prefix max: 2 + version(7) + suite_id(10) + label(13) = 32. Caller info up
// to SYMCRYPT_HPKE_MAX_INFO_SIZE; small info uses the stack buffer below,
// larger info heap-allocates.
//
const SYMCRYPT_HPKE_LABELED_INFO_PREFIX_MAX: usize =
    2 + internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE + internal.SYMCRYPT_HPKE_SUITE_ID_SIZE + SYMCRYPT_HPKE_MAX_LABEL_SIZE;

const SYMCRYPT_HPKE_LABELED_INFO_STACK_THRESHOLD: usize = 128;

const SYMCRYPT_HPKE_LABELED_INFO_STACK_SIZE: usize =
    SYMCRYPT_HPKE_LABELED_INFO_PREFIX_MAX + SYMCRYPT_HPKE_LABELED_INFO_STACK_THRESHOLD;

pub export fn SymCryptHpkeLabeledExpand(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pbSuiteId: PCBYTE,
    cbSuiteId: SIZE_T,
    pbPrk: PCBYTE,
    cbPrk: SIZE_T,
    pbLabel: PCBYTE,
    cbLabel: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbResult: PBYTE,
    cbResult: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var hkdfKey: internal.SYMCRYPT_HKDF_EXPANDED_KEY = undefined;
    var stackBuf: [SYMCRYPT_HPKE_LABELED_INFO_STACK_SIZE]BYTE = undefined;
    var pbLabeledInfo: PBYTE = undefined;
    var pbHeapBuf: ?PBYTE = null;
    var cbLabeledInfo: SIZE_T = 0;

    defer {
        internal.SymCryptWipeKnownSize(@ptrCast(&hkdfKey), @sizeOf(internal.SYMCRYPT_HKDF_EXPANDED_KEY));
        if (pbHeapBuf) |pHeap| {
            internal.SymCryptWipe(@ptrCast(pHeap), cbLabeledInfo);
            internal.SymCryptCallbackFree(@ptrCast(pHeap));
        } else {
            internal.SymCryptWipeKnownSize(@ptrCast(&stackBuf), stackBuf.len);
        }
    }

    if (cbInfo > internal.SYMCRYPT_HPKE_MAX_INFO_SIZE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    internal.SYMCRYPT_ASSERT(cbLabel <= SYMCRYPT_HPKE_MAX_LABEL_SIZE);

    //
    // Compute labeled_info size and select stack or heap buffer
    //
    cbLabeledInfo = 2 + internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE + cbSuiteId + cbLabel + cbInfo;

    if (cbLabeledInfo <= stackBuf.len) {
        pbLabeledInfo = &stackBuf;
    } else {
        const pMem = internal.SymCryptCallbackAlloc(cbLabeledInfo) orelse {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        };
        pbHeapBuf = @ptrCast(pMem);
        pbLabeledInfo = pbHeapBuf.?;
    }

    //
    // Build labeled_info = I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info
    //
    var offset: SIZE_T = 0;

    internal.SYMCRYPT_STORE_MSBFIRST16(pbLabeledInfo[0..2], cbResult);
    offset += 2;

    @memcpy(pbLabeledInfo[offset .. offset + internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE], internal.SYMCRYPT_HPKE_VERSION_LABEL);
    offset += internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE;

    @memcpy(pbLabeledInfo[offset .. offset + cbSuiteId], pbSuiteId[0..cbSuiteId]);
    offset += cbSuiteId;

    @memcpy(pbLabeledInfo[offset .. offset + cbLabel], pbLabel[0..cbLabel]);
    offset += cbLabel;

    if (cbInfo > 0) {
        @memcpy(pbLabeledInfo[offset .. offset + cbInfo], pbInfo.?[0..cbInfo]);
        offset += cbInfo;
    }

    internal.SYMCRYPT_ASSERT(offset == cbLabeledInfo);

    //
    // Expand(prk, labeled_info, L) via SymCrypt HKDF API
    //
    scError = internal.SymCryptHkdfPrkExpandKey(&hkdfKey, SymCryptHpkeHkdfMacFromId(kdfId).?, pbPrk, cbPrk);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = internal.SymCryptHkdfDerive(&hkdfKey, pbLabeledInfo, cbLabeledInfo, pbResult, cbResult);
    return scError;
}

//
// One-stage KDF state and primitives for SHAKE-backed HPKE KDFs.
//

const SYMCRYPT_HPKE_ONESTAGE_STATE = extern union {
    shake128: internal.SYMCRYPT_SHAKE128_STATE,
    shake256: internal.SYMCRYPT_SHAKE256_STATE,
};
const PSYMCRYPT_HPKE_ONESTAGE_STATE = *SYMCRYPT_HPKE_ONESTAGE_STATE;

fn SymCryptHpkeOneStageInit(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pState: PSYMCRYPT_HPKE_ONESTAGE_STATE,
) void {
    switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128 => internal.SymCryptShake128Init(&pState.shake128),
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256 => internal.SymCryptShake256Init(&pState.shake256),
        else => internal.SYMCRYPT_ASSERT(false),
    }
}

fn SymCryptHpkeOneStageAppend(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pState: PSYMCRYPT_HPKE_ONESTAGE_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) void {
    switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128 => internal.SymCryptShake128Append(&pState.shake128, pbData, cbData),
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256 => internal.SymCryptShake256Append(&pState.shake256, pbData, cbData),
        else => internal.SYMCRYPT_ASSERT(false),
    }
}

fn SymCryptHpkeOneStageExtract(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pState: PSYMCRYPT_HPKE_ONESTAGE_STATE,
    pbResult: PBYTE,
    cbResult: SIZE_T,
    bWipe: BOOLEAN,
) void {
    switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128 => internal.SymCryptShake128Extract(&pState.shake128, pbResult, cbResult, bWipe),
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256 => internal.SymCryptShake256Extract(&pState.shake256, pbResult, cbResult, bWipe),
        else => internal.SYMCRYPT_ASSERT(false),
    }
}

//
// LabeledDerive_OneStage from draft-ietf-hpke-hpke-03:
//   KDF( ikm || "HPKE-v1" || suite_id ||
//        I2OSP(len(label), 2) || label || I2OSP(L, 2) || context, L )
//
pub export fn SymCryptHpkeLabeledDeriveOneStage(
    kdfId: SYMCRYPT_HPKE_KDF_ID,
    pbSuiteId: PCBYTE,
    cbSuiteId: SIZE_T,
    pbIkm: ?PCBYTE,
    cbIkm: SIZE_T,
    pbLabel: PCBYTE,
    cbLabel: UINT16,
    pbContext: ?PCBYTE,
    cbContext: SIZE_T,
    pbResult: PBYTE,
    cbResult: UINT16,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_HPKE_ONESTAGE_STATE = undefined;
    var lengthBuf: [2]BYTE = undefined;

    SymCryptHpkeOneStageInit(kdfId, &state);

    if (cbIkm > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbIkm.?, cbIkm);
    }

    SymCryptHpkeOneStageAppend(kdfId, &state, internal.SYMCRYPT_HPKE_VERSION_LABEL.ptr, internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE);
    SymCryptHpkeOneStageAppend(kdfId, &state, pbSuiteId, cbSuiteId);

    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbLabel);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    if (cbLabel > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbLabel, cbLabel);
    }

    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbResult);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);

    if (cbContext > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbContext.?, cbContext);
    }

    SymCryptHpkeOneStageExtract(kdfId, &state, pbResult, cbResult, 1);
}

//
// CombineSecrets_OneStage from draft-ietf-hpke-hpke-03 for SHAKE-backed KDFs.
// Output is consumed in order as key, base_nonce, and exporter_secret.
//
pub export fn SymCryptHpkeCombineSecretsOneStage(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    mode: BYTE,
    pbSharedSecret: PCBYTE,
    cbSharedSecret: UINT16,
    pbInfo: ?PCBYTE,
    cbInfo: UINT16,
    pbPsk: ?PCBYTE,
    cbPsk: UINT16,
    pbPskId: ?PCBYTE,
    cbPskId: UINT16,
) callconv(SYMCRYPT_CALL) void {
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pHpkeContext.ciphersuite.kdfId));
    const cbKdfOutput: UINT16 = SymCryptHpkeKdfOutputSizeFromId(kdfId);
    const cbSecret: UINT16 = pHpkeContext.aeadParams.cbKey + pHpkeContext.aeadParams.cbNonce + cbKdfOutput;
    var lengthBuf: [2]BYTE = undefined;
    var hpkeSuiteId: [internal.SYMCRYPT_HPKE_SUITE_ID_SIZE]BYTE = undefined;
    var state: SYMCRYPT_HPKE_ONESTAGE_STATE = undefined;
    var modeBuf: [1]BYTE = .{mode};

    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext.ciphersuite.kemId,
        pHpkeContext.ciphersuite.kdfId,
        pHpkeContext.ciphersuite.aeadId,
        &hpkeSuiteId,
    );

    //
    // CombineSecrets_OneStage from draft-ietf-hpke-hpke-03:
    //   secrets = I2OSP(len(psk), 2) || psk ||
    //             I2OSP(len(shared_secret), 2) || shared_secret
    //   context = mode || I2OSP(len(psk_id), 2) || psk_id ||
    //             I2OSP(len(info), 2) || info
    //   L = Nk + Nn + Nh
    //   secret = LabeledDerive(suite_id, secrets, "secret", context, L)
    // The output is consumed in order as key, base_nonce, and exporter_secret.
    //

    SymCryptHpkeOneStageInit(kdfId, &state);

    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbPsk);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    if (cbPsk > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbPsk.?, cbPsk);
    }

    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbSharedSecret);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    SymCryptHpkeOneStageAppend(kdfId, &state, pbSharedSecret, cbSharedSecret);

    SymCryptHpkeOneStageAppend(kdfId, &state, internal.SYMCRYPT_HPKE_VERSION_LABEL.ptr, internal.SYMCRYPT_HPKE_VERSION_LABEL_SIZE);
    SymCryptHpkeOneStageAppend(kdfId, &state, &hpkeSuiteId, internal.SYMCRYPT_HPKE_SUITE_ID_SIZE);
    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, 6);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    SymCryptHpkeOneStageAppend(kdfId, &state, "secret", 6);
    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbSecret);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);

    SymCryptHpkeOneStageAppend(kdfId, &state, &modeBuf, 1);
    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbPskId);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    if (cbPskId > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbPskId.?, cbPskId);
    }
    internal.SYMCRYPT_STORE_MSBFIRST16(&lengthBuf, cbInfo);
    SymCryptHpkeOneStageAppend(kdfId, &state, &lengthBuf, 2);
    if (cbInfo > 0) {
        SymCryptHpkeOneStageAppend(kdfId, &state, pbInfo.?, cbInfo);
    }

    if (pHpkeContext.aeadParams.cbKey > 0) {
        SymCryptHpkeOneStageExtract(kdfId, &state, &pHpkeContext.key, pHpkeContext.aeadParams.cbKey, 0);
    }
    if (pHpkeContext.aeadParams.cbNonce > 0) {
        SymCryptHpkeOneStageExtract(kdfId, &state, &pHpkeContext.baseNonce, pHpkeContext.aeadParams.cbNonce, 0);
    }
    SymCryptHpkeOneStageExtract(kdfId, &state, &pHpkeContext.exporterSecret, cbKdfOutput, 1);
}

//
// CombineSecrets_TwoStage from draft-ietf-hpke-hpke-03 for HKDF-based KDFs.
//
pub export fn SymCryptHpkeCombineSecretsTwoStage(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    mode: BYTE,
    pbSharedSecret: PCBYTE,
    cbSharedSecret: UINT16,
    pbInfo: ?PCBYTE,
    cbInfo: UINT16,
    pbPsk: ?PCBYTE,
    cbPsk: UINT16,
    pbPskId: ?PCBYTE,
    cbPskId: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pHpkeContext.ciphersuite.kdfId));
    const cbKdfOutput: UINT16 = SymCryptHpkeKdfOutputSizeFromId(kdfId);

    // ks_context = mode(1) || psk_id_hash(Nh) || info_hash(Nh)
    // Maximum size: 1 + 2*64 = 129
    var ksContext: [1 + 2 * internal.SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE]BYTE = undefined;
    const cbKsContext: UINT16 = 1 + 2 * cbKdfOutput;

    var secret: [internal.SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE]BYTE = undefined;
    var hpkeSuiteId: [internal.SYMCRYPT_HPKE_SUITE_ID_SIZE]BYTE = undefined;

    defer {
        internal.SymCryptWipeKnownSize(@ptrCast(&ksContext), ksContext.len);
        internal.SymCryptWipeKnownSize(@ptrCast(&secret), secret.len);
    }

    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext.ciphersuite.kemId,
        pHpkeContext.ciphersuite.kdfId,
        pHpkeContext.ciphersuite.aeadId,
        &hpkeSuiteId,
    );

    //
    // Step 1: psk_id_hash = LabeledExtract("", "psk_id_hash", psk_id)
    //
    ksContext[0] = mode;

    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        &hpkeSuiteId,
        internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
        null,
        0, // empty salt
        "psk_id_hash",
        11,
        pbPskId,
        cbPskId,
        ksContext[1..].ptr,
        cbKdfOutput,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // Step 2: info_hash = LabeledExtract("", "info_hash", info)
    //
    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        &hpkeSuiteId,
        internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
        null,
        0,
        "info_hash",
        9,
        pbInfo,
        cbInfo,
        ksContext[1 + cbKdfOutput ..].ptr,
        cbKdfOutput,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // Step 3: secret = LabeledExtract(shared_secret, "secret", psk)
    //
    scError = SymCryptHpkeLabeledExtract(
        kdfId,
        &hpkeSuiteId,
        internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
        pbSharedSecret,
        cbSharedSecret, // shared_secret as salt
        "secret",
        6,
        pbPsk,
        cbPsk,
        &secret,
        cbKdfOutput,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // Step 4: key = LabeledExpand(secret, "key", ks_context, Nk)
    //   (Skip for Export-Only mode where Nk = 0)
    //
    if (pHpkeContext.aeadParams.cbKey > 0) {
        scError = SymCryptHpkeLabeledExpand(
            kdfId,
            &hpkeSuiteId,
            internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
            &secret,
            cbKdfOutput,
            "key",
            3,
            &ksContext,
            cbKsContext,
            &pHpkeContext.key,
            pHpkeContext.aeadParams.cbKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    //
    // Step 5: base_nonce = LabeledExpand(secret, "base_nonce", ks_context, Nn)
    //   (Skip for Export-Only mode where Nn = 0)
    //
    if (pHpkeContext.aeadParams.cbNonce > 0) {
        scError = SymCryptHpkeLabeledExpand(
            kdfId,
            &hpkeSuiteId,
            internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
            &secret,
            cbKdfOutput,
            "base_nonce",
            10,
            &ksContext,
            cbKsContext,
            &pHpkeContext.baseNonce,
            pHpkeContext.aeadParams.cbNonce,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    //
    // Step 6: exporter_secret = LabeledExpand(secret, "exp", ks_context, Nh)
    //
    scError = SymCryptHpkeLabeledExpand(
        kdfId,
        &hpkeSuiteId,
        internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
        &secret,
        cbKdfOutput,
        "exp",
        3,
        &ksContext,
        cbKsContext,
        &pHpkeContext.exporterSecret,
        cbKdfOutput,
    );

    return scError;
}

pub export fn SymCryptHpkeSecretExport(
    pHpkeContext: PCSYMCRYPT_HPKECONTEXT,
    pbExporterContext: ?PCBYTE,
    cbExporterContext: SIZE_T,
    pbResult: PBYTE,
    cbResult: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);
    internal.SYMCRYPT_ASSERT(pbExporterContext != null or cbExporterContext == 0);

    if (pHpkeContext.state == .SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbExporterContext > internal.SYMCRYPT_HPKE_MAX_EXPORT_SIZE or
        cbResult > internal.SYMCRYPT_HPKE_MAX_EXPORT_SIZE)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var hpkeSuiteId: [internal.SYMCRYPT_HPKE_SUITE_ID_SIZE]BYTE = undefined;
    SymCryptHpkeBuildHpkeSuiteId(
        pHpkeContext.ciphersuite.kemId,
        pHpkeContext.ciphersuite.kdfId,
        pHpkeContext.ciphersuite.aeadId,
        &hpkeSuiteId,
    );

    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pHpkeContext.ciphersuite.kdfId));

    switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
        => {
            return SymCryptHpkeLabeledExpand(
                kdfId,
                &hpkeSuiteId,
                internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
                &pHpkeContext.exporterSecret,
                SymCryptHpkeKdfOutputSizeFromId(kdfId),
                "sec",
                3,
                pbExporterContext,
                cbExporterContext,
                pbResult,
                cbResult,
            );
        },
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256,
        => {
            SymCryptHpkeLabeledDeriveOneStage(
                kdfId,
                &hpkeSuiteId,
                internal.SYMCRYPT_HPKE_SUITE_ID_SIZE,
                &pHpkeContext.exporterSecret,
                SymCryptHpkeKdfOutputSizeFromId(kdfId),
                "sec",
                3,
                pbExporterContext,
                cbExporterContext,
                pbResult,
                cbResult,
            );
            return .SYMCRYPT_NO_ERROR;
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }
}
