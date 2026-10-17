//
// hpke.zig
//
// HPKE (Hybrid Public Key Encryption) for SymCrypt.
//
// Implements draft-ietf-hpke-hpke-03 with DHKEM and ML-KEM support from
// draft-ietf-hpke-pq.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");
const hpke_kem = @import("hpke_kem.zig");
const hpke_kdf = @import("hpke_kdf.zig");
const hpke_aead = @import("hpke_aead.zig");

const BYTE = internal.BYTE;
const PBYTE = internal.PBYTE;
const PCBYTE = internal.PCBYTE;
const UINT16 = internal.UINT16;
const UINT32 = internal.UINT32;
const SIZE_T = internal.SIZE_T;
const SYMCRYPT_CALL = internal.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = internal.SYMCRYPT_ERROR;
const SYMCRYPT_HPKE_KEM_ID = internal.SYMCRYPT_HPKE_KEM_ID;
const SYMCRYPT_HPKE_KDF_ID = internal.SYMCRYPT_HPKE_KDF_ID;
const SYMCRYPT_HPKE_AEAD_ID = internal.SYMCRYPT_HPKE_AEAD_ID;
const SYMCRYPT_HPKE_CIPHERSUITE = internal.SYMCRYPT_HPKE_CIPHERSUITE;
const SYMCRYPT_HPKE_KEM_PARAMS = internal.SYMCRYPT_HPKE_KEM_PARAMS;
const PSYMCRYPT_HPKE_KEM_PARAMS = internal.PSYMCRYPT_HPKE_KEM_PARAMS;
const SYMCRYPT_HPKE_AEAD_PARAMS = internal.SYMCRYPT_HPKE_AEAD_PARAMS;
const PSYMCRYPT_HPKE_AEAD_PARAMS = internal.PSYMCRYPT_HPKE_AEAD_PARAMS;
const SYMCRYPT_HPKE_CONTEXT_STATE = internal.SYMCRYPT_HPKE_CONTEXT_STATE;
const PCSYMCRYPT_HPKEKEY = internal.PCSYMCRYPT_HPKEKEY;
const SYMCRYPT_HPKECONTEXT = internal.SYMCRYPT_HPKECONTEXT;
const PSYMCRYPT_HPKECONTEXT = internal.PSYMCRYPT_HPKECONTEXT;

//
// Initialize an HPKECONTEXT from a pre-validated ciphersuite. Used by
// HpkeContextAllocate and by the SingleShot APIs which stack-allocate the
// context.
//
fn SymCryptHpkeContextInit(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE,
    aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS,
) void {
    internal.SymCryptWipe(@ptrCast(pHpkeContext), @sizeOf(SYMCRYPT_HPKECONTEXT));

    pHpkeContext.ciphersuite = ciphersuite;
    pHpkeContext.aeadParams = aeadParams;
    // fGcmKeyExpanded (FALSE) and state (UNINITIALIZED) are already 0 from the wipe.

    internal.SYMCRYPT_SET_MAGIC(pHpkeContext);
}

pub export fn SymCryptHpkeContextAllocate(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_HPKECONTEXT {
    var aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS = undefined;

    const scError = SymCryptHpkeValidateCiphersuite(params, null, &aeadParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const pMem = internal.SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_HPKECONTEXT)) orelse {
        return null;
    };
    const pHpkeContext: PSYMCRYPT_HPKECONTEXT = @ptrCast(@alignCast(pMem));

    SymCryptHpkeContextInit(pHpkeContext, params, aeadParams);
    return pHpkeContext;
}

pub export fn SymCryptHpkeContextFree(
    pHpkeContext: ?PSYMCRYPT_HPKECONTEXT,
) callconv(SYMCRYPT_CALL) void {
    const pCtx = pHpkeContext orelse return;

    internal.SYMCRYPT_CHECK_MAGIC(pCtx);

    internal.SymCryptWipeKnownSize(@ptrCast(pCtx), @sizeOf(SYMCRYPT_HPKECONTEXT));
    internal.SymCryptCallbackFree(@ptrCast(pCtx));
}

// Wipe a context's derived key material and any cached AEAD-expanded state.
fn SymCryptHpkeContextWipe(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
) void {
    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);
    SymCryptHpkeContextInit(
        pHpkeContext,
        pHpkeContext.ciphersuite,
        pHpkeContext.aeadParams,
    );
}

//
// Validate a ciphersuite (KEM, KDF and AEAD must all be supported) and return
// the corresponding internal params structs.
//
pub export fn SymCryptHpkeValidateCiphersuite(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pKemParams: ?PSYMCRYPT_HPKE_KEM_PARAMS,
    pAeadParams: ?PSYMCRYPT_HPKE_AEAD_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pKemParamsFromId = hpke_kem.SymCryptHpkeKemParamsFromId(@fromBackingInt(@intCast(params.kemId))) orelse {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    };
    if (pKemParams) |pOutKem| {
        pOutKem.* = pKemParamsFromId.*;
    }

    // Validate the KDF is supported.
    switch (@as(SYMCRYPT_HPKE_KDF_ID, @fromBackingInt(@intCast(params.kdfId)))) {
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256,
        => {},
        else => return .SYMCRYPT_NOT_IMPLEMENTED,
    }

    const pAeadParamsFromId = hpke_aead.SymCryptHpkeAeadParamsFromId(@fromBackingInt(@intCast(params.aeadId))) orelse {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    };
    if (pAeadParams) |pOutAead| {
        pOutAead.* = pAeadParamsFromId.*;
    }

    return .SYMCRYPT_NO_ERROR;
}

//
// Common tail of SetupSender/SetupRecipient after the KEM has produced the
// shared secret. Determines mode from PSK presence and runs the key schedule.
//
pub export fn SymCryptHpkeFinishSetup(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    role: SYMCRYPT_HPKE_CONTEXT_STATE,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbPsk: ?PCBYTE,
    cbPsk: SIZE_T,
    pbPskId: ?PCBYTE,
    cbPskId: SIZE_T,
    pbSharedSecret: PCBYTE,
    cbSharedSecret: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pHpkeContext.ciphersuite.kdfId));
    var mode: BYTE = undefined;

    defer {
        if (scError != .SYMCRYPT_NO_ERROR) {
            SymCryptHpkeContextWipe(pHpkeContext);
        }
    }

    internal.SYMCRYPT_ASSERT(role == .SYMCRYPT_HPKE_CONTEXT_STATE_SENDER or
        role == .SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT);

    // PSK and PSK ID must both be provided, or both omitted.
    if ((pbPsk != null and pbPskId == null) or
        (pbPsk == null and pbPskId != null))
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    if (cbInfo > internal.SYMCRYPT_HPKE_MAX_INFO_SIZE or
        cbPsk > internal.SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE or
        cbPskId > internal.SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE)
    {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
        return scError;
    }

    if (pbPsk != null) {
        // PSK and PSK ID must be non-empty when using PSK mode.
        if (cbPsk == 0 or cbPskId == 0) {
            scError = .SYMCRYPT_INVALID_ARGUMENT;
            return scError;
        }
        mode = internal.SYMCRYPT_HPKE_MODE_PSK;
    } else {
        mode = internal.SYMCRYPT_HPKE_MODE_BASE;
        internal.SYMCRYPT_ASSERT(cbPsk == 0);
        internal.SYMCRYPT_ASSERT(pbPskId == null);
        internal.SYMCRYPT_ASSERT(cbPskId == 0);
    }

    if (pHpkeContext.state != .SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED) {
        SymCryptHpkeContextWipe(pHpkeContext);
    }

    switch (kdfId) {
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
        .SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
        => {
            scError = hpke_kdf.SymCryptHpkeCombineSecretsTwoStage(
                pHpkeContext,
                mode,
                pbSharedSecret,
                cbSharedSecret,
                pbInfo,
                @intCast(cbInfo),
                pbPsk,
                @intCast(cbPsk),
                pbPskId,
                @intCast(cbPskId),
            );
        },
        .SYMCRYPT_HPKE_KDF_ID_SHAKE128,
        .SYMCRYPT_HPKE_KDF_ID_SHAKE256,
        => {
            hpke_kdf.SymCryptHpkeCombineSecretsOneStage(
                pHpkeContext,
                mode,
                pbSharedSecret,
                cbSharedSecret,
                pbInfo,
                @intCast(cbInfo),
                pbPsk,
                @intCast(cbPsk),
                pbPskId,
                @intCast(cbPskId),
            );
            scError = .SYMCRYPT_NO_ERROR;
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded == 0);
    if (pHpkeContext.aeadParams.aeadId == @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_AESGCM128) or
        pHpkeContext.aeadParams.aeadId == @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_AESGCM256))
    {
        scError = internal.SymCryptGcmExpandKey(
            &pHpkeContext.gcmExpandedKey,
            internal.SymCryptGetBlockCipher(.SYMCRYPT_BLOCKCIPHER_ID_AES).?,
            &pHpkeContext.key,
            pHpkeContext.aeadParams.cbKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pHpkeContext.fGcmKeyExpanded = 1;
    }

    pHpkeContext.seqNum = 0;
    pHpkeContext.state = role;

    return scError;
}

pub export fn SymCryptHpkeSetupSender(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbPsk: ?PCBYTE,
    cbPsk: SIZE_T,
    pbPskId: ?PCBYTE,
    cbPskId: SIZE_T,
    pbEnc: PBYTE,
    cbEnc: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var sharedSecret: [internal.SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&sharedSecret), sharedSecret.len);

    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);
    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    if ((pbInfo == null and cbInfo != 0) or
        (pbPsk == null and cbPsk != 0) or
        (pbPskId == null and cbPskId != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pHpkeContext.ciphersuite.kemId != pkHpkekey.ciphersuite.kemId or
        pHpkeContext.ciphersuite.kdfId != pkHpkekey.ciphersuite.kdfId or
        pHpkeContext.ciphersuite.aeadId != pkHpkekey.ciphersuite.aeadId)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbEnc != pkHpkekey.kemParams.cbEnc) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbSharedSecret: UINT16 = pkHpkekey.kemParams.cbSharedSecret;

    scError = hpke_kem.SymCryptHpkeKemEncapsulate(
        pkHpkekey,
        &sharedSecret,
        cbSharedSecret,
        pbEnc,
        cbEnc,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptHpkeFinishSetup(
        pHpkeContext,
        .SYMCRYPT_HPKE_CONTEXT_STATE_SENDER,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        &sharedSecret,
        cbSharedSecret,
    );

    return scError;
}

pub export fn SymCryptHpkeSetupRecipient(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbEnc: PCBYTE,
    cbEnc: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbPsk: ?PCBYTE,
    cbPsk: SIZE_T,
    pbPskId: ?PCBYTE,
    cbPskId: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var sharedSecret: [internal.SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&sharedSecret), sharedSecret.len);

    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);
    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    if ((pbInfo == null and cbInfo != 0) or
        (pbPsk == null and cbPsk != 0) or
        (pbPskId == null and cbPskId != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pHpkeContext.ciphersuite.kemId != pkHpkekey.ciphersuite.kemId or
        pHpkeContext.ciphersuite.kdfId != pkHpkekey.ciphersuite.kdfId or
        pHpkeContext.ciphersuite.aeadId != pkHpkekey.ciphersuite.aeadId)
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbEnc != pkHpkekey.kemParams.cbEnc) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbSharedSecret: UINT16 = pkHpkekey.kemParams.cbSharedSecret;

    scError = hpke_kem.SymCryptHpkeKemDecapsulate(
        pkHpkekey,
        pbEnc,
        cbEnc,
        &sharedSecret,
        cbSharedSecret,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptHpkeFinishSetup(
        pHpkeContext,
        .SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        &sharedSecret,
        cbSharedSecret,
    );

    return scError;
}

pub export fn SymCryptHpkeSealSingleShot(
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbPsk: ?PCBYTE,
    cbPsk: SIZE_T,
    pbPskId: ?PCBYTE,
    cbPskId: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    cbSrc: SIZE_T,
    pbEnc: PBYTE,
    cbEnc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var ctx: SYMCRYPT_HPKECONTEXT = undefined;
    var aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS = undefined;

    scError = SymCryptHpkeValidateCiphersuite(pkHpkekey.ciphersuite, null, &aeadParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeContextInit(&ctx, pkHpkekey.ciphersuite, aeadParams);
    defer internal.SymCryptWipeKnownSize(@ptrCast(&ctx), @sizeOf(SYMCRYPT_HPKECONTEXT));

    scError = SymCryptHpkeSetupSender(
        &ctx,
        pkHpkekey,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        pbEnc,
        cbEnc,
        flags,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = hpke_aead.SymCryptHpkeSeal(
        &ctx,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbSrc,
        pbDst,
        cbDst,
        null,
    );

    return scError;
}

pub export fn SymCryptHpkeOpenSingleShot(
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbEnc: PCBYTE,
    cbEnc: SIZE_T,
    pbInfo: ?PCBYTE,
    cbInfo: SIZE_T,
    pbPsk: ?PCBYTE,
    cbPsk: SIZE_T,
    pbPskId: ?PCBYTE,
    cbPskId: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var ctx: SYMCRYPT_HPKECONTEXT = undefined;
    var aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS = undefined;

    scError = SymCryptHpkeValidateCiphersuite(pkHpkekey.ciphersuite, null, &aeadParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeContextInit(&ctx, pkHpkekey.ciphersuite, aeadParams);
    defer internal.SymCryptWipeKnownSize(@ptrCast(&ctx), @sizeOf(SYMCRYPT_HPKECONTEXT));

    scError = SymCryptHpkeSetupRecipient(
        &ctx,
        pkHpkekey,
        pbEnc,
        cbEnc,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        flags,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = hpke_aead.SymCryptHpkeOpen(
        &ctx,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbSrc,
        pbDst,
        cbDst,
    );

    return scError;
}
