//
// hpke_aead.zig
//
// HPKE AEAD layer: parameter lookup, nonce construction, Seal / Open /
// OpenUnordered, and the public AEAD-overhead size query.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");

const BYTE = internal.BYTE;
const PBYTE = internal.PBYTE;
const PCBYTE = internal.PCBYTE;
const UINT64 = internal.UINT64;
const SIZE_T = internal.SIZE_T;
const PSIZE_T = internal.PSIZE_T;
const SYMCRYPT_CALL = internal.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = internal.SYMCRYPT_ERROR;
const SYMCRYPT_HPKE_AEAD_ID = internal.SYMCRYPT_HPKE_AEAD_ID;
const SYMCRYPT_HPKE_AEAD_PARAMS = internal.SYMCRYPT_HPKE_AEAD_PARAMS;
const PCSYMCRYPT_HPKE_AEAD_PARAMS = internal.PCSYMCRYPT_HPKE_AEAD_PARAMS;
const SYMCRYPT_HPKE_CIPHERSUITE = internal.SYMCRYPT_HPKE_CIPHERSUITE;
const PSYMCRYPT_HPKECONTEXT = internal.PSYMCRYPT_HPKECONTEXT;
const PCSYMCRYPT_HPKECONTEXT = internal.PCSYMCRYPT_HPKECONTEXT;

const SymCryptHpkeAeadParamsAesGcm128 = SYMCRYPT_HPKE_AEAD_PARAMS{
    .aeadId = @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_AESGCM128),
    .cbKey = 16,
    .cbNonce = 12,
    .cbTag = 16,
};

const SymCryptHpkeAeadParamsAesGcm256 = SYMCRYPT_HPKE_AEAD_PARAMS{
    .aeadId = @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_AESGCM256),
    .cbKey = 32,
    .cbNonce = 12,
    .cbTag = 16,
};

const SymCryptHpkeAeadParamsChacha20Poly1305 = SYMCRYPT_HPKE_AEAD_PARAMS{
    .aeadId = @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305),
    .cbKey = 32,
    .cbNonce = 12,
    .cbTag = 16,
};

const SymCryptHpkeAeadParamsExportOnly = SYMCRYPT_HPKE_AEAD_PARAMS{
    .aeadId = @backingInt(SYMCRYPT_HPKE_AEAD_ID.SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY),
    .cbKey = 0,
    .cbNonce = 0,
    .cbTag = 0,
};

pub export fn SymCryptHpkeAeadParamsFromId(
    aeadId: SYMCRYPT_HPKE_AEAD_ID,
) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_HPKE_AEAD_PARAMS {
    const pParams: PCSYMCRYPT_HPKE_AEAD_PARAMS = switch (aeadId) {
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM128 => &SymCryptHpkeAeadParamsAesGcm128,
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM256 => &SymCryptHpkeAeadParamsAesGcm256,
        .SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 => &SymCryptHpkeAeadParamsChacha20Poly1305,
        .SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY => &SymCryptHpkeAeadParamsExportOnly,
        else => return null,
    };

    internal.SYMCRYPT_ASSERT(pParams.cbKey <= internal.SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE);
    internal.SYMCRYPT_ASSERT(pParams.cbNonce <= internal.SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE);

    return pParams;
}

pub export fn SymCryptHpkeSizeofAeadOverheadFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pcbAeadOverhead: PSIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const aeadId: SYMCRYPT_HPKE_AEAD_ID = @fromBackingInt(@intCast(params.aeadId));

    if (aeadId == .SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pAeadParams = SymCryptHpkeAeadParamsFromId(aeadId) orelse {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    };

    pcbAeadOverhead.* = pAeadParams.cbTag;
    return .SYMCRYPT_NO_ERROR;
}

//
// AEAD nonce construction: nonce = base_nonce XOR I2OSP(seq, Nn).
//
fn SymCryptHpkeComputeNonce(
    pbBaseNonce: PCBYTE,
    cbNonce: SIZE_T,
    seqNum: UINT64,
    pbNonce: PBYTE,
) void {
    const cbPrefix: SIZE_T = cbNonce - 8;

    internal.SYMCRYPT_ASSERT(cbNonce >= 8);
    internal.SYMCRYPT_ASSERT(cbNonce <= internal.SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE);

    // For cbNonce > 8 the leading (cbNonce - 8) bytes of the I2OSP encoding are
    // implicitly zero, so the XOR with base_nonce reduces to a memcpy there.
    @memcpy(pbNonce[0..cbPrefix], pbBaseNonce[0..cbPrefix]);
    internal.SYMCRYPT_STORE_MSBFIRST64(
        pbNonce[cbPrefix .. cbPrefix + 8][0..8],
        seqNum ^ internal.SYMCRYPT_LOAD_MSBFIRST64(pbBaseNonce[cbPrefix .. cbPrefix + 8][0..8]),
    );
}

fn SymCryptHpkeAeadValidateBufferSizes(
    pHpkeContext: PCSYMCRYPT_HPKECONTEXT,
    cbPlaintext: SIZE_T,
    cbCiphertext: SIZE_T,
    cbAuthData: SIZE_T,
) SYMCRYPT_ERROR {
    if (cbCiphertext < pHpkeContext.aeadParams.cbTag) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbPlaintext != cbCiphertext - pHpkeContext.aeadParams.cbTag) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    return switch (@as(SYMCRYPT_HPKE_AEAD_ID, @fromBackingInt(@intCast(pHpkeContext.aeadParams.aeadId)))) {
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
        => {
            if ((@as(UINT64, cbPlaintext) > internal.SYMCRYPT_GCM_MAX_DATA_SIZE) or
                ((@as(UINT64, cbAuthData) >> 61) > 0))
            {
                return .SYMCRYPT_WRONG_DATA_SIZE;
            }
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 => {
            if (@as(UINT64, cbPlaintext) > internal.SYMCRYPT_CHACHA20_POLY1305_MAX_DATA_SIZE) {
                return .SYMCRYPT_WRONG_DATA_SIZE;
            }
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY => .SYMCRYPT_INVALID_ARGUMENT,
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    };
}

pub export fn SymCryptHpkeSeal(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pu64SeqNumber: ?*UINT64,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var nonce: [internal.SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&nonce), nonce.len);

    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);

    if (pHpkeContext.state != .SYMCRYPT_HPKE_CONTEXT_STATE_SENDER) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if ((pbSrc == null and cbSrc != 0) or
        (pbAuthData == null and cbAuthData != 0))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    // Validate AEAD size limits before consuming a sequence number.
    scError = SymCryptHpkeAeadValidateBufferSizes(pHpkeContext, cbSrc, cbDst, cbAuthData);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // Atomically increment sequence number and get the value before increment.
    // This makes Seal thread-safe.
    //
    const seqNum: UINT64 = @atomicRmw(UINT64, &pHpkeContext.seqNum, .Add, 1, .monotonic);
    if (seqNum >= internal.SYMCRYPT_HPKE_SEQ_LIMIT) {
        return .SYMCRYPT_INVALID_ARGUMENT; // Sequence number exhausted
    }

    SymCryptHpkeComputeNonce(
        &pHpkeContext.baseNonce,
        pHpkeContext.aeadParams.cbNonce,
        seqNum,
        &nonce,
    );

    switch (@as(SYMCRYPT_HPKE_AEAD_ID, @fromBackingInt(@intCast(pHpkeContext.aeadParams.aeadId)))) {
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
        => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded != 0);

            internal.SymCryptGcmEncrypt(
                &pHpkeContext.gcmExpandedKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbSrc,
                pbDst + cbSrc,
                pHpkeContext.aeadParams.cbTag,
            );
        },
        .SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded == 0);

            scError = internal.SymCryptChaCha20Poly1305Encrypt(
                &pHpkeContext.key,
                pHpkeContext.aeadParams.cbKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbSrc,
                pbDst + cbSrc,
                pHpkeContext.aeadParams.cbTag,
            );
            internal.SYMCRYPT_ASSERT(scError == .SYMCRYPT_NO_ERROR);
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    if (pu64SeqNumber) |pSeq| {
        pSeq.* = seqNum;
    }

    return scError;
}

pub export fn SymCryptHpkeOpen(
    pHpkeContext: PSYMCRYPT_HPKECONTEXT,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var nonce: [internal.SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&nonce), nonce.len);

    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);

    if (pHpkeContext.state != .SYMCRYPT_HPKE_CONTEXT_STATE_RECIPIENT) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pbAuthData == null and cbAuthData != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = SymCryptHpkeAeadValidateBufferSizes(pHpkeContext, cbDst, cbSrc, cbAuthData);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    // Open (ordered) is NOT thread-safe by design.
    const seqNum: UINT64 = pHpkeContext.seqNum;
    if (seqNum >= internal.SYMCRYPT_HPKE_SEQ_LIMIT) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    SymCryptHpkeComputeNonce(
        &pHpkeContext.baseNonce,
        pHpkeContext.aeadParams.cbNonce,
        seqNum,
        &nonce,
    );

    switch (@as(SYMCRYPT_HPKE_AEAD_ID, @fromBackingInt(@intCast(pHpkeContext.aeadParams.aeadId)))) {
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
        => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded != 0);

            scError = internal.SymCryptGcmDecrypt(
                &pHpkeContext.gcmExpandedKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbDst,
                pbSrc + cbDst,
                pHpkeContext.aeadParams.cbTag,
            );
        },
        .SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded == 0);

            scError = internal.SymCryptChaCha20Poly1305Decrypt(
                &pHpkeContext.key,
                pHpkeContext.aeadParams.cbKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbDst,
                pbSrc + cbDst,
                pHpkeContext.aeadParams.cbTag,
            );
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    if (scError == .SYMCRYPT_NO_ERROR) {
        // Only increment sequence number on successful decryption
        pHpkeContext.seqNum = seqNum + 1;
    }

    return scError;
}

pub export fn SymCryptHpkeOpenUnordered(
    pHpkeContext: PCSYMCRYPT_HPKECONTEXT,
    u64SeqNumber: UINT64,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: ?PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var nonce: [internal.SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&nonce), nonce.len);

    internal.SYMCRYPT_CHECK_MAGIC(pHpkeContext);

    if (pHpkeContext.state == .SYMCRYPT_HPKE_CONTEXT_STATE_UNINITIALIZED) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (u64SeqNumber >= internal.SYMCRYPT_HPKE_SEQ_LIMIT) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pbAuthData == null and cbAuthData != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    scError = SymCryptHpkeAeadValidateBufferSizes(pHpkeContext, cbDst, cbSrc, cbAuthData);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    SymCryptHpkeComputeNonce(
        &pHpkeContext.baseNonce,
        pHpkeContext.aeadParams.cbNonce,
        u64SeqNumber,
        &nonce,
    );

    switch (@as(SYMCRYPT_HPKE_AEAD_ID, @fromBackingInt(@intCast(pHpkeContext.aeadParams.aeadId)))) {
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        .SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
        => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded != 0);

            scError = internal.SymCryptGcmDecrypt(
                &pHpkeContext.gcmExpandedKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbDst,
                pbSrc + cbDst,
                pHpkeContext.aeadParams.cbTag,
            );
        },
        .SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 => {
            internal.SYMCRYPT_ASSERT(pHpkeContext.fGcmKeyExpanded == 0);

            scError = internal.SymCryptChaCha20Poly1305Decrypt(
                &pHpkeContext.key,
                pHpkeContext.aeadParams.cbKey,
                &nonce,
                pHpkeContext.aeadParams.cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbDst,
                pbSrc + cbDst,
                pHpkeContext.aeadParams.cbTag,
            );
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    return scError;
}
