//
// hpke_kem_dhkem.zig
//
// HPKE DHKEM support: DHKEM key lifecycle, deterministic key derivation,
// DHKEM Encap/Decap, and DHKEM ExtractAndExpand.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");
const ec_encoding = @import("ec_encoding.zig");
const hpke_kdf = @import("hpke_kdf.zig");

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
const SYMCRYPT_HPKEKEY_FORMAT = internal.SYMCRYPT_HPKEKEY_FORMAT;
const PCSYMCRYPT_HPKEKEY = internal.PCSYMCRYPT_HPKEKEY;
const SYMCRYPT_ECURVE_ID = internal.SYMCRYPT_ECURVE_ID;
const PSYMCRYPT_ECURVE = internal.PSYMCRYPT_ECURVE;
const PSYMCRYPT_ECKEY = internal.PSYMCRYPT_ECKEY;
const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT = internal.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT;
const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT = internal.SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT;
const SYMCRYPT_NUMBER_FORMAT = internal.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = internal.SYMCRYPT_ECPOINT_FORMAT;

const SYMCRYPT_HPKE_DHKEM_MAX_PRIVATE_KEY_SIZE: usize = internal.SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE;
const SYMCRYPT_HPKE_DHKEM_MAX_PUBLIC_KEY_SIZE: usize = internal.SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE;
const SYMCRYPT_HPKE_DHKEM_MAX_KEM_CONTEXT_SIZE: usize = 2 * SYMCRYPT_HPKE_DHKEM_MAX_PUBLIC_KEY_SIZE;
const SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE: usize = internal.SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE;

pub const SYMCRYPT_HPKE_DHKEM_PARAMS = extern struct {
    kemId: UINT16,
    kdfId: UINT16,
    cbRawSharedSecret: UINT16,
    cbPrivateKey: UINT16,
    cbPublicKey: UINT16,
    publicKeyFormat: SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT,
    privateKeyFormat: SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT,
    privateKeyNumberFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    ecurveId: SYMCRYPT_ECURVE_ID,
};
pub const PCSYMCRYPT_HPKE_DHKEM_PARAMS = *const SYMCRYPT_HPKE_DHKEM_PARAMS;

pub const SYMCRYPT_HPKE_DHKEMKEY = extern struct {
    pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS,
    pCurve: PSYMCRYPT_ECURVE,
    pEckey: PSYMCRYPT_ECKEY,
};
pub const PSYMCRYPT_HPKE_DHKEMKEY = *SYMCRYPT_HPKE_DHKEMKEY;
pub const PCSYMCRYPT_HPKE_DHKEMKEY = *const SYMCRYPT_HPKE_DHKEMKEY;

const SymCryptHpkeDhkemParamsP256 = SYMCRYPT_HPKE_DHKEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P256),
    .kdfId = @backingInt(SYMCRYPT_HPKE_KDF_ID.SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256),
    .cbRawSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .publicKeyFormat = .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat = .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId = .SYMCRYPT_ECURVE_ID_NIST_P256,
};

const SymCryptHpkeDhkemParamsP384 = SYMCRYPT_HPKE_DHKEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P384),
    .kdfId = @backingInt(SYMCRYPT_HPKE_KDF_ID.SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384),
    .cbRawSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .publicKeyFormat = .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat = .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId = .SYMCRYPT_ECURVE_ID_NIST_P384,
};

const SymCryptHpkeDhkemParamsP521 = SYMCRYPT_HPKE_DHKEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P521),
    .kdfId = @backingInt(SYMCRYPT_HPKE_KDF_ID.SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512),
    .cbRawSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .publicKeyFormat = .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED,
    .privateKeyFormat = .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR,
    .privateKeyNumberFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
    .ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY,
    .ecurveId = .SYMCRYPT_ECURVE_ID_NIST_P521,
};

const SymCryptHpkeDhkemParamsX25519 = SYMCRYPT_HPKE_DHKEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519),
    .kdfId = @backingInt(SYMCRYPT_HPKE_KDF_ID.SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256),
    .cbRawSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .publicKeyFormat = .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE,
    .privateKeyFormat = .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519,
    .privateKeyNumberFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
    .ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X,
    .ecurveId = .SYMCRYPT_ECURVE_ID_CURVE25519,
};

fn SymCryptHpkeDhkemParamsFromId(
    kemId: UINT16,
) ?PCSYMCRYPT_HPKE_DHKEM_PARAMS {
    return switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256 => &SymCryptHpkeDhkemParamsP256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384 => &SymCryptHpkeDhkemParamsP384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521 => &SymCryptHpkeDhkemParamsP521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519 => &SymCryptHpkeDhkemParamsX25519,
        else => null,
    };
}

pub export fn SymCryptHpkeDhkemkeyAllocate(
    kemId: UINT16,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_HPKE_DHKEMKEY {
    const pParams = SymCryptHpkeDhkemParamsFromId(kemId) orelse return null;
    const pCurveParams = internal.SymCryptGetEcurveParams(pParams.ecurveId) orelse return null;

    const pCurve = internal.SymCryptEcurveAllocate(pCurveParams, 0) orelse return null;
    errdefer internal.SymCryptEcurveFree(pCurve);

    const pEckey = internal.SymCryptEckeyAllocate(pCurve) orelse {
        internal.SymCryptEcurveFree(pCurve);
        return null;
    };

    const pMem = internal.SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_HPKE_DHKEMKEY)) orelse {
        internal.SymCryptEckeyFree(pEckey);
        internal.SymCryptEcurveFree(pCurve);
        return null;
    };

    const pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY = @ptrCast(@alignCast(pMem));
    internal.SymCryptWipeKnownSize(pMem, @sizeOf(SYMCRYPT_HPKE_DHKEMKEY));

    pkDhkemkey.pParams = pParams;
    pkDhkemkey.pCurve = pCurve;
    pkDhkemkey.pEckey = pEckey;

    return pkDhkemkey;
}

pub export fn SymCryptHpkeDhkemkeyFree(
    pkDhkemkey: ?PSYMCRYPT_HPKE_DHKEMKEY,
) callconv(SYMCRYPT_CALL) void {
    const pKey = pkDhkemkey orelse return;

    internal.SymCryptEckeyFree(pKey.pEckey);
    internal.SymCryptEcurveFree(pKey.pCurve);

    internal.SymCryptWipeKnownSize(@ptrCast(pKey), @sizeOf(SYMCRYPT_HPKE_DHKEMKEY));
    internal.SymCryptCallbackFree(@ptrCast(pKey));
}

pub export fn SymCryptHpkeDhkemkeyGenerate(
    pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return internal.SymCryptEckeySetRandom(
        internal.SYMCRYPT_FLAG_ECKEY_ECDH | flags,
        pkDhkemkey.pEckey,
    );
}

pub export fn SymCryptHpkeDhkemkeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    hpkeKeyFormat: SYMCRYPT_HPKEKEY_FORMAT,
    flags: UINT32,
    pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return switch (hpkeKeyFormat) {
        .SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY => ec_encoding.SymCryptEckeySetValueIetfPrivateKey(
            pbSrc,
            cbSrc,
            pkDhkemkey.pParams.privateKeyFormat,
            internal.SYMCRYPT_FLAG_ECKEY_ECDH | flags,
            pkDhkemkey.pEckey,
        ),
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY => ec_encoding.SymCryptEckeySetValueIetfPublicKey(
            pbSrc,
            cbSrc,
            pkDhkemkey.pParams.publicKeyFormat,
            internal.SYMCRYPT_FLAG_ECKEY_ECDH | flags,
            pkDhkemkey.pEckey,
        ),
        else => .SYMCRYPT_INVALID_ARGUMENT,
    };
}

pub export fn SymCryptHpkeDhkemkeyGetValue(
    pkDhkemkey: PCSYMCRYPT_HPKE_DHKEMKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    hpkeKeyFormat: SYMCRYPT_HPKEKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    switch (hpkeKeyFormat) {
        .SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY => {
            if (cbDst != pkDhkemkey.pParams.cbPrivateKey) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
            return internal.SymCryptEckeyGetValue(
                pkDhkemkey.pEckey,
                pbDst,
                cbDst,
                null,
                0,
                pkDhkemkey.pParams.privateKeyNumberFormat,
                pkDhkemkey.pParams.ecPointFormat,
                0,
            );
        },
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY => {
            return ec_encoding.SymCryptEckeyGetValueIetfPublicKey(
                pkDhkemkey.pEckey,
                pkDhkemkey.pParams.publicKeyFormat,
                pbDst,
                cbDst,
            );
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

fn SymCryptHpkeDhkemDeriveNistKeyPair(
    pbIkm: PCBYTE,
    cbIkm: SIZE_T,
    pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY,
) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var kemSuiteId: [internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE]BYTE = undefined;
    var dkpPrk: [internal.SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE = undefined;
    var candidate: [SYMCRYPT_HPKE_DHKEM_MAX_PRIVATE_KEY_SIZE]BYTE = undefined;
    var fFound: bool = false;
    const pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS = pkDhkemkey.pParams;
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pParams.kdfId));
    const cbDkpPrk: UINT16 = hpke_kdf.SymCryptHpkeKdfOutputSizeFromId(kdfId);

    defer {
        internal.SymCryptWipeKnownSize(@ptrCast(&candidate), candidate.len);
        internal.SymCryptWipeKnownSize(@ptrCast(&dkpPrk), dkpPrk.len);
    }

    hpke_kdf.SymCryptHpkeBuildKemSuiteId(pParams.kemId, &kemSuiteId);

    scError = hpke_kdf.SymCryptHpkeLabeledExtract(
        kdfId,
        &kemSuiteId,
        internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        null,
        0,
        "dkp_prk",
        7,
        pbIkm,
        cbIkm,
        &dkpPrk,
        cbDkpPrk,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var counter: UINT32 = 0;
    while (counter <= 255) : (counter += 1) {
        var counterByte: [1]BYTE = .{@intCast(counter)};

        scError = hpke_kdf.SymCryptHpkeLabeledExpand(
            kdfId,
            &kemSuiteId,
            internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
            &dkpPrk,
            cbDkpPrk,
            "candidate",
            9,
            &counterByte,
            1,
            &candidate,
            pParams.cbPrivateKey,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        // Special case for P521 because its group order is 521-bits which is
        // 1 modulo 8; we must mask out the most-significant 7 bits
        if (pParams.kemId == @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P521)) {
            candidate[0] &= 0x01;
        }

        scError = internal.SymCryptEckeySetValue(
            &candidate,
            pParams.cbPrivateKey,
            null,
            0,
            pParams.privateKeyNumberFormat,
            pParams.ecPointFormat,
            internal.SYMCRYPT_FLAG_ECKEY_ECDH,
            pkDhkemkey.pEckey,
        );
        if (scError == .SYMCRYPT_NO_ERROR) {
            fFound = true;
            break;
        }

        internal.SYMCRYPT_ASSERT(scError == .SYMCRYPT_INVALID_ARGUMENT);
        if (scError != .SYMCRYPT_INVALID_ARGUMENT) {
            return scError;
        }
    }

    if (!fFound) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    }

    return scError;
}

fn SymCryptHpkeDhkemDeriveX25519KeyPair(
    pbIkm: PCBYTE,
    cbIkm: SIZE_T,
    pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY,
) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var kemSuiteId: [internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE]BYTE = undefined;
    var dkpPrk: [internal.SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE = undefined;
    var privateScalar: [internal.SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE]BYTE = undefined;
    const pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS = pkDhkemkey.pParams;
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pParams.kdfId));
    const cbDkpPrk: UINT16 = hpke_kdf.SymCryptHpkeKdfOutputSizeFromId(kdfId);

    defer {
        internal.SymCryptWipeKnownSize(@ptrCast(&privateScalar), privateScalar.len);
        internal.SymCryptWipeKnownSize(@ptrCast(&dkpPrk), dkpPrk.len);
    }

    hpke_kdf.SymCryptHpkeBuildKemSuiteId(pParams.kemId, &kemSuiteId);

    scError = hpke_kdf.SymCryptHpkeLabeledExtract(
        kdfId,
        &kemSuiteId,
        internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        null,
        0,
        "dkp_prk",
        7,
        pbIkm,
        cbIkm,
        &dkpPrk,
        cbDkpPrk,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = hpke_kdf.SymCryptHpkeLabeledExpand(
        kdfId,
        &kemSuiteId,
        internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        &dkpPrk,
        cbDkpPrk,
        "sk",
        2,
        null,
        0,
        &privateScalar,
        privateScalar.len,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = ec_encoding.SymCryptEckeySetValueIetfPrivateKey(
        &privateScalar,
        privateScalar.len,
        pParams.privateKeyFormat,
        internal.SYMCRYPT_FLAG_ECKEY_ECDH,
        pkDhkemkey.pEckey,
    );

    return scError;
}

pub export fn SymCryptHpkeDhkemDeriveKeyPair(
    pbIkm: PCBYTE,
    cbIkm: SIZE_T,
    pkDhkemkey: PSYMCRYPT_HPKE_DHKEMKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkDhkemkey.pParams.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        => SymCryptHpkeDhkemDeriveNistKeyPair(pbIkm, cbIkm, pkDhkemkey),
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519 => SymCryptHpkeDhkemDeriveX25519KeyPair(pbIkm, cbIkm, pkDhkemkey),
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    };
}

fn SymCryptHpkeDhkemDeriveSharedSecret(
    pkRecipientKey: PCSYMCRYPT_HPKEKEY,
    pbRawSharedSecret: PCBYTE,
    cbRawSharedSecret: SIZE_T,
    pbEnc: PCBYTE,
    cbEnc: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var prk: [internal.SYMCRYPT_MAC_MAX_RESULT_SIZE]BYTE = undefined;
    var kemSuiteId: [internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE]BYTE = undefined;
    var kemContext: [SYMCRYPT_HPKE_DHKEM_MAX_KEM_CONTEXT_SIZE]BYTE = undefined; // enc || pkR
    const pkDhkemkey: PCSYMCRYPT_HPKE_DHKEMKEY = @ptrCast(@alignCast(pkRecipientKey.pKemKeyData.?));
    const pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS = pkDhkemkey.pParams;
    const kdfId: SYMCRYPT_HPKE_KDF_ID = @fromBackingInt(@intCast(pParams.kdfId));
    const cbPrk: SIZE_T = hpke_kdf.SymCryptHpkeKdfOutputSizeFromId(kdfId);

    defer {
        internal.SymCryptWipeKnownSize(@ptrCast(&prk), prk.len);
        internal.SymCryptWipeKnownSize(@ptrCast(&kemContext), kemContext.len);
    }

    internal.SYMCRYPT_ASSERT(pParams.kemId == pkRecipientKey.ciphersuite.kemId);

    hpke_kdf.SymCryptHpkeBuildKemSuiteId(pkRecipientKey.ciphersuite.kemId, &kemSuiteId);

    //
    // kem_context = enc || SerializePublicKey(pkR)
    //
    const cbKemContext: SIZE_T = cbEnc + pParams.cbPublicKey;
    internal.SYMCRYPT_ASSERT(cbKemContext <= kemContext.len);

    @memcpy(kemContext[0..cbEnc], pbEnc[0..cbEnc]);
    scError = SymCryptHpkeDhkemkeyGetValue(
        pkDhkemkey,
        kemContext[cbEnc..].ptr,
        pParams.cbPublicKey,
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY,
        0,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // eae_prk = LabeledExtract("", "eae_prk", dh)
    //
    scError = hpke_kdf.SymCryptHpkeLabeledExtract(
        kdfId,
        &kemSuiteId,
        internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        null,
        0, // empty salt
        "eae_prk",
        7,
        pbRawSharedSecret,
        cbRawSharedSecret,
        &prk,
        cbPrk,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    //
    // shared_secret = LabeledExpand(eae_prk, "shared_secret", kem_context, Nsecret)
    //
    scError = hpke_kdf.SymCryptHpkeLabeledExpand(
        kdfId,
        &kemSuiteId,
        internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
        &prk,
        cbPrk,
        "shared_secret",
        13,
        &kemContext,
        cbKemContext,
        pbSharedSecret,
        cbSharedSecret,
    );

    return scError;
}

pub export fn SymCryptHpkeDhkemEncapsulate(
    pkRecipientKey: PCSYMCRYPT_HPKEKEY,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
    pbEnc: PBYTE,
    cbEnc: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptHpkeDhkemEncapsulateEx(
        pkRecipientKey,
        null,
        0,
        pbSharedSecret,
        cbSharedSecret,
        pbEnc,
        cbEnc,
    );
}

pub export fn SymCryptHpkeDhkemEncapsulateEx(
    pkRecipientKey: PCSYMCRYPT_HPKEKEY,
    pbIkmE: ?PCBYTE,
    cbIkmE: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
    pbEnc: PBYTE,
    cbEnc: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    const pkRecipientDhkemKey: PCSYMCRYPT_HPKE_DHKEMKEY = @ptrCast(@alignCast(pkRecipientKey.pKemKeyData.?));
    var pkEphemeralEckey: ?PSYMCRYPT_ECKEY = null;
    var rawSharedSecret: [SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE]BYTE = undefined;
    const pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS = pkRecipientDhkemKey.pParams;

    defer {
        if (pkEphemeralEckey) |pEph| {
            internal.SymCryptEckeyFree(pEph);
        }
        internal.SymCryptWipeKnownSize(@ptrCast(&rawSharedSecret), rawSharedSecret.len);
    }

    internal.SYMCRYPT_ASSERT(pParams.kemId == pkRecipientKey.ciphersuite.kemId);

    pkEphemeralEckey = internal.SymCryptEckeyAllocate(pkRecipientDhkemKey.pCurve);
    if (pkEphemeralEckey == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    if (pbIkmE) |pbIkm| {
        var senderDhkemKey = SYMCRYPT_HPKE_DHKEMKEY{
            .pParams = pkRecipientDhkemKey.pParams,
            .pCurve = pkRecipientDhkemKey.pCurve,
            .pEckey = pkEphemeralEckey.?,
        };
        scError = SymCryptHpkeDhkemDeriveKeyPair(pbIkm, cbIkmE, &senderDhkemKey);
    } else {
        scError = internal.SymCryptEckeySetRandom(internal.SYMCRYPT_FLAG_ECKEY_ECDH, pkEphemeralEckey.?);
    }
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = internal.SymCryptEcDhSecretAgreement(
        pkEphemeralEckey.?,
        pkRecipientDhkemKey.pEckey,
        pParams.privateKeyNumberFormat,
        0,
        &rawSharedSecret,
        pParams.cbRawSharedSecret,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = ec_encoding.SymCryptEckeyGetValueIetfPublicKey(
        pkEphemeralEckey.?,
        pParams.publicKeyFormat,
        pbEnc,
        cbEnc,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptHpkeDhkemDeriveSharedSecret(
        pkRecipientKey,
        &rawSharedSecret,
        pParams.cbRawSharedSecret,
        pbEnc,
        cbEnc,
        pbSharedSecret,
        cbSharedSecret,
    );

    return scError;
}

pub export fn SymCryptHpkeDhkemDecapsulate(
    pkRecipientKey: PCSYMCRYPT_HPKEKEY,
    pbEnc: PCBYTE,
    cbEnc: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    const pkRecipientDhkemKey: PCSYMCRYPT_HPKE_DHKEMKEY = @ptrCast(@alignCast(pkRecipientKey.pKemKeyData.?));
    var pkEphemeralEckey: ?PSYMCRYPT_ECKEY = null;
    var rawSharedSecret: [SYMCRYPT_HPKE_DHKEM_MAX_RAW_SHARED_SECRET_SIZE]BYTE = undefined;
    const pParams: PCSYMCRYPT_HPKE_DHKEM_PARAMS = pkRecipientDhkemKey.pParams;

    defer {
        if (pkEphemeralEckey) |pEph| {
            internal.SymCryptEckeyFree(pEph);
        }
        internal.SymCryptWipeKnownSize(@ptrCast(&rawSharedSecret), rawSharedSecret.len);
    }

    internal.SYMCRYPT_ASSERT(pParams.kemId == pkRecipientKey.ciphersuite.kemId);

    pkEphemeralEckey = internal.SymCryptEckeyAllocate(pkRecipientDhkemKey.pCurve);
    if (pkEphemeralEckey == null) {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    }

    scError = ec_encoding.SymCryptEckeySetValueIetfPublicKey(
        pbEnc,
        cbEnc,
        pParams.publicKeyFormat,
        internal.SYMCRYPT_FLAG_ECKEY_ECDH,
        pkEphemeralEckey.?,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = internal.SymCryptEcDhSecretAgreement(
        pkRecipientDhkemKey.pEckey,
        pkEphemeralEckey.?,
        pParams.privateKeyNumberFormat,
        0,
        &rawSharedSecret,
        pParams.cbRawSharedSecret,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    scError = SymCryptHpkeDhkemDeriveSharedSecret(
        pkRecipientKey,
        &rawSharedSecret,
        pParams.cbRawSharedSecret,
        pbEnc,
        cbEnc,
        pbSharedSecret,
        cbSharedSecret,
    );

    return scError;
}
