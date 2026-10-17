//
// hpke_kem.zig
//
// HPKE KEM layer: per-KEM parameter table and ID lookup, Hpkekey lifecycle,
// KEM Encapsulate / Decapsulate dispatch, and KEM-dependent public size queries.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");
const hpke = @import("hpke.zig");
const hpke_kdf = @import("hpke_kdf.zig");
const dhkem = @import("hpke_kem_dhkem.zig");

const BYTE = internal.BYTE;
const PBYTE = internal.PBYTE;
const PCBYTE = internal.PCBYTE;
const UINT16 = internal.UINT16;
const UINT32 = internal.UINT32;
const SIZE_T = internal.SIZE_T;
const PSIZE_T = internal.PSIZE_T;
const SYMCRYPT_CALL = internal.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = internal.SYMCRYPT_ERROR;
const SYMCRYPT_HPKE_KEM_ID = internal.SYMCRYPT_HPKE_KEM_ID;
const SYMCRYPT_HPKE_KEM_PARAMS = internal.SYMCRYPT_HPKE_KEM_PARAMS;
const PCSYMCRYPT_HPKE_KEM_PARAMS = internal.PCSYMCRYPT_HPKE_KEM_PARAMS;
const SYMCRYPT_HPKE_CIPHERSUITE = internal.SYMCRYPT_HPKE_CIPHERSUITE;
const SYMCRYPT_HPKEKEY_FORMAT = internal.SYMCRYPT_HPKEKEY_FORMAT;
const SYMCRYPT_HPKEKEY = internal.SYMCRYPT_HPKEKEY;
const PSYMCRYPT_HPKEKEY = internal.PSYMCRYPT_HPKEKEY;
const PCSYMCRYPT_HPKEKEY = internal.PCSYMCRYPT_HPKEKEY;
const SYMCRYPT_MLKEMKEY_FORMAT = internal.SYMCRYPT_MLKEMKEY_FORMAT;
const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT = internal.SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT;

fn SymCryptHpkeToMlKemKeyFormat(
    format: SYMCRYPT_HPKEKEY_FORMAT,
) SYMCRYPT_MLKEMKEY_FORMAT {
    return switch (format) {
        .SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY => .SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY => .SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
        else => .SYMCRYPT_MLKEMKEY_FORMAT_NULL,
    };
}

fn SymCryptHpkeToCompositeMlKemKeyFormat(
    format: SYMCRYPT_HPKEKEY_FORMAT,
) SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT {
    return switch (format) {
        .SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY => .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED,
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY => .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY,
        else => .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL,
    };
}

const SymCryptHpkeKemParamsDhkemP256 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P256),
    .cbSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P256_SHARED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P256_PUBLIC_KEY_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P256_SCALAR_SIZE,
};

const SymCryptHpkeKemParamsDhkemP384 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P384),
    .cbSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P384_SHARED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P384_PUBLIC_KEY_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P384_SCALAR_SIZE,
};

const SymCryptHpkeKemParamsDhkemP521 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_P521),
    .cbSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_P521_SHARED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_P521_PUBLIC_KEY_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_P521_SCALAR_SIZE,
};

const SymCryptHpkeKemParamsDhkemX25519 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519),
    .cbSharedSecret = internal.SYMCRYPT_HPKE_DHKEM_X25519_SHARED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .cbPublicKey = internal.SYMCRYPT_HPKE_DHKEM_X25519_PUBLIC_KEY_SIZE,
    .cbPrivateKey = internal.SYMCRYPT_HPKE_DHKEM_X25519_SCALAR_SIZE,
};

const SymCryptHpkeKemParamsMlKem512 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM_512),
    .cbSharedSecret = internal.SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM512,
    .cbPublicKey = internal.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM512,
    .cbPrivateKey = internal.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
};

const SymCryptHpkeKemParamsMlKem768 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM_768),
    .cbSharedSecret = internal.SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM768,
    .cbPublicKey = internal.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM768,
    .cbPrivateKey = internal.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
};

const SymCryptHpkeKemParamsMlKem1024 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM_1024),
    .cbSharedSecret = internal.SYMCRYPT_MLKEM_AGREED_SECRET_SIZE,
    .cbEnc = internal.SYMCRYPT_MLKEM_CIPHERTEXT_SIZE_MLKEM1024,
    .cbPublicKey = internal.SYMCRYPT_MLKEM_ENCAPSULATION_KEY_SIZE_MLKEM1024,
    .cbPrivateKey = internal.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE,
};

const SymCryptHpkeKemParamsCompositeMlKem768P256 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256),
    .cbSharedSecret = 32,
    .cbEnc = internal.SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_P256,
    .cbPublicKey = internal.SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_P256,
    .cbPrivateKey = internal.SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
};

const SymCryptHpkeKemParamsCompositeMlKem1024P384 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384),
    .cbSharedSecret = 32,
    .cbEnc = internal.SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM1024_P384,
    .cbPublicKey = internal.SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM1024_P384,
    .cbPrivateKey = internal.SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
};

const SymCryptHpkeKemParamsCompositeMlKem768X25519 = SYMCRYPT_HPKE_KEM_PARAMS{
    .kemId = @backingInt(SYMCRYPT_HPKE_KEM_ID.SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519),
    .cbSharedSecret = 32,
    .cbEnc = internal.SYMCRYPT_COMPOSITE_MLKEM_CIPHERTEXT_SIZE_MLKEM768_X25519,
    .cbPublicKey = internal.SYMCRYPT_COMPOSITE_MLKEM_PUBLIC_KEY_SIZE_MLKEM768_X25519,
    .cbPrivateKey = internal.SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
};

pub export fn SymCryptHpkeKemParamsFromId(
    kemId: SYMCRYPT_HPKE_KEM_ID,
) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_HPKE_KEM_PARAMS {
    return switch (kemId) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256 => &SymCryptHpkeKemParamsDhkemP256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384 => &SymCryptHpkeKemParamsDhkemP384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521 => &SymCryptHpkeKemParamsDhkemP521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519 => &SymCryptHpkeKemParamsDhkemX25519,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512 => &SymCryptHpkeKemParamsMlKem512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768 => &SymCryptHpkeKemParamsMlKem768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024 => &SymCryptHpkeKemParamsMlKem1024,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256 => &SymCryptHpkeKemParamsCompositeMlKem768P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384 => &SymCryptHpkeKemParamsCompositeMlKem1024P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519 => &SymCryptHpkeKemParamsCompositeMlKem768X25519,
        else => null,
    };
}

pub export fn SymCryptHpkekeyAllocate(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_HPKEKEY {
    var kemParams: SYMCRYPT_HPKE_KEM_PARAMS = undefined;

    const scError = hpke.SymCryptHpkeValidateCiphersuite(params, &kemParams, null);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return null;
    }

    const pMem = internal.SymCryptCallbackAlloc(@sizeOf(SYMCRYPT_HPKEKEY)) orelse {
        return null;
    };
    const pKey: PSYMCRYPT_HPKEKEY = @ptrCast(@alignCast(pMem));
    internal.SymCryptWipe(pMem, @sizeOf(SYMCRYPT_HPKEKEY));

    pKey.ciphersuite = params;
    pKey.kemParams = kemParams;

    pKey.pKemKeyData = switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(params.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => if (dhkem.SymCryptHpkeDhkemkeyAllocate(params.kemId)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512 => if (internal.SymCryptMlKemkeyAllocate(.SYMCRYPT_MLKEM_PARAMS_MLKEM512)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768 => if (internal.SymCryptMlKemkeyAllocate(.SYMCRYPT_MLKEM_PARAMS_MLKEM768)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024 => if (internal.SymCryptMlKemkeyAllocate(.SYMCRYPT_MLKEM_PARAMS_MLKEM1024)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256 => if (internal.SymCryptCompositeMlKemkeyAllocate(.SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384 => if (internal.SymCryptCompositeMlKemkeyAllocate(.SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384)) |p| @ptrCast(p) else null,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519 => if (internal.SymCryptCompositeMlKemkeyAllocate(.SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519)) |p| @ptrCast(p) else null,
        else => blk: {
            internal.SYMCRYPT_ASSERT(false);
            break :blk null;
        },
    };

    if (pKey.pKemKeyData == null) {
        internal.SymCryptCallbackFree(pMem);
        return null;
    }

    internal.SYMCRYPT_SET_MAGIC(pKey);
    return pKey;
}

pub export fn SymCryptHpkekeyFree(
    pkHpkekey: ?PSYMCRYPT_HPKEKEY,
) callconv(SYMCRYPT_CALL) void {
    const pKey = pkHpkekey orelse return;

    internal.SYMCRYPT_CHECK_MAGIC(pKey);

    if (pKey.pKemKeyData) |pData| {
        switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pKey.ciphersuite.kemId)))) {
            .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
            .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
            .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
            .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
            => dhkem.SymCryptHpkeDhkemkeyFree(@ptrCast(@alignCast(pData))),
            .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
            .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
            => internal.SymCryptMlKemkeyFree(@ptrCast(pData)),
            .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
            .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
            .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
            => internal.SymCryptCompositeMlKemkeyFree(@ptrCast(pData)),
            else => internal.SYMCRYPT_ASSERT(false),
        }
    }

    internal.SymCryptWipe(@ptrCast(pKey), @sizeOf(SYMCRYPT_HPKEKEY));
    internal.SymCryptCallbackFree(@ptrCast(pKey));
}

pub export fn SymCryptHpkekeyGenerate(
    pkHpkekey: PSYMCRYPT_HPKEKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    return switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => dhkem.SymCryptHpkeDhkemkeyGenerate(@ptrCast(@alignCast(pkHpkekey.pKemKeyData.?)), flags),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => internal.SymCryptMlKemkeyGenerate(@ptrCast(pkHpkekey.pKemKeyData.?), flags),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => internal.SymCryptCompositeMlKemkeyGenerate(@ptrCast(pkHpkekey.pKemKeyData.?), flags),
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    };
}

pub export fn SymCryptHpkekeySetValue(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    hpkeKeyFormat: SYMCRYPT_HPKEKEY_FORMAT,
    flags: UINT32,
    pkHpkekey: PSYMCRYPT_HPKEKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    if (hpkeKeyFormat == .SYMCRYPT_HPKEKEY_FORMAT_NULL) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => {
            return dhkem.SymCryptHpkeDhkemkeySetValue(
                pbSrc,
                cbSrc,
                hpkeKeyFormat,
                flags,
                @ptrCast(@alignCast(pkHpkekey.pKemKeyData.?)),
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => {
            const mlKemFormat = SymCryptHpkeToMlKemKeyFormat(hpkeKeyFormat);
            if (mlKemFormat == .SYMCRYPT_MLKEMKEY_FORMAT_NULL) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            return internal.SymCryptMlKemkeySetValue(
                pbSrc,
                cbSrc,
                mlKemFormat,
                flags,
                @ptrCast(pkHpkekey.pKemKeyData.?),
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => {
            const compositeMlKemFormat = SymCryptHpkeToCompositeMlKemKeyFormat(hpkeKeyFormat);
            if (compositeMlKemFormat == .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            return internal.SymCryptCompositeMlKemkeySetValue(
                pbSrc,
                cbSrc,
                compositeMlKemFormat,
                flags,
                @ptrCast(pkHpkekey.pKemKeyData.?),
            );
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }
}

pub export fn SymCryptHpkekeyGetValue(
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    hpkeKeyFormat: SYMCRYPT_HPKEKEY_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    if (hpkeKeyFormat == .SYMCRYPT_HPKEKEY_FORMAT_NULL) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => {
            return dhkem.SymCryptHpkeDhkemkeyGetValue(
                @ptrCast(@alignCast(pkHpkekey.pKemKeyData.?)),
                pbDst,
                cbDst,
                hpkeKeyFormat,
                flags,
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => {
            const mlKemFormat = SymCryptHpkeToMlKemKeyFormat(hpkeKeyFormat);
            if (mlKemFormat == .SYMCRYPT_MLKEMKEY_FORMAT_NULL) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            return internal.SymCryptMlKemkeyGetValue(
                @ptrCast(pkHpkekey.pKemKeyData.?),
                pbDst,
                cbDst,
                mlKemFormat,
                flags,
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => {
            const compositeMlKemFormat = SymCryptHpkeToCompositeMlKemKeyFormat(hpkeKeyFormat);
            if (compositeMlKemFormat == .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_NULL) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            return internal.SymCryptCompositeMlKemkeyGetValue(
                @ptrCast(pkHpkekey.pKemKeyData.?),
                pbDst,
                cbDst,
                compositeMlKemFormat,
                flags,
            );
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }
}

pub export fn SymCryptHpkekeyDerive(
    pbIkm: PCBYTE,
    cbIkm: SIZE_T,
    pkHpkekey: PSYMCRYPT_HPKEKEY,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var seed: [internal.SYMCRYPT_MLKEM_PRIVATE_SEED_SIZE]BYTE = undefined;
    var kemSuiteId: [internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE]BYTE = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&seed), seed.len);

    internal.SYMCRYPT_CHECK_MAGIC(pkHpkekey);

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbIkm == 0 or cbIkm > internal.SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    hpke_kdf.SymCryptHpkeBuildKemSuiteId(pkHpkekey.ciphersuite.kemId, &kemSuiteId);

    switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => {
            hpke_kdf.SymCryptHpkeLabeledDeriveOneStage(
                .SYMCRYPT_HPKE_KDF_ID_SHAKE256,
                &kemSuiteId,
                internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
                pbIkm,
                cbIkm,
                "DeriveKeyPair",
                13,
                null,
                0,
                &seed,
                seed.len,
            );

            scError = internal.SymCryptMlKemkeySetValue(
                &seed,
                seed.len,
                .SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
                0,
                @ptrCast(pkHpkekey.pKemKeyData.?),
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => {
            hpke_kdf.SymCryptHpkeLabeledDeriveOneStage(
                .SYMCRYPT_HPKE_KDF_ID_SHAKE256,
                &kemSuiteId,
                internal.SYMCRYPT_HPKE_KEM_SUITE_ID_SIZE,
                pbIkm,
                cbIkm,
                "DeriveKeyPair",
                13,
                null,
                0,
                &seed,
                internal.SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
            );

            scError = internal.SymCryptCompositeMlKemkeySetValue(
                &seed,
                internal.SYMCRYPT_COMPOSITE_MLKEM_IRTF_PRIVATE_SEED_SIZE,
                .SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED,
                0,
                @ptrCast(pkHpkekey.pKemKeyData.?),
            );
        },
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => {
            scError = dhkem.SymCryptHpkeDhkemDeriveKeyPair(
                pbIkm,
                cbIkm,
                @ptrCast(@alignCast(pkHpkekey.pKemKeyData.?)),
            );
        },
        else => {
            internal.SYMCRYPT_ASSERT(false);
            scError = .SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    return scError;
}

pub export fn SymCryptHpkeSizeofKeyFormatFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    hpkeKeyFormat: SYMCRYPT_HPKEKEY_FORMAT,
    pcbKeyFormat: PSIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pKemParams = SymCryptHpkeKemParamsFromId(@fromBackingInt(@intCast(params.kemId))) orelse {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    };

    switch (hpkeKeyFormat) {
        .SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY => {
            pcbKeyFormat.* = pKemParams.cbPrivateKey;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY => {
            pcbKeyFormat.* = pKemParams.cbPublicKey;
            return .SYMCRYPT_NO_ERROR;
        },
        else => return .SYMCRYPT_INCOMPATIBLE_FORMAT,
    }
}

pub export fn SymCryptHpkeSizeofEncapsCiphertextFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pcbEncapsCiphertext: PSIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pKemParams = SymCryptHpkeKemParamsFromId(@fromBackingInt(@intCast(params.kemId))) orelse {
        return .SYMCRYPT_NOT_IMPLEMENTED;
    };

    pcbEncapsCiphertext.* = pKemParams.cbEnc;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptHpkeKemEncapsulate(
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
    pbEnc: PBYTE,
    cbEnc: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => dhkem.SymCryptHpkeDhkemEncapsulate(
            pkHpkekey,
            pbSharedSecret,
            cbSharedSecret,
            pbEnc,
            cbEnc,
        ),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => internal.SymCryptMlKemEncapsulate(
            @ptrCast(pkHpkekey.pKemKeyData.?),
            pbSharedSecret,
            cbSharedSecret,
            pbEnc,
            cbEnc,
        ),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => internal.SymCryptCompositeMlKemEncapsulate(
            @ptrCast(pkHpkekey.pKemKeyData.?),
            pbSharedSecret,
            cbSharedSecret,
            pbEnc,
            cbEnc,
        ),
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    };
}

pub export fn SymCryptHpkeKemDecapsulate(
    pkHpkekey: PCSYMCRYPT_HPKEKEY,
    pbEnc: PCBYTE,
    cbEnc: SIZE_T,
    pbSharedSecret: PBYTE,
    cbSharedSecret: UINT16,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return switch (@as(SYMCRYPT_HPKE_KEM_ID, @fromBackingInt(@intCast(pkHpkekey.ciphersuite.kemId)))) {
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        .SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => dhkem.SymCryptHpkeDhkemDecapsulate(
            pkHpkekey,
            pbEnc,
            cbEnc,
            pbSharedSecret,
            cbSharedSecret,
        ),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => internal.SymCryptMlKemDecapsulate(
            @ptrCast(pkHpkekey.pKemKeyData.?),
            pbEnc,
            cbEnc,
            pbSharedSecret,
            cbSharedSecret,
        ),
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        .SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => internal.SymCryptCompositeMlKemDecapsulate(
            @ptrCast(pkHpkekey.pKemKeyData.?),
            pbEnc,
            cbEnc,
            pbSharedSecret,
            cbSharedSecret,
        ),
        else => {
            internal.SYMCRYPT_ASSERT(false);
            return .SYMCRYPT_NOT_IMPLEMENTED;
        },
    };
}
