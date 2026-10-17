//
// ec_encoding.zig
//
// IETF-standard EC encoding helpers. Thin wrappers around
// SymCryptEckey{Get,Set}Value that pre/post-process the wire format
// expected by IETF protocols built on top of SymCrypt's primitives.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const internal = @import("hpke_internal.zig");

const BYTE = internal.BYTE;
const PBYTE = internal.PBYTE;
const PCBYTE = internal.PCBYTE;
const UINT32 = internal.UINT32;
const SIZE_T = internal.SIZE_T;
const SYMCRYPT_CALL = internal.SYMCRYPT_CALL;
const SYMCRYPT_ERROR = internal.SYMCRYPT_ERROR;
const PSYMCRYPT_ECKEY = internal.PSYMCRYPT_ECKEY;
const PCSYMCRYPT_ECKEY = internal.PCSYMCRYPT_ECKEY;
const SYMCRYPT_NUMBER_FORMAT = internal.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = internal.SYMCRYPT_ECPOINT_FORMAT;
const SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT = internal.SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT;
const SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT = internal.SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT;

const SEC1_TAG_UNCOMPRESSED: BYTE = 0x04;
const CURVE25519_PRIVATE_KEY_SIZE: SIZE_T = 32;

pub export fn SymCryptEckeySetValueIetfPrivateKey(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    format: SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = undefined;
    var cbPrivateKey: SIZE_T = undefined;
    var pbPrivateKey: PCBYTE = pbSrc;
    var privateKey: [CURVE25519_PRIVATE_KEY_SIZE]BYTE = undefined;
    var numFormat: SYMCRYPT_NUMBER_FORMAT = undefined;
    var ecPointFormat: SYMCRYPT_ECPOINT_FORMAT = undefined;

    defer internal.SymCryptWipeKnownSize(@ptrCast(&privateKey), privateKey.len);

    switch (format) {
        .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_NIST_SCALAR => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY;
            cbPrivateKey = internal.SymCryptEckeySizeofPrivateKey(pEckey);
        },
        .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519 => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X;
            cbPrivateKey = internal.SymCryptEckeySizeofPrivateKey(pEckey);
            if (cbPrivateKey != privateKey.len) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    if (cbSrc != cbPrivateKey) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    if (format == .SYMCRYPT_ECKEY_IETF_PRIVATE_KEY_FORMAT_C25519) {
        // SymCrypt expects the key to already be clamped for Curve25519
        @memcpy(privateKey[0..cbSrc], pbSrc[0..cbSrc]);
        privateKey[0] &= 0xF8;
        privateKey[31] &= 0x7F;
        privateKey[31] |= 0x40;
        pbPrivateKey = &privateKey;
    }

    scError = internal.SymCryptEckeySetValue(
        pbPrivateKey,
        cbPrivateKey,
        null,
        0,
        numFormat,
        ecPointFormat,
        flags,
        pEckey,
    );

    return scError;
}

pub export fn SymCryptEckeySetValueIetfPublicKey(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    format: SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbCurr: PCBYTE = pbSrc;
    var cbPayload: SIZE_T = undefined;
    var numFormat: SYMCRYPT_NUMBER_FORMAT = undefined;
    var ecPointFormat: SYMCRYPT_ECPOINT_FORMAT = undefined;

    switch (format) {
        .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY;
            cbPayload = internal.SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat);

            if (cbSrc != cbPayload + 1) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
            if (pbCurr[0] != SEC1_TAG_UNCOMPRESSED) {
                return .SYMCRYPT_INVALID_BLOB;
            }
            pbCurr += 1;
        },
        .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X;
            cbPayload = internal.SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat);

            if (cbSrc != cbPayload) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    return internal.SymCryptEckeySetValue(
        null,
        0,
        pbCurr,
        cbPayload,
        numFormat,
        ecPointFormat,
        flags,
        pEckey,
    );
}

pub export fn SymCryptEckeyGetValueIetfPublicKey(
    pEckey: PCSYMCRYPT_ECKEY,
    format: SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbCurr: PBYTE = pbDst;
    var cbPayload: SIZE_T = undefined;
    var numFormat: SYMCRYPT_NUMBER_FORMAT = undefined;
    var ecPointFormat: SYMCRYPT_ECPOINT_FORMAT = undefined;

    switch (format) {
        .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_SEC1_UNCOMPRESSED => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY;
            cbPayload = internal.SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat);

            if (cbDst != cbPayload + 1) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
            pbCurr[0] = SEC1_TAG_UNCOMPRESSED;
            pbCurr += 1;
        },
        .SYMCRYPT_ECKEY_IETF_PUBLIC_KEY_FORMAT_RAW_X_LE => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X;
            cbPayload = internal.SymCryptEckeySizeofPublicKey(pEckey, ecPointFormat);

            if (cbDst != cbPayload) {
                return .SYMCRYPT_WRONG_KEY_SIZE;
            }
        },
        else => {
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    return internal.SymCryptEckeyGetValue(
        pEckey,
        null,
        0,
        pbCurr,
        cbPayload,
        numFormat,
        ecPointFormat,
        0,
    );
}
