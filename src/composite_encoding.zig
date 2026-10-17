//
// composite_encoding.zig   Shared encoding/decoding functionality for composite algorithms
//                          according to draft-ietf-lamps-pq-composite-kem-12.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_ECPOINT_FORMAT = types.SYMCRYPT_ECPOINT_FORMAT;
const SYMCRYPT_CACHED_ECURVE_ID = types.SYMCRYPT_CACHED_ECURVE_ID;

pub const SYMCRYPT_ECURVE = types.SYMCRYPT_ECURVE;
pub const PCSYMCRYPT_ECURVE = types.PCSYMCRYPT_ECURVE;

pub const SYMCRYPT_ECKEY = types.SYMCRYPT_ECKEY;
pub const PSYMCRYPT_ECKEY = types.PSYMCRYPT_ECKEY;
pub const PCSYMCRYPT_ECKEY = types.PCSYMCRYPT_ECKEY;

pub extern fn SymCryptGetCachedEcurve(curveId: SYMCRYPT_CACHED_ECURVE_ID) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_ECURVE;
pub extern fn SymCryptEckeySizeofPrivateKey(pkEckey: PCSYMCRYPT_ECKEY) callconv(SYMCRYPT_CALL) UINT32;
pub extern fn SymCryptEckeyGetValue(
    pkEckey: PCSYMCRYPT_ECKEY,
    pbPrivateKey: ?PBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
pub extern fn SymCryptEckeySetValue(
    pbPrivateKey: ?PCBYTE,
    cbPrivateKey: SIZE_T,
    pbPublicKey: ?PCBYTE,
    cbPublicKey: SIZE_T,
    numFormat: SYMCRYPT_NUMBER_FORMAT,
    ecPointFormat: SYMCRYPT_ECPOINT_FORMAT,
    flags: UINT32,
    pkEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256: UINT32 = 65;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384: UINT32 = 97;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_CURVE_25519: UINT32 = 32;

pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256: UINT32 = 51;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384: UINT32 = 64;
pub const SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_CURVE_25519: UINT32 = 32;

const DER_TAG_SEQUENCE: BYTE = 0x30;
const DER_TAG_INTEGER: BYTE = 0x02;
const DER_TAG_OCTET_STRING: BYTE = 0x04;
const DER_TAG_OID: BYTE = 0x06;
const DER_TAG_CONTEXT_0: BYTE = 0xA0;

const DER_INTEGER_VERSION_1: BYTE = 0x01;

const MAX_SINGLE_BYTE_LENGTH: usize = 127;
const MAX_ENCODING_LENGTH: usize = 2 + MAX_SINGLE_BYTE_LENGTH;
const MAX_OID_LENGTH: usize = MAX_SINGLE_BYTE_LENGTH - 2;

const SEC1_TAG_UNCOMPRESSED: BYTE = 0x04;

const rgbOidP256 = [_]BYTE{ 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const rgbOidP384 = [_]BYTE{ 0x2B, 0x81, 0x04, 0x00, 0x22 };

inline fn nistEcSkDerExpectedEncodingSize(cbPrivateKey: SIZE_T, cbOid: SIZE_T) SIZE_T {
    return 2 + 3 + (2 + cbPrivateKey) + 2 + (2 + cbOid);
}

pub export fn SymCryptCompositeGetSizeOfEncodedEcSk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
) callconv(SYMCRYPT_CALL) UINT32 {
    return switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P256,
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_P384,
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PRIVATE_KEY_CURVE_25519,
        else => blk: {
            macros.ASSERT(false);
            break :blk 0;
        },
    };
}

pub export fn SymCryptCompositeGetSizeOfEncodedEcPk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
) callconv(SYMCRYPT_CALL) UINT32 {
    return switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P256,
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_P384,
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => SYMCRYPT_COMPOSITE_SIZEOF_ENCODED_EC_PUBLIC_KEY_CURVE_25519,
        else => blk: {
            macros.ASSERT(false);
            break :blk 0;
        },
    };
}

fn SymCryptCompositeEncodeNistEcSkDer(
    pEckey: PCSYMCRYPT_ECKEY,
    pbOid: PCBYTE,
    cbOid: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) SYMCRYPT_ERROR {
    var pbCurr: PBYTE = pbDst;
    const cbPrivateKey: SIZE_T = SymCryptEckeySizeofPrivateKey(pEckey);
    const cbEncoding: SIZE_T = nistEcSkDerExpectedEncodingSize(cbPrivateKey, cbOid);

    macros.ASSERT(cbDst == cbEncoding);
    macros.ASSERT(cbEncoding <= MAX_ENCODING_LENGTH);
    macros.ASSERT(cbPrivateKey <= MAX_SINGLE_BYTE_LENGTH);
    macros.ASSERT(cbOid <= MAX_OID_LENGTH);

    pbCurr[0] = DER_TAG_SEQUENCE;
    pbCurr[1] = @intCast(cbEncoding - 2);
    pbCurr[2] = DER_TAG_INTEGER;
    pbCurr[3] = 0x01;
    pbCurr[4] = DER_INTEGER_VERSION_1;
    pbCurr[5] = DER_TAG_OCTET_STRING;
    pbCurr[6] = @intCast(cbPrivateKey);
    pbCurr += 7;

    const scError = SymCryptEckeyGetValue(
        pEckey,
        pbCurr,
        cbPrivateKey,
        null,
        0,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        0,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }
    pbCurr += cbPrivateKey;

    pbCurr[0] = DER_TAG_CONTEXT_0;
    pbCurr[1] = @intCast(cbOid + 2);
    pbCurr[2] = DER_TAG_OID;
    pbCurr[3] = @intCast(cbOid);
    pbCurr += 4;

    @memcpy(pbCurr[0..cbOid], pbOid[0..cbOid]);
    pbCurr += cbOid;

    macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbDst) + cbDst);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptEckeyGetValueCompositeEncodingSk(
    pEckey: PCSYMCRYPT_ECKEY,
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(pEckey.pCurve == SymCryptGetCachedEcurve(curveId));

    if (cbDst != SymCryptCompositeGetSizeOfEncodedEcSk(curveId)) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    var pbOid: PCBYTE = undefined;
    var cbOid: SIZE_T = 0;
    var fDoNistEcDerEncode: bool = false;

    switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 => {
            pbOid = &rgbOidP256;
            cbOid = rgbOidP256.len;
            fDoNistEcDerEncode = true;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => {
            pbOid = &rgbOidP384;
            cbOid = rgbOidP384.len;
            fDoNistEcDerEncode = true;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => {},
        else => {
            macros.ASSERT(false);
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    if (fDoNistEcDerEncode) {
        return SymCryptCompositeEncodeNistEcSkDer(pEckey, pbOid, cbOid, pbDst, cbDst);
    } else {
        return SymCryptEckeyGetValue(
            pEckey,
            pbDst,
            cbDst,
            null,
            0,
            .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            .SYMCRYPT_ECPOINT_FORMAT_X,
            0,
        );
    }
}

pub export fn SymCryptEckeyGetValueCompositeEncodingPk(
    pEckey: PCSYMCRYPT_ECKEY,
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbCurr: PBYTE = pbDst;
    var cbBytesToWrite: SIZE_T = SymCryptCompositeGetSizeOfEncodedEcPk(curveId);

    macros.ASSERT(pEckey.pCurve == SymCryptGetCachedEcurve(curveId));

    if (cbDst != cbBytesToWrite) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    var numFormat: SYMCRYPT_NUMBER_FORMAT = undefined;
    var ecPointFormat: SYMCRYPT_ECPOINT_FORMAT = undefined;

    switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
        => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY;

            pbCurr[0] = SEC1_TAG_UNCOMPRESSED;
            pbCurr += 1;
            cbBytesToWrite -= 1;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X;
        },
        else => {
            macros.ASSERT(false);
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    return SymCryptEckeyGetValue(
        pEckey,
        null,
        0,
        pbCurr,
        cbBytesToWrite,
        numFormat,
        ecPointFormat,
        0,
    );
}

pub export fn SymCryptEckeySetValueCompositeEncodingPk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbCurr: PCBYTE = pbSrc;
    var cbBytesToRead: SIZE_T = SymCryptCompositeGetSizeOfEncodedEcPk(curveId);

    macros.ASSERT(pEckey.pCurve == SymCryptGetCachedEcurve(curveId));

    if (cbSrc != cbBytesToRead) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    var numFormat: SYMCRYPT_NUMBER_FORMAT = undefined;
    var ecPointFormat: SYMCRYPT_ECPOINT_FORMAT = undefined;

    switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
        => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_XY;

            if (pbCurr[0] != SEC1_TAG_UNCOMPRESSED) {
                return .SYMCRYPT_INVALID_BLOB;
            }
            pbCurr += 1;
            cbBytesToRead -= 1;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => {
            numFormat = .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            ecPointFormat = .SYMCRYPT_ECPOINT_FORMAT_X;
        },
        else => {
            macros.ASSERT(false);
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    return SymCryptEckeySetValue(
        null,
        0,
        pbCurr,
        cbBytesToRead,
        numFormat,
        ecPointFormat,
        flags,
        pEckey,
    );
}

fn SymCryptCompositeDecodeNistEcSkDer(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbExpectedOid: PCBYTE,
    cbExpectedOid: SIZE_T,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) SYMCRYPT_ERROR {
    var pbCurr: PCBYTE = pbSrc;
    const cbPrivateKey: SIZE_T = SymCryptEckeySizeofPrivateKey(pEckey);

    macros.ASSERT(cbSrc == nistEcSkDerExpectedEncodingSize(cbPrivateKey, cbExpectedOid));
    macros.ASSERT(cbExpectedOid <= MAX_OID_LENGTH);
    macros.ASSERT(cbSrc <= MAX_ENCODING_LENGTH);
    macros.ASSERT(cbPrivateKey <= MAX_SINGLE_BYTE_LENGTH);

    if (pbCurr[0] != DER_TAG_SEQUENCE or pbCurr[1] != @as(BYTE, @intCast(cbSrc - 2))) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += 2;

    if (pbCurr[0] != DER_TAG_INTEGER or pbCurr[1] != 0x01 or pbCurr[2] != DER_INTEGER_VERSION_1) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += 3;

    if (pbCurr[0] != DER_TAG_OCTET_STRING) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    const cbParsedPrivateKey: SIZE_T = pbCurr[1];
    pbCurr += 2;

    const pbParsedPrivateKey: PCBYTE = pbCurr;
    if (cbParsedPrivateKey != cbPrivateKey) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += cbParsedPrivateKey;

    if (pbCurr[0] != DER_TAG_CONTEXT_0 or pbCurr[1] != @as(BYTE, @intCast(cbExpectedOid + 2))) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += 2;

    if (pbCurr[0] != DER_TAG_OID or pbCurr[1] != @as(BYTE, @intCast(cbExpectedOid))) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += 2;

    if (!std.mem.eql(u8, pbCurr[0..cbExpectedOid], pbExpectedOid[0..cbExpectedOid])) {
        return .SYMCRYPT_INVALID_BLOB;
    }
    pbCurr += cbExpectedOid;

    macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbSrc) + cbSrc);

    return SymCryptEckeySetValue(
        pbParsedPrivateKey,
        cbParsedPrivateKey,
        null,
        0,
        .SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        .SYMCRYPT_ECPOINT_FORMAT_XY,
        flags,
        pEckey,
    );
}

pub export fn SymCryptEckeySetValueCompositeEncodingSk(
    curveId: SYMCRYPT_CACHED_ECURVE_ID,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pEckey: PSYMCRYPT_ECKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(pEckey.pCurve == SymCryptGetCachedEcurve(curveId));

    if (cbSrc != SymCryptCompositeGetSizeOfEncodedEcSk(curveId)) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    var pbExpectedOid: PCBYTE = undefined;
    var cbExpectedOid: SIZE_T = 0;
    var fDoNistEcDerDecode: bool = false;

    switch (curveId) {
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P256 => {
            pbExpectedOid = &rgbOidP256;
            cbExpectedOid = rgbOidP256.len;
            fDoNistEcDerDecode = true;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => {
            pbExpectedOid = &rgbOidP384;
            cbExpectedOid = rgbOidP384.len;
            fDoNistEcDerDecode = true;
        },
        .SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => {},
        else => {
            macros.ASSERT(false);
            return .SYMCRYPT_INVALID_ARGUMENT;
        },
    }

    if (fDoNistEcDerDecode) {
        return SymCryptCompositeDecodeNistEcSkDer(
            pbSrc,
            cbSrc,
            pbExpectedOid,
            cbExpectedOid,
            flags,
            pEckey,
        );
    } else {
        return SymCryptEckeySetValue(
            pbSrc,
            cbSrc,
            null,
            0,
            .SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
            .SYMCRYPT_ECPOINT_FORMAT_X,
            flags,
            pEckey,
        );
    }
}

pub export fn SymCryptEcdsaSigValueCompositeEncode(
    pbRawSignature: PCBYTE,
    cbRawSignature: SIZE_T,
    pbEncodedSignature: PBYTE,
    cbEncodedSignature: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbRawInteger: SIZE_T = cbRawSignature / 2;

    pcbResult.* = 0;

    if (cbEncodedSignature < 8 or (cbRawSignature % 2) != 0 or cbRawInteger < 1) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    var cbSequence: SIZE_T = 2 * (1 + 1 + cbRawInteger);
    var pbInteger = [2]PCBYTE{ pbRawSignature, pbRawSignature + cbRawInteger };
    var cbInteger = [2]SIZE_T{ cbRawInteger, cbRawInteger };
    var bPadInteger = [2]bool{ false, false };
    var pbWrite: PBYTE = pbEncodedSignature;

    for (0..2) |i| {
        if ((pbInteger[i][0] & 0x80) != 0) {
            bPadInteger[i] = true;
            cbSequence += 1;
        } else {
            const pbIntegerOriginal = pbInteger[i];
            for (0..cbRawInteger - 1) |b| {
                if (pbIntegerOriginal[b] == 0 and (pbIntegerOriginal[b + 1] & 0x80) == 0) {
                    pbInteger[i] += 1;
                    cbInteger[i] -= 1;
                    cbSequence -= 1;
                } else {
                    break;
                }
            }
        }
    }

    if (cbSequence > cbEncodedSignature - 2) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    } else if (cbSequence > MAX_SINGLE_BYTE_LENGTH) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pbWrite[0] = DER_TAG_SEQUENCE;
    pbWrite[1] = @intCast(cbSequence);
    pbWrite += 2;

    for (0..2) |i| {
        pbWrite[0] = DER_TAG_INTEGER;
        pbWrite += 1;
        if (bPadInteger[i]) {
            pbWrite[0] = @intCast(cbInteger[i] + 1);
            pbWrite[1] = 0;
            pbWrite += 2;
        } else {
            pbWrite[0] = @intCast(cbInteger[i]);
            pbWrite += 1;
        }
        @memcpy(pbWrite[0..cbInteger[i]], pbInteger[i][0..cbInteger[i]]);
        pbWrite += cbInteger[i];
    }

    pcbResult.* = @intFromPtr(pbWrite) - @intFromPtr(pbEncodedSignature);
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptEcdsaSigValueCompositeDecode(
    pbEncodedSignature: PCBYTE,
    cbEncodedSignature: SIZE_T,
    pbRawSignature: PBYTE,
    cbRawSignature: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbRawInteger: SIZE_T = cbRawSignature / 2;

    if (cbEncodedSignature < 8 or (cbRawSignature % 2) != 0 or cbRawInteger < 1) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    var pbInteger: [2]PCBYTE = undefined;
    var cbInteger = [2]SIZE_T{ 0, 0 };
    var bPadInteger = [2]bool{ false, false };
    var pbRead: PCBYTE = pbEncodedSignature;
    var cbReadRemaining: SIZE_T = cbEncodedSignature;
    var pbWrite: PBYTE = pbRawSignature;

    if (pbRead[0] != DER_TAG_SEQUENCE) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    const cbSequence: SIZE_T = pbRead[1];
    pbRead += 2;
    cbReadRemaining -= 2;

    if (cbSequence > MAX_SINGLE_BYTE_LENGTH or cbSequence > cbReadRemaining) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    cbReadRemaining = cbSequence;

    for (0..2) |i| {
        if (cbReadRemaining < 3) {
            return .SYMCRYPT_INVALID_BLOB;
        }

        if (pbRead[0] != DER_TAG_INTEGER) {
            return .SYMCRYPT_INVALID_BLOB;
        }

        cbInteger[i] = pbRead[1];
        pbRead += 2;
        pbInteger[i] = pbRead;
        cbReadRemaining -= 2;

        if (cbInteger[i] > cbReadRemaining or
            cbInteger[i] > MAX_SINGLE_BYTE_LENGTH or
            cbInteger[i] < 1 or
            (pbInteger[i][0] & 0x80) != 0 or
            (pbInteger[i][0] == 0 and (cbInteger[i] < 2 or (pbInteger[i][1] & 0x80) == 0)))
        {
            return .SYMCRYPT_INVALID_BLOB;
        }

        if (cbInteger[i] > cbRawInteger) {
            if (cbInteger[i] == (cbRawInteger + 1) and pbInteger[i][0] == 0) {
                bPadInteger[i] = true;
            } else {
                return .SYMCRYPT_INVALID_BLOB;
            }
        }

        pbRead += cbInteger[i];
        cbReadRemaining -= cbInteger[i];
    }

    if (cbReadRemaining > 0) {
        return .SYMCRYPT_INVALID_BLOB;
    }

    for (0..2) |i| {
        if (bPadInteger[i]) {
            pbInteger[i] += 1;
            cbInteger[i] -= 1;
        }

        if (cbInteger[i] < cbRawInteger) {
            const cbZeros: SIZE_T = cbRawInteger - cbInteger[i];
            @memset(pbWrite[0..cbZeros], 0);
            pbWrite += cbZeros;
        }

        @memcpy(pbWrite[0..cbInteger[i]], pbInteger[i][0..cbInteger[i]]);
        pbWrite += cbInteger[i];
    }

    return .SYMCRYPT_NO_ERROR;
}
