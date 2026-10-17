//
// rsa_padding.zig   RSA padding algorithms
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const equal = @import("equal.zig");
const scs_tools = @import("scs_tools.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const PCSYMCRYPT_OID = types.PCSYMCRYPT_OID;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;

extern fn SymCryptCallbackRandom(pbBuffer: PBYTE, cbBuffer: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;

const ASN1_SEQUENCE_BYTE: BYTE = 0x30;
const ASN1_OCTET_STRING_BYTE: BYTE = 0x04;

const PKCS_BLOCKTYPE_1: BYTE = 0x01;
const PKCS_BLOCKTYPE_2: BYTE = 0x02;

pub export const SymCryptMd5OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 12, .pbOID = "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00" },
    .{ .cbOID = 10, .pbOID = "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05" },
};

pub export const SymCryptSha1OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 9, .pbOID = "\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00" },
    .{ .cbOID = 7, .pbOID = "\x06\x05\x2b\x0e\x03\x02\x1a" },
};

pub export const SymCryptSha224OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04" },
};

pub export const SymCryptSha256OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01" },
};

pub export const SymCryptSha384OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02" },
};

pub export const SymCryptSha512OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03" },
};

pub export const SymCryptSha512_224OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x05" },
};

pub export const SymCryptSha512_256OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06" },
};

pub export const SymCryptSha3_224OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07" },
};

pub export const SymCryptSha3_256OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08" },
};

pub export const SymCryptSha3_384OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09" },
};

pub export const SymCryptSha3_512OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a" },
};

pub export const SymCryptShake128OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0b" },
};

pub export const SymCryptShake256OidList = [2]SYMCRYPT_OID{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0c" },
};

pub export fn SymCryptRsaPaddingMaskGeneration(
    hashAlgorithm: PCSYMCRYPT_HASH,
    pHashState: PVOID,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var rgbHash: [hash.SYMCRYPT_HASH_MAX_RESULT_SIZE]BYTE = @splat(0);
    var rgbCount: [4]BYTE = @splat(0);
    var cbMaskRemaining: SIZE_T = cbDst;
    var pbMaskIndex: PBYTE = pbDst;

    const cbHashAlg: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    const cIterations: SIZE_T = (cbDst + (cbHashAlg - 1)) / cbHashAlg;

    var i: UINT32 = 0;
    while (i < cIterations) : (i += 1) {
        hash.SymCryptHashInit(hashAlgorithm, pHashState);
        hash.SymCryptHashAppend(hashAlgorithm, pHashState, pbSrc, cbSrc);

        macros.STORE_MSBFIRST32(&rgbCount, i);

        hash.SymCryptHashAppend(hashAlgorithm, pHashState, &rgbCount, @sizeOf(UINT32));

        if (cbMaskRemaining >= cbHashAlg) {
            hash.SymCryptHashResult(hashAlgorithm, pHashState, pbMaskIndex, cbHashAlg);

            cbMaskRemaining -= cbHashAlg;
            pbMaskIndex += cbHashAlg;
        } else {
            hash.SymCryptHashResult(hashAlgorithm, pHashState, &rgbHash, cbHashAlg);

            @memcpy(pbMaskIndex[0..cbMaskRemaining], rgbHash[0..cbMaskRemaining]);
            break;
        }
    }
}

pub export fn SymCryptRsaPkcs1ApplyEncryptionPadding(
    pbPlaintext: ?PCBYTE,
    cbPlaintext: SIZE_T,
    pbPkcs1Format: PBYTE,
    cbPkcs1Format: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if (cbPkcs1Format < (cbPlaintext + 11)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbPS: SIZE_T = cbPkcs1Format - (cbPlaintext + 3);

    pbPkcs1Format[0] = 0x00;
    pbPkcs1Format[1] = PKCS_BLOCKTYPE_2;

    scError = SymCryptCallbackRandom(pbPkcs1Format + 2, cbPS);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    var i: SIZE_T = 0;
    while (i < cbPS) : (i += 1) {
        while (pbPkcs1Format[2 + i] == 0x00) {
            scError = SymCryptCallbackRandom(pbPkcs1Format + 2 + i, 1);
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    pbPkcs1Format[2 + cbPS] = 0x00;

    if (cbPlaintext > 0) {
        @memcpy((pbPkcs1Format + 3 + cbPS)[0..cbPlaintext], pbPlaintext.?[0..cbPlaintext]);
    }

    return scError;
}

pub export fn SymCryptRsaPkcs1RemoveEncryptionPadding(
    pbPkcs1Format: PBYTE,
    cbPkcs1Format: SIZE_T,
    cbPkcs1Buffer: SIZE_T,
    pbPlaintext: ?PBYTE,
    cbPlaintext: SIZE_T,
    pcbPlaintext: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var mPaddingError: UINT32 = 0;
    var mBufferSizeError: UINT32 = 0;

    var cbPlaintextResult: UINT32 = 0;

    macros.SYMCRYPT_ASSERT(cbPkcs1Buffer >= cbPkcs1Format);
    macros.SYMCRYPT_ASSERT(cbPkcs1Buffer >= 32);
    macros.SYMCRYPT_ASSERT((cbPkcs1Buffer & (cbPkcs1Buffer - 1)) == 0);
    macros.SYMCRYPT_ASSERT(cbPkcs1Buffer <= (1 << 30));

    if (cbPkcs1Format < 11) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else {
        mPaddingError |= scs_tools.SymCryptMask32IsNonzeroU31(pbPkcs1Format[0]);
        mPaddingError |= scs_tools.SymCryptMask32NeqU31(pbPkcs1Format[1], PKCS_BLOCKTYPE_2);

        var iFirstZero: UINT32 = 0;
        var mLengthFound: UINT32 = 0;
        var i: UINT32 = 2;
        while (i < cbPkcs1Format) : (i += 1) {
            const mByteIsZero: UINT32 = scs_tools.SymCryptMask32IsZeroU31(pbPkcs1Format[i]);

            iFirstZero |= i & mByteIsZero & ~mLengthFound;
            mLengthFound |= mByteIsZero;
        }
        mPaddingError |= ~mLengthFound;

        mPaddingError |= scs_tools.SymCryptMask32LtU31(iFirstZero, 10);

        cbPlaintextResult = ~mPaddingError & (@as(UINT32, @intCast(cbPkcs1Format)) -% iFirstZero -% 1);

        if (pbPlaintext) |pbOut| {
            const cbPlaintextTruncated: UINT32 = @as(UINT32, @truncate(cbPlaintext)) & 0x7fffffff;
            if (cbPlaintextTruncated == cbPlaintext) {
                mBufferSizeError = scs_tools.SymCryptMask32LtU31(cbPlaintextTruncated, cbPlaintextResult);
            }

            scs_tools.SymCryptScsRotateBuffer(
                pbPkcs1Format,
                cbPkcs1Buffer,
                (@as(SIZE_T, iFirstZero) + 1) & (cbPkcs1Buffer - 1),
            );

            scs_tools.SymCryptScsCopy(
                pbPkcs1Format,
                cbPlaintextResult,
                pbOut,
                @min(cbPlaintext, cbPkcs1Format),
            );
        }
    }

    var scErrorVal: u32 = @bitCast(@backingInt(scError));
    const bufSmallVal: u32 = @bitCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_BUFFER_TOO_SMALL));
    const invArgVal: u32 = @bitCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_INVALID_ARGUMENT));

    scErrorVal ^= mBufferSizeError & (scErrorVal ^ bufSmallVal);
    scErrorVal ^= mPaddingError & (scErrorVal ^ invArgVal);

    pcbPlaintext.* = cbPlaintextResult;
    return @fromBackingInt(@intCast(@as(c_int, @bitCast(scErrorVal))));
}

pub export fn SymCryptRsaOaepApplyEncryptionPadding(
    pbPlaintext: ?PCBYTE,
    cbPlaintext: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    pbSeed: ?PCBYTE,
    cbSeed: SIZE_T,
    pbOaepFormat: PBYTE,
    cbOaepFormat: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbHash: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    const cbHashState: SIZE_T = hash.SymCryptHashStateSize(hashAlgorithm);

    if (cbOaepFormat < (cbPlaintext + (cbHash * 2) + 2) or
        ((pbSeed != null) and (cbSeed > cbHash)) or
        ((pbSeed == null) and (cbSeed != 0)))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbPS: SIZE_T = cbOaepFormat - (cbPlaintext + (cbHash * 2) + 2);
    const cbDB: SIZE_T = cbOaepFormat - (cbHash + 1);

    macros.SYMCRYPT_ASSERT(cbScratch >= cbHashState + (cbHash * 2) + (cbDB * 2));

    const pHashState: PVOID = @ptrCast(pbScratch);
    const pbSeedInternal: PBYTE = pbScratch + cbHashState;
    const pbSeedMask: PBYTE = pbSeedInternal + cbHash;
    const pbDB: PBYTE = pbSeedMask + cbHash;
    const pbDBMask: PBYTE = pbDB + cbDB;

    const emptyLabel: [1]BYTE = .{0};
    hash.SymCryptHash(hashAlgorithm, pbLabel orelse &emptyLabel, cbLabel, pbDB, cbHash);

    macros.SymCryptWipe(@ptrCast(pbDB + cbHash), cbPS);
    pbDB[cbHash + cbPS] = 0x01;

    if (cbPlaintext > 0) {
        @memcpy((pbDB + cbHash + cbPS + 1)[0..cbPlaintext], pbPlaintext.?[0..cbPlaintext]);
    }

    if (pbSeed == null) {
        scError = SymCryptCallbackRandom(pbSeedInternal, cbHash);
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else {
        macros.SymCryptWipe(@ptrCast(pbSeedInternal), cbHash);
        if (cbSeed > 0) {
            @memcpy(pbSeedInternal[0..cbSeed], pbSeed.?[0..cbSeed]);
        }
    }

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbSeedInternal,
        cbHash,
        pbDBMask,
        cbDB,
    );

    pbOaepFormat[0] = 0x00;

    var i: SIZE_T = 0;
    while (i < cbDB) : (i += 1) {
        pbOaepFormat[cbHash + 1 + i] = pbDB[i] ^ pbDBMask[i];
    }

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbOaepFormat + cbHash + 1,
        cbDB,
        pbSeedMask,
        cbHash,
    );

    i = 0;
    while (i < cbHash) : (i += 1) {
        pbOaepFormat[1 + i] = pbSeedInternal[i] ^ pbSeedMask[i];
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaOaepRemoveEncryptionPadding(
    pbOAEPFormat: PCBYTE,
    cbOAEPFormat: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    pbLabel: ?PCBYTE,
    cbLabel: SIZE_T,
    flags: UINT32,
    pbPlaintext: ?PBYTE,
    cbPlaintext: SIZE_T,
    pcbPlaintext: *SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHashAlg: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    const cbHashState: SIZE_T = hash.SymCryptHashStateSize(hashAlgorithm);

    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var mPaddingError: UINT32 = scs_tools.SymCryptMask32IsNonzeroU31(pbOAEPFormat[0]);

    if (cbOAEPFormat < (2 * cbHashAlg + 2)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbDB: SIZE_T = cbOAEPFormat - (cbHashAlg + 1);

    macros.SYMCRYPT_ASSERT(cbScratch >= cbHashState + (cbHashAlg * 3) + (cbDB * 2));

    const pHashState: PVOID = @ptrCast(pbScratch);
    const pbSeedMask: PBYTE = pbScratch + cbHashState;
    const pbSeed: PBYTE = pbSeedMask + cbHashAlg;
    const pbDBMask: PBYTE = pbSeed + cbHashAlg;
    const pbDB: PBYTE = pbDBMask + cbDB;
    const pbLabelHash: PBYTE = pbDB + cbDB;

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbOAEPFormat + cbHashAlg + 1,
        cbDB,
        pbSeedMask,
        cbHashAlg,
    );

    var i: SIZE_T = 0;
    while (i < cbHashAlg) : (i += 1) {
        pbSeed[i] = pbOAEPFormat[1 + i] ^ pbSeedMask[i];
    }

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbSeed,
        cbHashAlg,
        pbDBMask,
        cbDB,
    );

    i = 0;
    while (i < cbDB) : (i += 1) {
        pbDB[i] = pbOAEPFormat[cbHashAlg + 1 + i] ^ pbDBMask[i];
    }

    const emptyLabel: [1]BYTE = .{0};
    hash.SymCryptHash(hashAlgorithm, pbLabel orelse &emptyLabel, cbLabel, pbLabelHash, cbHashAlg);

    mPaddingError |= scs_tools.SymCryptMask32IsZeroU31(equal.SymCryptEqual(pbLabelHash, pbDB, cbHashAlg));

    if (mPaddingError != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var cnt: SIZE_T = cbHashAlg;
    while (cnt < cbDB) : (cnt += 1) {
        if (pbDB[cnt] == 0x01) {
            cnt += 1;
            break;
        } else if (pbDB[cnt] != 0x00) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    }

    if (pbDB[cnt - 1] != 0x01) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pcbPlaintext.* = cbDB - cnt;

    if (pbPlaintext == null) {
        return .SYMCRYPT_NO_ERROR;
    }

    if (cbPlaintext < pcbPlaintext.*) {
        return .SYMCRYPT_BUFFER_TOO_SMALL;
    }

    if (pcbPlaintext.* > 0) {
        @memcpy(pbPlaintext.?[0..pcbPlaintext.*], (pbDB + cnt)[0..pcbPlaintext.*]);
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPkcs1ApplySignaturePadding(
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    pbHashOid: ?PCBYTE,
    cbHashOid: SIZE_T,
    flags: UINT32,
    pbPKCS1Format: PBYTE,
    cbPKCS1Format: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var cbEncoding: SIZE_T = 0;

    if ((flags & ~types.SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (cbHash >= cbPKCS1Format) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const fInsertASN1: bool = ((flags & types.SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1) == 0);

    if (fInsertASN1) {
        if ((pbHashOid != null) and (cbHashOid > 0)) {
            cbEncoding = 6 + cbHashOid + cbHash;
        } else {
            if (cbHashOid > 0) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            cbEncoding = 2 + cbHash;
        }

        if (cbEncoding > 0x80) {
            return .SYMCRYPT_INVALID_ARGUMENT;
        }
    } else {
        cbEncoding = cbHash;
    }

    if (3 + 8 + cbEncoding > cbPKCS1Format) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbPadding: SIZE_T = cbPKCS1Format - 3 - cbEncoding;

    pbPKCS1Format[0] = 0x00;
    pbPKCS1Format[1] = PKCS_BLOCKTYPE_1;
    pbPKCS1Format[2 + cbPadding] = 0x00;

    @memset((pbPKCS1Format + 2)[0..cbPadding], 0xff);

    if (fInsertASN1) {
        var cbOidOffset: SIZE_T = 1;
        if ((pbHashOid != null) and (cbHashOid > 0)) {
            pbPKCS1Format[2 + cbPadding + 1] = ASN1_SEQUENCE_BYTE;
            pbPKCS1Format[2 + cbPadding + 2] = @as(BYTE, @truncate(cbEncoding)) - 2;

            pbPKCS1Format[2 + cbPadding + 3] = ASN1_SEQUENCE_BYTE;
            pbPKCS1Format[2 + cbPadding + 4] = @truncate(cbHashOid);
            cbOidOffset += 4;
            @memcpy((pbPKCS1Format + 2 + cbPadding + cbOidOffset)[0..cbHashOid], pbHashOid.?[0..cbHashOid]);
        }

        pbPKCS1Format[2 + cbPadding + cbOidOffset + cbHashOid] = ASN1_OCTET_STRING_BYTE;
        pbPKCS1Format[2 + cbPadding + cbOidOffset + cbHashOid + 1] = @truncate(cbHash);
        if (cbHash > 0) {
            @memcpy((pbPKCS1Format + 2 + cbPadding + cbOidOffset + cbHashOid + 2)[0..cbHash], pbHash.?[0..cbHash]);
        }
    } else {
        if (cbHash > 0) {
            @memcpy((pbPKCS1Format + 3 + cbPadding)[0..cbHash], pbHash.?[0..cbHash]);
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPkcs1CheckSignaturePadding(
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    pbHashOid: ?PCBYTE,
    cbHashOid: SIZE_T,
    pbPKCS1Format: PCBYTE,
    flags: UINT32,
    pbScratch: PBYTE,
    cbPKCS1Format: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.SymCryptWipe(@ptrCast(pbScratch), cbPKCS1Format);

    const scError = SymCryptRsaPkcs1ApplySignaturePadding(
        pbHash,
        cbHash,
        pbHashOid,
        cbHashOid,
        flags,
        pbScratch,
        cbPKCS1Format,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    if (equal.SymCryptEqual(pbScratch, pbPKCS1Format, cbPKCS1Format) != 0) {
        return .SYMCRYPT_NO_ERROR;
    } else {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }
}

pub export fn SymCryptRsaPkcs1VerifySignaturePadding(
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    pHashOIDs: ?[*]const SYMCRYPT_OID,
    nOIDCount: SIZE_T,
    pbPKCS1Format: PCBYTE,
    cbPKCS1Format: SIZE_T,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    macros.SYMCRYPT_ASSERT(cbScratch >= cbPKCS1Format);

    if ((flags & ~types.SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID) != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (pHashOIDs) |oids| {
        var i: SIZE_T = 0;
        while (i < nOIDCount) : (i += 1) {
            scError = SymCryptRsaPkcs1CheckSignaturePadding(
                pbHash,
                cbHash,
                oids[i].pbOID,
                oids[i].cbOID,
                pbPKCS1Format,
                0,
                pbScratch,
                cbPKCS1Format,
            );
            if (scError == .SYMCRYPT_NO_ERROR) {
                break;
            }
        }
    }

    if ((pHashOIDs == null) or
        (scError != .SYMCRYPT_NO_ERROR and
            (flags & types.SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID) != 0))
    {
        scError = SymCryptRsaPkcs1CheckSignaturePadding(
            pbHash,
            cbHash,
            null,
            0,
            pbPKCS1Format,
            types.SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1,
            pbScratch,
            cbPKCS1Format,
        );
    }

    return scError;
}

pub export fn SymCryptRsaPssApplySignaturePadding(
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    pbSalt: ?PCBYTE,
    cbSalt: SIZE_T,
    nBitsOfModulus: UINT32,
    flags: UINT32,
    pbPSSFormat_in: ?PBYTE,
    cbPSSFormat_in: SIZE_T,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    const cbHashAlg: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    const cbHashState: SIZE_T = hash.SymCryptHashStateSize(hashAlgorithm);

    if ((cbPSSFormat_in == 0) or (pbPSSFormat_in == null)) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var pbPSSFormat: PBYTE = pbPSSFormat_in.?;
    var cbPSSFormat: SIZE_T = cbPSSFormat_in;

    if (nBitsOfModulus % 8 == 1) {
        pbPSSFormat[0] = 0;
        pbPSSFormat += 1;
        cbPSSFormat -= 1;
    }

    if ((flags != 0) or (cbPSSFormat < (cbHashAlg + cbSalt + 2))) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const cbDB: SIZE_T = cbPSSFormat - (cbHashAlg + 1);
    const cbPadding2: SIZE_T = cbDB - cbSalt - 1;
    const cbMPrime: SIZE_T = 8 + cbHash + cbSalt;

    macros.SYMCRYPT_ASSERT(cbScratch >= cbHashState + cbMPrime + (cbDB * 2));

    const pHashState: PVOID = @ptrCast(pbScratch);
    const pbMPrime: PBYTE = pbScratch + cbHashState;
    const pbDB: PBYTE = pbMPrime + cbMPrime;
    const pbDBMask: PBYTE = pbDB + cbDB;

    macros.SymCryptWipe(@ptrCast(pbMPrime), 8);
    if (cbHash > 0) {
        @memcpy((pbMPrime + 8)[0..cbHash], pbHash.?[0..cbHash]);
    }

    if (pbSalt == null) {
        scError = SymCryptCallbackRandom(
            pbMPrime + 8 + cbHash,
            cbSalt,
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    } else if (cbSalt > 0) {
        @memcpy((pbMPrime + 8 + cbHash)[0..cbSalt], pbSalt.?[0..cbSalt]);
    }

    hash.SymCryptHash(hashAlgorithm, pbMPrime, cbMPrime, pbPSSFormat + cbDB, cbHashAlg);

    macros.SymCryptWipe(@ptrCast(pbDB), cbPadding2);
    pbDB[cbPadding2] = 0x01;
    if (cbSalt > 0) {
        @memcpy((pbDB + cbPadding2 + 1)[0..cbSalt], (pbMPrime + 8 + cbHash)[0..cbSalt]);
    }

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbPSSFormat + cbDB,
        cbHashAlg,
        pbDBMask,
        cbDB,
    );

    var i: SIZE_T = 0;
    while (i < cbDB) : (i += 1) {
        pbPSSFormat[i] = pbDB[i] ^ pbDBMask[i];
    }

    const dwZeroBits: SIZE_T = 8 * cbPSSFormat + 1 - nBitsOfModulus;

    pbPSSFormat[0] &= @truncate(@as(u32, 0xff) >> @intCast(dwZeroBits));

    pbPSSFormat[cbPSSFormat - 1] = 0xbc;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptRsaPssVerifySignaturePadding(
    pbHash: ?PCBYTE,
    cbHash: SIZE_T,
    hashAlgorithm: PCSYMCRYPT_HASH,
    cbSalt: SIZE_T,
    pbPSSFormat_in: ?PCBYTE,
    cbPSSFormat_in: SIZE_T,
    nBitsOfModulus: UINT32,
    flags: UINT32,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const cbHashAlg: SIZE_T = hash.SymCryptHashResultSize(hashAlgorithm);
    const cbHashState: SIZE_T = hash.SymCryptHashStateSize(hashAlgorithm);

    if (((flags & ~types.SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT) != 0) or
        (cbPSSFormat_in == 0) or
        (pbPSSFormat_in == null))
    {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    var pbPSSFormat: PCBYTE = pbPSSFormat_in.?;
    var cbPSSFormat: SIZE_T = cbPSSFormat_in;

    if (nBitsOfModulus % 8 == 1) {
        if (pbPSSFormat[0] != 0) {
            return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
        }
        pbPSSFormat += 1;
        cbPSSFormat -= 1;
    }

    const dwZeroBits: SIZE_T = 8 * cbPSSFormat + 1 - nBitsOfModulus;
    const highMask: BYTE = @truncate(@as(u32, 0xff) << @intCast(8 - dwZeroBits));

    if ((cbPSSFormat < (cbHashAlg + cbSalt + 2)) or
        (pbPSSFormat[0] & highMask) != 0 or
        pbPSSFormat[cbPSSFormat - 1] != 0xbc)
    {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    const cbDB: SIZE_T = cbPSSFormat - (cbHashAlg + 1);

    const pHashState: PVOID = @ptrCast(pbScratch);
    const pbDBMask: PBYTE = pbScratch + cbHashState;

    const pbHashOfMPrimeIndex: PCBYTE = pbPSSFormat + (cbPSSFormat - (cbHashAlg + 1));

    SymCryptRsaPaddingMaskGeneration(
        hashAlgorithm,
        pHashState,
        pbHashOfMPrimeIndex,
        cbHashAlg,
        pbDBMask,
        cbDB,
    );

    var i: SIZE_T = 0;
    while (i < cbDB) : (i += 1) {
        pbDBMask[i] = pbPSSFormat[i] ^ pbDBMask[i];
    }

    pbDBMask[0] &= @truncate(@as(u32, 0xff) >> @intCast(dwZeroBits));

    var cbPadding2: SIZE_T = 0;
    while (cbPadding2 < (cbDB - cbSalt)) : (cbPadding2 += 1) {
        if (pbDBMask[cbPadding2] == 0x01) {
            break;
        }

        if (pbDBMask[cbPadding2] != 0x00) {
            return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
        }
    }

    if (cbPadding2 == cbDB - cbSalt) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    const cbSaltObserved: SIZE_T = cbDB - cbPadding2 - 1;

    if (((flags & types.SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT) == 0) and
        cbSaltObserved != cbSalt)
    {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    const pbMPrime: PBYTE = pbDBMask + cbDB;
    const cbMPrime: SIZE_T = 8 + cbHash + cbSaltObserved;
    const pbMPrimeHash: PBYTE = pbMPrime + cbMPrime;

    macros.SYMCRYPT_ASSERT(cbScratch >= cbHashState + cbDB + cbMPrime + cbHashAlg);

    macros.SymCryptWipe(@ptrCast(pbMPrime), 8);
    if (cbHash > 0) {
        @memcpy((pbMPrime + 8)[0..cbHash], pbHash.?[0..cbHash]);
    }
    if (cbSaltObserved > 0) {
        @memcpy(
            (pbMPrime + 8 + cbHash)[0..cbSaltObserved],
            (pbDBMask + (cbDB - cbSaltObserved))[0..cbSaltObserved],
        );
    }

    hash.SymCryptHash(hashAlgorithm, pbMPrime, cbMPrime, pbMPrimeHash, cbHashAlg);

    if (equal.SymCryptEqual(pbPSSFormat + cbDB, pbMPrimeHash, cbHashAlg) == 0) {
        return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
    }

    return .SYMCRYPT_NO_ERROR;
}
