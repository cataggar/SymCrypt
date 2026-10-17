//
// padding_pkcs7.zig   Add/Remove PKCS7 padding
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const SIZE_T = types.SIZE_T;
const UINT32 = types.UINT32;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

extern fn SymCryptMask32IsZeroU31(v: UINT32) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptMask32IsNonzeroU31(v: UINT32) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptMask32LtU31(a: UINT32, b: UINT32) callconv(SYMCRYPT_CALL) UINT32;

pub export fn SymCryptPaddingPkcs7Add(
    cbBlockSize: SIZE_T,
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    pbDst: PBYTE,
    cbDst: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(cbBlockSize < 256);
    macros.SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);

    const cbDataLastBlock: SIZE_T = cbSrc & (cbBlockSize - 1);
    const cbResult: SIZE_T = cbSrc - cbDataLastBlock + cbBlockSize;

    macros.SYMCRYPT_ASSERT(cbDst >= cbResult);

    if (cbResult <= cbDst) {
        const cbPadVal: SIZE_T = cbBlockSize - cbDataLastBlock;

        if (@intFromPtr(pbDst) != @intFromPtr(pbSrc) and cbSrc > 0) {
            @memcpy(pbDst[0..cbSrc], pbSrc[0..cbSrc]);
        }

        @memset((pbDst + cbSrc)[0..cbPadVal], @truncate(cbPadVal));
    }

    pcbResult.* = cbResult;
}

pub export fn SymCryptPaddingPkcs7Remove(
    cbBlockSize: SIZE_T,
    pbSrcIn: PCBYTE,
    cbSrcIn: SIZE_T,
    pbDstIn: PBYTE,
    cbDstIn: SIZE_T,
    pcbResult: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: UINT32 = @intCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_NO_ERROR));

    var mPaddingError: UINT32 = 0;
    var mBufferSizeError: UINT32 = 0;
    var mask: UINT32 = 0;

    var pbSrc: PCBYTE = pbSrcIn;
    var cbSrc: SIZE_T = cbSrcIn;
    var pbDst: PBYTE = pbDstIn;
    var cbDst: SIZE_T = cbDstIn;

    macros.SYMCRYPT_ASSERT(cbBlockSize < 256);
    macros.SYMCRYPT_ASSERT((cbBlockSize & (cbBlockSize - 1)) == 0);
    macros.SYMCRYPT_ASSERT((cbSrc & (cbBlockSize - 1)) == 0);
    macros.SYMCRYPT_ASSERT(cbSrc > 0);

    var cbPadVal: UINT32 = pbSrc[cbSrc - 1];

    mPaddingError |= SymCryptMask32IsZeroU31(cbPadVal) | SymCryptMask32LtU31(@truncate(cbBlockSize), cbPadVal);

    const cbResult: SIZE_T = cbSrc -% @as(SIZE_T, cbPadVal);

    cbDst = @min(cbDst, cbSrc);
    const cbBulk: SIZE_T = cbSrc - cbBlockSize;

    if (cbDst < cbBulk) {
        scError = @intCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_BUFFER_TOO_SMALL));
    } else {
        if (@intFromPtr(pbDst) != @intFromPtr(pbSrc) and cbBulk > 0) {
            @memcpy(pbDst[0..cbBulk], pbSrc[0..cbBulk]);
        }

        pbSrc += cbBulk;
        cbSrc -= cbBulk;
        pbDst += cbBulk;
        cbDst -= cbBulk;

        const cbDst32: UINT32 = @truncate(cbDst);

        cbPadVal = 1 +% ((cbPadVal -% 1) & @as(UINT32, @truncate(cbBlockSize - 1)));
        const cbMsg32: UINT32 = @as(UINT32, @truncate(cbBlockSize)) -% cbPadVal;

        mBufferSizeError |= SymCryptMask32LtU31(cbDst32, cbMsg32);

        const blockSize32: UINT32 = @truncate(cbBlockSize);
        var i: UINT32 = 0;
        while (i < blockSize32) : (i += 1) {
            mask = SymCryptMask32LtU31(i, cbMsg32);

            mPaddingError |= SymCryptMask32IsNonzeroU31(@as(UINT32, pbSrc[i]) ^ cbPadVal) & ~mask;

            if (i < cbDst) {
                pbDst[i] ^= (pbDst[i] ^ pbSrc[i]) & @as(u8, @truncate(mask));
            }
        }
    }

    pcbResult.* = cbResult;

    const errBufferTooSmall: UINT32 = @intCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_BUFFER_TOO_SMALL));
    const errInvalidArgument: UINT32 = @intCast(@backingInt(SYMCRYPT_ERROR.SYMCRYPT_INVALID_ARGUMENT));
    scError ^= mBufferSizeError & (scError ^ errBufferTooSmall);
    scError ^= mPaddingError & (scError ^ errInvalidArgument);

    return @fromBackingInt(@intCast(@as(c_int, @intCast(scError))));
}
