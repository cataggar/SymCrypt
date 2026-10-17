//
// md4.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// MD4 implementation from RFC 1320, ported from lib/md4.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const hash_pattern = @import("hash_pattern.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_HASH = types.SYMCRYPT_HASH;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

pub const SYMCRYPT_MD4_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD4_INPUT_BLOCK_SIZE: usize = 64;
pub const SYMCRYPT_MD4_STATE_EXPORT_SIZE: usize = 116;

pub const SYMCRYPT_MD4_CHAINING_STATE = hash.SYMCRYPT_MD4_CHAINING_STATE;
pub const PSYMCRYPT_MD4_CHAINING_STATE = hash.PSYMCRYPT_MD4_CHAINING_STATE;
pub const SYMCRYPT_MD4_STATE = hash.SYMCRYPT_MD4_STATE;
pub const PSYMCRYPT_MD4_STATE = hash.PSYMCRYPT_MD4_STATE;
pub const PCSYMCRYPT_MD4_STATE = hash.PCSYMCRYPT_MD4_STATE;

pub const SYMCRYPT_MD4_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    chain: [16]BYTE,
    dataLength: UINT64 align(1),
    buffer: [64]BYTE,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

const Pattern = hash_pattern.HashPattern(
    SYMCRYPT_MD4_STATE,
    SYMCRYPT_MD4_CHAINING_STATE,
    &SymCryptMd4Init,
    &SymCryptMd4Append,
    &SymCryptMd4Result,
    &SymCryptMd4AppendBlocks,
);

pub export const SymCryptMd4Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Pattern.initVoid,
    .appendFunc = &Pattern.appendVoid,
    .resultFunc = &Pattern.resultVoid,
    .appendBlockFunc = &Pattern.appendBlocksVoid,
    .stateCopyFunc = &Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_MD4_STATE),
    .resultSize = SYMCRYPT_MD4_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_MD4_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_MD4_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_MD4_CHAINING_STATE),
};

pub export const SymCryptMd4Algorithm: PCSYMCRYPT_HASH = &SymCryptMd4Algorithm_default;

const md4Const: [3]UINT32 = .{
    0x00000000,
    0x5A827999,
    0x6ED9EBA1,
};

const md4Rotate: [48]u5 = .{
    3, 7, 11, 19,
    3, 7, 11, 19,
    3, 7, 11, 19,
    3, 7, 11, 19,

    3, 5, 9,  13,
    3, 5, 9,  13,
    3, 5, 9,  13,
    3, 5, 9,  13,

    3, 9, 11, 15,
    3, 9, 11, 15,
    3, 9, 11, 15,
    3, 9, 11, 15,
};

const md4MsgIndex: [48]usize = .{
    0, 1, 2, 3,  4, 5,  6, 7,  8, 9, 10, 11, 12, 13, 14, 15,
    0, 4, 8, 12, 1, 5,  9, 13, 2, 6, 10, 14, 3,  7,  11, 15,
    0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5,  13, 3,  11, 7,  15,
};

const md4InitialState: [4]UINT32 = .{
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
};

pub export fn SymCryptMd4(
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptMd4StateCopy(
    pSrc: PCSYMCRYPT_MD4_STATE,
    pDst: PSYMCRYPT_MD4_STATE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptMd4Init(pState: PSYMCRYPT_MD4_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = md4InitialState;
}

pub export fn SymCryptMd4Append(
    pState: PSYMCRYPT_MD4_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashAppendInternal(SymCryptMd4Algorithm, @ptrCast(pState), pbData, cbData);
}

pub export fn SymCryptMd4Result(
    pState: PSYMCRYPT_MD4_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashCommonPaddingMd4Style(SymCryptMd4Algorithm, @ptrCast(pState));

    macros.SymCryptUint32ToLsbFirst(&pState.chain.H, pbResult, 4);

    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_MD4_STATE));
    SymCryptMd4Init(pState);
}

inline fn md4F(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn md4G(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((x | y) & z) | (x & y));
}

inline fn md4H(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (x ^ y ^ z);
}

pub export fn SymCryptMd4AppendBlocks(
    pChain: PSYMCRYPT_MD4_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var W: [16]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var ad: [4]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var Wt: UINT32 = 0;
    var currPbData = pbData;
    var currCbData = cbData;

    ad[0] = pChain.H[0];
    ad[1] = pChain.H[3];
    ad[2] = pChain.H[2];
    ad[3] = pChain.H[1];

    while (currCbData >= 64) {
        inline for (0..16) |r| {
            Wt = macros.LOAD_LSBFIRST32(currPbData + 4 * md4MsgIndex[r]);
            W[r] = Wt;
            ad[r % 4] = macros.ROL32(
                ad[r % 4] +% md4F(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md4Const[r / 16],
                md4Rotate[r],
            );
        }

        inline for (16..32) |r| {
            Wt = W[md4MsgIndex[r]];
            ad[r % 4] = macros.ROL32(
                ad[r % 4] +% md4G(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md4Const[r / 16],
                md4Rotate[r],
            );
        }

        inline for (32..48) |r| {
            Wt = W[md4MsgIndex[r]];
            ad[r % 4] = macros.ROL32(
                ad[r % 4] +% md4H(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md4Const[r / 16],
                md4Rotate[r],
            );
        }

        ad[0] +%= pChain.H[0];
        pChain.H[0] = ad[0];
        ad[1] +%= pChain.H[3];
        pChain.H[3] = ad[1];
        ad[2] +%= pChain.H[2];
        pChain.H[2] = ad[2];
        ad[3] +%= pChain.H[1];
        pChain.H[1] = ad[3];

        currPbData += 64;
        currCbData -= 64;
    }

    pcbRemaining.* = currCbData;

    hash.SymCryptWipeKnownSize(@ptrCast(&ad), @sizeOf(@TypeOf(ad)));
    hash.SymCryptWipeKnownSize(@ptrCast(&W), @sizeOf(@TypeOf(W)));
    macros.FORCE_WRITE32(&Wt, 0);
}

pub export fn SymCryptMd4StateExport(
    pState: PCSYMCRYPT_MD4_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var blob: SYMCRYPT_MD4_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_MD4_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd4State);

    macros.SymCryptUint32ToLsbFirst(&pState.chain.H, &blob.chain, 4);
    blob.dataLength = pState.dataLengthL;
    const bytesInBuffer: usize = @intCast(blob.dataLength & 0x3f);
    @memcpy(blob.buffer[0..bytesInBuffer], pState.buffer[0..bytesInBuffer]);

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_MD4_STATE_EXPORT_SIZE], @as(*const [SYMCRYPT_MD4_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)));

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB));
}

pub export fn SymCryptMd4StateImport(
    pState: PSYMCRYPT_MD4_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var blob: SYMCRYPT_MD4_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;

    @memcpy(@as(*[SYMCRYPT_MD4_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)), pbBlob[0..SYMCRYPT_MD4_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_MD4_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd4State))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptLsbFirstToUint32(&blob.chain, &pState.chain.H, 4);
    pState.dataLengthL = blob.dataLength;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = @intCast(blob.dataLength & 0x3f);
    @memcpy(pState.buffer[0..pState.bytesInBuffer], blob.buffer[0..pState.bytesInBuffer]);

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB));
    return scError;
}

const md4KATAnswer: [16]BYTE = .{
    0xa4, 0x48, 0x01, 0x7a, 0xaf, 0x21, 0xd8, 0x52,
    0x5f, 0xc1, 0x0a, 0xe8, 0x7a, 0xa6, 0x72, 0x9d,
};

pub export fn SymCryptMd4Selftest() callconv(SYMCRYPT_CALL) void {
    var result: [SYMCRYPT_MD4_RESULT_SIZE]BYTE = undefined;

    SymCryptMd4(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &result);

    hash.SymCryptInjectError(&result, result.len);

    if (!std.mem.eql(u8, &result, &md4KATAnswer)) {
        macros.SymCryptFatal(macros.multiCharConstant("MD4t"));
    }
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_MD4_STATE_EXPORT_BLOB) == SYMCRYPT_MD4_STATE_EXPORT_SIZE);
}
