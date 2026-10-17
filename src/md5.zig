//
// md5.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// MD5 implementation from RFC 1321, ported from lib/md5.c.
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
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

pub const SYMCRYPT_MD5_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD5_INPUT_BLOCK_SIZE: usize = 64;
pub const SYMCRYPT_MD5_STATE_EXPORT_SIZE: usize = 116;
pub const SYMCRYPT_MD5_OID_COUNT: usize = 2;

pub const SYMCRYPT_MD5_CHAINING_STATE = hash.SYMCRYPT_MD5_CHAINING_STATE;
pub const PSYMCRYPT_MD5_CHAINING_STATE = hash.PSYMCRYPT_MD5_CHAINING_STATE;
pub const SYMCRYPT_MD5_STATE = hash.SYMCRYPT_MD5_STATE;
pub const PSYMCRYPT_MD5_STATE = hash.PSYMCRYPT_MD5_STATE;
pub const PCSYMCRYPT_MD5_STATE = hash.PCSYMCRYPT_MD5_STATE;

pub const SYMCRYPT_MD5_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    chain: [16]BYTE,
    dataLength: UINT64 align(1),
    buffer: [64]BYTE,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

pub const SymCryptMd5OidList: [SYMCRYPT_MD5_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 12, .pbOID = "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00" },
    .{ .cbOID = 10, .pbOID = "\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05" },
};

const Pattern = hash_pattern.HashPattern(
    SYMCRYPT_MD5_STATE,
    SYMCRYPT_MD5_CHAINING_STATE,
    &SymCryptMd5Init,
    &SymCryptMd5Append,
    &SymCryptMd5Result,
    &SymCryptMd5AppendBlocks,
);

pub export const SymCryptMd5Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Pattern.initVoid,
    .appendFunc = &Pattern.appendVoid,
    .resultFunc = &Pattern.resultVoid,
    .appendBlockFunc = &Pattern.appendBlocksVoid,
    .stateCopyFunc = &Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_MD5_STATE),
    .resultSize = SYMCRYPT_MD5_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_MD5_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_MD5_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_MD5_CHAINING_STATE),
};

pub export const SymCryptMd5Algorithm: PCSYMCRYPT_HASH = &SymCryptMd5Algorithm_default;

const md5Const: [64]UINT32 = .{
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

const md5Rotate: [64]u5 = .{
    7, 12, 17, 22,
    7, 12, 17, 22,
    7, 12, 17, 22,
    7, 12, 17, 22,

    5, 9,  14, 20,
    5, 9,  14, 20,
    5, 9,  14, 20,
    5, 9,  14, 20,

    4, 11, 16, 23,
    4, 11, 16, 23,
    4, 11, 16, 23,
    4, 11, 16, 23,

    6, 10, 15, 21,
    6, 10, 15, 21,
    6, 10, 15, 21,
    6, 10, 15, 21,
};

const md5MsgIndex: [64]usize = .{
    0, 1, 2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
    1, 6, 11, 0,  5,  10, 15, 4,  9,  14, 3,  8,  13, 2,  7,  12,
    5, 8, 11, 14, 1,  4,  7,  10, 13, 0,  3,  6,  9,  12, 15, 2,
    0, 7, 14, 5,  12, 3,  10, 1,  8,  15, 6,  13, 4,  11, 2,  9,
};

const md5InitialState: [4]UINT32 = .{
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
};

pub export fn SymCryptMd5(
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptMd5StateCopy(
    pSrc: PCSYMCRYPT_MD5_STATE,
    pDst: PSYMCRYPT_MD5_STATE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptMd5Init(pState: PSYMCRYPT_MD5_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = md5InitialState;
}

pub export fn SymCryptMd5Append(
    pState: PSYMCRYPT_MD5_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashAppendInternal(SymCryptMd5Algorithm, @ptrCast(pState), pbData, cbData);
}

pub export fn SymCryptMd5Result(
    pState: PSYMCRYPT_MD5_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashCommonPaddingMd4Style(SymCryptMd5Algorithm, @ptrCast(pState));

    macros.SymCryptUint32ToLsbFirst(&pState.chain.H, pbResult, 4);

    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_MD5_STATE));
    SymCryptMd5Init(pState);
}

inline fn md5F(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn md5G(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return md5F(z, x, y);
}

inline fn md5H(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (x ^ y ^ z);
}

inline fn md5I(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (y ^ (x | ~z));
}

pub export fn SymCryptMd5AppendBlocks(
    pChain: PSYMCRYPT_MD5_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var W: [16]UINT32 = undefined;
    var ad: [4]UINT32 = undefined;
    var Wt: UINT32 = 0;
    var currPbData = pbData;
    var currCbData = cbData;

    ad[0] = pChain.H[0];
    ad[1] = pChain.H[3];
    ad[2] = pChain.H[2];
    ad[3] = pChain.H[1];

    while (currCbData >= 64) {
        inline for (0..16) |r| {
            Wt = macros.LOAD_LSBFIRST32(currPbData + 4 * md5MsgIndex[r]);
            W[r] = Wt;
            ad[r % 4] = ad[(r + 3) % 4] +% macros.ROL32(
                ad[r % 4] +% md5F(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md5Const[r],
                md5Rotate[r],
            );
        }

        inline for (16..32) |r| {
            Wt = W[md5MsgIndex[r]];
            ad[r % 4] = ad[(r + 3) % 4] +% macros.ROL32(
                ad[r % 4] +% md5G(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md5Const[r],
                md5Rotate[r],
            );
        }

        inline for (32..48) |r| {
            Wt = W[md5MsgIndex[r]];
            ad[r % 4] = ad[(r + 3) % 4] +% macros.ROL32(
                ad[r % 4] +% md5H(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md5Const[r],
                md5Rotate[r],
            );
        }

        inline for (48..64) |r| {
            Wt = W[md5MsgIndex[r]];
            ad[r % 4] = ad[(r + 3) % 4] +% macros.ROL32(
                ad[r % 4] +% md5I(ad[(r + 3) % 4], ad[(r + 2) % 4], ad[(r + 1) % 4]) +% Wt +% md5Const[r],
                md5Rotate[r],
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
    hash.SymCryptWipeKnownSize(@ptrCast(&Wt), @sizeOf(@TypeOf(Wt)));
}

pub export fn SymCryptMd5StateExport(
    pState: PCSYMCRYPT_MD5_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var blob: SYMCRYPT_MD5_STATE_EXPORT_BLOB = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_MD5_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd5State);

    macros.SymCryptUint32ToLsbFirst(&pState.chain.H, &blob.chain, 4);
    blob.dataLength = pState.dataLengthL;
    const bytesInBuffer: usize = @intCast(blob.dataLength & 0x3f);
    @memcpy(blob.buffer[0..bytesInBuffer], pState.buffer[0..bytesInBuffer]);

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_MD5_STATE_EXPORT_SIZE], @as(*const [SYMCRYPT_MD5_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)));

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB));
}

pub export fn SymCryptMd5StateImport(
    pState: PSYMCRYPT_MD5_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var blob: SYMCRYPT_MD5_STATE_EXPORT_BLOB = undefined;
    var checksum: [8]BYTE = undefined;

    @memcpy(@as(*[SYMCRYPT_MD5_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)), pbBlob[0..SYMCRYPT_MD5_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_MD5_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd5State))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptLsbFirstToUint32(&blob.chain, &pState.chain.H, 4);
    pState.dataLengthL = blob.dataLength;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = @intCast(blob.dataLength & 0x3f);
    @memcpy(pState.buffer[0..pState.bytesInBuffer], blob.buffer[0..pState.bytesInBuffer]);

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB));
    return scError;
}

const md5KATAnswer: [16]BYTE = .{
    0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0,
    0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1, 0x7f, 0x72,
};

pub export fn SymCryptMd5Selftest() callconv(SYMCRYPT_CALL) void {
    var result: [SYMCRYPT_MD5_RESULT_SIZE]BYTE = undefined;

    SymCryptMd5(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &result);

    hash.SymCryptInjectError(&result, result.len);

    if (!std.mem.eql(u8, &result, &md5KATAnswer)) {
        macros.SymCryptFatal(macros.multiCharConstant("MD5t"));
    }
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_MD5_STATE_EXPORT_BLOB) == SYMCRYPT_MD5_STATE_EXPORT_SIZE);
}
