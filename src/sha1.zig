//
// sha1.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// SHA-1 implementation from FIPS 180-4, ported from lib/sha1.c.
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

pub const SYMCRYPT_SHA1_RESULT_SIZE: usize = 20;
pub const SYMCRYPT_SHA1_INPUT_BLOCK_SIZE: usize = 64;
pub const SYMCRYPT_SHA1_STATE_EXPORT_SIZE: usize = 120;
pub const SYMCRYPT_SHA1_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA1_CHAINING_STATE = hash.SYMCRYPT_SHA1_CHAINING_STATE;
pub const PSYMCRYPT_SHA1_CHAINING_STATE = hash.PSYMCRYPT_SHA1_CHAINING_STATE;
pub const SYMCRYPT_SHA1_STATE = hash.SYMCRYPT_SHA1_STATE;
pub const PSYMCRYPT_SHA1_STATE = hash.PSYMCRYPT_SHA1_STATE;
pub const PCSYMCRYPT_SHA1_STATE = hash.PCSYMCRYPT_SHA1_STATE;

pub const SYMCRYPT_SHA1_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    chain: [20]BYTE,
    dataLength: UINT64 align(1),
    buffer: [64]BYTE,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

pub const SymCryptSha1OidList: [SYMCRYPT_SHA1_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 9, .pbOID = "\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00" },
    .{ .cbOID = 7, .pbOID = "\x06\x05\x2b\x0e\x03\x02\x1a" },
};

const Pattern = hash_pattern.HashPattern(
    SYMCRYPT_SHA1_STATE,
    SYMCRYPT_SHA1_CHAINING_STATE,
    &SymCryptSha1Init,
    &SymCryptSha1Append,
    &SymCryptSha1Result,
    &SymCryptSha1AppendBlocks,
);

pub export const SymCryptSha1Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Pattern.initVoid,
    .appendFunc = &Pattern.appendVoid,
    .resultFunc = &Pattern.resultVoid,
    .appendBlockFunc = &Pattern.appendBlocksVoid,
    .stateCopyFunc = &Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA1_STATE),
    .resultSize = SYMCRYPT_SHA1_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA1_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA1_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_SHA1_CHAINING_STATE),
};

pub export const SymCryptSha1Algorithm: PCSYMCRYPT_HASH = &SymCryptSha1Algorithm_default;

const Sha1K: [4]UINT32 = .{
    0x5a827999,
    0x6ed9eba1,
    0x8f1bbcdc,
    0xca62c1d6,
};

const sha1InitialState: [5]UINT32 = .{
    0x67452301,
    0xefcdab89,
    0x98badcfe,
    0x10325476,
    0xc3d2e1f0,
};

pub export fn SymCryptSha1(
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptSha1StateCopy(
    pSrc: PCSYMCRYPT_SHA1_STATE,
    pDst: PSYMCRYPT_SHA1_STATE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha1Init(pState: PSYMCRYPT_SHA1_STATE) callconv(SYMCRYPT_CALL) void {
    macros.SET_MAGIC(pState);

    pState.dataLengthL = 0;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = 0;

    pState.chain.H = sha1InitialState;
}

pub export fn SymCryptSha1Append(
    pState: PSYMCRYPT_SHA1_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashAppendInternal(SymCryptSha1Algorithm, @ptrCast(pState), pbData, cbData);
}

pub export fn SymCryptSha1Result(
    pState: PSYMCRYPT_SHA1_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var bytesInBuffer: UINT32 = undefined;
    var tmp: SIZE_T = 0;

    macros.CHECK_MAGIC(pState);

    bytesInBuffer = pState.bytesInBuffer;

    pState.buffer[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    if (bytesInBuffer > 64 - 8) {
        @memset(pState.buffer[bytesInBuffer..64], 0);
        SymCryptSha1AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);
        bytesInBuffer = 0;
    }

    @memset(pState.buffer[bytesInBuffer..64], 0);
    macros.STORE_MSBFIRST64(pState.buffer[64 - 8 ..].ptr, pState.dataLengthL *% 8);

    SymCryptSha1AppendBlocks(&pState.chain, &pState.buffer, 64, &tmp);

    macros.SymCryptUint32ToMsbFirst(&pState.chain.H, pbResult, 5);

    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_SHA1_STATE));
    SymCryptSha1Init(pState);
}

inline fn sha1Maj(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((x | y) & z) | (x & y));
}

inline fn sha1Ch(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (((z ^ y) & x) ^ z);
}

inline fn sha1Parity(x: UINT32, y: UINT32, z: UINT32) UINT32 {
    return (x ^ y ^ z);
}

inline fn sha1RoundFn(comptime r: usize, x: UINT32, y: UINT32, z: UINT32) UINT32 {
    if (r < 20) {
        return sha1Ch(x, y, z);
    } else if (r < 40) {
        return sha1Parity(x, y, z);
    } else if (r < 60) {
        return sha1Maj(x, y, z);
    } else {
        return sha1Parity(x, y, z);
    }
}

pub export fn SymCryptSha1AppendBlocks(
    pChain: PSYMCRYPT_SHA1_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var W: [16]UINT32 align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var A: UINT32 = pChain.H[0];
    var B: UINT32 = pChain.H[1];
    var C: UINT32 = pChain.H[2];
    var D: UINT32 = pChain.H[3];
    var E: UINT32 = pChain.H[4];
    var Wt: UINT32 = 0;
    var currPbData = pbData;
    var currCbData = cbData;

    const regs = [5]*UINT32{ &A, &B, &C, &D, &E };

    while (currCbData >= 64) {
        inline for (0..16) |r| {
            const a = regs[(500 - r) % 5];
            const b = regs[(500 - r + 1) % 5];
            const c = regs[(500 - r + 2) % 5];
            const d = regs[(500 - r + 3) % 5];
            const e = regs[(500 - r + 4) % 5];

            Wt = macros.LOAD_MSBFIRST32(currPbData + 4 * r);
            W[r % 16] = Wt;
            e.* +%= macros.ROL32(a.*, 5) +% sha1RoundFn(r, b.*, c.*, d.*) +% Sha1K[r / 20] +% Wt;
            b.* = macros.ROR32(b.*, 2);
        }

        inline for (16..80) |r| {
            const a = regs[(500 - r) % 5];
            const b = regs[(500 - r + 1) % 5];
            const c = regs[(500 - r + 2) % 5];
            const d = regs[(500 - r + 3) % 5];
            const e = regs[(500 - r + 4) % 5];

            Wt = macros.ROL32(W[(r + 13) % 16] ^ W[(r + 8) % 16] ^ W[(r + 2) % 16] ^ W[r % 16], 1);
            W[r % 16] = Wt;
            e.* +%= macros.ROL32(a.*, 5) +% sha1RoundFn(r, b.*, c.*, d.*) +% Sha1K[r / 20] +% Wt;
            b.* = macros.ROR32(b.*, 2);
        }

        A +%= pChain.H[0];
        pChain.H[0] = A;
        B +%= pChain.H[1];
        pChain.H[1] = B;
        C +%= pChain.H[2];
        pChain.H[2] = C;
        D +%= pChain.H[3];
        pChain.H[3] = D;
        E +%= pChain.H[4];
        pChain.H[4] = E;

        currPbData += 64;
        currCbData -= 64;
    }

    pcbRemaining.* = currCbData;

    hash.SymCryptWipeKnownSize(@ptrCast(&W), @sizeOf(@TypeOf(W)));
    macros.FORCE_WRITE32(&A, 0);
    macros.FORCE_WRITE32(&B, 0);
    macros.FORCE_WRITE32(&C, 0);
    macros.FORCE_WRITE32(&D, 0);
    macros.FORCE_WRITE32(&E, 0);
    macros.FORCE_WRITE32(&Wt, 0);
}

pub export fn SymCryptSha1StateExport(
    pState: PCSYMCRYPT_SHA1_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var blob: SYMCRYPT_SHA1_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_SHA1_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeSha1State);

    macros.SymCryptUint32ToMsbFirst(&pState.chain.H, &blob.chain, 5);
    blob.dataLength = pState.dataLengthL;
    const bytesInBuffer: usize = @intCast(blob.dataLength & 0x3f);
    @memcpy(blob.buffer[0..bytesInBuffer], pState.buffer[0..bytesInBuffer]);

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_SHA1_STATE_EXPORT_SIZE], @as(*const [SYMCRYPT_SHA1_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)));

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB));
}

pub export fn SymCryptSha1StateImport(
    pState: PSYMCRYPT_SHA1_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var blob: SYMCRYPT_SHA1_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;

    @memcpy(@as(*[SYMCRYPT_SHA1_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)), pbBlob[0..SYMCRYPT_SHA1_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_SHA1_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeSha1State))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptMsbFirstToUint32(&blob.chain, &pState.chain.H, 5);
    pState.dataLengthL = blob.dataLength;
    pState.dataLengthH = 0;
    pState.bytesInBuffer = @intCast(blob.dataLength & 0x3f);
    @memcpy(pState.buffer[0..pState.bytesInBuffer], blob.buffer[0..pState.bytesInBuffer]);

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB));
    return scError;
}

const sha1KATAnswer: [20]BYTE = .{
    0xa9, 0x99, 0x3e, 0x36,
    0x47, 0x06, 0x81, 0x6a,
    0xba, 0x3e, 0x25, 0x71,
    0x78, 0x50, 0xc2, 0x6c,
    0x9c, 0xd0, 0xd8, 0x9d,
};

pub export fn SymCryptSha1Selftest() callconv(SYMCRYPT_CALL) void {
    var result: [SYMCRYPT_SHA1_RESULT_SIZE]BYTE = undefined;

    SymCryptSha1(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &result);

    hash.SymCryptInjectError(&result, result.len);

    if (!std.mem.eql(u8, &result, &sha1KATAnswer)) {
        macros.SymCryptFatal(macros.multiCharConstant("SHA1"));
    }
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_SHA1_STATE_EXPORT_BLOB) == SYMCRYPT_SHA1_STATE_EXPORT_SIZE);
}
