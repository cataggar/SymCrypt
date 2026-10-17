//
// md2.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// MD2 implementation from RFC 1319, ported from lib/md2.c.
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
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_HASH = types.SYMCRYPT_HASH;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

pub const SYMCRYPT_MD2_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_MD2_INPUT_BLOCK_SIZE: usize = 16;
pub const SYMCRYPT_MD2_STATE_EXPORT_SIZE: usize = 80;

pub const SYMCRYPT_MD2_CHAINING_STATE = hash.SYMCRYPT_MD2_CHAINING_STATE;
pub const PSYMCRYPT_MD2_CHAINING_STATE = hash.PSYMCRYPT_MD2_CHAINING_STATE;
pub const SYMCRYPT_MD2_STATE = hash.SYMCRYPT_MD2_STATE;
pub const PSYMCRYPT_MD2_STATE = hash.PSYMCRYPT_MD2_STATE;
pub const PCSYMCRYPT_MD2_STATE = hash.PCSYMCRYPT_MD2_STATE;

pub const SYMCRYPT_MD2_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    C: [16]BYTE,
    X: [16]BYTE,
    bytesInBuffer: UINT32 align(1),
    buffer: [16]BYTE,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

const Pattern = hash_pattern.HashPattern(
    SYMCRYPT_MD2_STATE,
    SYMCRYPT_MD2_CHAINING_STATE,
    &SymCryptMd2Init,
    &SymCryptMd2Append,
    &SymCryptMd2Result,
    &SymCryptMd2AppendBlocks,
);

pub export const SymCryptMd2Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Pattern.initVoid,
    .appendFunc = &Pattern.appendVoid,
    .resultFunc = &Pattern.resultVoid,
    .appendBlockFunc = &Pattern.appendBlocksVoid,
    .stateCopyFunc = &Pattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_MD2_STATE),
    .resultSize = SYMCRYPT_MD2_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_MD2_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_MD2_STATE, "chain"),
    .chainSize = @sizeOf(SYMCRYPT_MD2_CHAINING_STATE),
};

pub export const SymCryptMd2Algorithm: PCSYMCRYPT_HASH = &SymCryptMd2Algorithm_default;

pub export const SymCryptMd2STable: [256]BYTE = .{
    41,  46,  67,  201, 162, 216, 124, 1,   61,  54,  84,  161, 236, 240, 6,
    19,  98,  167, 5,   243, 192, 199, 115, 140, 152, 147, 43,  217, 188, 76,
    130, 202, 30,  155, 87,  60,  253, 212, 224, 22,  103, 66,  111, 24,  138,
    23,  229, 18,  190, 78,  196, 214, 218, 158, 222, 73,  160, 251, 245, 142,
    187, 47,  238, 122, 169, 104, 121, 145, 21,  178, 7,   63,  148, 194, 16,
    137, 11,  34,  95,  33,  128, 127, 93,  154, 90,  144, 50,  39,  53,  62,
    204, 231, 191, 247, 151, 3,   255, 25,  48,  179, 72,  165, 181, 209, 215,
    94,  146, 42,  172, 86,  170, 198, 79,  184, 56,  210, 150, 164, 125, 182,
    118, 252, 107, 226, 156, 116, 4,   241, 69,  157, 112, 89,  100, 113, 135,
    32,  134, 91,  207, 101, 230, 45,  168, 2,   27,  96,  37,  173, 174, 176,
    185, 246, 28,  70,  97,  105, 52,  64,  126, 15,  85,  71,  163, 35,  221,
    81,  175, 58,  195, 92,  249, 206, 186, 197, 234, 38,  44,  83,  13,  110,
    133, 40,  132, 9,   211, 223, 205, 244, 65,  129, 77,  82,  106, 220, 55,
    200, 108, 193, 171, 250, 36,  225, 123, 8,   12,  189, 177, 74,  120, 136,
    149, 139, 227, 99,  232, 109, 233, 203, 213, 254, 59,  0,   29,  57,  242,
    239, 183, 14,  102, 88,  208, 228, 166, 119, 114, 248, 235, 117, 75,  10,
    49,  68,  80,  180, 143, 237, 31,  26,  219, 153, 141, 51,  159, 17,  131,
    20,
};

pub export fn SymCryptMd2(
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.hash(pbData, cbData, pbResult);
}

pub export fn SymCryptMd2StateCopy(
    pSrc: PCSYMCRYPT_MD2_STATE,
    pDst: PSYMCRYPT_MD2_STATE,
) callconv(SYMCRYPT_CALL) void {
    Pattern.stateCopy(pSrc, pDst);
}

pub export fn SymCryptMd2Init(pState: PSYMCRYPT_MD2_STATE) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptWipeKnownSize(@ptrCast(pState), @sizeOf(SYMCRYPT_MD2_STATE));
    macros.SET_MAGIC(pState);
}

pub export fn SymCryptMd2Append(
    pState: PSYMCRYPT_MD2_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptHashAppendInternal(SymCryptMd2Algorithm, @ptrCast(pState), pbData, cbData);
}

pub export fn SymCryptMd2Result(
    state: PSYMCRYPT_MD2_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var tmp: SIZE_T = 0;
    const paddingBytes: SIZE_T = 16 - state.bytesInBuffer;

    macros.CHECK_MAGIC(state);

    @memset(state.buffer[state.bytesInBuffer .. state.bytesInBuffer + paddingBytes], @truncate(paddingBytes));

    SymCryptMd2AppendBlocks(&state.chain, &state.buffer, SYMCRYPT_MD2_INPUT_BLOCK_SIZE, &tmp);

    // Append the checksum
    SymCryptMd2AppendBlocks(&state.chain, &state.chain.C, SYMCRYPT_MD2_INPUT_BLOCK_SIZE, &tmp);

    @memcpy(pbResult[0..SYMCRYPT_MD2_RESULT_SIZE], state.chain.X[0..SYMCRYPT_MD2_RESULT_SIZE]);

    // Wipe & re-initialize (Init wipes the state too)
    SymCryptMd2Init(state);
}

pub export fn SymCryptMd2AppendBlocks(
    pChain: PSYMCRYPT_MD2_CHAINING_STATE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pcbRemaining: *SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var currPbData = pbData;
    var currCbData = cbData;

    while (currCbData >= SYMCRYPT_MD2_INPUT_BLOCK_SIZE) {
        @memcpy(pChain.X[16..32], currPbData[0..SYMCRYPT_MD2_INPUT_BLOCK_SIZE]);

        var L: BYTE = pChain.C[15];
        for (0..16) |j| {
            L = pChain.C[j] ^ SymCryptMd2STable[L ^ pChain.X[16 + j]];
            pChain.C[j] = L;
        }

        hash.SymCryptXorBytes(pChain.X[0..].ptr, pChain.X[16..].ptr, pChain.X[32..].ptr, 16);

        var t: u32 = 0;
        for (0..18) |j| {
            for (0..48) |k| {
                t = @as(u32, pChain.X[k]) ^ @as(u32, SymCryptMd2STable[t]);
                pChain.X[k] = @truncate(t);
            }
            t = (t + @as(u32, @intCast(j))) & 0xff;
        }

        currPbData += SYMCRYPT_MD2_INPUT_BLOCK_SIZE;
        currCbData -= SYMCRYPT_MD2_INPUT_BLOCK_SIZE;
    }

    pcbRemaining.* = currCbData;
}

pub export fn SymCryptMd2StateExport(
    pState: PCSYMCRYPT_MD2_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var blob: SYMCRYPT_MD2_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    macros.CHECK_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_MD2_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd2State);

    @memcpy(&blob.C, &pState.chain.C);
    @memcpy(&blob.X, pState.chain.X[0..16]);
    blob.bytesInBuffer = pState.bytesInBuffer;
    @memcpy(blob.buffer[0..blob.bytesInBuffer], pState.buffer[0..blob.bytesInBuffer]);

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_MD2_STATE_EXPORT_SIZE], @as(*const [SYMCRYPT_MD2_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)));

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB));
}

pub export fn SymCryptMd2StateImport(
    pState: PSYMCRYPT_MD2_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var blob: SYMCRYPT_MD2_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;

    @memcpy(@as(*[SYMCRYPT_MD2_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)), pbBlob[0..SYMCRYPT_MD2_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_MD2_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(hash.SYMCRYPT_BLOB_TYPE.SymCryptBlobTypeMd2State))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB));
        return scError;
    }

    @memcpy(&pState.chain.C, &blob.C);
    @memcpy(pState.chain.X[0..16], &blob.X);
    @memcpy(&pState.buffer, &blob.buffer);
    pState.bytesInBuffer = blob.bytesInBuffer;

    pState.dataLengthL = blob.bytesInBuffer;
    pState.dataLengthH = 1;

    macros.SET_MAGIC(pState);

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB));
    return scError;
}

const md2KATAnswer: [16]BYTE = .{
    0xda, 0x85, 0x3b, 0x0d, 0x3f, 0x88, 0xd9, 0x9b,
    0x30, 0x28, 0x3a, 0x69, 0xe6, 0xde, 0xd6, 0xbb,
};

pub export fn SymCryptMd2Selftest() callconv(SYMCRYPT_CALL) void {
    var result: [SYMCRYPT_MD2_RESULT_SIZE]BYTE = undefined;

    SymCryptMd2(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &result);

    hash.SymCryptInjectError(&result, result.len);

    if (!std.mem.eql(u8, &result, &md2KATAnswer)) {
        macros.SymCryptFatal(macros.multiCharConstant("MD2t"));
    }
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_MD2_STATE_EXPORT_BLOB) == SYMCRYPT_MD2_STATE_EXPORT_SIZE);
}
