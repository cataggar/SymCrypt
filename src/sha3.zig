//
// sha3.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Keccak-f[1600] sponge construction and SHA-3 family (SHA3-224, SHA3-256,
// SHA3-384, SHA3-512) from FIPS 202, ported from lib/sha3.c, lib/sha3_224.c,
// lib/sha3_256.c, lib/sha3_384.c, and lib/sha3_512.c.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const hash = @import("hash.zig");
const hash_pattern = @import("hash_pattern.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT8 = types.UINT8;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const TRUE = types.TRUE;
const FALSE = types.FALSE;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_HASH = types.SYMCRYPT_HASH;
const PCSYMCRYPT_HASH = types.PCSYMCRYPT_HASH;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_ALIGN_VALUE = types.SYMCRYPT_ALIGN_VALUE;

// ==============================================================================================
// Keccak / SHA-3 Constants & Types
// ==============================================================================================

pub const SYMCRYPT_SHA3_PADDING_VALUE: UINT8 = 0x06; // 01 10* padding
pub const SYMCRYPT_SHAKE_PADDING_VALUE: UINT8 = 0x1f; // 11 11 10* padding
pub const SYMCRYPT_CSHAKE_PADDING_VALUE: UINT8 = 0x04; // 00 10* padding (used when N or S are non-empty strings)

pub const SYMCRYPT_KECCAK_STATE_EXPORT_SIZE: usize = 234;
pub const SYMCRYPT_SHA3_224_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_256_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_384_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_512_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;

pub const SYMCRYPT_SHA3_224_RESULT_SIZE: usize = 28;
pub const SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE: usize = 144;
pub const SYMCRYPT_SHA3_224_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA3_256_RESULT_SIZE: usize = 32;
pub const SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE: usize = 136;
pub const SYMCRYPT_SHA3_256_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA3_384_RESULT_SIZE: usize = 48;
pub const SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE: usize = 104;
pub const SYMCRYPT_SHA3_384_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHA3_512_RESULT_SIZE: usize = 64;
pub const SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE: usize = 72;
pub const SYMCRYPT_SHA3_512_OID_COUNT: usize = 2;

pub const SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE: usize = 168;
pub const SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE: usize = 136;

pub const SYMCRYPT_KECCAK_STATE = hash.SYMCRYPT_KECCAK_STATE;
pub const PSYMCRYPT_KECCAK_STATE = *SYMCRYPT_KECCAK_STATE;
pub const PCSYMCRYPT_KECCAK_STATE = *const SYMCRYPT_KECCAK_STATE;

pub const SYMCRYPT_SHA3_224_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHA3_224_STATE = *SYMCRYPT_SHA3_224_STATE;
pub const PCSYMCRYPT_SHA3_224_STATE = *const SYMCRYPT_SHA3_224_STATE;

pub const SYMCRYPT_SHA3_256_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHA3_256_STATE = *SYMCRYPT_SHA3_256_STATE;
pub const PCSYMCRYPT_SHA3_256_STATE = *const SYMCRYPT_SHA3_256_STATE;

pub const SYMCRYPT_SHA3_384_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHA3_384_STATE = *SYMCRYPT_SHA3_384_STATE;
pub const PCSYMCRYPT_SHA3_384_STATE = *const SYMCRYPT_SHA3_384_STATE;

pub const SYMCRYPT_SHA3_512_STATE = hash.SYMCRYPT_SHA3_STATE;
pub const PSYMCRYPT_SHA3_512_STATE = *SYMCRYPT_SHA3_512_STATE;
pub const PCSYMCRYPT_SHA3_512_STATE = *const SYMCRYPT_SHA3_512_STATE;

pub const SYMCRYPT_KECCAK_STATE_EXPORT_BLOB = extern struct {
    header: hash.SYMCRYPT_BLOB_HEADER align(1),
    state: [200]BYTE,
    stateIndex: UINT32 align(1),
    paddingValue: UINT8,
    squeezeMode: BOOLEAN,
    rfu: [8]BYTE,
    trailer: hash.SYMCRYPT_BLOB_TRAILER,
};

pub const SYMCRYPT_SHA3_224_STATE_EXPORT_BLOB = SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;
pub const SYMCRYPT_SHA3_256_STATE_EXPORT_BLOB = SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;
pub const SYMCRYPT_SHA3_384_STATE_EXPORT_BLOB = SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;
pub const SYMCRYPT_SHA3_512_STATE_EXPORT_BLOB = SYMCRYPT_KECCAK_STATE_EXPORT_BLOB;

// ==============================================================================================
// OID Lists
// ==============================================================================================

pub const SymCryptSha3_224OidList: [SYMCRYPT_SHA3_224_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07" },
};

pub const SymCryptSha3_256OidList: [SYMCRYPT_SHA3_256_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08" },
};

pub const SymCryptSha3_384OidList: [SYMCRYPT_SHA3_384_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09" },
};

pub const SymCryptSha3_512OidList: [SYMCRYPT_SHA3_512_OID_COUNT]SYMCRYPT_OID = .{
    .{ .cbOID = 13, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a\x05\x00" },
    .{ .cbOID = 11, .pbOID = "\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0a" },
};

// ==============================================================================================
// Keccak-f[1600] Permutation & Sponge Core (from lib/sha3.c)
// ==============================================================================================

const KeccakRhoK: [25]UINT8 = .{
    0, 1, 62, 28, 27, // y = 0
    36, 44, 6, 55, 20, // y = 1
    3, 10, 43, 25, 39, // y = 2
    41, 45, 15, 21, 8, // y = 3
    18, 2, 61, 56, 14, // y = 4
};

const KeccakIotaK: [24]UINT64 = .{
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
};

inline fn keccakColumnSum(state: [*]UINT64, comptime c: usize) UINT64 {
    return state[0 + c] ^ state[5 + c] ^ state[10 + c] ^ state[15 + c] ^ state[20 + c];
}

inline fn keccakColumnUpdate(state: [*]UINT64, comptime c: usize, w: UINT64) void {
    const t: UINT64 = w;
    state[0 + c] ^= t;
    state[5 + c] ^= t;
    state[10 + c] ^= t;
    state[15 + c] ^= t;
    state[20 + c] ^= t;
}

inline fn keccakTheta(state: [*]UINT64) void {
    var colSum: [5]UINT64 = undefined;
    colSum[0] = keccakColumnSum(state, 0);
    colSum[1] = keccakColumnSum(state, 1);
    colSum[2] = keccakColumnSum(state, 2);
    colSum[3] = keccakColumnSum(state, 3);
    colSum[4] = keccakColumnSum(state, 4);
    keccakColumnUpdate(state, 0, colSum[4] ^ macros.ROL64(colSum[1], 1));
    keccakColumnUpdate(state, 1, colSum[0] ^ macros.ROL64(colSum[2], 1));
    keccakColumnUpdate(state, 2, colSum[1] ^ macros.ROL64(colSum[3], 1));
    keccakColumnUpdate(state, 3, colSum[2] ^ macros.ROL64(colSum[4], 1));
    keccakColumnUpdate(state, 4, colSum[3] ^ macros.ROL64(colSum[0], 1));
}

inline fn keccakRhoRow(state: [*]UINT64, comptime r: usize) void {
    state[5 * r + 0] = macros.ROL64(state[5 * r + 0], KeccakRhoK[5 * r + 0]);
    state[5 * r + 1] = macros.ROL64(state[5 * r + 1], KeccakRhoK[5 * r + 1]);
    state[5 * r + 2] = macros.ROL64(state[5 * r + 2], KeccakRhoK[5 * r + 2]);
    state[5 * r + 3] = macros.ROL64(state[5 * r + 3], KeccakRhoK[5 * r + 3]);
    state[5 * r + 4] = macros.ROL64(state[5 * r + 4], KeccakRhoK[5 * r + 4]);
}

inline fn keccakRhoRow0(state: [*]UINT64) void {
    state[1] = macros.ROL64(state[1], KeccakRhoK[1]);
    state[2] = macros.ROL64(state[2], KeccakRhoK[2]);
    state[3] = macros.ROL64(state[3], KeccakRhoK[3]);
    state[4] = macros.ROL64(state[4], KeccakRhoK[4]);
}

inline fn keccakRho(state: [*]UINT64) void {
    keccakRhoRow0(state);
    keccakRhoRow(state, 1);
    keccakRhoRow(state, 2);
    keccakRhoRow(state, 3);
    keccakRhoRow(state, 4);
}

inline fn keccakPi(state: [*]UINT64) void {
    const t: UINT64 = state[1];
    state[1] = state[6];
    state[6] = state[9];
    state[9] = state[22];
    state[22] = state[14];
    state[14] = state[20];
    state[20] = state[2];
    state[2] = state[12];
    state[12] = state[13];
    state[13] = state[19];
    state[19] = state[23];
    state[23] = state[15];
    state[15] = state[4];
    state[4] = state[24];
    state[24] = state[21];
    state[21] = state[8];
    state[8] = state[16];
    state[16] = state[5];
    state[5] = state[3];
    state[3] = state[18];
    state[18] = state[17];
    state[17] = state[11];
    state[11] = state[7];
    state[7] = state[10];
    state[10] = t;
}

inline fn keccakChiRow(state: [*]UINT64, comptime r: usize) void {
    const t1: UINT64 = state[5 * r + 0] ^ (~state[5 * r + 1] & state[5 * r + 2]);
    const t2: UINT64 = state[5 * r + 1] ^ (~state[5 * r + 2] & state[5 * r + 3]);
    state[5 * r + 2] = state[5 * r + 2] ^ (~state[5 * r + 3] & state[5 * r + 4]);
    state[5 * r + 3] = state[5 * r + 3] ^ (~state[5 * r + 4] & state[5 * r + 0]);
    state[5 * r + 4] = state[5 * r + 4] ^ (~state[5 * r + 0] & state[5 * r + 1]);
    state[5 * r + 0] = t1;
    state[5 * r + 1] = t2;
}

inline fn keccakChi(state: [*]UINT64) void {
    keccakChiRow(state, 0);
    keccakChiRow(state, 1);
    keccakChiRow(state, 2);
    keccakChiRow(state, 3);
    keccakChiRow(state, 4);
}

inline fn keccakIota(state: [*]UINT64, rnd: usize) void {
    state[0] ^= KeccakIotaK[rnd];
}

inline fn keccakPermRound(state: [*]UINT64, rnd: usize) void {
    keccakTheta(state);
    keccakRho(state);
    keccakPi(state);
    keccakChi(state);
    keccakIota(state, rnd);
}

pub export fn SymCryptKeccakPermute(pState: [*]UINT64) callconv(SYMCRYPT_CALL) void {
    for (0..24) |r| {
        keccakPermRound(pState, r);
    }
}

pub export fn SymCryptKeccakInit(
    pState: PSYMCRYPT_KECCAK_STATE,
    inputBlockSize: UINT32,
    paddingValue: UINT8,
) callconv(SYMCRYPT_CALL) void {
    pState.inputBlockSize = inputBlockSize;
    pState.paddingValue = paddingValue;

    SymCryptKeccakReset(pState);
}

pub export fn SymCryptKeccakReset(pState: PSYMCRYPT_KECCAK_STATE) callconv(SYMCRYPT_CALL) void {
    hash.SymCryptWipeKnownSize(@ptrCast(&pState.state), @sizeOf(@TypeOf(pState.state)));
    pState.stateIndex = 0;
    pState.squeezeMode = FALSE;
}

inline fn SymCryptKeccakAppendByte(pState: PSYMCRYPT_KECCAK_STATE, val: BYTE) void {
    macros.ASSERT(pState.squeezeMode == FALSE);
    macros.ASSERT(pState.stateIndex < pState.inputBlockSize);

    const laneIdx: usize = pState.stateIndex / @sizeOf(UINT64);
    const bitShift: u6 = @intCast(8 * (pState.stateIndex % 8));
    pState.state[laneIdx] ^= (@as(UINT64, val) << bitShift);
    pState.stateIndex += 1;
}

inline fn SymCryptKeccakAppendBytes(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbBuffer: PCBYTE,
    cbBuffer: SIZE_T,
) void {
    macros.ASSERT(pState.squeezeMode == FALSE);
    macros.ASSERT((pState.stateIndex + cbBuffer) <= pState.inputBlockSize);

    var i: SIZE_T = 0;
    while (i < cbBuffer) : (i += 1) {
        const pos: usize = pState.stateIndex + i;
        const laneIdx: usize = pos / @sizeOf(UINT64);
        const bitShift: u6 = @intCast(8 * (pos % 8));
        pState.state[laneIdx] ^= (@as(UINT64, pbBuffer[i]) << bitShift);
    }

    pState.stateIndex += @intCast(cbBuffer);
}

pub export fn SymCryptKeccakAppendLanes(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbData: PCBYTE,
    uLaneCount: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pState.squeezeMode == FALSE);
    macros.ASSERT((pState.inputBlockSize & 0x7) == 0);
    macros.ASSERT((pState.stateIndex & 0x7) == 0);
    macros.ASSERT(pState.stateIndex != pState.inputBlockSize);

    var uLaneIndex: UINT32 = pState.stateIndex / @sizeOf(UINT64);

    var i: SIZE_T = 0;
    while (i < uLaneCount) : (i += 1) {
        pState.state[uLaneIndex] ^= macros.LOAD_LSBFIRST64(pbData + i * @sizeOf(UINT64));
        pState.stateIndex += @sizeOf(UINT64);
        uLaneIndex += 1;

        if (pState.stateIndex == pState.inputBlockSize) {
            SymCryptKeccakPermute(&pState.state);
            pState.stateIndex = 0;
            uLaneIndex = 0;
        }
    }
}

pub export fn SymCryptKeccakZeroAppendBlock(pState: PSYMCRYPT_KECCAK_STATE) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pState.squeezeMode == FALSE);
    SymCryptKeccakPermute(&pState.state);
    pState.stateIndex = 0;
}

pub export fn SymCryptKeccakAppend(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbDataIn: PCBYTE,
    cbDataIn: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbDataIn;
    var cbData = cbDataIn;

    macros.ASSERT(pState.inputBlockSize % 8 == 0);

    if (pState.squeezeMode != FALSE) {
        SymCryptKeccakReset(pState);
    }

    macros.ASSERT(pState.stateIndex < pState.inputBlockSize);

    while (cbData > 0 and (pState.stateIndex & 0x7) != 0) {
        SymCryptKeccakAppendByte(pState, pbData[0]);
        pbData += 1;
        cbData -= 1;
    }

    if (pState.stateIndex == pState.inputBlockSize) {
        SymCryptKeccakPermute(&pState.state);
        pState.stateIndex = 0;
    }

    const uFullLanes: SIZE_T = cbData / @sizeOf(UINT64);
    if (uFullLanes > 0) {
        SymCryptKeccakAppendLanes(pState, pbData, uFullLanes);
        pbData += uFullLanes * @sizeOf(UINT64);
        cbData -= uFullLanes * @sizeOf(UINT64);
    }

    macros.ASSERT(cbData < @sizeOf(UINT64));
    SymCryptKeccakAppendBytes(pState, pbData, cbData);

    macros.ASSERT(pState.stateIndex != pState.inputBlockSize);
}

pub export fn SymCryptKeccakApplyPadding(pState: PSYMCRYPT_KECCAK_STATE) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pState.squeezeMode == FALSE);

    const uLanePos: UINT32 = pState.stateIndex / @sizeOf(UINT64);
    const uBytePos: UINT32 = pState.stateIndex % @sizeOf(UINT64);
    const bitShift: u6 = @intCast(8 * uBytePos);
    pState.state[uLanePos] ^= (@as(UINT64, pState.paddingValue) << bitShift);

    pState.state[pState.inputBlockSize / @sizeOf(UINT64) - 1] ^= (@as(UINT64, 1) << 63);

    SymCryptKeccakPermute(&pState.state);
    pState.stateIndex = 0;
    pState.squeezeMode = TRUE;
}

inline fn SymCryptKeccakExtractByte(pState: PSYMCRYPT_KECCAK_STATE) BYTE {
    macros.ASSERT(pState.squeezeMode != FALSE);
    macros.ASSERT(pState.stateIndex < pState.inputBlockSize);

    const laneIdx: usize = pState.stateIndex / @sizeOf(UINT64);
    const bitShift: u6 = @intCast(8 * (pState.stateIndex % 8));
    const ret: BYTE = @truncate((pState.state[laneIdx] >> bitShift) & 0xff);
    pState.stateIndex += 1;
    return ret;
}

pub export fn SymCryptKeccakExtractLanes(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbResult: PBYTE,
    uLaneCount: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pState.squeezeMode != FALSE);
    macros.ASSERT((pState.inputBlockSize & 0x7) == 0);
    macros.ASSERT((pState.stateIndex & 0x7) == 0);

    var uLaneIndex: UINT32 = pState.stateIndex / @sizeOf(UINT64);

    var i: SIZE_T = 0;
    while (i < uLaneCount) : (i += 1) {
        macros.ASSERT(pState.stateIndex <= pState.inputBlockSize);

        if (pState.stateIndex == pState.inputBlockSize) {
            SymCryptKeccakPermute(&pState.state);
            pState.stateIndex = 0;
            uLaneIndex = 0;
        }

        macros.STORE_LSBFIRST64(pbResult + i * @sizeOf(UINT64), pState.state[uLaneIndex]);
        pState.stateIndex += @sizeOf(UINT64);
        uLaneIndex += 1;
    }
}

pub export fn SymCryptKeccakExtract(
    pState: PSYMCRYPT_KECCAK_STATE,
    pbResultIn: PBYTE,
    cbResultIn: SIZE_T,
    bWipe: BOOLEAN,
) callconv(SYMCRYPT_CALL) void {
    var pbResult = pbResultIn;
    var cbResult = cbResultIn;

    if (pState.squeezeMode == FALSE) {
        SymCryptKeccakApplyPadding(pState);
    }

    if ((cbResult > 0) and (pState.stateIndex == pState.inputBlockSize)) {
        SymCryptKeccakPermute(&pState.state);
        pState.stateIndex = 0;
    }

    while (cbResult > 0 and (pState.stateIndex & 0x7) != 0) {
        pbResult[0] = SymCryptKeccakExtractByte(pState);
        pbResult += 1;
        cbResult -= 1;
    }

    macros.ASSERT((cbResult == 0) or ((pState.stateIndex & 0x7) == 0));

    const uFullLanes: SIZE_T = cbResult / @sizeOf(UINT64);
    if (uFullLanes > 0) {
        SymCryptKeccakExtractLanes(pState, pbResult, uFullLanes);
        pbResult += uFullLanes * @sizeOf(UINT64);
        cbResult -= uFullLanes * @sizeOf(UINT64);
    }

    macros.ASSERT(cbResult < @sizeOf(UINT64));
    while (cbResult > 0) {
        if (pState.stateIndex == pState.inputBlockSize) {
            SymCryptKeccakPermute(&pState.state);
            pState.stateIndex = 0;
        }

        pbResult[0] = SymCryptKeccakExtractByte(pState);
        pbResult += 1;
        cbResult -= 1;
    }

    if (bWipe != FALSE) {
        SymCryptKeccakReset(pState);
    }
}

pub export fn SymCryptKeccakStateExport(
    blobType: hash.SYMCRYPT_BLOB_TYPE,
    pState: PCSYMCRYPT_KECCAK_STATE,
    pbBlob: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var blob: SYMCRYPT_KECCAK_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));

    blob.header.magic = hash.SYMCRYPT_BLOB_MAGIC;
    blob.header.size = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
    blob.header.type = @backingInt(blobType);

    macros.SymCryptUint64ToLsbFirst(&pState.state, &blob.state, 25);
    blob.stateIndex = pState.stateIndex;
    blob.paddingValue = pState.paddingValue;
    blob.squeezeMode = pState.squeezeMode;

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &blob.trailer.checksum,
    );

    @memcpy(pbBlob[0..SYMCRYPT_KECCAK_STATE_EXPORT_SIZE], @as(*const [SYMCRYPT_KECCAK_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)));

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
}

pub export fn SymCryptKeccakStateImport(
    blobType: hash.SYMCRYPT_BLOB_TYPE,
    pState: PSYMCRYPT_KECCAK_STATE,
    pbBlob: PCBYTE,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var blob: SYMCRYPT_KECCAK_STATE_EXPORT_BLOB align(SYMCRYPT_ALIGN_VALUE) = undefined;
    var checksum: [8]BYTE = undefined;

    @memcpy(@as(*[SYMCRYPT_KECCAK_STATE_EXPORT_SIZE]BYTE, @ptrCast(&blob)), pbBlob[0..SYMCRYPT_KECCAK_STATE_EXPORT_SIZE]);

    if (blob.header.magic != hash.SYMCRYPT_BLOB_MAGIC or
        blob.header.size != SYMCRYPT_KECCAK_STATE_EXPORT_SIZE or
        blob.header.type != @backingInt(blobType))
    {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptMarvin32(
        hash.SymCryptMarvin32DefaultSeed,
        @ptrCast(&blob),
        @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB) - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER),
        &checksum,
    );
    if (!std.mem.eql(u8, &checksum, &blob.trailer.checksum)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
        return scError;
    }

    macros.SymCryptLsbFirstToUint64(&blob.state, &pState.state, 25);
    pState.stateIndex = blob.stateIndex;
    pState.paddingValue = blob.paddingValue;
    pState.squeezeMode = blob.squeezeMode;

    pState.inputBlockSize = 0;
    pState.paddingValue = 0;

    switch (@as(hash.SYMCRYPT_BLOB_TYPE, @fromBackingInt(@intCast(blob.header.type)))) {
        .SymCryptBlobTypeSha3_224State => {
            pState.inputBlockSize = SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHA3_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        .SymCryptBlobTypeSha3_256State => {
            pState.inputBlockSize = SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHA3_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        .SymCryptBlobTypeSha3_384State => {
            pState.inputBlockSize = SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHA3_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        .SymCryptBlobTypeSha3_512State => {
            pState.inputBlockSize = SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHA3_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        .SymCryptBlobTypeShake128State => {
            pState.inputBlockSize = SYMCRYPT_SHAKE128_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHAKE_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        .SymCryptBlobTypeShake256State => {
            pState.inputBlockSize = SYMCRYPT_SHAKE256_INPUT_BLOCK_SIZE;
            if (blob.paddingValue == SYMCRYPT_SHAKE_PADDING_VALUE) {
                pState.paddingValue = blob.paddingValue;
            }
        },
        else => {
            scError = .SYMCRYPT_INVALID_BLOB;
            hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
            return scError;
        },
    }

    if (pState.inputBlockSize == 0 or pState.paddingValue == 0) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
        return scError;
    }

    if (pState.stateIndex > pState.inputBlockSize) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
        return scError;
    }

    if ((pState.stateIndex == pState.inputBlockSize) and (pState.squeezeMode == FALSE)) {
        scError = .SYMCRYPT_INVALID_BLOB;
        hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
        return scError;
    }

    hash.SymCryptWipeKnownSize(@ptrCast(&blob), @sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB));
    return scError;
}

// ==============================================================================================
// Comptime Generic SHA-3 Implementation
// ==============================================================================================

fn Sha3Pattern(
    comptime StateType: type,
    comptime input_block_size: UINT32,
    comptime result_size: SIZE_T,
    comptime blob_type: hash.SYMCRYPT_BLOB_TYPE,
    comptime kat_answer: *const [result_size]BYTE,
) type {
    return struct {
        fn dummyAppendBlocks(_: *UINT64, _: PCBYTE, _: SIZE_T, _: *SIZE_T) callconv(SYMCRYPT_CALL) void {}

        pub const BasePattern = hash_pattern.HashPattern(
            StateType,
            UINT64,
            &init,
            &append,
            &result,
            &dummyAppendBlocks,
        );

        pub fn hashOneShot(
            pbData: PCBYTE,
            cbData: SIZE_T,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            BasePattern.hash(pbData, cbData, pbResult);
        }

        pub fn stateCopy(
            pSrc: *const StateType,
            pDst: *StateType,
        ) callconv(SYMCRYPT_CALL) void {
            BasePattern.stateCopy(pSrc, pDst);
        }

        pub fn init(pState: *StateType) callconv(SYMCRYPT_CALL) void {
            SymCryptKeccakInit(&pState.ks, input_block_size, SYMCRYPT_SHA3_PADDING_VALUE);
            macros.SET_MAGIC(pState);
        }

        pub fn append(
            pState: *StateType,
            pbData: PCBYTE,
            cbData: SIZE_T,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptKeccakAppend(&pState.ks, pbData, cbData);
        }

        pub fn result(
            pState: *StateType,
            pbResult: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            SymCryptKeccakExtract(&pState.ks, pbResult, result_size, TRUE);
        }

        pub fn stateExport(
            pState: *const StateType,
            pbBlob: PBYTE,
        ) callconv(SYMCRYPT_CALL) void {
            macros.CHECK_MAGIC(pState);
            SymCryptKeccakStateExport(blob_type, &pState.ks, pbBlob);
        }

        pub fn stateImport(
            pState: *StateType,
            pbBlob: PCBYTE,
        ) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
            const scError = SymCryptKeccakStateImport(blob_type, &pState.ks, pbBlob);
            if (scError == .SYMCRYPT_NO_ERROR) {
                macros.SET_MAGIC(pState);
            }
            return scError;
        }

        pub fn selftest() callconv(SYMCRYPT_CALL) void {
            var res: [result_size]BYTE = undefined;

            hashOneShot(&hash.SymCryptTestMsg3, hash.SymCryptTestMsg3.len, &res);

            hash.SymCryptInjectError(&res, res.len);

            if (!std.mem.eql(u8, &res, kat_answer)) {
                macros.SymCryptFatal(macros.multiCharConstant("SHA3"));
            }
        }
    };
}

// ==============================================================================================
// SHA3-224 (from lib/sha3_224.c)
// ==============================================================================================

const sha3_224KATAnswer: [28]BYTE = .{
    0xe6, 0x42, 0x82, 0x4c, 0x3f, 0x8c, 0xf2, 0x4a,
    0xd0, 0x92, 0x34, 0xee, 0x7d, 0x3c, 0x76, 0x6f,
    0xc9, 0xa3, 0xa5, 0x16, 0x8d, 0x0c, 0x94, 0xad,
    0x73, 0xb4, 0x6f, 0xdf,
};

const Sha3_224Impl = Sha3Pattern(
    SYMCRYPT_SHA3_224_STATE,
    SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHA3_224_RESULT_SIZE,
    .SymCryptBlobTypeSha3_224State,
    &sha3_224KATAnswer,
);

pub export const SymCryptSha3_224Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha3_224Impl.BasePattern.initVoid,
    .appendFunc = &Sha3_224Impl.BasePattern.appendVoid,
    .resultFunc = &Sha3_224Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Sha3_224Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA3_224_STATE),
    .resultSize = SYMCRYPT_SHA3_224_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA3_224_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA3_224_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptSha3_224Algorithm: PCSYMCRYPT_HASH = &SymCryptSha3_224Algorithm_default;

pub export fn SymCryptSha3_224(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.hashOneShot(pbData, cbData, pbResult);
}

pub export fn SymCryptSha3_224StateCopy(pSrc: PCSYMCRYPT_SHA3_224_STATE, pDst: PSYMCRYPT_SHA3_224_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha3_224Init(pState: PSYMCRYPT_SHA3_224_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.init(pState);
}

pub export fn SymCryptSha3_224Append(pState: PSYMCRYPT_SHA3_224_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptSha3_224Result(pState: PSYMCRYPT_SHA3_224_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.result(pState, pbResult);
}

pub export fn SymCryptSha3_224StateExport(pState: PCSYMCRYPT_SHA3_224_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptSha3_224StateImport(pState: PSYMCRYPT_SHA3_224_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Sha3_224Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptSha3_224Selftest() callconv(SYMCRYPT_CALL) void {
    Sha3_224Impl.selftest();
}

// ==============================================================================================
// SHA3-256 (from lib/sha3_256.c)
// ==============================================================================================

const sha3_256KATAnswer: [32]BYTE = .{
    0x3a, 0x98, 0x5d, 0xa7, 0x4f, 0xe2, 0x25, 0xb2,
    0x04, 0x5c, 0x17, 0x2d, 0x6b, 0xd3, 0x90, 0xbd,
    0x85, 0x5f, 0x08, 0x6e, 0x3e, 0x9d, 0x52, 0x5b,
    0x46, 0xbf, 0xe2, 0x45, 0x11, 0x43, 0x15, 0x32,
};

const Sha3_256Impl = Sha3Pattern(
    SYMCRYPT_SHA3_256_STATE,
    SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHA3_256_RESULT_SIZE,
    .SymCryptBlobTypeSha3_256State,
    &sha3_256KATAnswer,
);

pub export const SymCryptSha3_256Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha3_256Impl.BasePattern.initVoid,
    .appendFunc = &Sha3_256Impl.BasePattern.appendVoid,
    .resultFunc = &Sha3_256Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Sha3_256Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA3_256_STATE),
    .resultSize = SYMCRYPT_SHA3_256_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA3_256_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA3_256_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptSha3_256Algorithm: PCSYMCRYPT_HASH = &SymCryptSha3_256Algorithm_default;

pub export fn SymCryptSha3_256(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.hashOneShot(pbData, cbData, pbResult);
}

pub export fn SymCryptSha3_256StateCopy(pSrc: PCSYMCRYPT_SHA3_256_STATE, pDst: PSYMCRYPT_SHA3_256_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha3_256Init(pState: PSYMCRYPT_SHA3_256_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.init(pState);
}

pub export fn SymCryptSha3_256Append(pState: PSYMCRYPT_SHA3_256_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptSha3_256Result(pState: PSYMCRYPT_SHA3_256_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.result(pState, pbResult);
}

pub export fn SymCryptSha3_256StateExport(pState: PCSYMCRYPT_SHA3_256_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptSha3_256StateImport(pState: PSYMCRYPT_SHA3_256_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Sha3_256Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptSha3_256Selftest() callconv(SYMCRYPT_CALL) void {
    Sha3_256Impl.selftest();
}

// ==============================================================================================
// SHA3-384 (from lib/sha3_384.c)
// ==============================================================================================

const sha3_384KATAnswer: [48]BYTE = .{
    0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9,
    0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
    0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25,
    0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
    0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5,
    0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25,
};

const Sha3_384Impl = Sha3Pattern(
    SYMCRYPT_SHA3_384_STATE,
    SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHA3_384_RESULT_SIZE,
    .SymCryptBlobTypeSha3_384State,
    &sha3_384KATAnswer,
);

pub export const SymCryptSha3_384Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha3_384Impl.BasePattern.initVoid,
    .appendFunc = &Sha3_384Impl.BasePattern.appendVoid,
    .resultFunc = &Sha3_384Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Sha3_384Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA3_384_STATE),
    .resultSize = SYMCRYPT_SHA3_384_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA3_384_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA3_384_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptSha3_384Algorithm: PCSYMCRYPT_HASH = &SymCryptSha3_384Algorithm_default;

pub export fn SymCryptSha3_384(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.hashOneShot(pbData, cbData, pbResult);
}

pub export fn SymCryptSha3_384StateCopy(pSrc: PCSYMCRYPT_SHA3_384_STATE, pDst: PSYMCRYPT_SHA3_384_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha3_384Init(pState: PSYMCRYPT_SHA3_384_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.init(pState);
}

pub export fn SymCryptSha3_384Append(pState: PSYMCRYPT_SHA3_384_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptSha3_384Result(pState: PSYMCRYPT_SHA3_384_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.result(pState, pbResult);
}

pub export fn SymCryptSha3_384StateExport(pState: PCSYMCRYPT_SHA3_384_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptSha3_384StateImport(pState: PSYMCRYPT_SHA3_384_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Sha3_384Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptSha3_384Selftest() callconv(SYMCRYPT_CALL) void {
    Sha3_384Impl.selftest();
}

// ==============================================================================================
// SHA3-512 (from lib/sha3_512.c)
// ==============================================================================================

const sha3_512KATAnswer: [64]BYTE = .{
    0xb7, 0x51, 0x85, 0x0b, 0x1a, 0x57, 0x16, 0x8a,
    0x56, 0x93, 0xcd, 0x92, 0x4b, 0x6b, 0x09, 0x6e,
    0x08, 0xf6, 0x21, 0x82, 0x74, 0x44, 0xf7, 0x0d,
    0x88, 0x4f, 0x5d, 0x02, 0x40, 0xd2, 0x71, 0x2e,
    0x10, 0xe1, 0x16, 0xe9, 0x19, 0x2a, 0xf3, 0xc9,
    0x1a, 0x7e, 0xc5, 0x76, 0x47, 0xe3, 0x93, 0x40,
    0x57, 0x34, 0x0b, 0x4c, 0xf4, 0x08, 0xd5, 0xa5,
    0x65, 0x92, 0xf8, 0x27, 0x4e, 0xec, 0x53, 0xf0,
};

const Sha3_512Impl = Sha3Pattern(
    SYMCRYPT_SHA3_512_STATE,
    SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE,
    SYMCRYPT_SHA3_512_RESULT_SIZE,
    .SymCryptBlobTypeSha3_512State,
    &sha3_512KATAnswer,
);

pub export const SymCryptSha3_512Algorithm_default: SYMCRYPT_HASH align(SYMCRYPT_ALIGN_VALUE) = .{
    .initFunc = &Sha3_512Impl.BasePattern.initVoid,
    .appendFunc = &Sha3_512Impl.BasePattern.appendVoid,
    .resultFunc = &Sha3_512Impl.BasePattern.resultVoid,
    .appendBlockFunc = null,
    .stateCopyFunc = &Sha3_512Impl.BasePattern.stateCopyVoid,
    .stateSize = @sizeOf(SYMCRYPT_SHA3_512_STATE),
    .resultSize = SYMCRYPT_SHA3_512_RESULT_SIZE,
    .inputBlockSize = SYMCRYPT_SHA3_512_INPUT_BLOCK_SIZE,
    .chainOffset = @offsetOf(SYMCRYPT_SHA3_512_STATE, "ks") + @offsetOf(SYMCRYPT_KECCAK_STATE, "state"),
    .chainSize = @sizeOf([25]UINT64),
};

pub export const SymCryptSha3_512Algorithm: PCSYMCRYPT_HASH = &SymCryptSha3_512Algorithm_default;

pub export fn SymCryptSha3_512(pbData: PCBYTE, cbData: SIZE_T, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.hashOneShot(pbData, cbData, pbResult);
}

pub export fn SymCryptSha3_512StateCopy(pSrc: PCSYMCRYPT_SHA3_512_STATE, pDst: PSYMCRYPT_SHA3_512_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.stateCopy(pSrc, pDst);
}

pub export fn SymCryptSha3_512Init(pState: PSYMCRYPT_SHA3_512_STATE) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.init(pState);
}

pub export fn SymCryptSha3_512Append(pState: PSYMCRYPT_SHA3_512_STATE, pbData: PCBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.append(pState, pbData, cbData);
}

pub export fn SymCryptSha3_512Result(pState: PSYMCRYPT_SHA3_512_STATE, pbResult: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.result(pState, pbResult);
}

pub export fn SymCryptSha3_512StateExport(pState: PCSYMCRYPT_SHA3_512_STATE, pbBlob: PBYTE) callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.stateExport(pState, pbBlob);
}

pub export fn SymCryptSha3_512StateImport(pState: PSYMCRYPT_SHA3_512_STATE, pbBlob: PCBYTE) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return Sha3_512Impl.stateImport(pState, pbBlob);
}

pub export fn SymCryptSha3_512Selftest() callconv(SYMCRYPT_CALL) void {
    Sha3_512Impl.selftest();
}

comptime {
    std.debug.assert(@sizeOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB) == SYMCRYPT_KECCAK_STATE_EXPORT_SIZE);
    std.debug.assert(@offsetOf(SYMCRYPT_KECCAK_STATE_EXPORT_BLOB, "trailer") == SYMCRYPT_KECCAK_STATE_EXPORT_SIZE - @sizeOf(hash.SYMCRYPT_BLOB_TRAILER));
}
