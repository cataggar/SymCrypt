//
// marvin32.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// This module contains the routines to implement the Marvin32 checksum function.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

pub const SYMCRYPT_MARVIN32_RESULT_SIZE: usize = 8;
pub const SYMCRYPT_MARVIN32_SEED_SIZE: usize = 8;
pub const SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE: usize = 4;

pub const SYMCRYPT_MARVIN32_EXPANDED_SEED = extern struct {
    s: [2]UINT32 align(types.SYMCRYPT_ALIGN_VALUE),
    magic: SIZE_T,
};
pub const PSYMCRYPT_MARVIN32_EXPANDED_SEED = *SYMCRYPT_MARVIN32_EXPANDED_SEED;
pub const PCSYMCRYPT_MARVIN32_EXPANDED_SEED = *const SYMCRYPT_MARVIN32_EXPANDED_SEED;

pub const SYMCRYPT_MARVIN32_CHAINING_STATE = SYMCRYPT_MARVIN32_EXPANDED_SEED;
pub const PSYMCRYPT_MARVIN32_CHAINING_STATE = *SYMCRYPT_MARVIN32_CHAINING_STATE;

pub const SYMCRYPT_MARVIN32_STATE = extern struct {
    buffer: [8]BYTE align(types.SYMCRYPT_ALIGN_VALUE),
    chain: SYMCRYPT_MARVIN32_CHAINING_STATE,
    pSeed: ?PCSYMCRYPT_MARVIN32_EXPANDED_SEED,
    dataLength: UINT32,
    magic: SIZE_T,
};
pub const PSYMCRYPT_MARVIN32_STATE = *SYMCRYPT_MARVIN32_STATE;
pub const PCSYMCRYPT_MARVIN32_STATE = *const SYMCRYPT_MARVIN32_STATE;

// Default initial seed, first 8 bytes of SHA256("Marvin32")
var SymCryptMarvin32DefaultSeedStruct: SYMCRYPT_MARVIN32_EXPANDED_SEED = .{
    .s = .{ 0xcd0893b7, 0xd53cd9ce },
    .magic = 0,
};

pub export const SymCryptMarvin32DefaultSeed: PCSYMCRYPT_MARVIN32_EXPANDED_SEED = &SymCryptMarvin32DefaultSeedStruct;

const rotate = [4]u5{ 20, 9, 27, 19 };

inline fn block(a: *UINT32, b: *UINT32) void {
    b.* ^= a.*;
    a.* = macros.ROL32(a.*, rotate[0]);
    a.* +%= b.*;
    b.* = macros.ROL32(b.*, rotate[1]);
    b.* ^= a.*;
    a.* = macros.ROL32(a.*, rotate[2]);
    a.* +%= b.*;
    b.* = macros.ROL32(b.*, rotate[3]);
}

pub export fn SymCryptMarvin32ExpandSeed(
    pExpandedSeed: PSYMCRYPT_MARVIN32_EXPANDED_SEED,
    pbSeed: PCBYTE,
    cbSeed: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbSeed != SYMCRYPT_MARVIN32_SEED_SIZE) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    pExpandedSeed.s[0] = macros.LOAD_LSBFIRST32(pbSeed);
    pExpandedSeed.s[1] = macros.LOAD_LSBFIRST32(pbSeed + 4);

    macros.SET_MAGIC(pExpandedSeed);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMarvin32SeedCopy(
    pSrc: PCSYMCRYPT_MARVIN32_EXPANDED_SEED,
    pDst: PSYMCRYPT_MARVIN32_EXPANDED_SEED,
) callconv(SYMCRYPT_CALL) void {
    if (pSrc != SymCryptMarvin32DefaultSeed) {
        macros.CHECK_MAGIC(pSrc);
    }
    pDst.* = pSrc.*;
    macros.SET_MAGIC(pDst);
}

pub export fn SymCryptMarvin32StateCopy(
    pSrc: PCSYMCRYPT_MARVIN32_STATE,
    pExpandedSeed: ?PCSYMCRYPT_MARVIN32_EXPANDED_SEED,
    pDst: PSYMCRYPT_MARVIN32_STATE,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pSrc);
    pDst.* = pSrc.*;

    if (pExpandedSeed == null) {
        if (pSrc.pSeed) |seed| {
            if (seed != SymCryptMarvin32DefaultSeed) {
                macros.CHECK_MAGIC(seed);
            }
        }
        pDst.pSeed = pSrc.pSeed;
    } else {
        const seed = pExpandedSeed.?;
        if (seed != SymCryptMarvin32DefaultSeed) {
            macros.CHECK_MAGIC(seed);
        }
        pDst.pSeed = seed;
    }

    macros.SET_MAGIC(pDst);
}

pub export fn SymCryptMarvin32Init(
    pState: PSYMCRYPT_MARVIN32_STATE,
    pExpandedSeed: PCSYMCRYPT_MARVIN32_EXPANDED_SEED,
) callconv(SYMCRYPT_CALL) void {
    if (types.DEBUG and pExpandedSeed == SymCryptMarvin32DefaultSeed and SymCryptMarvin32DefaultSeedStruct.magic == 0) {
        macros.SET_MAGIC(&SymCryptMarvin32DefaultSeedStruct);
    }
    pState.chain = pExpandedSeed.*;
    pState.dataLength = 0;
    pState.pSeed = pExpandedSeed;

    @memset(pState.buffer[4..8], 0);

    macros.SET_MAGIC(pState);
}

pub export fn SymCryptMarvin32Append(
    state: PSYMCRYPT_MARVIN32_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var bytesInBuffer: SIZE_T = state.dataLength;

    macros.CHECK_MAGIC(state);

    state.dataLength +%= @truncate(cbData);

    bytesInBuffer &= SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE - 1;

    if (bytesInBuffer > 0) {
        const freeInBuffer: SIZE_T = SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE - bytesInBuffer;
        if (cbData >= freeInBuffer) {
            @memcpy(state.buffer[bytesInBuffer .. bytesInBuffer + freeInBuffer], pbData[0..freeInBuffer]);
            pbData += freeInBuffer;
            cbData -= freeInBuffer;
            SymCryptMarvin32AppendBlocks(&state.chain, &state.buffer, SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE);
            bytesInBuffer = 0;
        }
    }

    if (cbData >= SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE) {
        const cbDataRoundedDown: SIZE_T = cbData & ~(SYMCRYPT_MARVIN32_INPUT_BLOCK_SIZE - 1);
        SymCryptMarvin32AppendBlocks(&state.chain, pbData, cbDataRoundedDown);
        pbData += cbDataRoundedDown;
        cbData -= cbDataRoundedDown;
    }

    if (cbData > 0) {
        @memcpy(state.buffer[bytesInBuffer .. bytesInBuffer + cbData], pbData[0..cbData]);
    }
}

pub export fn SymCryptMarvin32Result(
    pState: PSYMCRYPT_MARVIN32_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var bytesInBuffer: SIZE_T = pState.dataLength & 0x3;

    macros.CHECK_MAGIC(pState);

    @memset(pState.buffer[bytesInBuffer .. bytesInBuffer + 4], 0);

    pState.buffer[bytesInBuffer] = 0x80;
    bytesInBuffer += 1;

    SymCryptMarvin32AppendBlocks(&pState.chain, &pState.buffer, 8);

    macros.STORE_LSBFIRST32(pbResult, pState.chain.s[0]);
    macros.STORE_LSBFIRST32(pbResult + 4, pState.chain.s[1]);

    @memset(pState.buffer[0..4], 0);
    pState.dataLength = 0;

    pState.chain = pState.pSeed.?.*;
}

pub export fn SymCryptMarvin32AppendBlocks(
    pChain: PSYMCRYPT_MARVIN32_CHAINING_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var s0: UINT32 = pChain.s[0];
    var s1: UINT32 = pChain.s[1];

    macros.ASSERT((cbData & 3) == 0);

    while (cbData > 0) {
        s0 +%= macros.LOAD_LSBFIRST32(pbData);
        block(&s0, &s1);
        pbData += 4;
        cbData -= 4;
    }

    pChain.s[0] = s0;
    pChain.s[1] = s1;
}

pub export fn SymCryptMarvin32(
    pExpandedSeed: PCSYMCRYPT_MARVIN32_EXPANDED_SEED,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    if (types.DEBUG and pExpandedSeed == SymCryptMarvin32DefaultSeed and SymCryptMarvin32DefaultSeedStruct.magic == 0) {
        macros.SET_MAGIC(&SymCryptMarvin32DefaultSeedStruct);
    }

    var pbData = pbData_in;
    var cbData = cbData_in;
    var tmp: UINT32 = 0;

    var s0: UINT32 = pExpandedSeed.s[0];
    var s1: UINT32 = pExpandedSeed.s[1];

    while (cbData > 7) {
        s0 +%= macros.LOAD_LSBFIRST32(pbData);
        block(&s0, &s1);
        s0 +%= macros.LOAD_LSBFIRST32(pbData + 4);
        block(&s0, &s1);
        pbData += 8;
        cbData -= 8;
    }

    if (cbData >= 4) {
        s0 +%= macros.LOAD_LSBFIRST32(pbData);
        block(&s0, &s1);
        pbData += 4;
        cbData -= 4;
    }

    switch (cbData) {
        0 => tmp = 0x80,
        1 => tmp = 0x8000 | @as(UINT32, pbData[0]),
        2 => tmp = 0x800000 | @as(UINT32, macros.LOAD_LSBFIRST16(pbData)),
        3 => tmp = @as(UINT32, macros.LOAD_LSBFIRST16(pbData)) | (@as(UINT32, pbData[2]) << 16) | 0x80000000,
        else => unreachable,
    }
    s0 +%= tmp;

    block(&s0, &s1);
    block(&s0, &s1);

    macros.STORE_LSBFIRST32(pbResult, s0);
    macros.STORE_LSBFIRST32(pbResult + 4, s1);
}

extern const SymCryptTestMsg3: [3]BYTE;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const marvin32KATAnswer = [8]BYTE{
    0xbf, 0x69, 0x27, 0x49, 0x39, 0x43, 0xc7, 0x22,
};

pub export fn SymCryptMarvin32Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [SYMCRYPT_MARVIN32_RESULT_SIZE]BYTE = undefined;

    SymCryptMarvin32(SymCryptMarvin32DefaultSeed, &SymCryptTestMsg3, SymCryptTestMsg3.len, &res);

    SymCryptInjectError(&res, res.len);
    if (!std.mem.eql(u8, &res, &marvin32KATAnswer)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("marv"));
    }
}
