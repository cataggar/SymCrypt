//
// poly1305.zig
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
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;

pub const SYMCRYPT_POLY1305_RESULT_SIZE: usize = 16;
pub const SYMCRYPT_POLY1305_BLOCK_SIZE: usize = 16;
pub const SYMCRYPT_POLY1305_KEY_SIZE: usize = 32;

pub const SYMCRYPT_POLY1305_STATE = extern struct {
    r: [4]UINT32 align(types.SYMCRYPT_ALIGN_VALUE),
    s: [4]UINT32,
    a: [5]UINT32,
    bytesInBuffer: SIZE_T,
    buf: [16]BYTE,
    magic: SIZE_T,
};
pub const PSYMCRYPT_POLY1305_STATE = *SYMCRYPT_POLY1305_STATE;

extern fn SymCryptWipe(pbData: PVOID, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

inline fn mul32x32to64(a: UINT32, b: UINT32) UINT64 {
    return @as(UINT64, a) * @as(UINT64, b);
}

pub export fn SymCryptPoly1305(
    pbKey: PCBYTE,
    pbData: PCBYTE,
    cbData: SIZE_T,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var state: SYMCRYPT_POLY1305_STATE = undefined;

    SymCryptPoly1305Init(&state, pbKey);
    SymCryptPoly1305Append(&state, pbData, cbData);
    SymCryptPoly1305Result(&state, pbResult);
}

pub export fn SymCryptPoly1305Init(
    pState: PSYMCRYPT_POLY1305_STATE,
    pbKey: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    pState.r[0] = macros.LOAD_LSBFIRST32(pbKey + 0) & 0x0fffffff;
    pState.r[1] = macros.LOAD_LSBFIRST32(pbKey + 4) & 0x0ffffffc;
    pState.r[2] = macros.LOAD_LSBFIRST32(pbKey + 8) & 0x0ffffffc;
    pState.r[3] = macros.LOAD_LSBFIRST32(pbKey + 12) & 0x0ffffffc;

    pState.s[0] = macros.LOAD_LSBFIRST32(pbKey + 16);
    pState.s[1] = macros.LOAD_LSBFIRST32(pbKey + 20);
    pState.s[2] = macros.LOAD_LSBFIRST32(pbKey + 24);
    pState.s[3] = macros.LOAD_LSBFIRST32(pbKey + 28);

    // Set accumulator to zero
    SymCryptWipe(@ptrCast(&pState.a[0]), @sizeOf(@TypeOf(pState.a)));

    pState.bytesInBuffer = 0;
}

pub export fn SymCryptPoly1305Append(
    pState: PSYMCRYPT_POLY1305_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var bytesInBuffer: SIZE_T = pState.bytesInBuffer;

    if (bytesInBuffer != 0) {
        // We have a partial block in the buffer, keep filling the block
        macros.ASSERT(bytesInBuffer < 16);
        var nBytes: SIZE_T = 16 - bytesInBuffer;
        if (nBytes > cbData) {
            nBytes = cbData;
        }

        @memcpy(pState.buf[bytesInBuffer .. bytesInBuffer + nBytes], pbData[0..nBytes]);
        pbData += nBytes;
        cbData -= nBytes;
        bytesInBuffer += nBytes;

        if (bytesInBuffer == 16) {
            // Buffer is full, process it and empty the buffer
            SymCryptPoly1305ProcessBlocks(pState, &pState.buf, bytesInBuffer);
            bytesInBuffer = 0;
        }
        pState.bytesInBuffer = bytesInBuffer;
    }

    if (cbData >= 16) {
        // There are whole blocks to process
        SymCryptPoly1305ProcessBlocks(pState, pbData, cbData & ~@as(SIZE_T, 0xf));
        pbData += cbData;
        cbData &= 0xf;
        pbData -= cbData;
    }

    if (cbData > 0) {
        // Copy remaining data to buffer
        macros.ASSERT(cbData < 16);
        @memcpy(pState.buf[0..cbData], pbData[0..cbData]);
        pState.bytesInBuffer = cbData;
    }
}

pub export fn SymCryptPoly1305Result(
    pState: PSYMCRYPT_POLY1305_STATE,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var bytesInBuffer: SIZE_T = pState.bytesInBuffer;
    var t: UINT64 = 0;

    if (bytesInBuffer > 0) {
        // Add trailing '1' byte and pad with zeroes
        // Wipe function deals with 0-length wipes properly
        pState.buf[bytesInBuffer] = 1;
        bytesInBuffer += 1;
        SymCryptWipe(@ptrCast(pState.buf[bytesInBuffer..].ptr), 16 - bytesInBuffer);

        // Now we have to process the block, but the block function adds a trailing
        // 1 byte to each 16-byte block. We compensate for that by decrementing
        // the highest word of the accumulator first; the 1 byte added by the block
        // processing function has the effect of incrementing the highest accumulator
        // word so those two operations cancel each other out.
        pState.a[4] -%= 1;
        SymCryptPoly1305ProcessBlocks(pState, &pState.buf, 16);
    }

    // We have to fully reduce the accumulator first
    // We have a[4]<6 at this point
    var a0: UINT32 = pState.a[0];
    var a1: UINT32 = pState.a[1];
    var a2: UINT32 = pState.a[2];
    var a3: UINT32 = pState.a[3];
    var a4: UINT32 = pState.a[4];

    macros.ASSERT(a4 < 6);
    // Because a4 < 6, we have to subtract either 0*P or 1*P
    // we subtract P and then mux-choose between the new and old value
    // Subtracting P is the same as subtracting 2^130 and adding 5
    t = 5;

    t += a0;
    a0 = @truncate(t);
    t >>= 32;

    t += a1;
    a1 = @truncate(t);
    t >>= 32;

    t += a2;
    a2 = @truncate(t);
    t >>= 32;

    t += a3;
    a3 = @truncate(t);
    t >>= 32;

    t +%= a4;
    t -%= 4;
    a4 = @truncate(t);
    t >>= 32;

    // If this subtraction produced a carry, then t = 0xffffffff, otherwise it is 0
    const maskOld: UINT32 = @truncate(t); // ffffffff if the old value is correct, 0 otherwise
    const maskNew: UINT32 = ~maskOld; // ffffffff if the new value is correct, 0 otherwise

    a0 = (maskNew & a0) | (maskOld & pState.a[0]);
    a1 = (maskNew & a1) | (maskOld & pState.a[1]);
    a2 = (maskNew & a2) | (maskOld & pState.a[2]);
    a3 = (maskNew & a3) | (maskOld & pState.a[3]);

    // Now we add S and return the data
    t = a0;
    t += pState.s[0];
    macros.STORE_LSBFIRST32(pbResult + 0, @truncate(t));
    t >>= 32;

    t += a1;
    t += pState.s[1];
    macros.STORE_LSBFIRST32(pbResult + 4, @truncate(t));
    t >>= 32;

    t += a2;
    t += pState.s[2];
    macros.STORE_LSBFIRST32(pbResult + 8, @truncate(t));
    t >>= 32;

    t += a3;
    t += pState.s[3];
    macros.STORE_LSBFIRST32(pbResult + 12, @truncate(t));

    SymCryptWipe(@ptrCast(pState), @sizeOf(SYMCRYPT_POLY1305_STATE));
}

pub export fn SymCryptPoly1305ProcessBlocks(
    pState: PSYMCRYPT_POLY1305_STATE,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;

    const r0: UINT32 = pState.r[0];
    const r1: UINT32 = pState.r[1];
    const r2: UINT32 = pState.r[2];
    const r3: UINT32 = pState.r[3];

    var a0: UINT32 = pState.a[0];
    var a1: UINT32 = pState.a[1];
    var a2: UINT32 = pState.a[2];
    var a3: UINT32 = pState.a[3];
    var a4: UINT32 = pState.a[4];

    // Here we have a4 < 6, but we sometimes decrement a4 to compensate for the
    // 2^128 this function always adds. So we test a4 + 1 < 7
    macros.ASSERT(a4 +% 1 < 7);

    while (cbData >= 16) {
        // Acc += data[0..15] + 2^128
        var t64: UINT64 = @as(UINT64, a0) + macros.LOAD_LSBFIRST32(pbData + 0);
        a0 = @truncate(t64);
        t64 >>= 32;

        t64 += @as(UINT64, a1) + macros.LOAD_LSBFIRST32(pbData + 4);
        a1 = @truncate(t64);
        t64 >>= 32;

        t64 += @as(UINT64, a2) + macros.LOAD_LSBFIRST32(pbData + 8);
        a2 = @truncate(t64);
        t64 >>= 32;

        t64 += @as(UINT64, a3) + macros.LOAD_LSBFIRST32(pbData + 12);
        a3 = @truncate(t64);
        t64 >>= 32;

        a4 = @as(UINT32, @truncate(t64)) +% a4 +% 1; // +1 is the padding '1' which we always apply
        macros.ASSERT(a4 < 8);

        pbData += 16;
        cbData -= 16;

        // Compute S3
        t64 = mul32x32to64(a3, r0) +
            mul32x32to64(a2, r1) +
            mul32x32to64(a1, r2) +
            mul32x32to64(a0, r3);

        macros.ASSERT(t64 < (@as(UINT64, 1) << 62));

        const T3: UINT32 = @truncate(t64);
        t64 >>= 32;

        // Compute T = S4 + floor(S3/2^32). We have the floor part in t64 already
        // now add S4 to it
        t64 += @as(UINT64, a4 * r0) + // this fits in 32 bits as r0 < 2^28 and a4 < 8
            mul32x32to64(a3, r1) +
            mul32x32to64(a2, r2) +
            mul32x32to64(a1, r3);

        const U: UINT32 = @as(UINT32, @truncate(t64)) & 3;
        t64 &= ~@as(UINT64, 3); // t64 = T4 here

        // Compute S0 + T4 + T4/4, and V0
        t64 += (t64 >> 2) + mul32x32to64(a0, r0);
        const V0: UINT32 = @truncate(t64);
        var cy: UINT32 = @truncate(t64 >> 32); // the carry from S0 to S1

        // Compute S5
        t64 = @as(UINT64, a4 * r1) + mul32x32to64(a3, r2) + mul32x32to64(a2, r3);
        t64 += t64 >> 2; // = S5 + S5/4

        t64 += mul32x32to64(a1, r0) + mul32x32to64(a0, r1);
        // t64 = S1 + S5 + S5/4

        t64 += cy;
        const V1: UINT32 = @truncate(t64);
        cy = @truncate(t64 >> 32); // the carry from S1 to S2

        // Compute S6
        t64 = @as(UINT64, a4 * r2) + mul32x32to64(a3, r3);
        t64 += t64 >> 2; // S6 + S6/4

        // now add S2
        t64 += mul32x32to64(a2, r0) + mul32x32to64(a1, r1) + mul32x32to64(a0, r2);
        t64 += cy;
        const V2: UINT32 = @truncate(t64);
        cy = @truncate(t64 >> 32);

        // Finally T3 + S7 + S7/4
        var t32: UINT32 = a4 * r3; // =S7, a 32-bit value
        t32 += t32 / 4;
        t64 = @as(UINT64, T3) + t32;
        t64 += cy;

        a0 = V0;
        a1 = V1;
        a2 = V2;
        a3 = @truncate(t64);
        a4 = U + @as(UINT32, @truncate(t64 >> 32));

        macros.ASSERT(a4 < 6);
    }

    pState.a[0] = a0;
    pState.a[1] = a1;
    pState.a[2] = a2;
    pState.a[3] = a3;
    pState.a[4] = a4;
}

extern const SymCryptTestKey32: [32]BYTE;
extern const SymCryptTestMsg16: [16]BYTE;
extern fn SymCryptInjectError(pbData: PBYTE, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

const poly1305Kat = [16]BYTE{
    0xef, 0x9e, 0x73, 0x2a, 0x7f, 0x2d, 0xf1, 0x85, 0xa7, 0x11, 0x80, 0xae, 0x58, 0x3a, 0x0f, 0x93,
};

pub export fn SymCryptPoly1305Selftest() callconv(SYMCRYPT_CALL) void {
    var res: [16]BYTE = undefined;

    SymCryptPoly1305(&SymCryptTestKey32, &SymCryptTestMsg16, 16, &res);

    SymCryptInjectError(&res, res.len);

    if (!std.mem.eql(u8, &res, &poly1305Kat)) {
        macros.SymCryptFatal(comptime macros.multiCharConstant("p135"));
    }
}
