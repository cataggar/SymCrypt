//
// ghash.zig
// GHASH implementation (ports lib/ghash.c and lib/ghash_definitions.h)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_GF128_FIELD_SIZE = types.SYMCRYPT_GF128_FIELD_SIZE;
const SYMCRYPT_GF128_BLOCK_SIZE = types.SYMCRYPT_GF128_BLOCK_SIZE;
const SYMCRYPT_GF128_ELEMENT = types.SYMCRYPT_GF128_ELEMENT;
const PSYMCRYPT_GF128_ELEMENT = types.PSYMCRYPT_GF128_ELEMENT;
const PCSYMCRYPT_GF128_ELEMENT = types.PCSYMCRYPT_GF128_ELEMENT;
const SYMCRYPT_GHASH_EXPANDED_KEY = types.SYMCRYPT_GHASH_EXPANDED_KEY;
const PSYMCRYPT_GHASH_EXPANDED_KEY = types.PSYMCRYPT_GHASH_EXPANDED_KEY;
const PCSYMCRYPT_GHASH_EXPANDED_KEY = types.PCSYMCRYPT_GHASH_EXPANDED_KEY;
const SYMCRYPT_EXTENDED_SAVE_DATA = types.SYMCRYPT_EXTENDED_SAVE_DATA;

const GF128_FIELD_R_BYTE: UINT64 = 0xe1;
pub const GHASH_H_LIMIT: usize = 32;

const V16U8 = @Vector(16, u8);
const V4U32 = @Vector(4, u32);
const V4I32 = @Vector(4, i32);
const V2U64 = @Vector(2, u64);

inline fn ghashHPowerPtr(table: PSYMCRYPT_GF128_ELEMENT, i: usize) *SYMCRYPT_GF128_ELEMENT {
    return &table[GHASH_H_LIMIT - i];
}

inline fn ghashHxPowerPtr(table: PSYMCRYPT_GF128_ELEMENT, i: usize) *SYMCRYPT_GF128_ELEMENT {
    return &table[2 * GHASH_H_LIMIT - i];
}

inline fn ghashHPowerConstPtr(table: PCSYMCRYPT_GF128_ELEMENT, i: usize) *const SYMCRYPT_GF128_ELEMENT {
    return &table[GHASH_H_LIMIT - i];
}

inline fn ghashHxPowerConstPtr(table: PCSYMCRYPT_GF128_ELEMENT, i: usize) *const SYMCRYPT_GF128_ELEMENT {
    return &table[2 * GHASH_H_LIMIT - i];
}

inline fn load128(ptr: PCBYTE) V2U64 {
    return @bitCast(std.mem.readInt(u128, ptr[0..16], .little));
}

inline fn store128(ptr: PBYTE, v: V2U64) void {
    std.mem.writeInt(u128, ptr[0..16], @bitCast(v), .little);
}

inline fn loadElement(el: *const SYMCRYPT_GF128_ELEMENT) V2U64 {
    return el.ull;
}

inline fn storeElement(el: *SYMCRYPT_GF128_ELEMENT, v: V2U64) void {
    el.ull = v;
}

inline fn byteReverse128(v: V2U64) V2U64 {
    const bytes: V16U8 = @bitCast(v);
    const rev = @shuffle(u8, bytes, undefined, [16]i32{
        15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0,
    });
    return @bitCast(rev);
}

inline fn srli128By8(v: V2U64) V2U64 {
    return V2U64{ v[1], 0 };
}

inline fn swap64Halves(v: V2U64) V2U64 {
    return V2U64{ v[1], v[0] };
}

inline fn clmul128(a: V2U64, b: V2U64, comptime imm8: u8) V2U64 {
    if (comptime (types.CPU_X86 or types.CPU_AMD64)) {
        var res = a;
        switch (imm8) {
            0x00 => asm ("pclmulqdq $0x00, %[b], %[res]"
                : [res] "+x" (res),
                : [b] "x" (b),
            ),
            0x01 => asm ("pclmulqdq $0x01, %[b], %[res]"
                : [res] "+x" (res),
                : [b] "x" (b),
            ),
            0x10 => asm ("pclmulqdq $0x10, %[b], %[res]"
                : [res] "+x" (res),
                : [b] "x" (b),
            ),
            0x11 => asm ("pclmulqdq $0x11, %[b], %[res]"
                : [res] "+x" (res),
                : [b] "x" (b),
            ),
            else => @compileError("invalid pclmulqdq imm8"),
        }
        return res;
    } else if (comptime types.CPU_ARM64) {
        var res: V2U64 = undefined;
        switch (imm8) {
            0x00 => asm (
                \\.arch armv8-a+crypto
                \\pmull %[res].1q, %[a].1d, %[b].1d
                : [res] "=w" (res),
                : [a] "w" (a),
                  [b] "w" (b),
            ),
            0x11 => asm (
                \\.arch armv8-a+crypto
                \\pmull2 %[res].1q, %[a].2d, %[b].2d
                : [res] "=w" (res),
                : [a] "w" (a),
                  [b] "w" (b),
            ),
            else => @compileError("invalid pmull imm8"),
        }
        return res;
    } else {
        @compileError("clmul128 unsupported on this architecture");
    }
}

inline fn clmulX3(opA: V2U64, opA_x: V2U64, opB: V2U64, opB_x: V2U64, rl: *V2U64, rm: *V2U64, rh: *V2U64) void {
    rl.* = clmul128(opA, opB, 0x00);
    rm.* = clmul128(opA_x, opB_x, 0x00);
    rh.* = clmul128(opA, opB, 0x11);
}

inline fn clmul3(opA: V2U64, opB: V2U64, opB_x: V2U64, rl: *V2U64, rm: *V2U64, rh: *V2U64) void {
    const t0 = opA ^ (if (comptime (types.CPU_X86 or types.CPU_AMD64)) srli128By8(opA) else swap64Halves(opA));
    clmulX3(opA, t0, opB, opB_x, rl, rm, rh);
}

inline fn clmulAccX3(opA: V2U64, opA_x: V2U64, opB: V2U64, opB_x: V2U64, rl: *V2U64, rm: *V2U64, rh: *V2U64) void {
    const tl = clmul128(opA, opB, 0x00);
    const tm = clmul128(opA_x, opB_x, 0x00);
    const th = clmul128(opA, opB, 0x11);
    rl.* ^= tl;
    rm.* ^= tm;
    rh.* ^= th;
}

inline fn clmulAcc3(opA: V2U64, opB: V2U64, opB_x: V2U64, rl: *V2U64, rm: *V2U64, rh: *V2U64) void {
    const t0 = opA ^ (if (comptime (types.CPU_X86 or types.CPU_AMD64)) srli128By8(opA) else swap64Halves(opA));
    clmulAccX3(opA, t0, opB, opB_x, rl, rm, rh);
}

inline fn clmul3Post(rl: *V2U64, rm: *V2U64, rh: *V2U64) void {
    rm.* ^= rl.* ^ rh.*;
}

inline fn modReduce(rl_in: V2U64, rm_in: V2U64, rh: V2U64) V2U64 {
    const vMultConst = V2U64{ 0xc200000000000000, 0 };
    var rl = rl_in;
    var rm = rm_in;

    var t0 = clmul128(rl, vMultConst, 0x00);
    rl = swap64Halves(rl);
    rm ^= t0 ^ rl;

    t0 = clmul128(rm << @splat(1), vMultConst, 0x00);
    rm = swap64Halves(rm);
    const res32: V4U32 = @bitCast(rh ^ rm);

    const t1: V4U32 = res32 << @splat(1);
    const res_shr: V4U32 = res32 >> @splat(31);
    const t0_32: V4U32 = @as(V4U32, @bitCast(t0)) ^ t1;
    const res_shuf: V4U32 = @shuffle(u32, res_shr, undefined, [4]i32{ 3, 0, 1, 2 });
    return @bitCast(res_shuf ^ t0_32);
}

pub export fn SymCryptGHashExpandKeyC(
    expandedKey: PSYMCRYPT_GF128_ELEMENT,
    pH: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    var H0: UINT64 = macros.SYMCRYPT_LOAD_MSBFIRST64(pH + 8);
    var H1: UINT64 = macros.SYMCRYPT_LOAD_MSBFIRST64(pH);

    for (0..SYMCRYPT_GF128_FIELD_SIZE) |i| {
        expandedKey[i].ull[0] = H0;
        expandedKey[i].ull[1] = H1;

        const t: UINT64 = (0 -% (H0 & 1)) & (GF128_FIELD_R_BYTE << (8 * (@sizeOf(UINT64) - 1)));
        H0 = (H0 >> 1) | (H1 << 63);
        H1 = (H1 >> 1) ^ t;
    }
}

pub export fn SymCryptGHashAppendDataC(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    var state32: [4]UINT32 align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    state32[0] = @truncate(pState.ull[0]);
    state32[1] = @truncate(pState.ull[0] >> 32);
    state32[2] = @truncate(pState.ull[1]);
    state32[3] = @truncate(pState.ull[1] >> 32);

    while (cbData >= SYMCRYPT_GF128_BLOCK_SIZE) {
        var r0: UINT64 = 0;
        var r1: UINT64 = 0;

        for (0..4) |i| {
            var v: UINT32 = macros.SYMCRYPT_LOAD_MSBFIRST32(pbData + 4 * i) ^ state32[3 - i];

            for (0..32) |j| {
                const mask: UINT64 = 0 -% @as(UINT64, v >> 31);
                v <<= 1;
                const hp = &expandedKeyTable[32 * i + j];
                r0 ^= mask & hp.ull[0];
                r1 ^= mask & hp.ull[1];
            }
        }

        state32[0] = @truncate(r0);
        state32[1] = @truncate(r0 >> 32);
        state32[2] = @truncate(r1);
        state32[3] = @truncate(r1 >> 32);

        pbData += SYMCRYPT_GF128_BLOCK_SIZE;
        cbData -= SYMCRYPT_GF128_BLOCK_SIZE;
    }

    pState.ull[0] = @as(UINT64, state32[0]) | (@as(UINT64, state32[1]) << 32);
    pState.ull[1] = @as(UINT64, state32[2]) | (@as(UINT64, state32[3]) << 32);

    macros.SymCryptWipeKnownSize(@ptrCast(&state32[0]), @sizeOf(@TypeOf(state32)));
}

pub export fn SymCryptGHashResult(
    pState: *const SYMCRYPT_GF128_ELEMENT,
    pbResult: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_STORE_MSBFIRST64(pbResult, pState.ull[1]);
    macros.SYMCRYPT_STORE_MSBFIRST64(pbResult + 8, pState.ull[0]);
}

pub export fn SymCryptGHashExpandKeyXmm(
    expandedKey: PSYMCRYPT_GF128_ELEMENT,
    pH: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    SymCryptGHashExpandKeyC(expandedKey, pH);
}

inline fn ghashAppendDataVec128(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData_in: PCBYTE,
    cbData_in: SIZE_T,
) void {
    var pbData = pbData_in;
    var cbData = cbData_in;
    const cmpValue: V4I32 = @splat(0);

    while (cbData >= SYMCRYPT_GF128_BLOCK_SIZE) {
        var R: V4U32 = @splat(0);
        var pIndex: usize = 0;

        for (0..4) |i| {
            const t: UINT32 = macros.SYMCRYPT_LOAD_MSBFIRST32(pbData + 4 * i) ^ pState.ul[3 - i];
            var T: V4U32 = @splat(t);
            const pLimit = pIndex + 32;

            while (pIndex < pLimit) : (pIndex += 4) {
                inline for (0..4) |k| {
                    const maskBool = cmpValue > @as(V4I32, @bitCast(T));
                    const mask: V4U32 = @select(u32, maskBool, @as(V4U32, @splat(0xffffffff)), @as(V4U32, @splat(0)));
                    T +%= T;
                    const pVec: V4U32 = expandedKeyTable[pIndex + k].ul;
                    R ^= mask & pVec;
                }
            }
        }

        pState.ul = R;
        pbData += SYMCRYPT_GF128_BLOCK_SIZE;
        cbData -= SYMCRYPT_GF128_BLOCK_SIZE;
    }
}

pub fn SymCryptGHashAppendDataXmm(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    ghashAppendDataVec128(expandedKeyTable, pState, pbData, cbData);
}

pub fn SymCryptGHashAppendDataNeon(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    ghashAppendDataVec128(expandedKeyTable, pState, pbData, cbData);
}

pub fn SymCryptGHashExpandKeyPclmulqdq(
    expandedKey: PSYMCRYPT_GF128_ELEMENT,
    pH: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !(types.CPU_X86 or types.CPU_AMD64)) return;

    var a0: V2U64 = undefined;
    var a1: V2U64 = undefined;
    var a2: V2U64 = undefined;

    const H = byteReverse128(load128(pH));
    const Hx = H ^ srli128By8(H);

    storeElement(ghashHPowerPtr(expandedKey, 1), H);
    storeElement(ghashHxPowerPtr(expandedKey, 1), Hx);

    var Hi = H;
    for (2..(GHASH_H_LIMIT + 1)) |i| {
        clmul3(Hi, H, Hx, &a0, &a1, &a2);
        clmul3Post(&a0, &a1, &a2);
        Hi = modReduce(a0, a1, a2);
        const Hi_x = Hi ^ srli128By8(Hi);

        storeElement(ghashHPowerPtr(expandedKey, i), Hi);
        storeElement(ghashHxPowerPtr(expandedKey, i), Hi_x);
    }
}

pub fn SymCryptGHashAppendDataPclmulqdq(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData_in: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !(types.CPU_X86 or types.CPU_AMD64)) return;

    var pbData = pbData_in;
    var nBlocks: SIZE_T = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    if (nBlocks == 0) {
        return;
    }

    var state = loadElement(pState);
    var todo: SIZE_T = @min(nBlocks, GHASH_H_LIMIT);

    var a0 = byteReverse128(load128(pbData));
    var a1: V2U64 = undefined;
    var a2: V2U64 = undefined;

    state ^= a0;
    clmul3(
        state,
        loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
        loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
        &a0,
        &a1,
        &a2,
    );
    pbData += SYMCRYPT_GF128_BLOCK_SIZE;
    nBlocks -= 1;
    todo -= 1;

    while (nBlocks > 0) {
        while (todo > 0) {
            const t0 = byteReverse128(load128(pbData));
            clmulAcc3(
                t0,
                loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
                loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
                &a0,
                &a1,
                &a2,
            );
            pbData += SYMCRYPT_GF128_BLOCK_SIZE;
            nBlocks -= 1;
            todo -= 1;
        }

        if (nBlocks > 0) {
            todo = @min(nBlocks, GHASH_H_LIMIT);

            clmul3Post(&a0, &a1, &a2);
            state = modReduce(a0, a1, a2);

            a0 = byteReverse128(load128(pbData));
            state ^= a0;
            clmul3(
                state,
                loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
                loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
                &a0,
                &a1,
                &a2,
            );
            pbData += SYMCRYPT_GF128_BLOCK_SIZE;
            nBlocks -= 1;
            todo -= 1;
        }
    }

    clmul3Post(&a0, &a1, &a2);
    state = modReduce(a0, a1, a2);

    storeElement(pState, state);
}

pub fn SymCryptGHashExpandKeyPmull(
    expandedKey: PSYMCRYPT_GF128_ELEMENT,
    pH: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !types.CPU_ARM64) return;

    var a0: V2U64 = undefined;
    var a1: V2U64 = undefined;
    var a2: V2U64 = undefined;

    const H = byteReverse128(load128(pH));
    const Hx = H ^ swap64Halves(H);

    storeElement(ghashHPowerPtr(expandedKey, 1), H);
    storeElement(ghashHxPowerPtr(expandedKey, 1), Hx);

    var Hi = H;
    for (2..(GHASH_H_LIMIT + 1)) |i| {
        clmul3(Hi, H, Hx, &a0, &a1, &a2);
        clmul3Post(&a0, &a1, &a2);
        Hi = modReduce(a0, a1, a2);
        const Hi_x = Hi ^ swap64Halves(Hi);

        storeElement(ghashHPowerPtr(expandedKey, i), Hi);
        storeElement(ghashHxPowerPtr(expandedKey, i), Hi_x);
    }
}

pub fn SymCryptGHashAppendDataPmull(
    expandedKeyTable: PCSYMCRYPT_GF128_ELEMENT,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData_in: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (comptime !types.CPU_ARM64) return;

    var pbData = pbData_in;
    var nBlocks: SIZE_T = cbData / SYMCRYPT_GF128_BLOCK_SIZE;
    if (nBlocks == 0) {
        return;
    }

    var state = loadElement(pState);
    var todo: SIZE_T = @min(nBlocks, GHASH_H_LIMIT);

    var a0 = byteReverse128(load128(pbData));
    var a1: V2U64 = undefined;
    var a2: V2U64 = undefined;

    state ^= a0;
    clmul3(
        state,
        loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
        loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
        &a0,
        &a1,
        &a2,
    );
    pbData += SYMCRYPT_GF128_BLOCK_SIZE;
    nBlocks -= 1;
    todo -= 1;

    while (nBlocks > 0) {
        while (todo > 0) {
            var r0 = load128(pbData);
            var r0x = @as(V2U64, @bitCast(@shuffle(u8, @as(V16U8, @bitCast(r0)), undefined, [16]i32{
                7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8,
            })));
            r0 = swap64Halves(r0x);
            r0x ^= r0;
            clmulAccX3(
                r0,
                r0x,
                loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
                loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
                &a0,
                &a1,
                &a2,
            );
            pbData += SYMCRYPT_GF128_BLOCK_SIZE;
            nBlocks -= 1;
            todo -= 1;
        }

        if (nBlocks > 0) {
            todo = @min(nBlocks, GHASH_H_LIMIT);

            clmul3Post(&a0, &a1, &a2);
            state = modReduce(a0, a1, a2);

            a0 = byteReverse128(load128(pbData));
            state ^= a0;
            clmul3(
                state,
                loadElement(ghashHPowerConstPtr(expandedKeyTable, todo)),
                loadElement(ghashHxPowerConstPtr(expandedKeyTable, todo)),
                &a0,
                &a1,
                &a2,
            );
            pbData += SYMCRYPT_GF128_BLOCK_SIZE;
            nBlocks -= 1;
            todo -= 1;
        }
    }

    clmul3Post(&a0, &a1, &a2);
    state = modReduce(a0, a1, a2);

    storeElement(pState, state);
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&SymCryptGHashAppendDataXmm, .{ .name = "SymCryptGHashAppendDataXmm" });
        @export(&SymCryptGHashExpandKeyPclmulqdq, .{ .name = "SymCryptGHashExpandKeyPclmulqdq" });
        @export(&SymCryptGHashAppendDataPclmulqdq, .{ .name = "SymCryptGHashAppendDataPclmulqdq" });
    }
    if (types.CPU_ARM or types.CPU_ARM64) {
        @export(&SymCryptGHashAppendDataNeon, .{ .name = "SymCryptGHashAppendDataNeon" });
    }
    if (types.CPU_ARM64) {
        @export(&SymCryptGHashExpandKeyPmull, .{ .name = "SymCryptGHashExpandKeyPmull" });
        @export(&SymCryptGHashAppendDataPmull, .{ .name = "SymCryptGHashAppendDataPmull" });
    }
}

pub inline fn expandedKeyTableConstPtr(expandedKey: PCSYMCRYPT_GHASH_EXPANDED_KEY) PCSYMCRYPT_GF128_ELEMENT {
    if (comptime types.CPU_X86) {
        return @ptrCast(@alignCast(&expandedKey.tableSpace[expandedKey.tableOffset]));
    } else {
        return @ptrCast(&expandedKey.table[0]);
    }
}

pub inline fn expandedKeyTablePtr(expandedKey: PSYMCRYPT_GHASH_EXPANDED_KEY) PSYMCRYPT_GF128_ELEMENT {
    if (comptime types.CPU_X86) {
        return @ptrCast(@alignCast(&expandedKey.tableSpace[expandedKey.tableOffset]));
    } else {
        return @ptrCast(&expandedKey.table[0]);
    }
}

pub export fn SymCryptGHashExpandKey(
    expandedKey: PSYMCRYPT_GHASH_EXPANDED_KEY,
    pH: PCBYTE,
) callconv(SYMCRYPT_CALL) void {
    if (comptime types.CPU_X86) {
        expandedKey.tableOffset = @truncate((0 -% @intFromPtr(&expandedKey.tableSpace[0])) & 15);
        macros.SYMCRYPT_ASSERT(
            expandedKey.tableOffset + SYMCRYPT_GF128_FIELD_SIZE * @sizeOf(SYMCRYPT_GF128_ELEMENT) <=
                @sizeOf(@TypeOf(expandedKey.tableSpace)),
        );
    }

    const expandedKeyTable = expandedKeyTablePtr(expandedKey);

    if (comptime !build_options.use_asm) {
        SymCryptGHashExpandKeyC(expandedKeyTable, pH);
        return;
    }

    if (comptime types.CPU_AMD64) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE)) {
            var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
            if (macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR) {
                SymCryptGHashExpandKeyPclmulqdq(expandedKeyTable, pH);
                macros.SymCryptRestoreXmm(&saveData);
                return;
            }
        }
        SymCryptGHashExpandKeyXmm(expandedKeyTable, pH);
    } else if (comptime types.CPU_X86) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(
            types.SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE | types.SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL,
        )) {
            var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;
            if (macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR) {
                SymCryptGHashExpandKeyPclmulqdq(expandedKeyTable, pH);
                macros.SymCryptRestoreXmm(&saveData);
                return;
            }
        }
        SymCryptGHashExpandKeyXmm(expandedKeyTable, pH);
    } else if (comptime types.CPU_ARM64) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_PMULL)) {
            SymCryptGHashExpandKeyPmull(expandedKeyTable, pH);
        } else {
            SymCryptGHashExpandKeyC(expandedKeyTable, pH);
        }
    } else {
        SymCryptGHashExpandKeyC(expandedKeyTable, pH);
    }
}

pub export fn SymCryptGHashAppendData(
    expandedKey: PCSYMCRYPT_GHASH_EXPANDED_KEY,
    pState: *SYMCRYPT_GF128_ELEMENT,
    pbData: PCBYTE,
    cbData: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    if (cbData < SYMCRYPT_GF128_BLOCK_SIZE) {
        return;
    }

    if (comptime types.CPU_X86) {
        macros.SYMCRYPT_ASSERT((expandedKey.tableOffset & 3) == 0 and expandedKey.tableOffset < 16);
    }
    const expandedKeyTable = expandedKeyTableConstPtr(expandedKey);

    if (comptime !build_options.use_asm) {
        SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
        return;
    }

    if (comptime types.CPU_AMD64) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;

        if (macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR) {
            if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE)) {
                SymCryptGHashAppendDataPclmulqdq(expandedKeyTable, pState, pbData, cbData);
            } else {
                SymCryptGHashAppendDataXmm(expandedKeyTable, pState, pbData, cbData);
            }
            macros.SymCryptRestoreXmm(&saveData);
        } else {
            // Note: we can ONLY fallback to the C code if Pclmulqdq is NOT used, because Pclmulqdq uses
            // a different key expansion from the other implementations.
            SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
        }
    } else if (comptime types.CPU_X86) {
        var saveData: SYMCRYPT_EXTENDED_SAVE_DATA = undefined;

        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(
            types.SYMCRYPT_CPU_FEATURES_FOR_PCLMULQDQ_CODE | types.SYMCRYPT_CPU_FEATURE_SAVEXMM_NOFAIL,
        )) {
            if (macros.SymCryptSaveXmm(&saveData) != .SYMCRYPT_NO_ERROR) {
                macros.SymCryptFatal(macros.multiCharConstant("svxm"));
            }
            SymCryptGHashAppendDataPclmulqdq(expandedKeyTable, pState, pbData, cbData);
            macros.SymCryptRestoreXmm(&saveData);
        } else if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_SSE2) and
            macros.SymCryptSaveXmm(&saveData) == .SYMCRYPT_NO_ERROR)
        {
            SymCryptGHashAppendDataXmm(expandedKeyTable, pState, pbData, cbData);
            macros.SymCryptRestoreXmm(&saveData);
        } else {
            SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
        }
    } else if (comptime types.CPU_ARM64) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON_PMULL)) {
            SymCryptGHashAppendDataPmull(expandedKeyTable, pState, pbData, cbData);
        } else if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON)) {
            SymCryptGHashAppendDataNeon(expandedKeyTable, pState, pbData, cbData);
        } else {
            SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
        }
    } else if (comptime types.CPU_ARM) {
        if (libmain.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_NEON)) {
            SymCryptGHashAppendDataNeon(expandedKeyTable, pState, pbData, cbData);
        } else {
            SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
        }
    } else {
        SymCryptGHashAppendDataC(expandedKeyTable, pState, pbData, cbData);
    }
}
