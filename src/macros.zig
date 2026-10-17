//
// macros.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Core helper functions matching inc/symcrypt_internal.h and lib/sc_lib.h:
// volatile forced memory access, fixed-endianness loads/stores, bit rotations,
// constant-time masks, and magic value validation.
//

const std = @import("std");
const builtin = @import("builtin");
const types = @import("types.zig");

// ==============================================================================================
// Volatile Forced Memory Access
// ==============================================================================================

pub inline fn FORCE_READ8(ptr: anytype) u8 {
    const p: *align(1) const volatile u8 = @ptrCast(ptr);
    return p.*;
}

pub inline fn FORCE_READ16(ptr: anytype) u16 {
    const p: *align(1) const volatile u16 = @ptrCast(ptr);
    return p.*;
}

pub inline fn FORCE_READ32(ptr: anytype) u32 {
    const p: *align(1) const volatile u32 = @ptrCast(ptr);
    return p.*;
}

pub inline fn FORCE_READ64(ptr: anytype) u64 {
    if (builtin.cpu.arch == .arm) {
        const bytes: [*]const u8 = @ptrCast(ptr);
        const lo: u64 = FORCE_READ32(bytes);
        const hi: u64 = FORCE_READ32(bytes + 4);
        return (hi << 32) | lo;
    }
    const p: *align(1) const volatile u64 = @ptrCast(ptr);
    return p.*;
}

pub inline fn FORCE_WRITE8(ptr: anytype, val: u8) void {
    const p: *align(1) volatile u8 = @ptrCast(ptr);
    p.* = val;
}

pub inline fn FORCE_WRITE16(ptr: anytype, val: u16) void {
    const p: *align(1) volatile u16 = @ptrCast(ptr);
    p.* = val;
}

pub inline fn FORCE_WRITE32(ptr: anytype, val: u32) void {
    const p: *align(1) volatile u32 = @ptrCast(ptr);
    p.* = val;
}

pub inline fn FORCE_WRITE64(ptr: anytype, val: u64) void {
    if (builtin.cpu.arch == .arm) {
        const bytes: [*]u8 = @ptrCast(ptr);
        FORCE_WRITE32(bytes, @truncate(val));
        FORCE_WRITE32(bytes + 4, @truncate(val >> 32));
        return;
    }
    const p: *align(1) volatile u64 = @ptrCast(ptr);
    p.* = val;
}

pub const SYMCRYPT_FORCE_READ8 = FORCE_READ8;
pub const SYMCRYPT_FORCE_READ16 = FORCE_READ16;
pub const SYMCRYPT_FORCE_READ32 = FORCE_READ32;
pub const SYMCRYPT_FORCE_READ64 = FORCE_READ64;

pub const SYMCRYPT_FORCE_WRITE8 = FORCE_WRITE8;
pub const SYMCRYPT_FORCE_WRITE16 = FORCE_WRITE16;
pub const SYMCRYPT_FORCE_WRITE32 = FORCE_WRITE32;
pub const SYMCRYPT_FORCE_WRITE64 = FORCE_WRITE64;

// ==============================================================================================
// Fixed-Endianness Load / Store Helpers
// ==============================================================================================

pub inline fn LOAD_LSBFIRST16(p: [*]const u8) u16 {
    return std.mem.readInt(u16, p[0..2], .little);
}

pub inline fn LOAD_LSBFIRST32(p: [*]const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .little);
}

pub inline fn LOAD_LSBFIRST64(p: [*]const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .little);
}

pub inline fn LOAD_MSBFIRST16(p: [*]const u8) u16 {
    return std.mem.readInt(u16, p[0..2], .big);
}

pub inline fn LOAD_MSBFIRST32(p: [*]const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .big);
}

pub inline fn LOAD_MSBFIRST64(p: [*]const u8) u64 {
    return std.mem.readInt(u64, p[0..8], .big);
}

pub inline fn STORE_LSBFIRST16(p: [*]u8, v: u16) void {
    std.mem.writeInt(u16, p[0..2], v, .little);
}

pub inline fn STORE_LSBFIRST32(p: [*]u8, v: u32) void {
    std.mem.writeInt(u32, p[0..4], v, .little);
}

pub inline fn STORE_LSBFIRST64(p: [*]u8, v: u64) void {
    std.mem.writeInt(u64, p[0..8], v, .little);
}

pub inline fn STORE_MSBFIRST16(p: [*]u8, v: u16) void {
    std.mem.writeInt(u16, p[0..2], v, .big);
}

pub inline fn STORE_MSBFIRST32(p: [*]u8, v: u32) void {
    std.mem.writeInt(u32, p[0..4], v, .big);
}

pub inline fn STORE_MSBFIRST64(p: [*]u8, v: u64) void {
    std.mem.writeInt(u64, p[0..8], v, .big);
}

pub const SYMCRYPT_LOAD_LSBFIRST16 = LOAD_LSBFIRST16;
pub const SYMCRYPT_LOAD_LSBFIRST32 = LOAD_LSBFIRST32;
pub const SYMCRYPT_LOAD_LSBFIRST64 = LOAD_LSBFIRST64;
pub const SYMCRYPT_LOAD_MSBFIRST16 = LOAD_MSBFIRST16;
pub const SYMCRYPT_LOAD_MSBFIRST32 = LOAD_MSBFIRST32;
pub const SYMCRYPT_LOAD_MSBFIRST64 = LOAD_MSBFIRST64;

pub const SYMCRYPT_STORE_LSBFIRST16 = STORE_LSBFIRST16;
pub const SYMCRYPT_STORE_LSBFIRST32 = STORE_LSBFIRST32;
pub const SYMCRYPT_STORE_LSBFIRST64 = STORE_LSBFIRST64;
pub const SYMCRYPT_STORE_MSBFIRST16 = STORE_MSBFIRST16;
pub const SYMCRYPT_STORE_MSBFIRST32 = STORE_MSBFIRST32;
pub const SYMCRYPT_STORE_MSBFIRST64 = STORE_MSBFIRST64;

pub const LSBFIRST16 = struct {
    pub const LOAD = LOAD_LSBFIRST16;
    pub const STORE = STORE_LSBFIRST16;
};

pub const LSBFIRST32 = struct {
    pub const LOAD = LOAD_LSBFIRST32;
    pub const STORE = STORE_LSBFIRST32;
};

pub const LSBFIRST64 = struct {
    pub const LOAD = LOAD_LSBFIRST64;
    pub const STORE = STORE_LSBFIRST64;
};

pub const MSBFIRST16 = struct {
    pub const LOAD = LOAD_MSBFIRST16;
    pub const STORE = STORE_MSBFIRST16;
};

pub const MSBFIRST32 = struct {
    pub const LOAD = LOAD_MSBFIRST32;
    pub const STORE = STORE_MSBFIRST32;
};

pub const MSBFIRST64 = struct {
    pub const LOAD = LOAD_MSBFIRST64;
    pub const STORE = STORE_MSBFIRST64;
};

pub inline fn BSWAP16(x: u16) u16 {
    return @byteSwap(x);
}

pub inline fn BSWAP32(x: u32) u32 {
    return @byteSwap(x);
}

pub inline fn BSWAP64(x: u64) u64 {
    return @byteSwap(x);
}

pub const SYMCRYPT_BSWAP16 = BSWAP16;
pub const SYMCRYPT_BSWAP32 = BSWAP32;
pub const SYMCRYPT_BSWAP64 = BSWAP64;

// ==============================================================================================
// Bit Rotation Helpers
// ==============================================================================================

pub inline fn ROL16(x: u16, n: anytype) u16 {
    return std.math.rotl(u16, x, n);
}

pub inline fn ROR16(x: u16, n: anytype) u16 {
    return std.math.rotr(u16, x, n);
}

pub inline fn ROL32(x: u32, n: anytype) u32 {
    return std.math.rotl(u32, x, n);
}

pub inline fn ROR32(x: u32, n: anytype) u32 {
    return std.math.rotr(u32, x, n);
}

pub inline fn ROL64(x: u64, n: anytype) u64 {
    return std.math.rotl(u64, x, n);
}

pub inline fn ROR64(x: u64, n: anytype) u64 {
    return std.math.rotr(u64, x, n);
}

// ==============================================================================================
// Constant-Time Mask Helpers
// ==============================================================================================

pub const MASK32_SET: u32 = 0xffffffff;
pub const SYMCRYPT_MASK32_SET: u32 = MASK32_SET;

pub inline fn MASK32_NONZERO(v: u32) u32 {
    return @truncate((@as(u64, 0) -% @as(u64, v)) >> 32);
}

pub inline fn MASK32_ZERO(v: u32) u32 {
    return ~MASK32_NONZERO(v);
}

pub inline fn MASK32_EQ(a: u32, b: u32) u32 {
    return ~MASK32_NONZERO(a ^ b);
}

pub inline fn MASK32_LT(a: u32, b: u32) u32 {
    return @truncate((@as(u64, a) -% @as(u64, b)) >> 32);
}

pub const SYMCRYPT_MASK32_NONZERO = MASK32_NONZERO;
pub const SYMCRYPT_MASK32_ZERO = MASK32_ZERO;
pub const SYMCRYPT_MASK32_EQ = MASK32_EQ;
pub const SYMCRYPT_MASK32_LT = MASK32_LT;

// ==============================================================================================
// Magic Value & Fatal Error Helpers
// ==============================================================================================

pub extern fn SymCryptFatal(fatalCode: u32) callconv(types.SYMCRYPT_CALL) noreturn;

pub inline fn multiCharConstant(comptime str: []const u8) u32 {
    return comptime blk: {
        std.debug.assert(str.len >= 1 and str.len <= 4);
        var val: u32 = 0;
        for (str) |c| {
            val = (val << 8) | @as(u32, c);
        }
        break :blk val;
    };
}

pub const MAGIC_CONSTANT: usize =
    @as(usize, multiCharConstant("S1mv")) +% @as(usize, types.SYMCRYPT_API_VERSION);

pub inline fn SYMCRYPT_MAGIC_VALUE(ptr: anytype) usize {
    return @intFromPtr(ptr) +% MAGIC_CONSTANT;
}

pub inline fn SET_MAGIC(ptr: anytype) void {
    if (types.DEBUG) {
        ptr.magic = SYMCRYPT_MAGIC_VALUE(ptr);
    }
}

pub inline fn CHECK_MAGIC(ptr: anytype) void {
    if (types.DEBUG) {
        if (ptr.magic != SYMCRYPT_MAGIC_VALUE(ptr)) {
            SymCryptFatal(multiCharConstant("magc"));
        }
    }
}

pub inline fn WIPE_MAGIC(ptr: anytype) void {
    if (types.DEBUG) {
        ptr.magic = 0;
    }
}

pub inline fn ASSERT(cond: bool) void {
    if (types.DEBUG) {
        if (!cond) {
            SymCryptFatal(multiCharConstant("asrt"));
        }
    }
}

pub const SYMCRYPT_SET_MAGIC = SET_MAGIC;
pub const SYMCRYPT_CHECK_MAGIC = CHECK_MAGIC;
pub const SYMCRYPT_WIPE_MAGIC = WIPE_MAGIC;
pub const SYMCRYPT_ASSERT = ASSERT;

// ==============================================================================================
// Array Conversion & Buffer Helpers (from lib/sc_lib.h)
// ==============================================================================================

pub inline fn REPEAT_BYTE_TO_UINT32(x: u8) u32 {
    return (@as(u32, x) << 24) | (@as(u32, x) << 16) | (@as(u32, x) << 8) | @as(u32, x);
}

pub inline fn REPEAT_BYTE_TO_UINT64(x: u8) u64 {
    const u32_val = REPEAT_BYTE_TO_UINT32(x);
    return (@as(u64, u32_val) << 32) | @as(u64, u32_val);
}

pub inline fn SymCryptUint32ToMsbFirst(puData: [*]const u32, pbResult: [*]u8, cuData: usize) void {
    var i: usize = 0;
    while (i < cuData) : (i += 1) {
        STORE_MSBFIRST32(pbResult + i * 4, puData[i]);
    }
}

pub inline fn SymCryptMsbFirstToUint32(pbData: [*]const u8, puResult: [*]u32, cuResult: usize) void {
    var i: usize = 0;
    while (i < cuResult) : (i += 1) {
        puResult[i] = LOAD_MSBFIRST32(pbData + i * 4);
    }
}

pub inline fn SymCryptUint32ToLsbFirst(puData: [*]const u32, pbResult: [*]u8, cuData: usize) void {
    var i: usize = 0;
    while (i < cuData) : (i += 1) {
        STORE_LSBFIRST32(pbResult + i * 4, puData[i]);
    }
}

pub inline fn SymCryptLsbFirstToUint32(pbData: [*]const u8, puResult: [*]u32, cuResult: usize) void {
    var i: usize = 0;
    while (i < cuResult) : (i += 1) {
        puResult[i] = LOAD_LSBFIRST32(pbData + i * 4);
    }
}

pub inline fn SymCryptUint64ToLsbFirst(puData: [*]const u64, pbResult: [*]u8, cuData: usize) void {
    var i: usize = 0;
    while (i < cuData) : (i += 1) {
        STORE_LSBFIRST64(pbResult + i * 8, puData[i]);
    }
}

pub inline fn SymCryptLsbFirstToUint64(pbData: [*]const u8, puResult: [*]u64, cuResult: usize) void {
    var i: usize = 0;
    while (i < cuResult) : (i += 1) {
        puResult[i] = LOAD_LSBFIRST64(pbData + i * 8);
    }
}

pub inline fn SymCryptUint64ToMsbFirst(puData: [*]const u64, pbResult: [*]u8, cuData: usize) void {
    var i: usize = 0;
    while (i < cuData) : (i += 1) {
        STORE_MSBFIRST64(pbResult + i * 8, puData[i]);
    }
}

pub inline fn SymCryptMsbFirstToUint64(pbData: [*]const u8, puResult: [*]u64, cuResult: usize) void {
    var i: usize = 0;
    while (i < cuResult) : (i += 1) {
        puResult[i] = LOAD_MSBFIRST64(pbData + i * 8);
    }
}

pub inline fn XorByteIntoBuffer(pbBuf: [*]u8, cqBuf: usize, v: u8) void {
    const v64 = REPEAT_BYTE_TO_UINT64(v);
    var i: usize = 0;
    while (i < cqBuf) : (i += 1) {
        const ptr = pbBuf + i * 8;
        STORE_LSBFIRST64(ptr, LOAD_LSBFIRST64(ptr) ^ v64);
    }
}
