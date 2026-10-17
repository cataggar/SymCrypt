// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const sc = @import("sc_implementations.zig");
const tu = @import("testutil.zig");

const SYMCRYPT_SHA256_RESULT_SIZE: usize = 32;

extern fn SymCryptSha256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptScsRotateBuffer(pbBuffer: [*]u8, cbBuffer: usize, lshift: usize) callconv(.c) void;
extern fn SymCryptScsCopy(pbSrc: [*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize) callconv(.c) void;
extern fn SymCryptMask32IsZeroU31(v: u32) callconv(.c) u32;
extern fn SymCryptMask32IsNonzeroU31(v: u32) callconv(.c) u32;
extern fn SymCryptMask32EqU32(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMask32NeqU31(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMask32LtU31(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMapUint32(uValue: u32, uDefaultValue: u32, pTable: [*]const [2]u32, cTable: usize) callconv(.c) u32;

extern fn scTestIsAlgorithmPresentCstr(name: [*:0]const u8, isPrefix: c_int) callconv(.c) c_int;
const scTestIsAlgorithmPresent = scTestIsAlgorithmPresentCstr;

fn testScsRotateBuffer() void {
    var buf1: [4096]u8 = undefined;
    var buf2: [4096]u8 = undefined;

    for (buf1[0..], 0..) |*b, i| {
        b.* = rng.scTestRngByte(&rng.g_rng);
        buf2[i] = b.*;
    }

    var size: usize = 32;
    while (size < buf1.len) : (size *= 2) {
        for (0..30) |_| {
            const offset = rng.scTestRngSizet(&rng.g_rng, buf1.len - size + 1);
            const rot = rng.scTestRngSizet(&rng.g_rng, size);

            sc.callSymCrypt(
                "SymCryptScsRotateBuffer",
                *const fn ([*]u8, usize, usize) callconv(.c) void,
                SymCryptScsRotateBuffer,
                .{ buf1[offset..].ptr, size, rot },
            );

            h.check(std.mem.eql(u8, buf1[0..offset], buf2[0..offset]), "Pre buffer corrupted");
            h.check(
                std.mem.eql(u8, buf1[offset + size ..], buf2[offset + size ..]),
                "Post buffer corrupted",
            );
            h.check(
                std.mem.eql(u8, buf1[offset .. offset + size - rot], buf2[offset + rot .. offset + size]),
                "Part 1 mismatch",
            );
            h.check(
                std.mem.eql(u8, buf1[offset + size - rot .. offset + size], buf2[offset .. offset + rot]),
                "Part 2 mismatch",
            );

            @memcpy(buf2[offset .. offset + size], buf1[offset .. offset + size]);
        }
    }
}

fn testScsCopy() void {
    var buf1: [256]u8 = undefined;
    var buf2: [256]u8 = undefined;
    var buf3: [256]u8 = undefined;

    var hash2: [SYMCRYPT_SHA256_RESULT_SIZE]u8 = undefined;
    var hash3: [SYMCRYPT_SHA256_RESULT_SIZE]u8 = undefined;

    for (buf1[0..], 0..) |*b, i| {
        b.* = rng.scTestRngByte(&rng.g_rng);
        buf2[i] = rng.scTestRngByte(&rng.g_rng);
        buf3[i] = buf2[i];
    }

    for (0..10000) |_| {
        const offset = rng.scTestRngSizet(&rng.g_rng, buf1.len);
        const cbDst = rng.scTestRngSizet(&rng.g_rng, buf1.len - offset);
        const cbSrc = rng.scTestRngSizet(&rng.g_rng, cbDst + 1);

        sc.callSymCrypt(
            "SymCryptScsCopy",
            *const fn ([*]const u8, usize, [*]u8, usize) callconv(.c) void,
            SymCryptScsCopy,
            .{ buf1[offset..].ptr, cbSrc, buf2[offset..].ptr, cbDst },
        );
        @memcpy(buf3[offset .. offset + cbSrc], buf1[offset .. offset + cbSrc]);

        sc.callSymCrypt(
            "SymCryptSha256",
            *const fn (?[*]const u8, usize, [*]u8) callconv(.c) void,
            SymCryptSha256,
            .{ &buf2, buf2.len, &hash2 },
        );
        sc.callSymCrypt(
            "SymCryptSha256",
            *const fn (?[*]const u8, usize, [*]u8) callconv(.c) void,
            SymCryptSha256,
            .{ &buf3, buf3.len, &hash3 },
        );

        h.check(std.mem.eql(u8, &hash2, &hash3), "State difference");
    }
}

fn randomU31() u32 {
    switch (rng.scTestRngByte(&rng.g_rng) & 3) {
        0 => return 0,
        1 => return @as(u32, 1) << @intCast(rng.scTestRngByte(&rng.g_rng) % 31),
        2 => return 0x7fffffff ^ (@as(u32, 1) << @intCast(rng.scTestRngByte(&rng.g_rng) % 31)),
        3 => return rng.scTestRngUint32(&rng.g_rng) & 0x7fffffff,
        else => unreachable,
    }
}

fn randomU32() u32 {
    var res = randomU31();
    res |= @as(u32, rng.scTestRngByte(&rng.g_rng) & 1) << 31;
    return res;
}

fn testMask(m: u32, b: bool) void {
    const expected: u32 = if (b) 0xffffffff else 0;
    h.check(m == expected, "Wrong mask value");
}

fn testScsMasks() void {
    var a31: u32 = 0;
    var b31: u32 = 0;
    var a32: u32 = 0;
    var b32: u32 = 0;

    for (0..10000) |_| {
        a31 = b31;
        b31 = randomU31();

        a32 = b32;
        b32 = randomU32();

        testMask(
            sc.callSymCrypt("SymCryptMask32IsZeroU31", *const fn (u32) callconv(.c) u32, SymCryptMask32IsZeroU31, .{a31}),
            a31 == 0,
        );
        testMask(
            sc.callSymCrypt("SymCryptMask32IsNonzeroU31", *const fn (u32) callconv(.c) u32, SymCryptMask32IsNonzeroU31, .{a31}),
            a31 != 0,
        );
        testMask(
            sc.callSymCrypt("SymCryptMask32EqU32", *const fn (u32, u32) callconv(.c) u32, SymCryptMask32EqU32, .{ a32, b32 }),
            a32 == b32,
        );
        testMask(
            sc.callSymCrypt("SymCryptMask32NeqU31", *const fn (u32, u32) callconv(.c) u32, SymCryptMask32NeqU31, .{ a31, b31 }),
            a31 != b31,
        );
        testMask(
            sc.callSymCrypt("SymCryptMask32LtU31", *const fn (u32, u32) callconv(.c) u32, SymCryptMask32LtU31, .{ a31, b31 }),
            a31 < b31,
        );
    }
}

fn testScsMap() void {
    const mapTable = [_][2]u32{
        .{ 0, 1 },
        .{ 2, 100 },
        .{ 4, 42 },
    };

    var uResult = sc.callSymCrypt(
        "SymCryptMapUint32",
        *const fn (u32, u32, [*]const [2]u32, usize) callconv(.c) u32,
        SymCryptMapUint32,
        .{ 0, 0xFF, &mapTable, mapTable.len },
    );
    h.check(uResult == 1, "SymCryptMapUint32: Known value did not map to expected value");

    uResult = sc.callSymCrypt(
        "SymCryptMapUint32",
        *const fn (u32, u32, [*]const [2]u32, usize) callconv(.c) u32,
        SymCryptMapUint32,
        .{ 1, 0xFF, &mapTable, mapTable.len },
    );
    h.check(uResult == 0xFF, "SymCryptMapUint32: Unknown value did not map to expected default value");

    const mapDuplicateTable = [_][2]u32{
        .{ 1, 2 },
        .{ 3, 4 },
        .{ 1, 5 },
    };

    uResult = sc.callSymCrypt(
        "SymCryptMapUint32",
        *const fn (u32, u32, [*]const [2]u32, usize) callconv(.c) u32,
        SymCryptMapUint32,
        .{ 1, 0xFF, &mapDuplicateTable, mapDuplicateTable.len },
    );
    h.check(uResult == 5, "SymCryptMapUint32: Duplicate value did not map to expected value");
}

pub export fn testScsTools() callconv(.c) void {
    if (scTestIsAlgorithmPresent("ScsTools", 0) == 0) {
        return;
    }

    if (tu.hasDispatchSym("SymCryptScsRotateBuffer")) {
        testScsRotateBuffer();
        testScsCopy();
        testScsMasks();
    }
    if (tu.hasDispatchSym("SymCryptMapUint32")) {
        testScsMap();
    }
}
