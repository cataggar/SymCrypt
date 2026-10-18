// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800e;
const SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN: u32 = 0x02;

const SYMCRYPT_CODE_VERSION_API: u32 = 103;
const SYMCRYPT_CODE_VERSION_MINOR: u32 = 13;

const SCTEST_DYNSYM_FUNCTION_PTR: u32 = 1;

extern fn initVectorRegisters() callconv(.c) void;
extern fn verifyVectorRegisters() callconv(.c) void;
extern fn getDynamicSymbolPointerFromString(hDynamicModule: ?*anyopaque, pSymbolName: [*:0]const u8, symbolType: u32) callconv(.c) ?*anyopaque;

extern fn SymCryptUint32Bitsize(v: u32) callconv(.c) u32;
extern fn SymCryptUint32Bytesize(v: u32) callconv(.c) u32;
extern fn SymCryptUint64Bitsize(v: u64) callconv(.c) u32;
extern fn SymCryptUint64Bytesize(v: u64) callconv(.c) u32;

extern fn SymCryptLoadMsbFirstUint32(pbSrc: [*]const u8, cbSrc: usize, puDst: *u32) callconv(.c) u32;
extern fn SymCryptLoadMsbFirstUint64(pbSrc: [*]const u8, cbSrc: usize, puDst: *u64) callconv(.c) u32;
extern fn SymCryptLoadLsbFirstUint32(pbSrc: [*]const u8, cbSrc: usize, puDst: *u32) callconv(.c) u32;
extern fn SymCryptLoadLsbFirstUint64(pbSrc: [*]const u8, cbSrc: usize, puDst: *u64) callconv(.c) u32;

extern fn SymCryptStoreMsbFirstUint32(uSrc: u32, pbDst: [*]u8, cbDst: usize) callconv(.c) u32;
extern fn SymCryptStoreMsbFirstUint64(uSrc: u64, pbDst: [*]u8, cbDst: usize) callconv(.c) u32;
extern fn SymCryptStoreLsbFirstUint32(uSrc: u32, pbDst: [*]u8, cbDst: usize) callconv(.c) u32;
extern fn SymCryptStoreLsbFirstUint64(uSrc: u64, pbDst: [*]u8, cbDst: usize) callconv(.c) u32;

extern fn SymCryptUint64Gcd(a: u64, b: u64, flags: u32) callconv(.c) u64;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

pub fn hasDispatchSym(name: [*:0]const u8) bool {
    if (h.g_useDynamicFunctionsInTestCall != 0) {
        return getDynamicSymbolPointerFromString(h.g_dynamicSymCryptModuleHandle, name, SCTEST_DYNSYM_FUNCTION_PTR) != null;
    }
    return true;
}

fn callSymCrypt(comptime name: [*:0]const u8, comptime FnPtr: type, comptime staticFn: FnPtr, args: anytype) @typeInfo(@typeInfo(FnPtr).pointer.child).@"fn".return_type.? {
    if (h.g_useDynamicFunctionsInTestCall != 0) {
        const sym = getDynamicSymbolPointerFromString(h.g_dynamicSymCryptModuleHandle, name, SCTEST_DYNSYM_FUNCTION_PTR);
        h.check(sym != null, "Could not find dynamic function");
        const fn_ptr: FnPtr = @ptrCast(@alignCast(sym.?));
        return @call(.auto, fn_ptr, args);
    } else {
        initVectorRegisters();
        const res = @call(.auto, staticFn, args);
        verifyVectorRegisters();
        return res;
    }
}

fn testBitByteSize() void {
    if (!hasDispatchSym("SymCryptUint64Bitsize") or
        !hasDispatchSym("SymCryptUint64Bytesize") or
        !hasDispatchSym("SymCryptUint32Bitsize") or
        !hasDispatchSym("SymCryptUint32Bytesize"))
    {
        h.zprint("    testBitByteSize skipped\n", .{});
        return;
    }

    var v: u64 = 0;
    h.fillRandom(std.mem.asBytes(&v)) catch h.fatal("getrandom failed", .{});
    v |= (@as(u64, 1) << 63);

    var bits: u32 = 64;
    while (bits != std.math.maxInt(u32)) : (bits -%= 1) {
        const bytes: u32 = (bits + 7) / 8;
        h.check(callSymCrypt("SymCryptUint64Bitsize", *const fn (u64) callconv(.c) u32, SymCryptUint64Bitsize, .{v}) == bits, "Wrong bitsize 64");
        h.check(callSymCrypt("SymCryptUint64Bytesize", *const fn (u64) callconv(.c) u32, SymCryptUint64Bytesize, .{v}) == bytes, "Wrong bytesize 64");

        if (bits <= 32) {
            const v32: u32 = @truncate(v);
            h.check(callSymCrypt("SymCryptUint32Bitsize", *const fn (u32) callconv(.c) u32, SymCryptUint32Bitsize, .{v32}) == bits, "Wrong bitsize 32");
            h.check(callSymCrypt("SymCryptUint32Bytesize", *const fn (u32) callconv(.c) u32, SymCryptUint32Bytesize, .{v32}) == bytes, "Wrong bytesize 32");
        }
        v >>= 1;
    }
}

fn testLoadStore() void {
    var val: [12]u8 = undefined;
    var buf1: [12]u8 = undefined;
    var buf2: [12]u8 = undefined;
    var buf3: [12]u8 = undefined;
    var buf4: [12]u8 = undefined;

    if (!hasDispatchSym("SymCryptWipe") or
        !hasDispatchSym("SymCryptLoadLsbFirstUint64") or
        !hasDispatchSym("SymCryptLoadLsbFirstUint32") or
        !hasDispatchSym("SymCryptLoadMsbFirstUint64") or
        !hasDispatchSym("SymCryptLoadMsbFirstUint32"))
    {
        h.zprint("    testLoadStore skipped\n", .{});
        return;
    }

    var nBytes: u32 = 0;
    while (nBytes <= 8) : (nBytes += 1) {
        h.fillRandom(&val) catch h.fatal("getrandom failed", .{});
        _ = callSymCrypt("SymCryptWipe", *const fn ([*]u8, usize) callconv(.c) void, SymCryptWipe, .{ val[nBytes..].ptr, val.len - nBytes });

        if (nBytes > 0) {
            val[nBytes - 1] |= 0x1;
        }

        var n: u32 = 0;
        while (n <= 12) : (n += 1) {
            var v64: u64 = std.mem.readInt(u64, val[0..8], .little);
            var v32: u32 = @truncate(v64);
            var w32: u32 = 0;
            var w64: u64 = 0;

            @memset(&buf1, 'n');
            @memset(&buf2, 'n');
            @memset(&buf3, 'n');
            @memset(&buf4, 'n');

            var sc1 = callSymCrypt("SymCryptStoreLsbFirstUint64", *const fn (u64, [*]u8, usize) callconv(.c) u32, SymCryptStoreLsbFirstUint64, .{ v64, &buf1, n });
            var sc2 = callSymCrypt("SymCryptStoreLsbFirstUint32", *const fn (u32, [*]u8, usize) callconv(.c) u32, SymCryptStoreLsbFirstUint32, .{ v32, &buf2, n });
            var sc3 = callSymCrypt("SymCryptStoreMsbFirstUint64", *const fn (u64, [*]u8, usize) callconv(.c) u32, SymCryptStoreMsbFirstUint64, .{ v64, &buf3, n });
            var sc4 = callSymCrypt("SymCryptStoreMsbFirstUint32", *const fn (u32, [*]u8, usize) callconv(.c) u32, SymCryptStoreMsbFirstUint32, .{ v32, &buf4, n });

            h.check(n == 12 or (buf1[n] == 'n' and buf2[n] == 'n' and buf3[n] == 'n' and buf4[n] == 'n'), "?");

            h.check((sc1 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?");
            h.check((sc3 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?");
            if (nBytes <= 4) {
                h.check((sc2 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?");
                h.check((sc4 == SYMCRYPT_NO_ERROR) == (n >= nBytes), "?");
            }

            var j: u32 = 0;
            while (j < n) : (j += 1) {
                h.check((sc1 != SYMCRYPT_NO_ERROR) or buf1[j] == val[j], "?");
                h.check((sc3 != SYMCRYPT_NO_ERROR) or buf3[j] == val[n - j - 1], "?");

                if (nBytes <= 4) {
                    h.check((sc2 != SYMCRYPT_NO_ERROR) or buf2[j] == val[j], "?");
                    h.check((sc4 != SYMCRYPT_NO_ERROR) or buf4[j] == val[n - j - 1], "?");
                }
            }

            sc1 = callSymCrypt("SymCryptLoadLsbFirstUint64", *const fn ([*]const u8, usize, *u64) callconv(.c) u32, SymCryptLoadLsbFirstUint64, .{ &buf1, n, &v64 });
            sc2 = callSymCrypt("SymCryptLoadLsbFirstUint32", *const fn ([*]const u8, usize, *u32) callconv(.c) u32, SymCryptLoadLsbFirstUint32, .{ &buf2, n, &v32 });
            sc3 = callSymCrypt("SymCryptLoadMsbFirstUint64", *const fn ([*]const u8, usize, *u64) callconv(.c) u32, SymCryptLoadMsbFirstUint64, .{ &buf3, n, &w64 });
            sc4 = callSymCrypt("SymCryptLoadMsbFirstUint32", *const fn ([*]const u8, usize, *u32) callconv(.c) u32, SymCryptLoadMsbFirstUint32, .{ &buf4, n, &w32 });

            h.check(sc1 == SYMCRYPT_NO_ERROR and sc2 == SYMCRYPT_NO_ERROR and sc3 == SYMCRYPT_NO_ERROR and sc4 == SYMCRYPT_NO_ERROR, "?");
            h.check(v64 == w64 and v32 == w32, "?");
            h.check(@as(u32, @truncate(v64)) == v32, "?");
            h.check((n < nBytes) or (v64 == std.mem.readInt(u64, val[0..8], .little)), "?");
        }
    }

    var j: u32 = 0;
    while (j < 12) : (j += 1) {
        var v64: u64 = 0;
        var v32: u32 = 0;
        var w64: u64 = 0;
        var w32: u32 = 0;
        _ = callSymCrypt("SymCryptWipe", *const fn ([*]u8, usize) callconv(.c) void, SymCryptWipe, .{ &buf1, buf1.len });
        buf1[j] = 1;

        const sc1 = callSymCrypt("SymCryptLoadLsbFirstUint64", *const fn ([*]const u8, usize, *u64) callconv(.c) u32, SymCryptLoadLsbFirstUint64, .{ &buf1, 12, &v64 });
        const sc2 = callSymCrypt("SymCryptLoadLsbFirstUint32", *const fn ([*]const u8, usize, *u32) callconv(.c) u32, SymCryptLoadLsbFirstUint32, .{ &buf1, 12, &v32 });
        const sc3 = callSymCrypt("SymCryptLoadMsbFirstUint64", *const fn ([*]const u8, usize, *u64) callconv(.c) u32, SymCryptLoadMsbFirstUint64, .{ &buf1, 12, &w64 });
        const sc4 = callSymCrypt("SymCryptLoadMsbFirstUint32", *const fn ([*]const u8, usize, *u32) callconv(.c) u32, SymCryptLoadMsbFirstUint32, .{ &buf1, 12, &w32 });
        h.check((sc1 == SYMCRYPT_NO_ERROR) == (j < 8), "?");
        h.check((sc2 == SYMCRYPT_NO_ERROR) == (j < 4), "?");
        h.check((sc3 == SYMCRYPT_NO_ERROR) == (j >= 4), "?");
        h.check((sc4 == SYMCRYPT_NO_ERROR) == (j >= 8), "?");
    }
}

fn testUint64Gcd() void {
    if (!hasDispatchSym("SymCryptUint64Gcd")) {
        h.zprint("    testUint64Gcd skipped\n", .{});
        return;
    }

    var a: u64 = 0;
    var b: u64 = 0;
    var t: u64 = 0;

    for (0..64 * 64) |i| {
        h.fillRandom(std.mem.asBytes(&a)) catch h.fatal("getrandom failed", .{});
        h.fillRandom(std.mem.asBytes(&b)) catch h.fatal("getrandom failed", .{});

        a >>= @intCast(i % 64);
        b >>= @intCast((i / 64) % 64);

        if (((a | b) & 1) == 0) {
            t = (a >> 14) & 1;
            a |= t;
            b |= 1 - t;
        }

        const gcd = callSymCrypt("SymCryptUint64Gcd", *const fn (u64, u64, u32) callconv(.c) u64, SymCryptUint64Gcd, .{ a, b, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN });
        h.check(gcd != 0 and a % gcd == 0 and b % gcd == 0, "Wrong GCD output from SymCryptUint64Gcd()");
    }

    for (0..64 * 64) |i| {
        h.fillRandom(std.mem.asBytes(&t)) catch h.fatal("getrandom failed", .{});
        t >>= @intCast(i % 64);
        t |= 1;

        while (true) {
            h.fillRandom(std.mem.asBytes(&a)) catch h.fatal("getrandom failed", .{});
            h.fillRandom(std.mem.asBytes(&b)) catch h.fatal("getrandom failed", .{});

            a -= a % t;
            b -= b % t;
            if (((a | b) & 1) != 0) break;
        }

        const gcd = callSymCrypt("SymCryptUint64Gcd", *const fn (u64, u64, u32) callconv(.c) u64, SymCryptUint64Gcd, .{ a, b, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN });
        h.check(gcd >= t and gcd % t == 0, "SymCryptUint64Gcd did not detect a common factor");
    }

    h.check(
        callSymCrypt("SymCryptUint64Gcd", *const fn (u64, u64, u32) callconv(.c) u64, SymCryptUint64Gcd, .{ @as(u64, 1) << 63, (@as(u64, 1) << 31) + 1, SYMCRYPT_FLAG_GCD_INPUTS_NOT_BOTH_EVEN }) == 1,
        "Wrong uint64GCD result",
    );
}

fn testCountLeadingTrailingZeros() void {
    h.check(@clz(@as(u32, 0)) == 32, "CLZ32(0) should be 32");
    h.check(@ctz(@as(u32, 0)) == 32, "CTZ32(0) should be 32");

    var i: u32 = 0;
    while (i < 32) : (i += 1) {
        const v: u32 = @as(u32, 1) << @intCast(i);
        h.check(@clz(v) == 31 - i, "CLZ32(1<<i) wrong");
        h.check(@ctz(v) == i, "CTZ32(1<<i) wrong");
    }

    h.check(@clz(@as(u32, 0xFFFFFFFF)) == 0, "CLZ32(0xFFFFFFFF) should be 0");
    h.check(@ctz(@as(u32, 0xFFFFFFFF)) == 0, "CTZ32(0xFFFFFFFF) should be 0");

    h.check(@clz(@as(u32, 0x00010000)) == 15, "CLZ32(0x00010000)");
    h.check(@ctz(@as(u32, 0x00010000)) == 16, "CTZ32(0x00010000)");

    for (0..1000) |_| {
        var v: u32 = 0;
        h.fillRandom(std.mem.asBytes(&v)) catch h.fatal("getrandom failed", .{});
        if (v == 0) continue;

        const clz: u32 = @clz(v);
        const ctz: u32 = @ctz(v);

        h.check(((v >> @intCast(31 - clz)) & 1) != 0, "CLZ32 inconsistent with value");
        if (clz > 0) {
            h.check((v >> @intCast(32 - clz)) == 0, "CLZ32 too large");
        }
        h.check(((v >> @intCast(ctz)) & 1) != 0, "CTZ32 inconsistent with value");
        if (ctz > 0) {
            h.check((v & ((@as(u32, 1) << @intCast(ctz)) - 1)) == 0, "CTZ32 too large");
        }
    }

    h.check(@clz(@as(u64, 0)) == 64, "CLZ64(0) should be 64");
    h.check(@ctz(@as(u64, 0)) == 64, "CTZ64(0) should be 64");

    i = 0;
    while (i < 64) : (i += 1) {
        const v: u64 = @as(u64, 1) << @intCast(i);
        h.check(@clz(v) == 63 - i, "CLZ64(1<<i) wrong");
        h.check(@ctz(v) == i, "CTZ64(1<<i) wrong");
    }

    h.check(@clz(@as(u64, 0xFFFFFFFFFFFFFFFF)) == 0, "CLZ64(UINT64_MAX) should be 0");
    h.check(@ctz(@as(u64, 0xFFFFFFFFFFFFFFFF)) == 0, "CTZ64(UINT64_MAX) should be 0");

    h.check(@clz(@as(u64, 0x0000000100000000)) == 31, "CLZ64(1<<32)");
    h.check(@ctz(@as(u64, 0x0000000100000000)) == 32, "CTZ64(1<<32)");
    h.check(@clz(@as(u64, 0x00000000FFFFFFFF)) == 32, "CLZ64(0xFFFFFFFF)");
    h.check(@ctz(@as(u64, 0x8000000000000000)) == 63, "CTZ64(1<<63)");

    for (0..1000) |_| {
        var v: u64 = 0;
        h.fillRandom(std.mem.asBytes(&v)) catch h.fatal("getrandom failed", .{});
        if (v == 0) continue;

        const clz: u32 = @clz(v);
        const ctz: u32 = @ctz(v);

        h.check(((v >> @intCast(63 - clz)) & 1) != 0, "CLZ64 inconsistent with value");
        if (clz > 0) {
            h.check((v >> @intCast(64 - clz)) == 0, "CLZ64 too large");
        }
        h.check(((v >> @intCast(ctz)) & 1) != 0, "CTZ64 inconsistent with value");
        if (ctz > 0) {
            h.check((v & ((@as(u64, 1) << @intCast(ctz)) - 1)) == 0, "CTZ64 too large");
        }
    }
}

pub export fn testUtil() callconv(.c) void {
    h.zprint("    utilities\n", .{});

    testBitByteSize();
    testLoadStore();
    testUint64Gcd();
    testCountLeadingTrailingZeros();
}

pub export fn testModuleInitEx() callconv(.c) void {
    if (h.g_dynamicSymCryptModuleHandle == null) {
        h.zprint("    testModuleInitEx skipped (no dynamic module loaded)\n", .{});
        return;
    }

    const sym = getDynamicSymbolPointerFromString(h.g_dynamicSymCryptModuleHandle, "SymCryptModuleInitEx", SCTEST_DYNSYM_FUNCTION_PTR);
    if (sym == null) {
        h.zprint("    testModuleInitEx skipped (symbol not available)\n", .{});
        return;
    }

    const pfnSymCryptModuleInitEx: *const fn (u32, u32) callconv(.c) u32 = @ptrCast(@alignCast(sym.?));
    h.check(
        pfnSymCryptModuleInitEx(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR) == SYMCRYPT_NO_ERROR,
        "SymCryptModuleInitEx should succeed with current version",
    );
    h.check(
        pfnSymCryptModuleInitEx(SYMCRYPT_CODE_VERSION_API + 1, 0) == SYMCRYPT_INVALID_ARGUMENT,
        "SymCryptModuleInitEx should fail when requested API version is newer than module",
    );
    h.check(
        pfnSymCryptModuleInitEx(SYMCRYPT_CODE_VERSION_API, SYMCRYPT_CODE_VERSION_MINOR + 1) == SYMCRYPT_INVALID_ARGUMENT,
        "SymCryptModuleInitEx should fail when requested minor version is newer than module",
    );

    h.zprint("    testModuleInitEx passed\n", .{});
}
