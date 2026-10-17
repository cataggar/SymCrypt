// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const rng = @import("rng.zig");
const h = @import("main_harness.zig");

const SYMCRYPT_ASYM_ALIGN_VALUE: usize = 32;
const MAGIC_STRT: u64 = 0x73747274; // 'strt'
const MAGIC_END: u64 = 0x656e642e; // 'end.'

pub export var g_nOutstandingCheckedAllocs: i64 = 0;
pub export var g_nAllocs: i64 = 0;

pub export var g_nOutstandingCheckedAllocsMsBignum: i64 = 0;
pub export var g_nAllocsMsBignum: i64 = 0;

pub export var g_bAllocFill: u8 = 0;
pub export var g_magic: u64 = 0;

extern fn scTestAllocateFastInprocMutex() callconv(.c) ?*anyopaque;
extern fn scTestFreeFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void;
extern fn scTestAcquireFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void;
extern fn scTestReleaseFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void;

pub export fn AllocWithChecksInit() callconv(.c) void {
    while (true) {
        g_bAllocFill = rng.scTestRngByte(&rng.g_rng);
        if (g_bAllocFill != 0) break;
    }
    h.fillRandom(std.mem.asBytes(&g_magic)) catch h.fatal("getrandom failed in AllocWithChecksInit", .{});
}

pub export fn AllocWithChecks(nBytes: usize, pOutstandingAllocs: *i64, pAllocs: *i64) callconv(.c) ?*anyopaque {
    h.check(g_bAllocFill != 0, "AllocFill not initialized");

    const nAdditionalBytes: usize = SYMCRYPT_ASYM_ALIGN_VALUE + 16 + 8;
    h.check(nBytes <= std.math.maxInt(u32) - nAdditionalBytes, "?");

    const nAllocated: usize = nBytes + nAdditionalBytes;
    const raw_ptr = std.c.malloc(nAllocated) orelse return null;
    const p: [*]u8 = @ptrCast(raw_ptr);

    const fill_val: u8 = g_bAllocFill ^ (rng.scTestRngByte(&rng.g_rng) & 1);
    @memset(p[0..nAllocated], fill_val);

    const p_addr: usize = @intFromPtr(p);
    const res_addr: usize = (p_addr + 16 + SYMCRYPT_ASYM_ALIGN_VALUE - 1) & ~@as(usize, SYMCRYPT_ASYM_ALIGN_VALUE - 1);
    const offset: u32 = @intCast(res_addr - p_addr);
    h.check(offset >= 16 and offset < 256, "?");

    const start_magic: u64 = g_magic ^ @as(u64, res_addr) ^ MAGIC_STRT;
    const start_ptr: *align(1) u64 = @ptrFromInt(res_addr - 8);
    start_ptr.* = start_magic;

    const end_magic: u64 = g_magic ^ @as(u64, res_addr) ^ MAGIC_END;
    const end_ptr: *align(1) u64 = @ptrFromInt(res_addr + nBytes);
    end_ptr.* = std.mem.nativeToLittle(u64, end_magic);

    const len_ptr: *align(1) u32 = @ptrFromInt(res_addr - 12);
    len_ptr.* = @intCast(nBytes);

    const offset_ptr: *align(1) u32 = @ptrFromInt(res_addr - 16);
    offset_ptr.* = offset;

    _ = @atomicRmw(i64, pOutstandingAllocs, .Add, 1, .seq_cst);
    _ = @atomicRmw(i64, pAllocs, .Add, 1, .seq_cst);

    return @ptrFromInt(res_addr);
}

pub export fn AllocWithChecksSc(nBytes: usize) callconv(.c) ?*anyopaque {
    return AllocWithChecks(nBytes, &g_nOutstandingCheckedAllocs, &g_nAllocs);
}

pub export fn AllocWithChecksMsBignum(nBytes: usize) callconv(.c) ?*anyopaque {
    return AllocWithChecks(nBytes, &g_nOutstandingCheckedAllocsMsBignum, &g_nAllocsMsBignum);
}

pub export fn SymCryptCallbackAlloc(nBytes: usize) callconv(.c) ?*anyopaque {
    return AllocWithChecksSc(nBytes);
}

pub export fn FreeWithChecks(ptr: ?*anyopaque, pOutstandingAllocs: *i64) callconv(.c) void {
    h.check(ptr != null, "Freeing NULL pointer");
    const p_addr: usize = @intFromPtr(ptr.?);
    const p: [*]const u8 = @ptrFromInt(p_addr);

    const len_ptr: *align(1) const u32 = @ptrFromInt(p_addr - 12);
    const nBytes: usize = len_ptr.*;

    if (h.g_perfTestsRunning == 0) {
        for (0..nBytes) |i| {
            h.check(p[i] == 0 or p[i] == g_bAllocFill, "Free called with nonzero remenant data");
        }
    }

    const start_ptr: *align(1) const u64 = @ptrFromInt(p_addr - 8);
    h.check(start_ptr.* == (g_magic ^ @as(u64, p_addr) ^ MAGIC_STRT), "Left magic corrupted");

    const end_ptr: *align(1) const u64 = @ptrFromInt(p_addr + nBytes);
    h.check(std.mem.littleToNative(u64, end_ptr.*) == (g_magic ^ @as(u64, p_addr) ^ MAGIC_END), "Right magic corrupted");

    const prev = @atomicRmw(i64, pOutstandingAllocs, .Sub, 1, .seq_cst);
    h.check(prev != 0, "?");

    const offset_ptr: *align(1) const u32 = @ptrFromInt(p_addr - 16);
    const offset: usize = offset_ptr.*;
    std.c.free(@ptrFromInt(p_addr - offset));
}

pub export fn FreeWithChecksSc(ptr: ?*anyopaque) callconv(.c) void {
    FreeWithChecks(ptr, &g_nOutstandingCheckedAllocs);
}

pub export fn FreeWithChecksMsBignum(ptr: ?*anyopaque) callconv(.c) void {
    FreeWithChecks(ptr, &g_nOutstandingCheckedAllocsMsBignum);
}

pub export fn SymCryptCallbackFree(ptr: ?*anyopaque) callconv(.c) void {
    FreeWithChecksSc(ptr);
}

pub export fn SymCryptCallbackRandom(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) c_uint {
    h.check(cbBuffer < 0xffffffff, "Random buffer too large");
    h.fillRandom(pbBuffer[0..cbBuffer]) catch return 0x8015; // SYMCRYPT_EXTERNAL_FAILURE
    return 0; // SYMCRYPT_NO_ERROR
}

pub export fn SymCryptCallbackAllocateMutexFastInproc() callconv(.c) ?*anyopaque {
    return scTestAllocateFastInprocMutex();
}

pub export fn SymCryptCallbackFreeMutexFastInproc(pMutex: ?*anyopaque) callconv(.c) void {
    scTestFreeFastInprocMutex(pMutex);
}

pub export fn SymCryptCallbackAcquireMutexFastInproc(pMutex: ?*anyopaque) callconv(.c) void {
    scTestAcquireFastInprocMutex(pMutex);
}

pub export fn SymCryptCallbackReleaseMutexFastInproc(pMutex: ?*anyopaque) callconv(.c) void {
    scTestReleaseFastInprocMutex(pMutex);
}
