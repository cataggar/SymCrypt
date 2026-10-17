// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

extern fn SymCryptSha1(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub const Rng = extern struct {
    m_seed: [20]u8,
    m_blockCtr: u64,
    m_bytesInBuf: usize,
    m_buf: [20]u8,

    pub fn byte(self: *Rng) u8 {
        return scTestRngByte(self);
    }

    pub fn uint32(self: *Rng) u32 {
        return scTestRngUint32(self);
    }

    pub fn sizet(self: *Rng, upb: usize) usize {
        return scTestRngSizet(self, upb);
    }

    pub fn sizetRange(self: *Rng, min: usize, upb: usize) usize {
        return scTestRngSizetRange(self, min, upb);
    }

    pub fn sizetNonUniform(self: *Rng, upb: usize, uniformLimit: usize, logIncrease: u32) usize {
        return scTestRngSizetNonUniform(self, upb, uniformLimit, logIncrease);
    }

    pub fn randomSubRange(self: *Rng, bufSize: usize, pStart: *usize, pLen: *usize) void {
        scTestRngRandomSubRange(self, bufSize, pStart, pLen);
    }

    pub fn bytes(self: *Rng, buf: []u8) void {
        for (buf) |*b| {
            b.* = scTestRngByte(self);
        }
    }
};

pub export var g_rng: Rng = .{
    .m_seed = @splat(0),
    .m_blockCtr = std.math.maxInt(u64),
    .m_bytesInBuf = 0,
    .m_buf = @splat(0),
};

pub export fn scTestRngInit(rng: *Rng) callconv(.c) void {
    rng.m_blockCtr = std.math.maxInt(u64);
    rng.m_bytesInBuf = 0;
}

pub export fn scTestRngDeinit(rng: *Rng) callconv(.c) void {
    std.crypto.secureZero(u8, &rng.m_seed);
    std.crypto.secureZero(u8, &rng.m_buf);
}

pub export fn scTestRngReset(rng: *Rng, pbSeed: [*]const u8, cbSeed: usize) callconv(.c) void {
    SymCryptSha1(pbSeed, cbSeed, &rng.m_seed);
    rng.m_blockCtr = 0;
    rng.m_bytesInBuf = 0;
}

pub export fn scTestRngByte(rng: *Rng) callconv(.c) u8 {
    h.check(rng.m_blockCtr != std.math.maxInt(u64), "Use of unseeded Rng object");
    if (rng.m_bytesInBuf == 0) {
        var input: [28]u8 = undefined;
        @memcpy(input[0..20], &rng.m_seed);
        @memcpy(input[20..28], std.mem.asBytes(&rng.m_blockCtr));
        SymCryptSha1(&input, input.len, &rng.m_buf);
        rng.m_blockCtr +%= 1;
        rng.m_bytesInBuf = 20;
    }

    const res = rng.m_buf[20 - rng.m_bytesInBuf];
    rng.m_bytesInBuf -= 1;
    return res;
}

pub export fn scTestRngUint32(rng: *Rng) callconv(.c) u32 {
    h.check(rng.m_blockCtr != std.math.maxInt(u64), "Use of unseeded Rng object");
    if (rng.m_bytesInBuf < 4) {
        var input: [28]u8 = undefined;
        @memcpy(input[0..20], &rng.m_seed);
        @memcpy(input[20..28], std.mem.asBytes(&rng.m_blockCtr));
        SymCryptSha1(&input, input.len, &rng.m_buf);
        rng.m_blockCtr +%= 1;
        rng.m_bytesInBuf = 20;
    }

    const idx = 20 - rng.m_bytesInBuf;
    const res = std.mem.readInt(u32, rng.m_buf[idx..][0..4], .little);
    rng.m_bytesInBuf -= 4;
    return res;
}

pub export fn scTestRngSizet(rng: *Rng, upb: usize) callconv(.c) usize {
    h.check(upb != 0, "Can't generate random value in empty range");

    const msBit: usize = (@bitSizeOf(usize) - 1) - @clz(upb);
    var mask: usize = (@as(usize, 1) << @intCast(msBit));
    mask |= mask - 1;

    const nBytes: u32 = @intCast((msBit + 8) / 8);
    while (true) {
        var val: usize = 0;
        var i: u32 = 0;
        while (i < nBytes) : (i += 1) {
            val = (val << 8) | scTestRngByte(rng);
        }
        val &= mask;
        if (val < upb) {
            return val;
        }
    }
}

pub export fn scTestRngSizetRange(rng: *Rng, min: usize, upb: usize) callconv(.c) usize {
    h.check(upb >= min, "Can't generate random value in empty range");
    return min + scTestRngSizet(rng, upb - min);
}

pub export fn scTestRngSizetNonUniform(rng: *Rng, upb: usize, uniformLimit: usize, logIncrease: u32) callconv(.c) usize {
    h.check(
        logIncrease != 0 and logIncrease <= 4 and (upb >> @intCast(8 * logIncrease)) <= uniformLimit,
        "Unsuitable parameters",
    );
    var prob: u8 = scTestRngByte(rng);
    var limit: usize = uniformLimit;
    while ((prob & 1) != 0 and limit < upb) {
        prob >>= 1;
        limit <<= @intCast(logIncrease);
    }
    limit = @min(upb, limit);
    return scTestRngSizet(rng, limit);
}

pub export fn scTestRngRandomSubRange(rng: *Rng, bufSize: usize, pStart: *usize, pLen: *usize) callconv(.c) void {
    const a = scTestRngSizet(rng, bufSize);
    const b = scTestRngSizet(rng, bufSize);
    pStart.* = @min(a, b);
    pLen.* = @max(a, b) - @min(a, b);
}
