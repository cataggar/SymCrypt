// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const result_merge = @import("result_merge.zig");
const sc_imp = @import("sc_implementations.zig");

const types = struct {
    pub const SYMCRYPT_CALL: std.builtin.CallingConvention = .c;
    pub const SYMCRYPT_ALIGN_VALUE: usize = 16;

    pub const SYMCRYPT_ERROR = enum(c_int) {
        SYMCRYPT_NO_ERROR = 0,
        _,
    };

    pub const PSYMCRYPT_MAC_EXPAND_KEY = *const fn (pExpandedKey: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
    pub const PSYMCRYPT_MAC_INIT = *const fn (pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(SYMCRYPT_CALL) void;
    pub const PSYMCRYPT_MAC_APPEND = *const fn (pState: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(SYMCRYPT_CALL) void;
    pub const PSYMCRYPT_MAC_RESULT = *const fn (pState: *anyopaque, pbResult: [*]u8) callconv(SYMCRYPT_CALL) void;

    pub const SYMCRYPT_MAC = extern struct {
        expandKeyFunc: ?PSYMCRYPT_MAC_EXPAND_KEY,
        initFunc: ?PSYMCRYPT_MAC_INIT,
        appendFunc: ?PSYMCRYPT_MAC_APPEND,
        resultFunc: ?PSYMCRYPT_MAC_RESULT,
        expandedKeySize: usize,
        stateSize: usize,
        resultSize: usize,
        ppHashAlgorithm: ?*const ?*const anyopaque,
        outerChainingStateOffset: u32,
    };
    pub const PCSYMCRYPT_MAC = *const SYMCRYPT_MAC;
};

const check = h.check;
const check3 = h.check3;
const iprint = h.iprint;

const STATUS_SUCCESS: i32 = 0;
const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));

const MAX_IMPS = 32;
const MAX_TLS_RECORD_LEN: usize = 1 << 14;

extern fn scTestResultMergeAddAlgImp(mergeHandle: *anyopaque, pAlgImp: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) void;
extern fn scTestAlgImpIncKatFailure(pAlgImp: *anyopaque, delta: u64) callconv(.c) void;
extern fn scTestGenRandom(pbBuf: *anyopaque, cbBuf: usize) callconv(.c) c_int;

extern fn scTestGetTlsCbcHmacImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize;
extern fn scTestTlsCbcHmacVerify(
    pImp: *anyopaque,
    pbKey: [*]const u8,
    cbKey: usize,
    pbHeader: [*]const u8,
    cbHeader: usize,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) i32;

extern const SymCryptHmacSha1Algorithm: types.PCSYMCRYPT_MAC;
extern const SymCryptHmacSha256Algorithm: types.PCSYMCRYPT_MAC;
extern const SymCryptHmacSha384Algorithm: types.PCSYMCRYPT_MAC;

const TlsCbcHmacMultiImp = struct {
    m_algorithmName: [128]u8 = @splat(0),
    m_algorithmNameLen: usize = 0,
    m_imps: [MAX_IMPS]*anyopaque = undefined,
    m_nImps: usize = 0,
    m_nErrorKatFailure: u64 = 0,

    fn init(algName: []const u8) TlsCbcHmacMultiImp {
        var self = TlsCbcHmacMultiImp{};
        const copyLen = @min(algName.len, self.m_algorithmName.len - 1);
        @memcpy(self.m_algorithmName[0..copyLen], algName[0..copyLen]);
        self.m_algorithmName[copyLen] = 0;
        self.m_algorithmNameLen = copyLen;
        self.m_nImps = scTestGetTlsCbcHmacImps(algName.ptr, algName.len, &self.m_imps, MAX_IMPS);
        return self;
    }

    fn deinit(self: *TlsCbcHmacMultiImp) void {
        for (self.m_imps[0..self.m_nImps]) |imp| {
            scTestAlgImpIncKatFailure(imp, self.m_nErrorKatFailure);
        }
    }

    fn algNameZ(self: *const TlsCbcHmacMultiImp) [*:0]const u8 {
        return @ptrCast(&self.m_algorithmName);
    }

    fn verify(
        self: *TlsCbcHmacMultiImp,
        pbKey: [*]const u8,
        cbKey: usize,
        pbHeader: [*]const u8,
        cbHeader: usize,
        pbData: [*]const u8,
        cbData: usize,
    ) i32 {
        const res = result_merge.scTestResultMergeCreate().?;
        defer result_merge.scTestResultMergeDestroy(res);

        var status: i32 = STATUS_SUCCESS;

        for (self.m_imps[0..self.m_nImps]) |imp| {
            status = scTestTlsCbcHmacVerify(imp, pbKey, cbKey, pbHeader, cbHeader, pbData, cbData);
            const b: u8 = if (status >= 0) 1 else 0;
            scTestResultMergeAddAlgImp(res, imp, @ptrCast(&b), 1);
        }

        var outB: u8 = 0;
        result_merge.scTestResultMergeGetResult(res, @ptrCast(&outB), 1, 1);

        return if (outB == 0) STATUS_UNSUCCESSFUL else STATUS_SUCCESS;
    }
};

fn testTlsCbcHmacSingle(
    pImp: *TlsCbcHmacMultiImp,
    pMac: types.PCSYMCRYPT_MAC,
) void {
    var header: [256]u8 = undefined;
    var key: [64]u8 = undefined;
    var buf: [MAX_TLS_RECORD_LEN + 48 + 255 + 1]u8 = undefined;
    var expandedKey: [1024]u8 align(types.SYMCRYPT_ALIGN_VALUE) = undefined;
    var state: [1024]u8 align(types.SYMCRYPT_ALIGN_VALUE) = undefined;

    for (0..1000) |iTest| {
        var headerLen: usize = h.g_rng.byte();
        var recordLen: usize = h.g_rng.sizetNonUniform(MAX_TLS_RECORD_LEN, 256, 1);
        var padLen: u8 = h.g_rng.byte();
        var byteLocation: usize = 0;
        var b: u8 = 0;

        @memset(&buf, 0);
        @memset(&header, 0);

        if (iTest == 0) {
            headerLen = 0;
            recordLen = 0;
            padLen = 0;

            @memset(&key, 'K');
            for (0..headerLen) |i| {
                header[i] = @truncate('H' + i);
            }
            for (0..recordLen) |i| {
                buf[i] = @truncate('d' + i);
            }
        } else {
            check(scTestGenRandom(&key, key.len) == 0, "?");
            check(scTestGenRandom(&header, headerLen) == 0, "?");
            check(scTestGenRandom(&buf, recordLen) == 0, "?");
        }

        const macLen: usize = pMac.resultSize;
        const totalLen: usize = recordLen + macLen + padLen + 1;

        _ = pMac.expandKeyFunc.?(&expandedKey, &key, key.len);
        pMac.initFunc.?(&state, &expandedKey);
        pMac.appendFunc.?(&state, &header, headerLen);
        pMac.appendFunc.?(&state, &buf, recordLen);
        pMac.resultFunc.?(&state, buf[recordLen..].ptr);

        @memset(buf[recordLen + macLen ..][0 .. @as(usize, padLen) + 1], padLen);

        check3(
            pImp.verify(&key, key.len, &header, headerLen, &buf, totalLen) >= 0,
            "TlsCbcHmac verify failure %lld",
            @as(u64, iTest),
        );

        if ((h.g_rng.byte() & 1) == 0) {
            byteLocation = recordLen + macLen + h.g_rng.sizet(@as(usize, padLen) + 1);
        } else {
            byteLocation = h.g_rng.sizet(totalLen);
        }

        while (true) {
            b = h.g_rng.byte();
            if (b != 0) break;
        }

        buf[byteLocation] ^= b;

        check(pImp.verify(&key, key.len, &header, headerLen, &buf, totalLen) < 0, "TlsCbcHmac verify success");
    }
}

pub export fn testTlsCbcHmacAlgorithms() callconv(.c) void {
    var sep: [*:0]const u8 = "    ";
    var doneAnything = false;

    {
        var imp = TlsCbcHmacMultiImp.init("TlsCbcHmacSha1");
        defer imp.deinit();
        if (imp.m_nImps > 0) {
            h.ziprint("{s}{s}", .{ std.mem.span(sep), std.mem.span(imp.algNameZ()) });
            sep = ", ";
            doneAnything = true;
            testTlsCbcHmacSingle(&imp, SymCryptHmacSha1Algorithm);
        }
    }

    {
        var imp = TlsCbcHmacMultiImp.init("TlsCbcHmacSha256");
        defer imp.deinit();
        if (imp.m_nImps > 0) {
            h.ziprint("{s}{s}", .{ std.mem.span(sep), std.mem.span(imp.algNameZ()) });
            sep = ", ";
            doneAnything = true;
            testTlsCbcHmacSingle(&imp, SymCryptHmacSha256Algorithm);
        }
    }

    {
        var imp = TlsCbcHmacMultiImp.init("TlsCbcHmacSha384");
        defer imp.deinit();
        if (imp.m_nImps > 0) {
            h.ziprint("{s}{s}", .{ std.mem.span(sep), std.mem.span(imp.algNameZ()) });
            sep = ", ";
            doneAnything = true;
            testTlsCbcHmacSingle(&imp, SymCryptHmacSha384Algorithm);
        }
    }

    if (doneAnything) {
        iprint("\n");
    }
}

pub export fn testTlsCbcHmac() callconv(.c) void {
    testTlsCbcHmacAlgorithms();
}
