// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

const check = h.check;

pub const SYMCRYPT_NO_ERROR: u32 = 0;
pub const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8002;
pub const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x8009;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));
pub const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

pub const DynamicSymbolType = enum(u32) {
    function_ptr = 1,
    data_ptr = 2,
    array = 3,
};

pub const ImpKind = enum {
    sc,
    sc_static,
    sc_dynamic,

    pub fn name(comptime self: ImpKind) []const u8 {
        return switch (self) {
            .sc => "SymCrypt",
            .sc_static => "SymCryptStatic",
            .sc_dynamic => "SymCryptDynamic",
        };
    }
};

extern fn initVectorRegisters() callconv(.c) void;
extern fn verifyVectorRegisters() callconv(.c) void;
extern fn getDynamicSymbolPointerFromString(
    hDynamicModule: ?*anyopaque,
    pSymbolName: [*:0]const u8,
    symbolType: u32,
) callconv(.c) ?*anyopaque;

extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;
extern fn SymCryptEqual(pb1: [*]const u8, pb2: [*]const u8, cb: usize) callconv(.c) u8;

extern fn SymCryptAesExpandKey(pExpandedKey: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) u32;
extern fn SymCryptAesCtrMsb32(
    pExpandedKey: *const anyopaque,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void;
extern fn SymCryptAesCtrMsb64(
    pExpandedKey: *const anyopaque,
    pbChainingValue: [*]u8,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void;

extern fn SymCryptRngAesInstantiate(
    pState: *anyopaque,
    pbKey: [*]const u8,
    cbKey: usize,
    useDerivationFunction: u8,
) callconv(.c) u32;
extern fn SymCryptRngAesReseed(
    pState: *anyopaque,
    pbEntropy: [*]const u8,
    cbEntropy: usize,
    useDerivationFunction: u8,
) callconv(.c) void;
extern fn SymCryptRngAesGenerate(
    pState: *anyopaque,
    pbDst: [*]u8,
    cbData: usize,
    pbAdditional: ?[*]const u8,
    cbAdditional: usize,
    useDerivationFunction: u8,
) callconv(.c) void;

extern fn SymCryptChaCha20Init(
    pState: *SYMCRYPT_CHACHA20_STATE,
    pbKey: [*]const u8,
    cbKey: usize,
    pbNonce: [*]const u8,
    cbNonce: usize,
    offset: u64,
) callconv(.c) u32;
extern fn SymCryptChaCha20Crypt(
    pState: *SYMCRYPT_CHACHA20_STATE,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void;
extern fn SymCryptPoly1305Init(
    pState: *SYMCRYPT_POLY1305_STATE,
    pbKey: [*]const u8,
) callconv(.c) void;
extern fn SymCryptPoly1305Append(
    pState: *SYMCRYPT_POLY1305_STATE,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void;
extern fn SymCryptPoly1305Result(
    pState: *SYMCRYPT_POLY1305_STATE,
    pbResult: [*]u8,
) callconv(.c) void;

// ============================================================================
// Dynamic / Vector-Register-Verified Dispatch Helpers
// ============================================================================

pub fn lookupDynamicSymbol(
    comptime T: type,
    comptime sym_name: [*:0]const u8,
    comptime sym_type: DynamicSymbolType,
) ?T {
    const Holder = struct {
        var cached: ?T = null;
        var attempted: bool = false;
    };
    if (!Holder.attempted) {
        const raw = getDynamicSymbolPointerFromString(
            h.g_dynamicSymCryptModuleHandle,
            sym_name,
            @backingInt(sym_type),
        );
        Holder.attempted = true;
        if (raw) |ptr| {
            Holder.cached = @ptrCast(@alignCast(ptr));
        }
    }
    return Holder.cached;
}

pub fn hasDynamicSymbol(comptime sym_name: [*:0]const u8) bool {
    return getDynamicSymbolPointerFromString(
        h.g_dynamicSymCryptModuleHandle,
        sym_name,
        @backingInt(DynamicSymbolType.function_ptr),
    ) != null;
}

pub fn lookupScImpSym(
    comptime imp: ImpKind,
    comptime T: type,
    comptime sym_name: [*:0]const u8,
    static_sym: T,
    comptime sym_type: DynamicSymbolType,
) ?T {
    return switch (imp) {
        .sc, .sc_static => static_sym,
        .sc_dynamic => lookupDynamicSymbol(T, sym_name, sym_type),
    };
}

pub fn callScImpFn(
    comptime imp: ImpKind,
    comptime sym_name: [*:0]const u8,
    comptime FnPtr: type,
    comptime static_fn: FnPtr,
    args: anytype,
) @typeInfo(@typeInfo(FnPtr).pointer.child).@"fn".return_type.? {
    switch (imp) {
        .sc, .sc_static => {
            initVectorRegisters();
            const res = @call(.auto, static_fn, args);
            verifyVectorRegisters();
            return res;
        },
        .sc_dynamic => {
            const fn_ptr = lookupDynamicSymbol(FnPtr, sym_name, .function_ptr);
            check(fn_ptr != null, "Could not find dynamic function");
            return @call(.auto, fn_ptr.?, args);
        },
    }
}

pub fn callSymCrypt(
    comptime sym_name: [*:0]const u8,
    comptime FnPtr: type,
    comptime static_fn: FnPtr,
    args: anytype,
) @typeInfo(@typeInfo(FnPtr).pointer.child).@"fn".return_type.? {
    if (h.g_useDynamicFunctionsInTestCall != 0) {
        return callScImpFn(.sc_dynamic, sym_name, FnPtr, static_fn, args);
    } else {
        return callScImpFn(.sc_static, sym_name, FnPtr, static_fn, args);
    }
}

pub fn lookupSymCryptSymbol(
    comptime T: type,
    comptime sym_name: [*:0]const u8,
    static_sym: T,
    comptime sym_type: DynamicSymbolType,
) ?T {
    if (h.g_useDynamicFunctionsInTestCall != 0) {
        return lookupDynamicSymbol(T, sym_name, sym_type);
    } else {
        return static_sym;
    }
}

// ============================================================================
// Trial Division Fake Context Helpers (exported for C++ and Zig callers)
// ============================================================================

pub const SYMCRYPT_TRIALDIVISION_PRIME = extern struct {
    invMod2e64: u64,
    compareLimit: u64,
};

pub const SYMCRYPT_TRIALDIVISION_GROUP = extern struct {
    nPrimes: u32,
    factor: [9]u32,
};

pub const SYMCRYPT_TRIALDIVISION_CONTEXT = extern struct {
    nBytesAlloc: usize,
    maxTrialPrime: u32,
    pGroupList: [*]SYMCRYPT_TRIALDIVISION_GROUP,
    pPrimeList: [*]SYMCRYPT_TRIALDIVISION_PRIME,
    pPrimes: [*]u32,
    Primes3_5_17: [3]SYMCRYPT_TRIALDIVISION_PRIME,
};

pub export fn trialDivisionSetFakePrime(
    p: *SYMCRYPT_TRIALDIVISION_PRIME,
) callconv(.c) void {
    p.invMod2e64 = 0x5a5a5a5a5a5a5a5b;
    p.compareLimit = 0;
}

pub export fn createFakeTrialDivisionContext(
    pBuf: [*]u8,
    primesPerGroup: u32,
) callconv(.c) void {
    var pAlloc: [*]u8 = pBuf;
    const nGroups: usize = 1000;
    const nPrimes: usize = nGroups * @as(usize, primesPerGroup);

    const pContext: *SYMCRYPT_TRIALDIVISION_CONTEXT = @ptrCast(@alignCast(pAlloc));
    pAlloc += @sizeOf(SYMCRYPT_TRIALDIVISION_CONTEXT);

    pContext.pGroupList = @ptrCast(@alignCast(pAlloc));
    pAlloc += (nGroups + 1) * @sizeOf(SYMCRYPT_TRIALDIVISION_GROUP);

    pContext.pPrimeList = @ptrCast(@alignCast(pAlloc));
    pAlloc += (nPrimes + 1) * @sizeOf(SYMCRYPT_TRIALDIVISION_PRIME);

    pContext.pPrimes = @ptrCast(@alignCast(pAlloc));
    pAlloc += (nPrimes + 1) * @sizeOf(u32);

    pContext.nBytesAlloc = @intFromPtr(pAlloc) - @intFromPtr(pBuf);

    trialDivisionSetFakePrime(&pContext.Primes3_5_17[0]);
    trialDivisionSetFakePrime(&pContext.Primes3_5_17[1]);
    trialDivisionSetFakePrime(&pContext.Primes3_5_17[2]);

    for (0..nPrimes) |i| {
        trialDivisionSetFakePrime(&pContext.pPrimeList[i]);
    }

    for (0..nGroups) |i| {
        pContext.pGroupList[i].nPrimes = primesPerGroup;
        @memset(std.mem.asBytes(&pContext.pGroupList[i].factor), 0xa5);
    }

    pContext.pGroupList[nGroups].nPrimes = 0;
}

// ============================================================================
// C-Callable SymCrypt Implementation Shims
// ============================================================================

pub const SYMCRYPT_AES_CTR_MSB32_STATE = extern struct {
    chaining: [16]u8 align(16),
};

pub const SYMCRYPT_AES_CTR_MSB64_STATE = extern struct {
    chaining: [16]u8 align(16),
};

pub const SYMCRYPT_RNG_AES_EXPANDED_KEY = extern struct {
    useDerivationFunction: u8,
};

pub const SYMCRYPT_POLY1305_STATE = extern struct {
    r: [4]u32 align(16),
    s: [4]u32,
    a: [5]u32,
    bytesInBuffer: usize,
    buf: [16]u8,
    magic: usize,
};

pub const SYMCRYPT_CHACHA20_STATE = extern struct {
    key: [8]u32 align(16),
    nonce: [3]u32,
    offset: u64,
    keystreamBufferValid: u8,
    keystream: [64]u8,
};

pub const SYMCRYPT_CHACHA20_POLY1305_STATE = extern struct {
    key: [32]u8,
    nonce: [12]u8,
    poly1305State: SYMCRYPT_POLY1305_STATE,
    chacha20State: SYMCRYPT_CHACHA20_STATE,
    cbAuthData: u64,
    cbData: u64,
    authDataDone: u8,
};

pub export fn SymCryptAesCtrMsb32Init(
    pExpandedKey: *anyopaque,
    pbKey: [*]const u8,
    cbKey: usize,
    pState: *SYMCRYPT_AES_CTR_MSB32_STATE,
) callconv(.c) u32 {
    @memset(&pState.chaining, 0);
    return SymCryptAesExpandKey(pExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptAesCtrMsb32Crypt(
    pExpandedKey: *const anyopaque,
    pState: *SYMCRYPT_AES_CTR_MSB32_STATE,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    SymCryptAesCtrMsb32(pExpandedKey, &pState.chaining, pbSrc, pbDst, cbData);
}

pub export fn SymCryptAesCtrMsb64Init(
    pExpandedKey: *anyopaque,
    pbKey: [*]const u8,
    cbKey: usize,
    pState: *SYMCRYPT_AES_CTR_MSB64_STATE,
) callconv(.c) u32 {
    @memset(&pState.chaining, 0);
    return SymCryptAesExpandKey(pExpandedKey, pbKey, cbKey);
}

pub export fn SymCryptAesCtrMsb64Crypt(
    pExpandedKey: *const anyopaque,
    pState: *SYMCRYPT_AES_CTR_MSB64_STATE,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    SymCryptAesCtrMsb64(pExpandedKey, &pState.chaining, pbSrc, pbDst, cbData);
}

pub export fn SymCryptAesCtrDrbgInit(
    pExpandedKey: *SYMCRYPT_RNG_AES_EXPANDED_KEY,
    pbKey: [*]const u8,
    cbKey: usize,
    pState: *anyopaque,
) callconv(.c) u32 {
    if (cbKey == 0) {
        var entropy: [48]u8 = @splat(0);
        pExpandedKey.useDerivationFunction = 1;
        return SymCryptRngAesInstantiate(pState, &entropy, entropy.len, pExpandedKey.useDerivationFunction);
    } else {
        pExpandedKey.useDerivationFunction = pbKey[0];
        return SymCryptRngAesInstantiate(pState, pbKey + 1, cbKey - 1, pExpandedKey.useDerivationFunction);
    }
}

pub export fn SymCryptAesCtrDrbgReseed(
    pExpandedKey: *SYMCRYPT_RNG_AES_EXPANDED_KEY,
    pState: *anyopaque,
    pbEntropy: [*]const u8,
    cbEntropy: usize,
) callconv(.c) void {
    SymCryptRngAesReseed(pState, pbEntropy, cbEntropy, pExpandedKey.useDerivationFunction);
}

pub export fn SymCryptAesCtrDrbgGenerate(
    pExpandedKey: *SYMCRYPT_RNG_AES_EXPANDED_KEY,
    pState: *anyopaque,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    _ = pbSrc;
    SymCryptRngAesGenerate(pState, pbDst, cbData, null, 0, pExpandedKey.useDerivationFunction);
}

pub export fn SymCryptChaCha20Poly1305Init(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbNonce: [*]const u8,
    cbNonce: usize,
    cbAuthData: usize,
    cbData: usize,
    cbTag: usize,
) callconv(.c) void {
    var poly1305Key: [32]u8 = @splat(0);

    check(cbNonce == 12, "Invalid nonce size");
    check(cbTag == 16, "Invalid tag size");
    _ = cbAuthData;
    _ = cbData;

    pState.cbAuthData = 0;
    pState.cbData = 0;
    pState.authDataDone = 0;
    @memcpy(pState.nonce[0..12], pbNonce[0..12]);

    _ = SymCryptChaCha20Init(&pState.chacha20State, &pState.key, pState.key.len, pbNonce, 12, 0);
    SymCryptChaCha20Crypt(&pState.chacha20State, &poly1305Key, &poly1305Key, poly1305Key.len);

    SymCryptPoly1305Init(&pState.poly1305State, &poly1305Key);
    SymCryptWipe(&poly1305Key, poly1305Key.len);

    // Move keystream past block 0 to offset 64
    _ = SymCryptChaCha20Init(&pState.chacha20State, &pState.key, pState.key.len, pbNonce, 12, 64);
}

pub export fn SymCryptChaCha20Poly1305AuthPart(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbAuthData: [*]const u8,
    cbAuthData: usize,
) callconv(.c) void {
    SymCryptPoly1305Append(&pState.poly1305State, pbAuthData, cbAuthData);
    pState.cbAuthData += cbAuthData;
}

fn chacha20Poly1305FinishAuthData(pState: *SYMCRYPT_CHACHA20_POLY1305_STATE) void {
    const zeroes: [16]u8 = @splat(0);
    if (pState.authDataDone == 0) {
        if ((pState.cbAuthData & 0xf) > 0) {
            SymCryptPoly1305Append(
                &pState.poly1305State,
                &zeroes,
                16 - @as(usize, @intCast(pState.cbAuthData & 0xf)),
            );
        }
        pState.authDataDone = 1;
    }
}

fn chacha20Poly1305ComputeTag(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbTag: [*]u8,
) void {
    var zeroes: [16]u8 = @splat(0);

    if ((pState.cbData & 0xf) > 0) {
        SymCryptPoly1305Append(
            &pState.poly1305State,
            &zeroes,
            16 - @as(usize, @intCast(pState.cbData & 0xf)),
        );
    }

    std.mem.writeInt(u64, zeroes[0..8], pState.cbAuthData, .little);
    std.mem.writeInt(u64, zeroes[8..16], pState.cbData, .little);
    SymCryptPoly1305Append(&pState.poly1305State, &zeroes, 16);
    SymCryptPoly1305Result(&pState.poly1305State, pbTag);
}

pub export fn SymCryptChaCha20Poly1305EncryptPart(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    chacha20Poly1305FinishAuthData(pState);
    SymCryptChaCha20Crypt(&pState.chacha20State, pbSrc, pbDst, cbData);
    SymCryptPoly1305Append(&pState.poly1305State, pbDst, cbData);
    pState.cbData += cbData;
}

pub export fn SymCryptChaCha20Poly1305DecryptPart(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbSrc: [*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    chacha20Poly1305FinishAuthData(pState);
    SymCryptPoly1305Append(&pState.poly1305State, pbSrc, cbData);
    SymCryptChaCha20Crypt(&pState.chacha20State, pbSrc, pbDst, cbData);
    pState.cbData += cbData;
}

pub export fn SymCryptChaCha20Poly1305EncryptFinal(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbTag: [*]u8,
    cbTag: usize,
) callconv(.c) void {
    check(cbTag == 16, "Invalid tag size");
    chacha20Poly1305FinishAuthData(pState);
    chacha20Poly1305ComputeTag(pState, pbTag);
}

pub export fn SymCryptChaCha20Poly1305DecryptFinal(
    pState: *SYMCRYPT_CHACHA20_POLY1305_STATE,
    pbTag: [*]const u8,
    cbTag: usize,
) callconv(.c) u32 {
    var tag: [16]u8 = undefined;
    check(cbTag == 16, "Invalid tag size");
    chacha20Poly1305FinishAuthData(pState);
    chacha20Poly1305ComputeTag(pState, &tag);
    const eq = SymCryptEqual(pbTag, &tag, 16);
    SymCryptWipe(&tag, tag.len);
    return if (eq != 0) SYMCRYPT_NO_ERROR else SYMCRYPT_AUTHENTICATION_FAILURE;
}

// ============================================================================
// Zig Implementation Adapters for SymCrypt Test Drivers (Chunks 8.3–8.6)
// ============================================================================

/// Generic Hash adapter wrapping a SymCrypt hash descriptor for ImpSc / ImpScStatic / ImpScDynamic.
pub fn HashImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const input_block_len: usize = Spec.input_block_len;
        pub const result_len: usize = Spec.result_len;

        state: Spec.State = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.init_symbol),
            };
        }

        pub fn init(self: *Self) void {
            callScImpFn(imp, Spec.init_symbol, @TypeOf(&Spec.initFn), &Spec.initFn, .{&self.state});
        }

        pub fn append(self: *Self, data: []const u8) void {
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.append_symbol, @TypeOf(&Spec.appendFn), &Spec.appendFn, .{ &self.state, ptr, data.len });
        }

        pub fn result(self: *Self, out: []u8) void {
            check(out.len == Spec.result_len, "Result len error");
            var tmp_state: Spec.State = undefined;
            callScImpFn(imp, Spec.state_copy_symbol, @TypeOf(&Spec.stateCopyFn), &Spec.stateCopyFn, .{ &self.state, &tmp_state });
            callScImpFn(imp, Spec.result_symbol, @TypeOf(&Spec.resultFn), &Spec.resultFn, .{ &tmp_state, out.ptr });
        }

        pub fn hash(data: []const u8, out: []u8) void {
            check(out.len == Spec.result_len, "Result len error");
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else out.ptr;
            callScImpFn(imp, Spec.hash_symbol, @TypeOf(&Spec.hashFn), &Spec.hashFn, .{ ptr, data.len, out.ptr });
        }
    };
}

/// Generic XOF adapter wrapping a SymCrypt XOF descriptor for ImpSc / ImpScStatic / ImpScDynamic.
pub fn XofImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const input_block_len: usize = Spec.input_block_len;

        state: Spec.State = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.init_symbol),
            };
        }

        pub fn init(self: *Self) void {
            callScImpFn(imp, Spec.init_symbol, @TypeOf(&Spec.initFn), &Spec.initFn, .{&self.state});
        }

        pub fn append(self: *Self, data: []const u8) void {
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.append_symbol, @TypeOf(&Spec.appendFn), &Spec.appendFn, .{ &self.state, ptr, data.len });
        }

        pub fn extract(self: *Self, out: []u8, bWipe: bool) void {
            const ptr: [*]u8 = if (out.len > 0) out.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.extract_symbol, @TypeOf(&Spec.extractFn), &Spec.extractFn, .{
                &self.state,
                ptr,
                out.len,
                @as(u8, @intFromBool(bWipe)),
            });
        }

        pub fn xof(data: []const u8, out: []u8) void {
            const in_ptr: [*]const u8 = if (data.len > 0) data.ptr else out.ptr;
            const out_ptr: [*]u8 = if (out.len > 0) out.ptr else @constCast(in_ptr);
            callScImpFn(imp, Spec.xof_symbol, @TypeOf(&Spec.xofFn), &Spec.xofFn, .{ in_ptr, data.len, out_ptr, out.len });
        }
    };
}

/// Generic MAC adapter wrapping a SymCrypt MAC descriptor for ImpSc / ImpScStatic / ImpScDynamic.
pub fn MacImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const input_block_len: usize = Spec.input_block_len;
        pub const result_len: usize = Spec.result_len;

        key: Spec.ExpandedKey = undefined,
        state: Spec.State = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.init_symbol),
            };
        }

        pub fn init(self: *Self, key_bytes: []const u8) i32 {
            const key_ptr: [*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else @ptrCast(&self.state);
            const sc_err = callScImpFn(imp, Spec.expand_key_symbol, @TypeOf(&Spec.expandKeyFn), &Spec.expandKeyFn, .{
                &self.key,
                key_ptr,
                key_bytes.len,
            });
            if (sc_err != SYMCRYPT_NO_ERROR) return STATUS_UNSUCCESSFUL;
            callScImpFn(imp, Spec.init_symbol, @TypeOf(&Spec.initFn), &Spec.initFn, .{ &self.state, &self.key });
            return STATUS_SUCCESS;
        }

        pub fn append(self: *Self, data: []const u8) void {
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.append_symbol, @TypeOf(&Spec.appendFn), &Spec.appendFn, .{ &self.state, ptr, data.len });
        }

        pub fn result(self: *Self, out: []u8) void {
            check(out.len == Spec.result_len, "Result len error");
            var tmp_state: Spec.State = undefined;
            callScImpFn(imp, Spec.state_copy_symbol, @TypeOf(&Spec.stateCopyFn), &Spec.stateCopyFn, .{ &self.state, null, &tmp_state });
            callScImpFn(imp, Spec.result_symbol, @TypeOf(&Spec.resultFn), &Spec.resultFn, .{ &tmp_state, out.ptr });
        }

        pub fn mac(key_bytes: []const u8, data: []const u8, out: []u8) i32 {
            check(out.len == Spec.result_len, "Result len error");
            var exp_key: Spec.ExpandedKey = undefined;
            const key_ptr: [*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else out.ptr;
            const data_ptr: [*]const u8 = if (data.len > 0) data.ptr else out.ptr;
            const sc_err = callScImpFn(imp, Spec.expand_key_symbol, @TypeOf(&Spec.expandKeyFn), &Spec.expandKeyFn, .{
                &exp_key,
                key_ptr,
                key_bytes.len,
            });
            if (sc_err != SYMCRYPT_NO_ERROR) return STATUS_UNSUCCESSFUL;
            callScImpFn(imp, Spec.mac_symbol, @TypeOf(&Spec.macFn), &Spec.macFn, .{ &exp_key, data_ptr, data.len, out.ptr });
            const key_raw = std.mem.asBytes(&exp_key);
            SymCryptWipe(key_raw.ptr, key_raw.len);
            return STATUS_SUCCESS;
        }
    };
}

/// Generic Customizable XOF adapter (cSHAKE128 / cSHAKE256) for ImpSc / ImpScStatic / ImpScDynamic.
pub fn CustomizableXofImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const input_block_len: usize = Spec.input_block_len;

        state: Spec.State = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.init_symbol),
            };
        }

        pub fn init(self: *Self, func_name: []const u8, custom_str: []const u8) void {
            const fn_ptr: ?[*]const u8 = if (func_name.len > 0) func_name.ptr else null;
            const cs_ptr: ?[*]const u8 = if (custom_str.len > 0) custom_str.ptr else null;
            callScImpFn(imp, Spec.init_symbol, @TypeOf(&Spec.initFn), &Spec.initFn, .{
                &self.state,
                fn_ptr,
                func_name.len,
                cs_ptr,
                custom_str.len,
            });
        }

        pub fn append(self: *Self, data: []const u8) void {
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.append_symbol, @TypeOf(&Spec.appendFn), &Spec.appendFn, .{ &self.state, ptr, data.len });
        }

        pub fn extract(self: *Self, out: []u8, bWipe: bool) void {
            const ptr: [*]u8 = if (out.len > 0) out.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.extract_symbol, @TypeOf(&Spec.extractFn), &Spec.extractFn, .{
                &self.state,
                ptr,
                out.len,
                @as(u8, @intFromBool(bWipe)),
            });
        }
    };
}

/// Generic KMAC adapter (KMAC128 / KMAC256) for ImpSc / ImpScStatic / ImpScDynamic.
pub fn KmacImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const input_block_len: usize = Spec.input_block_len;

        key: Spec.ExpandedKey = undefined,
        state: Spec.State = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.init_symbol),
            };
        }

        pub fn init(self: *Self, custom_str: []const u8, key_bytes: []const u8) i32 {
            const cs_ptr: ?[*]const u8 = if (custom_str.len > 0) custom_str.ptr else null;
            const key_ptr: ?[*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else null;
            const sc_err = callScImpFn(imp, Spec.expand_key_ex_symbol, @TypeOf(&Spec.expandKeyExFn), &Spec.expandKeyExFn, .{
                &self.key,
                key_ptr,
                key_bytes.len,
                cs_ptr,
                custom_str.len,
            });
            if (sc_err != SYMCRYPT_NO_ERROR) return STATUS_UNSUCCESSFUL;
            callScImpFn(imp, Spec.init_symbol, @TypeOf(&Spec.initFn), &Spec.initFn, .{ &self.state, &self.key });
            return STATUS_SUCCESS;
        }

        pub fn append(self: *Self, data: []const u8) void {
            const ptr: [*]const u8 = if (data.len > 0) data.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.append_symbol, @TypeOf(&Spec.appendFn), &Spec.appendFn, .{ &self.state, ptr, data.len });
        }

        pub fn extract(self: *Self, out: []u8, bWipe: bool) void {
            const ptr: [*]u8 = if (out.len > 0) out.ptr else @ptrCast(&self.state);
            callScImpFn(imp, Spec.extract_symbol, @TypeOf(&Spec.extractFn), &Spec.extractFn, .{
                &self.state,
                ptr,
                out.len,
                @as(u8, @intFromBool(bWipe)),
            });
        }
    };
}

/// Generic BlockCipher adapter (ECB / CBC / CFB) for ImpSc / ImpScStatic / ImpScDynamic.
pub fn BlockCipherImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;
        pub const mode_name = Spec.mode_name;
        pub const core_block_len: usize = Spec.core_block_len;

        key: Spec.ExpandedKey = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.expand_key_symbol),
            };
        }

        pub fn setKey(self: *Self, key_bytes: []const u8) i32 {
            const key_ptr: [*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else @ptrCast(&self.key);
            const sc_err = callScImpFn(imp, Spec.expand_key_symbol, @TypeOf(&Spec.expandKeyFn), &Spec.expandKeyFn, .{
                &self.key,
                key_ptr,
                key_bytes.len,
            });
            return if (sc_err == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
        }
    };
}

/// Generic KeyWrap adapter (AesKw / AesKwp) for ImpSc / ImpScStatic / ImpScDynamic.
pub fn KeyWrapImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;

        key: Spec.ExpandedKey = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.encrypt_symbol),
            };
        }

        pub fn setKey(self: *Self, key_bytes: []const u8) i32 {
            const key_ptr: [*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else @ptrCast(&self.key);
            const sc_err = callScImpFn(imp, Spec.expand_key_symbol, @TypeOf(&Spec.expandKeyFn), &Spec.expandKeyFn, .{
                &self.key,
                key_ptr,
                key_bytes.len,
            });
            return if (sc_err == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
        }

        pub fn encrypt(self: *Self, src: []const u8, dst: []u8) void {
            callScImpFn(imp, Spec.encrypt_symbol, @TypeOf(&Spec.encryptFn), &Spec.encryptFn, .{
                &self.key,
                src.ptr,
                src.len,
                dst.ptr,
            });
        }

        pub fn decrypt(self: *Self, src: []const u8, dst: []u8) i32 {
            const sc_err = callScImpFn(imp, Spec.decrypt_symbol, @TypeOf(&Spec.decryptFn), &Spec.decryptFn, .{
                &self.key,
                src.ptr,
                src.len,
                dst.ptr,
            });
            return if (sc_err == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
        }
    };
}

/// Generic XTS-AES adapter for ImpSc / ImpScStatic / ImpScDynamic.
pub fn XtsImpAdapter(comptime imp: ImpKind, comptime Spec: type) type {
    return struct {
        const Self = @This();
        pub const imp_name = imp.name();
        pub const alg_name = Spec.alg_name;

        key: Spec.ExpandedKey = undefined,

        pub fn isAvailable() bool {
            return switch (imp) {
                .sc, .sc_static => true,
                .sc_dynamic => hasDynamicSymbol(Spec.expand_key_ex_symbol),
            };
        }

        pub fn setKey(self: *Self, key_bytes: []const u8, flags: u32) i32 {
            const key_ptr: [*]const u8 = if (key_bytes.len > 0) key_bytes.ptr else @ptrCast(&self.key);
            const sc_err = callScImpFn(imp, Spec.expand_key_ex_symbol, @TypeOf(&Spec.expandKeyExFn), &Spec.expandKeyExFn, .{
                &self.key,
                key_ptr,
                key_bytes.len,
                flags,
            });
            return if (sc_err == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
        }
    };
}
