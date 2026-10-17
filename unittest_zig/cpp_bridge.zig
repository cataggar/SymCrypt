// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const builtin = @import("builtin");
const sc = @import("sc_implementations.zig");
const asym = @import("cpp_bridge_asym.zig");
const env = @import("env_unittest.zig");
const mh = @import("main_harness.zig");
const rm = @import("result_merge.zig");
const perf = @import("perf.zig");
const pt = @import("printtable.zig");
const rng_mod = @import("rng.zig");
const ref_imp = @import("ref_implementations.zig");
const test_hash_mod = @import("test_hash.zig");
const types = @import("symcrypt_types");

const c_alloc = std.heap.c_allocator;

fn CommonHashState(comptime inputBlockSize: usize, comptime chainBytes: usize) type {
    return extern struct {
        bytesInBuffer: u32 align(16) = 0,
        magic: usize = 0,
        dataLengthL: u64 = 0,
        dataLengthH: u64 = 0,
        buffer: [inputBlockSize]u8 align(16) = @splat(0),
        chain: [chainBytes]u8 align(16) = @splat(0),
    };
}

pub const Category = enum {
    Hash,
    ParHash,
    Xof,
    CXof,
    Kmac,
    Mac,
    Kdf,
    BlockCipher,
    AuthEnc,
    StreamCipher,
    RngSp800_90,
    Xts,
    KeyWrap,
    TlsCbcHmac,
    RsaEnc,
    RsaSign,
    Dh,
    Dsa,
    Ecurve,
    Hbs,
    Kem,
    PqDsa,
    Hpke,
    PerfOnly,
};

pub const HashKind = enum {
    Md2,
    Md4,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
};

pub const HashState = struct {
    kind: HashKind = .Sha256,
    state1: [512]u8 align(64) = @splat(0),
    state2: [512]u8 align(64) = @splat(0),
    isReset: bool = false,
};

pub const ParHashKind = enum {
    ParSha256,
    ParSha384,
    ParSha512,
};

pub const ParHashState = struct {
    kind: ParHashKind = .ParSha256,
    nHashes: usize = 0,
    states_256: [32]CommonHashState(64, 32) align(64) = @splat(.{}),
    states_512: [32]CommonHashState(128, 64) align(64) = @splat(.{}),
};

pub const XofKind = enum {
    Shake128,
    Shake256,
};

pub const XofState = struct {
    kind: XofKind = .Shake128,
    state1: [512]u8 align(64) = @splat(0),
    state2: [512]u8 align(64) = @splat(0),
    isReset: bool = false,
};

pub const CXofState = struct {
    kind: XofKind = .Shake128,
    state1: [512]u8 align(64) = @splat(0),
    state2: [512]u8 align(64) = @splat(0),
    isReset: bool = false,
};

pub const KmacKind = enum {
    Kmac128,
    Kmac256,
};

pub const KmacState = struct {
    kind: KmacKind = .Kmac128,
    key1: [512]u8 align(64) = @splat(0),
    key2: [512]u8 align(64) = @splat(0),
    state1: [512]u8 align(64) = @splat(0),
    state2: [512]u8 align(64) = @splat(0),
    isReset: bool = false,
};

pub const MacKind = enum {
    HmacMd5,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha512_224,
    HmacSha512_256,
    HmacSha3_224,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    AesCmac,
    Poly1305,
    RefPoly1305,
    Marvin32,
};

pub const MacState = struct {
    kind: MacKind = .HmacSha256,
    key1: [1024]u8 align(64) = @splat(0),
    key2: [1024]u8 align(64) = @splat(0),
    state1: [512]u8 align(64) = @splat(0),
    state2: [512]u8 align(64) = @splat(0),
    ref_poly: ref_imp.REF_POLY1305_STATE = std.mem.zeroes(ref_imp.REF_POLY1305_STATE),
    isReset: bool = false,
    has_key: bool = false,
};

pub const KdfKind = enum {
    Pbkdf2,
    Sp800_108,
    TlsPrf1_1,
    TlsPrf1_2,
    Hkdf,
    SshKdf,
    SrtpKdf,
    SskdfMac,
    SskdfHash,
};

pub const KdfModeKind = enum {
    HmacMd5,
    HmacSha1,
    HmacSha224,
    HmacSha256,
    HmacSha384,
    HmacSha512,
    HmacSha512_224,
    HmacSha512_256,
    HmacSha3_224,
    HmacSha3_256,
    HmacSha3_384,
    HmacSha3_512,
    AesCmac,
    Kmac128,
    Kmac256,
    Md5,
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Shake128,
    Shake256,
    None,
};

pub const KdfState = struct {
    kind: KdfKind = .Hkdf,
    mode: KdfModeKind = .None,
};

pub const BcAlgKind = enum {
    Aes,
    Des,
    Des2,
    TripleDes,
    Desx,
    Rc2,
};

pub const BcModeKind = enum {
    Ecb,
    Cbc,
    Cfb,
    CtrMsb32,
    CtrMsb64,
    CtrLsb64,
};

pub const BcState = struct {
    alg: BcAlgKind = .Aes,
    mode: BcModeKind = .Ecb,
    cfbShiftParam: usize = 1,
    key1: [2048]u8 align(64) = @splat(0),
    key2: [2048]u8 align(64) = @splat(0),
};

pub const AuthEncKind = enum {
    Ccm,
    Gcm,
    ChaCha20Poly1305,
};

pub const AuthEncState = struct {
    kind: AuthEncKind = .Gcm,
    key: [4096]u8 align(64) = @splat(0),
    key2: [4096]u8 align(64) = @splat(0),
    key_bytes: [64]u8 = @splat(0),
    key_len: usize = 0,
    state1: [1024]u8 align(64) = @splat(0),
    state2: [1024]u8 align(64) = @splat(0),
    inComputation: bool = false,
    totalCbData: usize = 0,
};

pub const StreamKind = enum {
    Rc4,
    ChaCha20,
};

pub const StreamState = struct {
    kind: StreamKind = .Rc4,
    state1: [1024]u8 align(64) = @splat(0),
    state2: [1024]u8 align(64) = @splat(0),
    key_buf: [256]u8 = @splat(0),
    key_len: usize = 0,
    nonce_buf: [16]u8 = @splat(0),
};

pub const RngKind = enum {
    Drbg,
    F142,
    DynamicRandom,
};

pub const RngState = struct {
    kind: RngKind = .Drbg,
    state1: [1024]u8 align(64) = @splat(0),
    state2: [1024]u8 align(64) = @splat(0),
};

pub const XtsState = struct {
    key1: [2048]u8 align(64) = @splat(0),
    key2: [2048]u8 align(64) = @splat(0),
};

pub const KwKind = enum {
    AesKw,
    AesKwp,
};

pub const KwState = struct {
    kind: KwKind = .AesKw,
    key1: [1024]u8 align(64) = @splat(0),
    key2: [1024]u8 align(64) = @splat(0),
};

pub const TlsCbcHmacKind = enum {
    Sha1,
    Sha256,
    Sha384,
};

pub const TlsCbcHmacState = struct {
    kind: TlsCbcHmacKind = .Sha256,
};

pub const PerfInfoEntry = struct {
    keySize: usize,
    dataSize: usize,
    postfix: [64]u8 = @splat(0),
    postfix_len: usize = 0,
    cPerByte: f64,
    cOverhead: f64,
    cRange: f64,
};

pub const AlgImp = struct {
    algName: [:0]const u8,
    algorithm_name: [:0]const u8,
    modeName: [:0]const u8 = "",
    fullAlgName: [:0]const u8,
    impName: [:0]const u8,
    implementation_name: [:0]const u8,
    imp_kind: sc.ImpKind,
    category: Category,

    n_results: u64 = 0,
    n_error_disagree: u64 = 0,
    n_error_no_majority: u64 = 0,
    n_error_kat_failure: u64 = 0,

    perf_infos: std.ArrayListUnmanaged(PerfInfoEntry) = .empty,

    hash_state: HashState = .{},
    par_hash_state: ParHashState = .{},
    xof_state: XofState = .{},
    cxof_state: CXofState = .{},
    kmac_state: KmacState = .{},
    mac_state: MacState = .{},
    kdf_state: KdfState = .{},
    bc_state: BcState = .{},
    authenc_state: AuthEncState = .{},
    stream_state: StreamState = .{},
    rng_state: RngState = .{},
    xts_state: XtsState = .{},
    kw_state: KwState = .{},
    tls_cbc_hmac_state: TlsCbcHmacState = .{},

    rsa_state: asym.RsaState = .{},
    dl_state: asym.DlState = .{},
    hbs_state: asym.HbsState = .{},
    kem_state: asym.KemState = .{},
    pqdsa_state: asym.PqDsaState = .{},
    hpke_state: asym.HpkeState = .{},
    perf_only_tag: u32 = 0,
};

// ============================================================================
// Dynamic Symbol Dispatch Helpers
// ============================================================================

pub fn callSym(
    imp_kind: sc.ImpKind,
    sym_name: [*:0]const u8,
    comptime static_fn: anytype,
    args: anytype,
) @typeInfo(@TypeOf(static_fn)).@"fn".return_type.? {
    if (imp_kind == .sc_dynamic) {
        if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, sym_name, env.SCTEST_DYNSYM_FUNCTION_PTR)) |ptr| {
            const FnPtr = *const @TypeOf(static_fn);
            const fn_ptr: FnPtr = @ptrCast(@alignCast(ptr));
            return @call(.auto, fn_ptr, args);
        }
        std.debug.panic("Missing dynamic symbol: {s}", .{std.mem.span(sym_name)});
    }
    env.initVectorRegisters();
    const res = @call(.auto, static_fn, args);
    env.verifyVectorRegisters();
    return res;
}

pub fn getSymPtr(
    imp_kind: sc.ImpKind,
    sym_name: [*:0]const u8,
    static_ptr: *const anyopaque,
) ?*const anyopaque {
    if (imp_kind == .sc_dynamic) {
        if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, sym_name, env.SCTEST_DYNSYM_DATA_PTR)) |ptr| {
            return @ptrCast(@alignCast(ptr));
        }
        return null;
    }
    return static_ptr;
}

pub fn getSymArrayPtr(
    imp_kind: sc.ImpKind,
    sym_name: [*:0]const u8,
    static_ptr: *const anyopaque,
) ?*const anyopaque {
    if (imp_kind == .sc_dynamic) {
        if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, sym_name, env.SCTEST_DYNSYM_ARRAY)) |ptr| {
            return @ptrCast(@alignCast(ptr));
        }
        return null;
    }
    return static_ptr;
}

pub fn hasSym(sym_name: [*:0]const u8) bool {
    return env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, sym_name, env.SCTEST_DYNSYM_FUNCTION_PTR) != null;
}

pub export fn scTestLookupSymbolDynamic(symName: [*:0]const u8, symType: u32) callconv(.c) ?*anyopaque {
    return env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, symName, symType);
}

pub export fn scTestHasSymCryptSymbol(symName: [*:0]const u8) callconv(.c) c_int {
    return if (hasSym(symName)) 1 else 0;
}

// ============================================================================
// Global Registry
// ============================================================================

var g_algImps: std.ArrayListUnmanaged(*AlgImp) = .empty;
var g_stringsToFree: std.ArrayListUnmanaged([:0]u8) = .empty;

var g_measureSizesBuf: [256]u8 = @splat(0);
var g_measureSizesLen: usize = 0;

var g_dynamicModulePathBuf: [1024]u8 = @splat(0);
var g_dynamicModulePathLen: usize = 0;

fn allocZString(s: []const u8) [:0]const u8 {
    const buf = c_alloc.allocSentinel(u8, s.len, 0) catch @panic("OOM");
    @memcpy(buf[0..s.len], s);
    g_stringsToFree.append(c_alloc, buf) catch @panic("OOM");
    return buf;
}

fn createAlgImp(
    imp_kind: sc.ImpKind,
    category: Category,
    alg_name: [:0]const u8,
    mode_name: [:0]const u8,
) *AlgImp {
    const p = c_alloc.create(AlgImp) catch @panic("OOM");
    const imp_name = std.mem.span(imp_kind.nameZ());
    const full_name: [:0]const u8 = if (mode_name.len == 0)
        alg_name
    else blk: {
        var tmp: [256]u8 = undefined;
        const formatted = std.fmt.bufPrint(&tmp, "{s}{s}", .{ alg_name, mode_name }) catch @panic("OOM");
        break :blk allocZString(formatted);
    };
    p.* = .{
        .algName = alg_name,
        .algorithm_name = alg_name,
        .modeName = mode_name,
        .fullAlgName = full_name,
        .impName = imp_name,
        .implementation_name = imp_name,
        .imp_kind = imp_kind,
        .category = category,
    };
    g_algImps.append(c_alloc, p) catch @panic("OOM");
    return p;
}

pub fn maybeCreateAlgImp(
    imp_kind: sc.ImpKind,
    category: Category,
    alg_name: [:0]const u8,
    mode_name: [:0]const u8,
) ?*AlgImp {
    var full_buf: [256]u8 = undefined;
    const full = if (mode_name.len == 0)
        alg_name
    else
        std.fmt.bufPrint(&full_buf, "{s}{s}", .{ alg_name, mode_name }) catch @panic("OOM");
    if (!mh.isAlgFilterMatch(full) or !mh.isImpPresent(imp_kind.name())) return null;
    return createAlgImp(imp_kind, category, alg_name, mode_name);
}

pub fn getImpsByCategory(
    cat: Category,
    target_name: []const u8,
    outImps: [*]*anyopaque,
    maxImps: usize,
) usize {
    var count: usize = 0;
    for (g_algImps.items) |imp| {
        if (imp.category != cat) continue;
        if (target_name.len != 0 and !std.mem.eql(u8, imp.fullAlgName, target_name) and !std.mem.eql(u8, imp.algName, target_name)) continue;
        if (!mh.isImpPresent(imp.impName)) continue;
        if (count < maxImps) {
            outImps[count] = @ptrCast(imp);
            count += 1;
        }
    }
    return count;
}

pub fn getAllImpsByName(
    target_name: []const u8,
    outImps: [*]*anyopaque,
    maxImps: usize,
) usize {
    var count: usize = 0;
    for (g_algImps.items) |imp| {
        if (target_name.len != 0 and !std.mem.eql(u8, imp.fullAlgName, target_name) and !std.mem.eql(u8, imp.algName, target_name)) continue;
        if (!mh.isImpPresent(imp.impName)) continue;
        if (count < maxImps) {
            outImps[count] = @ptrCast(imp);
            count += 1;
        }
    }
    return count;
}

// ============================================================================
// Registration for Symmetric / Hash / KDF / MAC / RNG / XTS / KW / TLS
// ============================================================================

fn registerImpAlgs(imp_kind: sc.ImpKind) void {
    const hashes = [_]struct { name: [:0]const u8, kind: HashKind, init_sym: [*:0]const u8 }{
        .{ .name = "Md2", .kind = .Md2, .init_sym = "SymCryptMd2Init" },
        .{ .name = "Md4", .kind = .Md4, .init_sym = "SymCryptMd4Init" },
        .{ .name = "Md5", .kind = .Md5, .init_sym = "SymCryptMd5Init" },
        .{ .name = "Sha1", .kind = .Sha1, .init_sym = "SymCryptSha1Init" },
        .{ .name = "Sha224", .kind = .Sha224, .init_sym = "SymCryptSha224Init" },
        .{ .name = "Sha256", .kind = .Sha256, .init_sym = "SymCryptSha256Init" },
        .{ .name = "Sha384", .kind = .Sha384, .init_sym = "SymCryptSha384Init" },
        .{ .name = "Sha512", .kind = .Sha512, .init_sym = "SymCryptSha512Init" },
        .{ .name = "Sha512-224", .kind = .Sha512_224, .init_sym = "SymCryptSha512_224Init" },
        .{ .name = "Sha512-256", .kind = .Sha512_256, .init_sym = "SymCryptSha512_256Init" },
        .{ .name = "Sha3-224", .kind = .Sha3_224, .init_sym = "SymCryptSha3_224Init" },
        .{ .name = "Sha3-256", .kind = .Sha3_256, .init_sym = "SymCryptSha3_256Init" },
        .{ .name = "Sha3-384", .kind = .Sha3_384, .init_sym = "SymCryptSha3_384Init" },
        .{ .name = "Sha3-512", .kind = .Sha3_512, .init_sym = "SymCryptSha3_512Init" },
    };
    for (hashes) |h| {
        if (imp_kind == .sc_dynamic and !hasSym(h.init_sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .Hash, h.name, "")) |imp| {
            imp.hash_state.kind = h.kind;
        }
    }

    const par_hashes = [_]struct { name: [:0]const u8, kind: ParHashKind, sym: [*:0]const u8 }{
        .{ .name = "ParSha256", .kind = .ParSha256, .sym = "SymCryptParallelSha256Process" },
        .{ .name = "ParSha384", .kind = .ParSha384, .sym = "SymCryptParallelSha384Process" },
        .{ .name = "ParSha512", .kind = .ParSha512, .sym = "SymCryptParallelSha512Process" },
    };
    for (par_hashes) |ph| {
        if (imp_kind == .sc_dynamic and !hasSym(ph.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .ParHash, ph.name, "")) |imp| {
            imp.par_hash_state.kind = ph.kind;
        }
    }

    const xofs = [_]struct { name: [:0]const u8, kind: XofKind, sym: [*:0]const u8 }{
        .{ .name = "Shake128", .kind = .Shake128, .sym = "SymCryptShake128Init" },
        .{ .name = "Shake256", .kind = .Shake256, .sym = "SymCryptShake256Init" },
    };
    for (xofs) |x| {
        if (imp_kind == .sc_dynamic and !hasSym(x.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .Xof, x.name, "")) |imp| {
            imp.xof_state.kind = x.kind;
        }
    }

    const cxofs = [_]struct { name: [:0]const u8, kind: XofKind, sym: [*:0]const u8 }{
        .{ .name = "CShake128", .kind = .Shake128, .sym = "SymCryptCShake128Init" },
        .{ .name = "CShake256", .kind = .Shake256, .sym = "SymCryptCShake256Init" },
    };
    for (cxofs) |cx| {
        if (imp_kind == .sc_dynamic and !hasSym(cx.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .CXof, cx.name, "")) |imp| {
            imp.cxof_state.kind = cx.kind;
        }
    }

    const kmacs = [_]struct { name: [:0]const u8, kind: KmacKind, sym: [*:0]const u8 }{
        .{ .name = "Kmac128", .kind = .Kmac128, .sym = "SymCryptKmac128Init" },
        .{ .name = "Kmac256", .kind = .Kmac256, .sym = "SymCryptKmac256Init" },
    };
    for (kmacs) |km| {
        if (imp_kind == .sc_dynamic and !hasSym(km.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .Kmac, km.name, "")) |imp| {
            imp.kmac_state.kind = km.kind;
        }
    }

    const macs = [_]struct { name: [:0]const u8, kind: MacKind, sym: [*:0]const u8 }{
        .{ .name = "HmacMd5", .kind = .HmacMd5, .sym = "SymCryptHmacMd5Init" },
        .{ .name = "HmacSha1", .kind = .HmacSha1, .sym = "SymCryptHmacSha1Init" },
        .{ .name = "HmacSha224", .kind = .HmacSha224, .sym = "SymCryptHmacSha224Init" },
        .{ .name = "HmacSha256", .kind = .HmacSha256, .sym = "SymCryptHmacSha256Init" },
        .{ .name = "HmacSha384", .kind = .HmacSha384, .sym = "SymCryptHmacSha384Init" },
        .{ .name = "HmacSha512", .kind = .HmacSha512, .sym = "SymCryptHmacSha512Init" },
        .{ .name = "HmacSha512-224", .kind = .HmacSha512_224, .sym = "SymCryptHmacSha512_224Init" },
        .{ .name = "HmacSha512-256", .kind = .HmacSha512_256, .sym = "SymCryptHmacSha512_256Init" },
        .{ .name = "HmacSha3-224", .kind = .HmacSha3_224, .sym = "SymCryptHmacSha3_224Init" },
        .{ .name = "HmacSha3-256", .kind = .HmacSha3_256, .sym = "SymCryptHmacSha3_256Init" },
        .{ .name = "HmacSha3-384", .kind = .HmacSha3_384, .sym = "SymCryptHmacSha3_384Init" },
        .{ .name = "HmacSha3-512", .kind = .HmacSha3_512, .sym = "SymCryptHmacSha3_512Init" },
        .{ .name = "AesCmac", .kind = .AesCmac, .sym = "SymCryptAesCmacInit" },
        .{ .name = "Poly1305", .kind = .Poly1305, .sym = "SymCryptPoly1305Init" },
        .{ .name = "Marvin32", .kind = .Marvin32, .sym = "SymCryptMarvin32Init" },
    };
    for (macs) |m| {
        if (imp_kind == .sc_dynamic and !hasSym(m.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .Mac, m.name, "")) |imp| {
            imp.mac_state.kind = m.kind;
        }
    }

    const bc_algs = [_]struct { name: [:0]const u8, alg: BcAlgKind, sym: [*:0]const u8 }{
        .{ .name = "Aes", .alg = .Aes, .sym = "SymCryptAesExpandKey" },
        .{ .name = "Des", .alg = .Des, .sym = "SymCryptDesExpandKey" },
        .{ .name = "2Des", .alg = .Des2, .sym = "SymCrypt3DesExpandKey" },
        .{ .name = "3Des", .alg = .TripleDes, .sym = "SymCrypt3DesExpandKey" },
        .{ .name = "Desx", .alg = .Desx, .sym = "SymCryptDesxExpandKey" },
        .{ .name = "Rc2", .alg = .Rc2, .sym = "SymCryptRc2ExpandKey" },
    };
    const bc_modes = [_]struct { name: [:0]const u8, mode: BcModeKind }{
        .{ .name = "Ecb", .mode = .Ecb },
        .{ .name = "Cbc", .mode = .Cbc },
        .{ .name = "Cfb", .mode = .Cfb },
        .{ .name = "CtrMsb32", .mode = .CtrMsb32 },
        .{ .name = "CtrMsb64", .mode = .CtrMsb64 },
        .{ .name = "CtrLsb64", .mode = .CtrLsb64 },
    };
    for (bc_algs) |ba| {
        if (imp_kind == .sc_dynamic and !hasSym(ba.sym)) continue;
        for (bc_modes) |bm| {
            // In sc_imp_pattern.cpp, CtrMsb32/CtrMsb64/CtrLsb64 are commented out; only Ecb, Cbc, Cfb are registered
            if (bm.mode != .Ecb and bm.mode != .Cbc and bm.mode != .Cfb) continue;
            if (maybeCreateAlgImp(imp_kind, .BlockCipher, ba.name, bm.name)) |imp| {
                imp.bc_state.alg = ba.alg;
                imp.bc_state.mode = bm.mode;
                imp.bc_state.cfbShiftParam = 1;
            }
        }
    }

    const authencs = [_]struct { name: [:0]const u8, mode: [:0]const u8, kind: AuthEncKind, sym: [*:0]const u8 }{
        .{ .name = "Aes", .mode = "Ccm", .kind = .Ccm, .sym = "SymCryptCcmInit" },
        .{ .name = "Aes", .mode = "Gcm", .kind = .Gcm, .sym = "SymCryptGcmInit" },
        .{ .name = "ChaCha20Poly1305", .mode = "", .kind = .ChaCha20Poly1305, .sym = "SymCryptChaCha20Poly1305Encrypt" },
    };
    for (authencs) |ae| {
        if (imp_kind == .sc_dynamic and !hasSym(ae.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .AuthEnc, ae.name, ae.mode)) |imp| {
            imp.authenc_state.kind = ae.kind;
        }
    }

    const streams = [_]struct { name: [:0]const u8, kind: StreamKind, sym: [*:0]const u8 }{
        .{ .name = "Rc4", .kind = .Rc4, .sym = "SymCryptRc4Init" },
        .{ .name = "ChaCha20", .kind = .ChaCha20, .sym = "SymCryptChaCha20Init" },
    };
    for (streams) |st| {
        if (imp_kind == .sc_dynamic and !hasSym(st.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .StreamCipher, st.name, "")) |imp| {
            imp.stream_state.kind = st.kind;
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptRngAesInstantiate")) {
        if (maybeCreateAlgImp(imp_kind, .RngSp800_90, "AesCtrDrbg", "")) |imp| {
            imp.rng_state.kind = .Drbg;
        }
    }
    if (imp_kind != .sc_dynamic or hasSym("SymCryptRngAesFips140_2Instantiate")) {
        if (maybeCreateAlgImp(imp_kind, .RngSp800_90, "AesCtrF142", "")) |imp| {
            imp.rng_state.kind = .F142;
        }
    }
    if (imp_kind == .sc_dynamic and hasSym("SymCryptRandom")) {
        if (maybeCreateAlgImp(imp_kind, .RngSp800_90, "DynamicRandom", "")) |imp| {
            imp.rng_state.kind = .DynamicRandom;
        }
    }

    // KDFs
    const kdf_mac_modes = [_]struct { name: [:0]const u8, mode: KdfModeKind }{
        .{ .name = "HmacMd5", .mode = .HmacMd5 },
        .{ .name = "HmacSha1", .mode = .HmacSha1 },
        .{ .name = "HmacSha224", .mode = .HmacSha224 },
        .{ .name = "HmacSha256", .mode = .HmacSha256 },
        .{ .name = "HmacSha384", .mode = .HmacSha384 },
        .{ .name = "HmacSha512", .mode = .HmacSha512 },
        .{ .name = "HmacSha512-224", .mode = .HmacSha512_224 },
        .{ .name = "HmacSha512-256", .mode = .HmacSha512_256 },
        .{ .name = "HmacSha3-224", .mode = .HmacSha3_224 },
        .{ .name = "HmacSha3-256", .mode = .HmacSha3_256 },
        .{ .name = "HmacSha3-384", .mode = .HmacSha3_384 },
        .{ .name = "HmacSha3-512", .mode = .HmacSha3_512 },
        .{ .name = "AesCmac", .mode = .AesCmac },
    };
    const kdf_hash_modes = [_]struct { name: [:0]const u8, mode: KdfModeKind }{
        .{ .name = "Md5", .mode = .Md5 },
        .{ .name = "Sha1", .mode = .Sha1 },
        .{ .name = "Sha224", .mode = .Sha224 },
        .{ .name = "Sha256", .mode = .Sha256 },
        .{ .name = "Sha384", .mode = .Sha384 },
        .{ .name = "Sha512", .mode = .Sha512 },
        .{ .name = "Sha512-224", .mode = .Sha512_224 },
        .{ .name = "Sha512-256", .mode = .Sha512_256 },
        .{ .name = "Sha3-224", .mode = .Sha3_224 },
        .{ .name = "Sha3-256", .mode = .Sha3_256 },
        .{ .name = "Sha3-384", .mode = .Sha3_384 },
        .{ .name = "Sha3-512", .mode = .Sha3_512 },
        .{ .name = "Shake128", .mode = .Shake128 },
        .{ .name = "Shake256", .mode = .Shake256 },
    };

    const mac_kdf_algs = [_]struct { name: [:0]const u8, kind: KdfKind, sym: [*:0]const u8 }{
        .{ .name = "Pbkdf2", .kind = .Pbkdf2, .sym = "SymCryptPbkdf2" },
        .{ .name = "Sp800_108", .kind = .Sp800_108, .sym = "SymCryptSp800_108" },
        .{ .name = "TlsPrf1_2", .kind = .TlsPrf1_2, .sym = "SymCryptTlsPrf1_2" },
        .{ .name = "Hkdf", .kind = .Hkdf, .sym = "SymCryptHkdf" },
    };
    for (mac_kdf_algs) |ka| {
        if (imp_kind == .sc_dynamic and !hasSym(ka.sym)) continue;
        for (kdf_mac_modes) |km| {
            if (ka.kind == .TlsPrf1_2 and (km.mode == .HmacMd5 or km.mode == .AesCmac)) continue;
            if (ka.kind == .Hkdf and km.mode == .AesCmac) continue;
            if (getMacStruct(imp_kind, km.mode) == null) continue;
            if (maybeCreateAlgImp(imp_kind, .Kdf, ka.name, km.name)) |imp| {
                imp.kdf_state.kind = ka.kind;
                imp.kdf_state.mode = km.mode;
            }
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptTlsPrf1_1")) {
        if (maybeCreateAlgImp(imp_kind, .Kdf, "TlsPrf1_1", "HmacMd5")) |imp| {
            imp.kdf_state.kind = .TlsPrf1_1;
            imp.kdf_state.mode = .HmacMd5;
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptSshKdf")) {
        for (kdf_hash_modes) |hm| {
            if (hm.mode != .Sha1 and hm.mode != .Sha256 and hm.mode != .Sha384 and hm.mode != .Sha512) continue;
            if (getHashStruct(imp_kind, hm.mode) == null) continue;
            if (maybeCreateAlgImp(imp_kind, .Kdf, "SshKdf", hm.name)) |imp| {
                imp.kdf_state.kind = .SshKdf;
                imp.kdf_state.mode = hm.mode;
            }
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptSrtpKdf")) {
        if (maybeCreateAlgImp(imp_kind, .Kdf, "SrtpKdf", "Aes")) |imp| {
            imp.kdf_state.kind = .SrtpKdf;
            imp.kdf_state.mode = .None;
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptSskdfMac")) {
        const sskdf_mac_modes = [_]struct { name: [:0]const u8, mode: KdfModeKind }{
            .{ .name = "HmacSha1", .mode = .HmacSha1 },
            .{ .name = "HmacSha224", .mode = .HmacSha224 },
            .{ .name = "HmacSha256", .mode = .HmacSha256 },
            .{ .name = "HmacSha384", .mode = .HmacSha384 },
            .{ .name = "HmacSha512", .mode = .HmacSha512 },
            .{ .name = "HmacSha512-224", .mode = .HmacSha512_224 },
            .{ .name = "HmacSha512-256", .mode = .HmacSha512_256 },
            .{ .name = "HmacSha3-224", .mode = .HmacSha3_224 },
            .{ .name = "HmacSha3-256", .mode = .HmacSha3_256 },
            .{ .name = "HmacSha3-384", .mode = .HmacSha3_384 },
            .{ .name = "HmacSha3-512", .mode = .HmacSha3_512 },
            .{ .name = "Kmac128", .mode = .Kmac128 },
            .{ .name = "Kmac256", .mode = .Kmac256 },
        };
        for (sskdf_mac_modes) |sm| {
            if (getMacStruct(imp_kind, sm.mode) == null) continue;
            if (maybeCreateAlgImp(imp_kind, .Kdf, "SskdfMac", sm.name)) |imp| {
                imp.kdf_state.kind = .SskdfMac;
                imp.kdf_state.mode = sm.mode;
            }
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptSskdfHash")) {
        for (kdf_hash_modes) |hm| {
            if (getHashStruct(imp_kind, hm.mode) == null) continue;
            if (maybeCreateAlgImp(imp_kind, .Kdf, "SskdfHash", hm.name)) |imp| {
                imp.kdf_state.kind = .SskdfHash;
                imp.kdf_state.mode = hm.mode;
            }
        }
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptXtsAesExpandKey")) {
        _ = maybeCreateAlgImp(imp_kind, .Xts, "XtsAes", "");
    }

    if (imp_kind != .sc_dynamic or hasSym("SymCryptAesKwEncrypt")) {
        if (maybeCreateAlgImp(imp_kind, .KeyWrap, "AesKw", "")) |imp| {
            imp.kw_state.kind = .AesKw;
        }
    }
    if (imp_kind != .sc_dynamic or hasSym("SymCryptAesKwpEncrypt")) {
        if (maybeCreateAlgImp(imp_kind, .KeyWrap, "AesKwp", "")) |imp| {
            imp.kw_state.kind = .AesKwp;
        }
    }

    const tls_cbc_modes = [_]struct { name: [:0]const u8, kind: TlsCbcHmacKind, sym: [*:0]const u8 }{
        .{ .name = "TlsCbcHmacSha1", .kind = .Sha1, .sym = "SymCryptTlsCbcHmacVerify" },
        .{ .name = "TlsCbcHmacSha256", .kind = .Sha256, .sym = "SymCryptTlsCbcHmacVerify" },
        .{ .name = "TlsCbcHmacSha384", .kind = .Sha384, .sym = "SymCryptTlsCbcHmacVerify" },
    };
    for (tls_cbc_modes) |tm| {
        if (imp_kind == .sc_dynamic and !hasSym(tm.sym)) continue;
        if (maybeCreateAlgImp(imp_kind, .TlsCbcHmac, tm.name, "")) |imp| {
            imp.tls_cbc_hmac_state.kind = tm.kind;
        }
    }

    asym.registerAsymAlgs(imp_kind);
}

pub export fn addAllAlgs() callconv(.c) void {
    if (mh.isImpPresent("SymCrypt")) {
        registerImpAlgs(.sc);
    }
    if (g_dynamicModulePathLen > 0 and mh.isImpPresent("SymCryptDynamic")) {
        registerImpAlgs(.sc_dynamic);
    }
    if (mh.isImpPresent("Ref")) {
        if (mh.isAlgFilterMatch("Poly1305")) {
            const p = c_alloc.create(AlgImp) catch @panic("OOM");
            p.* = .{
                .algName = "Poly1305",
                .algorithm_name = "Poly1305",
                .modeName = "",
                .fullAlgName = "Poly1305",
                .impName = "Ref",
                .implementation_name = "Ref",
                .imp_kind = .sc,
                .category = .Mac,
                .mac_state = .{ .kind = .RefPoly1305 },
            };
            g_algImps.append(c_alloc, p) catch @panic("OOM");
        }
    }
}

pub export fn scTestClearAndFreeAlgImps() callconv(.c) void {
    for (g_algImps.items) |imp| {
        imp.perf_infos.deinit(c_alloc);
        asym.deinitAsymAlgImp(imp);
        c_alloc.destroy(imp);
    }
    g_algImps.deinit(c_alloc);
    g_algImps = .empty;

    for (g_stringsToFree.items) |s| {
        c_alloc.free(s);
    }
    g_stringsToFree.deinit(c_alloc);
    g_stringsToFree = .empty;
}

pub export fn scTestGetNumImplementations() callconv(.c) usize {
    return g_algImps.items.len;
}

pub export fn scTestGetImplementation(idx: usize) callconv(.c) ?*anyopaque {
    if (idx >= g_algImps.items.len) return null;
    return @ptrCast(g_algImps.items[idx]);
}

pub export fn scTestIsAlgorithmPresent(name_ptr: [*]const u8, name_len: usize, isPrefix: u32) callconv(.c) u32 {
    const target = name_ptr[0..name_len];
    for (g_algImps.items) |imp| {
        if (std.mem.eql(u8, imp.algName, target) or (isPrefix != 0 and std.mem.startsWith(u8, imp.algName, target))) {
            return 1;
        }
    }
    return 0;
}

pub export fn scTestAlgImpName(pImp: *const anyopaque) callconv(.c) [*:0]const u8 {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return imp.impName.ptr;
}

pub export fn scTestAlgImpAlgorithmName(pImp: *const anyopaque) callconv(.c) [*:0]const u8 {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return imp.algName.ptr;
}

pub export fn scTestAlgImpModeName(pImp: *const anyopaque) callconv(.c) [*:0]const u8 {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return imp.modeName.ptr;
}

pub export fn scTestAlgImpFullName(pImp: *const anyopaque) callconv(.c) [*:0]const u8 {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return imp.fullAlgName.ptr;
}

pub export fn scTestAlgImpAddErrorKatFailure(pImp: *anyopaque, delta: u64) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    imp.n_error_kat_failure += delta;
}

pub export fn scTestAlgImpIncKatFailure(pAlgImp: *anyopaque, delta: u64) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pAlgImp));
    imp.n_error_kat_failure += delta;
}

pub export fn scTestResultMergeAddAlgImp(
    resMergeHandle: ?*anyopaque,
    pAlgImp: *anyopaque,
    pbData: [*]const u8,
    cbData: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pAlgImp));
    rm.scTestResultMergeAddResult(
        resMergeHandle,
        pAlgImp,
        imp.impName.ptr,
        imp.algName.ptr,
        &imp.n_results,
        &imp.n_error_disagree,
        &imp.n_error_no_majority,
        pbData,
        cbData,
    );
}

pub export fn scTestSummarizeFunctionalResults(pTotalErrors: *u64) callconv(.c) void {
    const numResults = pt.scTestPrintTableCreate();
    defer pt.scTestPrintTableDestroy(numResults);
    const numErrors = pt.scTestPrintTableCreate();
    defer pt.scTestPrintTableDestroy(numErrors);

    var total_errors: u64 = 0;
    for (g_algImps.items) |imp| {
        const alg = imp.fullAlgName;
        const imp_name = imp.impName;
        pt.scTestPrintTableAddItemNonZero(numResults, alg.ptr, alg.len, imp_name.ptr, imp_name.len, imp.n_results);
        pt.scTestPrintTableAddItemNonZero(numErrors, alg.ptr, alg.len, imp_name.ptr, imp_name.len, imp.n_error_disagree);
        pt.scTestPrintTableAddItemNonZero(numErrors, "no-maj", 6, imp_name.ptr, imp_name.len, imp.n_error_no_majority);
        pt.scTestPrintTableAddItemNonZero(numErrors, alg.ptr, alg.len, "KAT Failure", 11, imp.n_error_kat_failure);
        total_errors += imp.n_error_disagree + imp.n_error_no_majority + imp.n_error_kat_failure;
    }
    pt.scTestPrintTablePrint(numResults, "Number of verified results", 26);
    if (total_errors > 0) {
        pt.scTestPrintTablePrint(numErrors, "NUMBER OF ERRORS", 16);
    }
    pTotalErrors.* += total_errors;
}

extern fn testWipe() callconv(.c) void;
extern fn testScsTable() callconv(.c) void;
extern fn testScsTools() callconv(.c) void;
extern fn testPaddingPkcs7() callconv(.c) void;

extern fn testDataAccessors() callconv(.c) void;
extern fn testHashAlgorithms() callconv(.c) void;
extern fn testBlockCipherAlgorithms() callconv(.c) void;
extern fn testKeyWrapAlgorithms() callconv(.c) void;
extern fn testMacAlgorithms() callconv(.c) void;
extern fn testXofAlgorithms() callconv(.c) void;
extern fn testCustomizableXofAlgorithms() callconv(.c) void;
extern fn testKmacAlgorithms() callconv(.c) void;
extern fn testStreamCipherAlgorithms() callconv(.c) void;
extern fn testKdfAlgorithms() callconv(.c) void;
extern fn testAuthEncAlgorithms() callconv(.c) void;
extern fn testAesCtrDrbg() callconv(.c) void;
extern fn testXtsAlgorithms() callconv(.c) void;
extern fn testTlsCbcHmacAlgorithms() callconv(.c) void;
extern fn testArithmetic() callconv(.c) void;
extern fn testRsaSignAlgorithms() callconv(.c) void;
extern fn testRsaEncAlgorithms() callconv(.c) void;
extern fn testDhAlgorithms() callconv(.c) void;
extern fn testDsaAlgorithms() callconv(.c) void;
extern fn testEcc() callconv(.c) void;
extern fn testHbs() callconv(.c) void;
extern fn testKem() callconv(.c) void;
extern fn testHpke() callconv(.c) void;
extern fn testPqDsa() callconv(.c) void;
extern fn testCompositeHelpers() callconv(.c) void;
extern fn testEcEncoding() callconv(.c) void;

extern fn testStatusIndicator(printIndicator: c_int) callconv(.c) void;
extern fn testServiceIndicator() callconv(.c) void;

pub export fn scTestCheckAsmOffsets() callconv(.c) void {}

pub export fn scTestRunSingleLayerCppTests() callconv(.c) void {
    testWipe();
    testScsTable();
    testScsTools();
    testPaddingPkcs7();
}

pub export fn scTestRunMultiImpCppTests() callconv(.c) void {
    testDataAccessors();
    testHashAlgorithms();
    testBlockCipherAlgorithms();
    testKeyWrapAlgorithms();
    testMacAlgorithms();
    testXofAlgorithms();
    testCustomizableXofAlgorithms();
    testKmacAlgorithms();
    testStreamCipherAlgorithms();
    testKdfAlgorithms();
    testAuthEncAlgorithms();
    testAesCtrDrbg();
    testXtsAlgorithms();
    testTlsCbcHmacAlgorithms();
    testArithmetic();
    testRsaSignAlgorithms();
    testRsaEncAlgorithms();
    testDhAlgorithms();
    testDsaAlgorithms();
    testEcc();
    testHbs();
    testKem();
    testHpke();
    testPqDsa();
    testCompositeHelpers();
    testEcEncoding();
}

pub export fn scTestRunStatusAndServiceIndicatorTests(printIndicator: u32) callconv(.c) void {
    testStatusIndicator(@intCast(printIndicator));
    testServiceIndicator();
}

pub export fn scTestRunPerfTestsCpp() callconv(.c) void {
    perf.measurePerf();
}

const Timespec = extern struct {
    sec: isize = 0,
    nsec: isize = 0,
};
extern fn clock_gettime(clk_id: c_int, tp: *Timespec) callconv(.c) c_int;

pub export fn scTestGetPerfClock() callconv(.c) u64 {
    var ts: Timespec = .{};
    _ = clock_gettime(1, &ts);
    return @as(u64, @intCast(@max(0, ts.sec))) * 1_000_000_000 + @as(u64, @intCast(@max(0, ts.nsec)));
}

pub export fn scTestIsImpToTest(impNamePtr: [*]const u8, impNameLen: usize) callconv(.c) c_int {
    return if (mh.isImpPresent(impNamePtr[0..impNameLen])) 1 else 0;
}

pub export fn scTestGetAlgImpCount() callconv(.c) usize {
    return g_algImps.items.len;
}

pub export fn scTestGetAlgImpAt(idx: usize) callconv(.c) *anyopaque {
    return @ptrCast(g_algImps.items[idx]);
}

pub export fn scTestAlgImpGetAlgName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    outPtr.* = imp.algName.ptr;
    return imp.algName.len;
}

pub export fn scTestAlgImpGetModeName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    outPtr.* = imp.modeName.ptr;
    return imp.modeName.len;
}

pub export fn scTestAlgImpGetImpName(pImp: *anyopaque, outPtr: *[*]const u8) callconv(.c) usize {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    outPtr.* = imp.impName.ptr;
    return imp.impName.len;
}

pub export fn scTestAlgImpGetPerfFunctions(
    pImp: *anyopaque,
    pKeySizeSupported: *?perf.PerfKeySizeSupportedFn,
    pKeyFn: *?perf.PerfKeyFn,
    pDataFn: *?perf.PerfDataFn,
    pDecryptFn: *?perf.PerfDataFn,
    pCleanFn: *?perf.PerfCleanFn,
) callconv(.c) void {
    _ = pImp;
    pKeySizeSupported.* = null;
    pKeyFn.* = null;
    pDataFn.* = null;
    pDecryptFn.* = null;
    pCleanFn.* = null;
}

pub export fn scTestAlgImpAddPerfInfo(
    pImp: *anyopaque,
    keySize: usize,
    dataSize: usize,
    strPostfixPtr: [*]const u8,
    strPostfixLen: usize,
    cPerByte: f64,
    cOverhead: f64,
    cRange: f64,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    var entry = PerfInfoEntry{
        .keySize = keySize,
        .dataSize = dataSize,
        .cPerByte = cPerByte,
        .cOverhead = cOverhead,
        .cRange = cRange,
    };
    const copy_len = @min(strPostfixLen, entry.postfix.len);
    @memcpy(entry.postfix[0..copy_len], strPostfixPtr[0..copy_len]);
    entry.postfix_len = copy_len;
    imp.perf_infos.append(c_alloc, entry) catch @panic("OOM");
}

pub export fn scTestAlgImpGetPerfInfoCount(pImp: *anyopaque) callconv(.c) usize {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    return imp.perf_infos.items.len;
}

pub export fn scTestAlgImpGetPerfInfoAt(
    pImp: *anyopaque,
    idx: usize,
    pKeySize: *usize,
    pDataSize: *usize,
    outPostfixPtr: *[*]const u8,
    outPostfixLen: *usize,
    pCpb: *f64,
    pOverhead: *f64,
    pRange: *f64,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const entry = &imp.perf_infos.items[idx];
    pKeySize.* = entry.keySize;
    pDataSize.* = entry.dataSize;
    outPostfixPtr.* = &entry.postfix;
    outPostfixLen.* = entry.postfix_len;
    pCpb.* = entry.cPerByte;
    pOverhead.* = entry.cOverhead;
    pRange.* = entry.cRange;
}

pub export fn scTestGetMeasureSizesStringPrefix(outPtr: *[*]const u8) callconv(.c) usize {
    outPtr.* = &g_measureSizesBuf;
    return g_measureSizesLen;
}

extern fn getrandom(buf: [*]u8, buflen: usize, flags: c_uint) callconv(.c) isize;
extern fn arc4random_buf(buf: *anyopaque, nbytes: usize) callconv(.c) void;

pub export fn scTestGenRandom(pbBuf: [*]u8, cbBuf: usize) callconv(.c) c_int {
    if (comptime builtin.os.tag.isDarwin()) {
        arc4random_buf(pbBuf, cbBuf);
        return 0;
    } else {
        var offset: usize = 0;
        while (offset < cbBuf) {
            const rc = getrandom(pbBuf + offset, cbBuf - offset, 0);
            if (rc <= 0) return -1;
            offset += @intCast(rc);
        }
        return 0;
    }
}

const PthreadMutex = extern struct {
    data: [64]u8 align(8) = @splat(0),
};
extern fn pthread_mutex_init(mutex: *PthreadMutex, attr: ?*const anyopaque) callconv(.c) c_int;
extern fn pthread_mutex_destroy(mutex: *PthreadMutex) callconv(.c) c_int;
extern fn pthread_mutex_lock(mutex: *PthreadMutex) callconv(.c) c_int;
extern fn pthread_mutex_unlock(mutex: *PthreadMutex) callconv(.c) c_int;
extern fn usleep(usec: c_uint) callconv(.c) c_int;

pub export fn scTestAllocateFastInprocMutex() callconv(.c) ?*anyopaque {
    const m = c_alloc.create(PthreadMutex) catch return null;
    m.* = .{};
    _ = pthread_mutex_init(m, null);
    return m;
}

pub export fn scTestFreeFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void {
    const m: *PthreadMutex = @ptrCast(@alignCast(pMutex orelse return));
    _ = pthread_mutex_destroy(m);
    c_alloc.destroy(m);
}

pub export fn scTestAcquireFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void {
    const m: *PthreadMutex = @ptrCast(@alignCast(pMutex orelse return));
    _ = pthread_mutex_lock(m);
}

pub export fn scTestReleaseFastInprocMutex(pMutex: ?*anyopaque) callconv(.c) void {
    const m: *PthreadMutex = @ptrCast(@alignCast(pMutex orelse return));
    _ = pthread_mutex_unlock(m);
}

pub export fn scTestSleepMs(ms: u32) callconv(.c) void {
    _ = usleep(ms * 1000);
}

pub export fn scTestSetMeasureSizesPrefix(ptr: [*]const u8, len: usize) callconv(.c) void {
    const copy_len = @min(len, g_measureSizesBuf.len);
    @memcpy(g_measureSizesBuf[0..copy_len], ptr[0..copy_len]);
    g_measureSizesLen = copy_len;
}

pub export fn scTestGetMeasureSizesPrefix(out_len: *usize) callconv(.c) [*]const u8 {
    out_len.* = g_measureSizesLen;
    return &g_measureSizesBuf;
}

pub export fn scTestSetDynamicModulePath(ptr: [*]const u8, len: usize) callconv(.c) void {
    const copy_len = @min(len, g_dynamicModulePathBuf.len - 1);
    @memcpy(g_dynamicModulePathBuf[0..copy_len], ptr[0..copy_len]);
    g_dynamicModulePathBuf[copy_len] = 0;
    g_dynamicModulePathLen = copy_len;
}

pub export fn scTestGetDynamicModulePath() callconv(.c) ?[*:0]const u8 {
    if (g_dynamicModulePathLen == 0) return null;
    return @ptrCast(&g_dynamicModulePathBuf);
}

// ============================================================================
// Struct Offset & Scratch Helper Exports
// ============================================================================

pub export fn scTestEcurveGOrdDigits(pCurve: ?*const anyopaque) callconv(.c) u32 {
    const curve: *const types.SYMCRYPT_ECURVE = @ptrCast(@alignCast(pCurve.?));
    return curve.GOrdDigits;
}

pub export fn scTestEcurveScratchCommon(pCurve: ?*const anyopaque) callconv(.c) u32 {
    const curve: *const types.SYMCRYPT_ECURVE = @ptrCast(@alignCast(pCurve.?));
    return types.SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS(curve);
}

pub export fn scTestEcurveScratchScalar(pCurve: ?*const anyopaque) callconv(.c) u32 {
    const curve: *const types.SYMCRYPT_ECURVE = @ptrCast(@alignCast(pCurve.?));
    return types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(curve, 1);
}

pub export fn scTestEcurveScratchMultiScalar(pCurve: ?*const anyopaque, nPoints: u32) callconv(.c) u32 {
    const curve: *const types.SYMCRYPT_ECURVE = @ptrCast(@alignCast(pCurve.?));
    return types.SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS(curve, nPoints);
}

pub export fn scTestEcurveScratchGetSetValue(pCurve: ?*const anyopaque) callconv(.c) u32 {
    const curve: *const types.SYMCRYPT_ECURVE = @ptrCast(@alignCast(pCurve.?));
    return types.SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS(curve);
}

pub export fn scTestEckeyGetPublicKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque {
    const key: *const types.SYMCRYPT_ECKEY = @ptrCast(@alignCast(pkEckey.?));
    return @ptrCast(key.poPublicKey);
}

pub export fn scTestEckeyGetPrivateKey(pkEckey: ?*const anyopaque) callconv(.c) ?*anyopaque {
    const key: *const types.SYMCRYPT_ECKEY = @ptrCast(@alignCast(pkEckey.?));
    return @ptrCast(key.piPrivateKey);
}

// ============================================================================
// Hash Implementations
// ============================================================================

fn hashResultLen(kind: HashKind) usize {
    return switch (kind) {
        .Md2, .Md4, .Md5 => 16,
        .Sha1 => 20,
        .Sha224, .Sha512_224, .Sha3_224 => 28,
        .Sha256, .Sha512_256, .Sha3_256 => 32,
        .Sha384, .Sha3_384 => 48,
        .Sha512, .Sha3_512 => 64,
    };
}

fn hashInputBlockLen(kind: HashKind) usize {
    return switch (kind) {
        .Md2 => 16,
        .Md4, .Md5, .Sha1, .Sha224, .Sha256 => 64,
        .Sha384, .Sha512, .Sha512_224, .Sha512_256 => 128,
        .Sha3_224 => 144,
        .Sha3_256 => 136,
        .Sha3_384 => 104,
        .Sha3_512 => 72,
    };
}

fn hashStateSize(kind: HashKind) usize {
    return switch (kind) {
        .Md2 => 96,
        .Md4, .Md5 => 96,
        .Sha1 => 96,
        .Sha224, .Sha256 => 112,
        .Sha384, .Sha512, .Sha512_224, .Sha512_256 => 208,
        .Sha3_224, .Sha3_256, .Sha3_384, .Sha3_512 => 224,
    };
}

fn hashExportBlobSize(kind: HashKind) usize {
    return switch (kind) {
        .Md2 => sc.SYMCRYPT_MD2_STATE_EXPORT_SIZE,
        .Md4 => sc.SYMCRYPT_MD4_STATE_EXPORT_SIZE,
        .Md5 => sc.SYMCRYPT_MD5_STATE_EXPORT_SIZE,
        .Sha1 => sc.SYMCRYPT_SHA1_STATE_EXPORT_SIZE,
        .Sha224 => sc.SYMCRYPT_SHA224_STATE_EXPORT_SIZE,
        .Sha256 => sc.SYMCRYPT_SHA256_STATE_EXPORT_SIZE,
        .Sha384 => sc.SYMCRYPT_SHA384_STATE_EXPORT_SIZE,
        .Sha512 => sc.SYMCRYPT_SHA512_STATE_EXPORT_SIZE,
        .Sha512_224 => sc.SYMCRYPT_SHA512_224_STATE_EXPORT_SIZE,
        .Sha512_256 => sc.SYMCRYPT_SHA512_256_STATE_EXPORT_SIZE,
        .Sha3_224 => sc.SYMCRYPT_SHA3_224_STATE_EXPORT_SIZE,
        .Sha3_256 => sc.SYMCRYPT_SHA3_256_STATE_EXPORT_SIZE,
        .Sha3_384 => sc.SYMCRYPT_SHA3_384_STATE_EXPORT_SIZE,
        .Sha3_512 => sc.SYMCRYPT_SHA3_512_STATE_EXPORT_SIZE,
    };
}

pub export fn scTestGetHashImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Hash, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestHashImpResultLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return hashResultLen(imp.hash_state.kind);
}

pub export fn scTestHashImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return hashInputBlockLen(imp.hash_state.kind);
}

fn doHashInit(ik: sc.ImpKind, kind: HashKind, state_ptr: *anyopaque) void {
    switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2Init", sc.SymCryptMd2Init, .{state_ptr}),
        .Md4 => callSym(ik, "SymCryptMd4Init", sc.SymCryptMd4Init, .{state_ptr}),
        .Md5 => callSym(ik, "SymCryptMd5Init", sc.SymCryptMd5Init, .{state_ptr}),
        .Sha1 => callSym(ik, "SymCryptSha1Init", sc.SymCryptSha1Init, .{state_ptr}),
        .Sha224 => callSym(ik, "SymCryptSha224Init", sc.SymCryptSha224Init, .{state_ptr}),
        .Sha256 => callSym(ik, "SymCryptSha256Init", sc.SymCryptSha256Init, .{state_ptr}),
        .Sha384 => callSym(ik, "SymCryptSha384Init", sc.SymCryptSha384Init, .{state_ptr}),
        .Sha512 => callSym(ik, "SymCryptSha512Init", sc.SymCryptSha512Init, .{state_ptr}),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224Init", sc.SymCryptSha512_224Init, .{state_ptr}),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256Init", sc.SymCryptSha512_256Init, .{state_ptr}),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224Init", sc.SymCryptSha3_224Init, .{state_ptr}),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256Init", sc.SymCryptSha3_256Init, .{state_ptr}),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384Init", sc.SymCryptSha3_384Init, .{state_ptr}),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512Init", sc.SymCryptSha3_512Init, .{state_ptr}),
    }
}

fn doHashAppend(ik: sc.ImpKind, kind: HashKind, state_ptr: *anyopaque, pbData: ?[*]const u8, cbData: usize) void {
    switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2Append", sc.SymCryptMd2Append, .{ state_ptr, pbData, cbData }),
        .Md4 => callSym(ik, "SymCryptMd4Append", sc.SymCryptMd4Append, .{ state_ptr, pbData, cbData }),
        .Md5 => callSym(ik, "SymCryptMd5Append", sc.SymCryptMd5Append, .{ state_ptr, pbData, cbData }),
        .Sha1 => callSym(ik, "SymCryptSha1Append", sc.SymCryptSha1Append, .{ state_ptr, pbData, cbData }),
        .Sha224 => callSym(ik, "SymCryptSha224Append", sc.SymCryptSha224Append, .{ state_ptr, pbData, cbData }),
        .Sha256 => callSym(ik, "SymCryptSha256Append", sc.SymCryptSha256Append, .{ state_ptr, pbData, cbData }),
        .Sha384 => callSym(ik, "SymCryptSha384Append", sc.SymCryptSha384Append, .{ state_ptr, pbData, cbData }),
        .Sha512 => callSym(ik, "SymCryptSha512Append", sc.SymCryptSha512Append, .{ state_ptr, pbData, cbData }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224Append", sc.SymCryptSha512_224Append, .{ state_ptr, pbData, cbData }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256Append", sc.SymCryptSha512_256Append, .{ state_ptr, pbData, cbData }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224Append", sc.SymCryptSha3_224Append, .{ state_ptr, pbData, cbData }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256Append", sc.SymCryptSha3_256Append, .{ state_ptr, pbData, cbData }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384Append", sc.SymCryptSha3_384Append, .{ state_ptr, pbData, cbData }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512Append", sc.SymCryptSha3_512Append, .{ state_ptr, pbData, cbData }),
    }
}

fn doHashResult(ik: sc.ImpKind, kind: HashKind, state_ptr: *anyopaque, pbResult: [*]u8) void {
    switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2Result", sc.SymCryptMd2Result, .{ state_ptr, pbResult }),
        .Md4 => callSym(ik, "SymCryptMd4Result", sc.SymCryptMd4Result, .{ state_ptr, pbResult }),
        .Md5 => callSym(ik, "SymCryptMd5Result", sc.SymCryptMd5Result, .{ state_ptr, pbResult }),
        .Sha1 => callSym(ik, "SymCryptSha1Result", sc.SymCryptSha1Result, .{ state_ptr, pbResult }),
        .Sha224 => callSym(ik, "SymCryptSha224Result", sc.SymCryptSha224Result, .{ state_ptr, pbResult }),
        .Sha256 => callSym(ik, "SymCryptSha256Result", sc.SymCryptSha256Result, .{ state_ptr, pbResult }),
        .Sha384 => callSym(ik, "SymCryptSha384Result", sc.SymCryptSha384Result, .{ state_ptr, pbResult }),
        .Sha512 => callSym(ik, "SymCryptSha512Result", sc.SymCryptSha512Result, .{ state_ptr, pbResult }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224Result", sc.SymCryptSha512_224Result, .{ state_ptr, pbResult }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256Result", sc.SymCryptSha512_256Result, .{ state_ptr, pbResult }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224Result", sc.SymCryptSha3_224Result, .{ state_ptr, pbResult }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256Result", sc.SymCryptSha3_256Result, .{ state_ptr, pbResult }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384Result", sc.SymCryptSha3_384Result, .{ state_ptr, pbResult }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512Result", sc.SymCryptSha3_512Result, .{ state_ptr, pbResult }),
    }
}

fn doHashStateCopy(ik: sc.ImpKind, kind: HashKind, src_ptr: *const anyopaque, dst_ptr: *anyopaque) void {
    switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2StateCopy", sc.SymCryptMd2StateCopy, .{ src_ptr, dst_ptr }),
        .Md4 => callSym(ik, "SymCryptMd4StateCopy", sc.SymCryptMd4StateCopy, .{ src_ptr, dst_ptr }),
        .Md5 => callSym(ik, "SymCryptMd5StateCopy", sc.SymCryptMd5StateCopy, .{ src_ptr, dst_ptr }),
        .Sha1 => callSym(ik, "SymCryptSha1StateCopy", sc.SymCryptSha1StateCopy, .{ src_ptr, dst_ptr }),
        .Sha224 => callSym(ik, "SymCryptSha224StateCopy", sc.SymCryptSha224StateCopy, .{ src_ptr, dst_ptr }),
        .Sha256 => callSym(ik, "SymCryptSha256StateCopy", sc.SymCryptSha256StateCopy, .{ src_ptr, dst_ptr }),
        .Sha384 => callSym(ik, "SymCryptSha384StateCopy", sc.SymCryptSha384StateCopy, .{ src_ptr, dst_ptr }),
        .Sha512 => callSym(ik, "SymCryptSha512StateCopy", sc.SymCryptSha512StateCopy, .{ src_ptr, dst_ptr }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224StateCopy", sc.SymCryptSha512_224StateCopy, .{ src_ptr, dst_ptr }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256StateCopy", sc.SymCryptSha512_256StateCopy, .{ src_ptr, dst_ptr }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224StateCopy", sc.SymCryptSha3_224StateCopy, .{ src_ptr, dst_ptr }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256StateCopy", sc.SymCryptSha3_256StateCopy, .{ src_ptr, dst_ptr }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384StateCopy", sc.SymCryptSha3_384StateCopy, .{ src_ptr, dst_ptr }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512StateCopy", sc.SymCryptSha3_512StateCopy, .{ src_ptr, dst_ptr }),
    }
}

fn doHashStateExport(ik: sc.ImpKind, kind: HashKind, state_ptr: *const anyopaque, pbBlob: [*]u8) void {
    switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2StateExport", sc.SymCryptMd2StateExport, .{ state_ptr, pbBlob }),
        .Md4 => callSym(ik, "SymCryptMd4StateExport", sc.SymCryptMd4StateExport, .{ state_ptr, pbBlob }),
        .Md5 => callSym(ik, "SymCryptMd5StateExport", sc.SymCryptMd5StateExport, .{ state_ptr, pbBlob }),
        .Sha1 => callSym(ik, "SymCryptSha1StateExport", sc.SymCryptSha1StateExport, .{ state_ptr, pbBlob }),
        .Sha224 => callSym(ik, "SymCryptSha224StateExport", sc.SymCryptSha224StateExport, .{ state_ptr, pbBlob }),
        .Sha256 => callSym(ik, "SymCryptSha256StateExport", sc.SymCryptSha256StateExport, .{ state_ptr, pbBlob }),
        .Sha384 => callSym(ik, "SymCryptSha384StateExport", sc.SymCryptSha384StateExport, .{ state_ptr, pbBlob }),
        .Sha512 => callSym(ik, "SymCryptSha512StateExport", sc.SymCryptSha512StateExport, .{ state_ptr, pbBlob }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224StateExport", sc.SymCryptSha512_224StateExport, .{ state_ptr, pbBlob }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256StateExport", sc.SymCryptSha512_256StateExport, .{ state_ptr, pbBlob }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224StateExport", sc.SymCryptSha3_224StateExport, .{ state_ptr, pbBlob }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256StateExport", sc.SymCryptSha3_256StateExport, .{ state_ptr, pbBlob }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384StateExport", sc.SymCryptSha3_384StateExport, .{ state_ptr, pbBlob }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512StateExport", sc.SymCryptSha3_512StateExport, .{ state_ptr, pbBlob }),
    }
}

fn doHashStateImport(ik: sc.ImpKind, kind: HashKind, state_ptr: *anyopaque, pbBlob: [*]const u8) u32 {
    return switch (kind) {
        .Md2 => callSym(ik, "SymCryptMd2StateImport", sc.SymCryptMd2StateImport, .{ state_ptr, pbBlob }),
        .Md4 => callSym(ik, "SymCryptMd4StateImport", sc.SymCryptMd4StateImport, .{ state_ptr, pbBlob }),
        .Md5 => callSym(ik, "SymCryptMd5StateImport", sc.SymCryptMd5StateImport, .{ state_ptr, pbBlob }),
        .Sha1 => callSym(ik, "SymCryptSha1StateImport", sc.SymCryptSha1StateImport, .{ state_ptr, pbBlob }),
        .Sha224 => callSym(ik, "SymCryptSha224StateImport", sc.SymCryptSha224StateImport, .{ state_ptr, pbBlob }),
        .Sha256 => callSym(ik, "SymCryptSha256StateImport", sc.SymCryptSha256StateImport, .{ state_ptr, pbBlob }),
        .Sha384 => callSym(ik, "SymCryptSha384StateImport", sc.SymCryptSha384StateImport, .{ state_ptr, pbBlob }),
        .Sha512 => callSym(ik, "SymCryptSha512StateImport", sc.SymCryptSha512StateImport, .{ state_ptr, pbBlob }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224StateImport", sc.SymCryptSha512_224StateImport, .{ state_ptr, pbBlob }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256StateImport", sc.SymCryptSha512_256StateImport, .{ state_ptr, pbBlob }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224StateImport", sc.SymCryptSha3_224StateImport, .{ state_ptr, pbBlob }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256StateImport", sc.SymCryptSha3_256StateImport, .{ state_ptr, pbBlob }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384StateImport", sc.SymCryptSha3_384StateImport, .{ state_ptr, pbBlob }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512StateImport", sc.SymCryptSha3_512StateImport, .{ state_ptr, pbBlob }),
    };
}

pub export fn scTestHashImpInit(pImp: *anyopaque) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    if (!hs.isReset or (rng_mod.g_rng.uint32() & 1) == 0) {
        doHashInit(ik, hs.kind, &hs.state1);
        doHashStateCopy(ik, hs.kind, &hs.state1, &hs.state2);
    }
    hs.isReset = true;
}

pub export fn scTestHashImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    doHashAppend(ik, hs.kind, &hs.state1, pbData, cbData);
    doHashAppend(ik, hs.kind, &hs.state2, pbData, cbData);
    hs.isReset = false;
}

pub export fn scTestHashImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    const rlen = hashResultLen(hs.kind);
    std.debug.assert(cbResult == rlen);
    var buf2: [128]u8 = undefined;
    doHashResult(ik, hs.kind, &hs.state1, pbResult);
    doHashResult(ik, hs.kind, &hs.state2, &buf2);
    if (!std.mem.eql(u8, pbResult[0..rlen], buf2[0..rlen])) {
        @panic("State copy error in HashImpResult");
    }
    hs.isReset = true;
}

pub export fn scTestHashImpHash(
    pImp: *anyopaque,
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    const rlen = hashResultLen(hs.kind);
    std.debug.assert(cbResult == rlen);
    switch (hs.kind) {
        .Md2 => callSym(ik, "SymCryptMd2", sc.SymCryptMd2, .{ pbData, cbData, pbResult }),
        .Md4 => callSym(ik, "SymCryptMd4", sc.SymCryptMd4, .{ pbData, cbData, pbResult }),
        .Md5 => callSym(ik, "SymCryptMd5", sc.SymCryptMd5, .{ pbData, cbData, pbResult }),
        .Sha1 => callSym(ik, "SymCryptSha1", sc.SymCryptSha1, .{ pbData, cbData, pbResult }),
        .Sha224 => callSym(ik, "SymCryptSha224", sc.SymCryptSha224, .{ pbData, cbData, pbResult }),
        .Sha256 => callSym(ik, "SymCryptSha256", sc.SymCryptSha256, .{ pbData, cbData, pbResult }),
        .Sha384 => callSym(ik, "SymCryptSha384", sc.SymCryptSha384, .{ pbData, cbData, pbResult }),
        .Sha512 => callSym(ik, "SymCryptSha512", sc.SymCryptSha512, .{ pbData, cbData, pbResult }),
        .Sha512_224 => callSym(ik, "SymCryptSha512_224", sc.SymCryptSha512_224, .{ pbData, cbData, pbResult }),
        .Sha512_256 => callSym(ik, "SymCryptSha512_256", sc.SymCryptSha512_256, .{ pbData, cbData, pbResult }),
        .Sha3_224 => callSym(ik, "SymCryptSha3_224", sc.SymCryptSha3_224, .{ pbData, cbData, pbResult }),
        .Sha3_256 => callSym(ik, "SymCryptSha3_256", sc.SymCryptSha3_256, .{ pbData, cbData, pbResult }),
        .Sha3_384 => callSym(ik, "SymCryptSha3_384", sc.SymCryptSha3_384, .{ pbData, cbData, pbResult }),
        .Sha3_512 => callSym(ik, "SymCryptSha3_512", sc.SymCryptSha3_512, .{ pbData, cbData, pbResult }),
    }
}

pub export fn scTestHashImpInitWithLongMessage(pImp: *anyopaque, nBytes: u64) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    if (ik == .sc_dynamic) return sc.STATUS_NOT_SUPPORTED;
    if (hs.kind == .Sha3_224 or hs.kind == .Sha3_256 or hs.kind == .Sha3_384 or hs.kind == .Sha3_512) {
        return sc.STATUS_NOT_SUPPORTED;
    }
    doHashInit(ik, hs.kind, &hs.state1);
    switch (hs.kind) {
        .Md2 => {
            const st: *CommonHashState(16, 48) = @ptrCast(@alignCast(&hs.state1));
            @memset(&st.chain, 'b');
            st.dataLengthL = nBytes;
            st.dataLengthH = 0;
            st.bytesInBuffer = @intCast(nBytes % 16);
        },
        .Md4, .Md5 => {
            const st: *CommonHashState(64, 16) = @ptrCast(@alignCast(&hs.state1));
            @memset(&st.chain, 'b');
            st.dataLengthL = nBytes;
            st.dataLengthH = 0;
            st.bytesInBuffer = @intCast(nBytes % 64);
        },
        .Sha1 => {
            const st: *CommonHashState(64, 20) = @ptrCast(@alignCast(&hs.state1));
            @memset(&st.chain, 'b');
            st.dataLengthL = nBytes;
            st.dataLengthH = 0;
            st.bytesInBuffer = @intCast(nBytes % 64);
        },
        .Sha224, .Sha256 => {
            const st: *CommonHashState(64, 32) = @ptrCast(@alignCast(&hs.state1));
            @memset(&st.chain, 'b');
            st.dataLengthL = nBytes;
            st.dataLengthH = 0;
            st.bytesInBuffer = @intCast(nBytes % 64);
        },
        .Sha384, .Sha512, .Sha512_224, .Sha512_256 => {
            const st: *CommonHashState(128, 64) = @ptrCast(@alignCast(&hs.state1));
            @memset(&st.chain, 'b');
            st.dataLengthL = nBytes;
            st.dataLengthH = 0;
            st.bytesInBuffer = @intCast(nBytes % 128);
        },
        .Sha3_224, .Sha3_256, .Sha3_384, .Sha3_512 => return sc.STATUS_NOT_SUPPORTED,
    }
    doHashStateCopy(ik, hs.kind, &hs.state1, &hs.state2);
    hs.isReset = false;
    return sc.STATUS_SUCCESS;
}

pub export fn scTestHashImpExportSymCryptFormat(
    pImp: *anyopaque,
    pbResult: [*]u8,
    cbResultBufferSize: usize,
    pcbResult: *usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const hs = &imp.hash_state;
    const ik = imp.imp_kind;
    const export_size = hashExportBlobSize(hs.kind);
    std.debug.assert(cbResultBufferSize >= export_size);
    var blob: [512]u8 = @splat(0);
    doHashStateExport(ik, hs.kind, &hs.state1, &blob);
    @memcpy(pbResult[0..export_size], blob[0..export_size]);
    pcbResult.* = export_size;
    _ = doHashStateImport(ik, hs.kind, &hs.state2, &blob);
    return sc.STATUS_SUCCESS;
}

// ============================================================================
// ParallelHash Implementations
// ============================================================================

pub export fn scTestGetParallelHashImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.ParHash, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestParHashImpResultLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.par_hash_state.kind) {
        .ParSha256 => 32,
        .ParSha384 => 48,
        .ParSha512 => 64,
    };
}

pub export fn scTestParHashImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.par_hash_state.kind) {
        .ParSha256 => 64,
        .ParSha384, .ParSha512 => 128,
    };
}

pub export fn scTestParHashImpSymCryptHash(pImp: *const anyopaque) callconv(.c) ?*const anyopaque {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    const ik = imp.imp_kind;
    return switch (imp.par_hash_state.kind) {
        .ParSha256 => getSymPtr(ik, "SymCryptSha256Algorithm", sc.SymCryptSha256Algorithm),
        .ParSha384 => getSymPtr(ik, "SymCryptSha384Algorithm", sc.SymCryptSha384Algorithm),
        .ParSha512 => getSymPtr(ik, "SymCryptSha512Algorithm", sc.SymCryptSha512Algorithm),
    };
}

const MAX_PARALLEL_HASH_STATES: usize = 32;

pub export fn scTestParHashImpInit(pImp: *anyopaque, nHashes: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ph = &imp.par_hash_state;
    const ik = imp.imp_kind;
    mh.check(nHashes <= MAX_PARALLEL_HASH_STATES, "Too many hash states requested");
    ph.nHashes = nHashes;
    switch (ph.kind) {
        .ParSha256 => callSym(ik, "SymCryptParallelSha256Init", sc.SymCryptParallelSha256Init, .{ @as(*anyopaque, @ptrCast(&ph.states_256[0])), nHashes }),
        .ParSha384 => callSym(ik, "SymCryptParallelSha384Init", sc.SymCryptParallelSha384Init, .{ @as(*anyopaque, @ptrCast(&ph.states_512[0])), nHashes }),
        .ParSha512 => callSym(ik, "SymCryptParallelSha512Init", sc.SymCryptParallelSha512Init, .{ @as(*anyopaque, @ptrCast(&ph.states_512[0])), nHashes }),
    }
}

const BcryptMultiHashOp = extern struct {
    iHash: u32,
    hashOperation: u32,
    pbBuffer: [*]u8,
    cbBuffer: u32,
};

const SymCryptParallelHashOperation = extern struct {
    iHash: u32,
    hashOperation: u32,
    pbBuffer: [*]u8,
    cbBuffer: usize,
};

const BCRYPT_HASH_OPERATION_HASH_DATA: u32 = 1;
const SYMCRYPT_HASH_OPERATION_APPEND: u32 = 1;
const SYMCRYPT_HASH_OPERATION_RESULT: u32 = 2;
const MAX_PARALLEL_HASH_OPERATIONS: usize = 512;

pub export fn scTestParHashImpProcess(
    pImp: *anyopaque,
    pOperations: [*]const BcryptMultiHashOp,
    nOperations: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ph = &imp.par_hash_state;
    const ik = imp.imp_kind;

    mh.check(nOperations <= MAX_PARALLEL_HASH_OPERATIONS, "Too many operations");
    var ops: [MAX_PARALLEL_HASH_OPERATIONS]SymCryptParallelHashOperation = undefined;
    for (0..nOperations) |i| {
        ops[i] = .{
            .iHash = pOperations[i].iHash,
            .hashOperation = if (pOperations[i].hashOperation == BCRYPT_HASH_OPERATION_HASH_DATA) SYMCRYPT_HASH_OPERATION_APPEND else SYMCRYPT_HASH_OPERATION_RESULT,
            .pbBuffer = pOperations[i].pbBuffer,
            .cbBuffer = pOperations[i].cbBuffer,
        };
        mh.check(ops[i].iHash < ph.nHashes, "?");
    }

    var scratch: [32768]u8 align(64) = @splat(0);
    const scratchOffset = rng_mod.g_rng.sizet(64);
    const nScratch = switch (ph.kind) {
        .ParSha256 => 2048 + ph.nHashes * 256,
        .ParSha384, .ParSha512 => 4096 + ph.nHashes * 384,
    };
    const scError = switch (ph.kind) {
        .ParSha256 => callSym(ik, "SymCryptParallelSha256Process", sc.SymCryptParallelSha256Process, .{
            @as(*anyopaque, @ptrCast(&ph.states_256[0])),
            ph.nHashes,
            @as(*const anyopaque, @ptrCast(&ops[0])),
            nOperations,
            scratch[scratchOffset..].ptr,
            nScratch,
        }),
        .ParSha384 => callSym(ik, "SymCryptParallelSha384Process", sc.SymCryptParallelSha384Process, .{
            @as(*anyopaque, @ptrCast(&ph.states_512[0])),
            ph.nHashes,
            @as(*const anyopaque, @ptrCast(&ops[0])),
            nOperations,
            scratch[scratchOffset..].ptr,
            nScratch,
        }),
        .ParSha512 => callSym(ik, "SymCryptParallelSha512Process", sc.SymCryptParallelSha512Process, .{
            @as(*anyopaque, @ptrCast(&ph.states_512[0])),
            ph.nHashes,
            @as(*const anyopaque, @ptrCast(&ops[0])),
            nOperations,
            scratch[scratchOffset..].ptr,
            nScratch,
        }),
    };
    mh.check(scError == sc.SYMCRYPT_NO_ERROR, "Parallel SHA Process returned an error");
}

pub export fn scTestParHashImpInitWithLongMessage(pImp: *anyopaque, nBytes: u64) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ph = &imp.par_hash_state;
    if (imp.imp_kind == .sc_dynamic) return sc.STATUS_NOT_SUPPORTED;
    switch (ph.kind) {
        .ParSha256 => {
            mh.check(nBytes % 64 == 0, "Odd bytes in initWithLongMessage");
            for (0..ph.nHashes) |i| {
                @memset(&ph.states_256[i].chain, 'b');
                ph.states_256[i].dataLengthL = nBytes;
                ph.states_256[i].dataLengthH = 0;
                ph.states_256[i].bytesInBuffer = 0;
            }
        },
        .ParSha384, .ParSha512 => {
            mh.check(nBytes % 128 == 0, "Odd bytes in initWithLongMessage");
            for (0..ph.nHashes) |i| {
                @memset(&ph.states_512[i].chain, 'b');
                ph.states_512[i].dataLengthL = nBytes;
                ph.states_512[i].dataLengthH = 0;
                ph.states_512[i].bytesInBuffer = 0;
            }
        },
    }
    return sc.STATUS_SUCCESS;
}

// ============================================================================
// XOF, CustomizableXof, Kmac Implementations
// ============================================================================

pub export fn scTestGetXofImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Xof, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestXofImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.xof_state.kind) {
        .Shake128 => 168,
        .Shake256 => 136,
    };
}

pub export fn scTestXofImpInit(pImp: *anyopaque) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xof_state;
    const ik = imp.imp_kind;
    switch (xs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptShake128Init", sc.SymCryptShake128Init, .{&xs.state1});
            callSym(ik, "SymCryptShake128StateCopy", sc.SymCryptShake128StateCopy, .{ &xs.state1, &xs.state2 });
        },
        .Shake256 => {
            callSym(ik, "SymCryptShake256Init", sc.SymCryptShake256Init, .{&xs.state1});
            callSym(ik, "SymCryptShake256StateCopy", sc.SymCryptShake256StateCopy, .{ &xs.state1, &xs.state2 });
        },
    }
    xs.isReset = true;
}

pub export fn scTestXofImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xof_state;
    const ik = imp.imp_kind;
    switch (xs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptShake128Append", sc.SymCryptShake128Append, .{ &xs.state1, pbData, cbData });
            callSym(ik, "SymCryptShake128Append", sc.SymCryptShake128Append, .{ &xs.state2, pbData, cbData });
        },
        .Shake256 => {
            callSym(ik, "SymCryptShake256Append", sc.SymCryptShake256Append, .{ &xs.state1, pbData, cbData });
            callSym(ik, "SymCryptShake256Append", sc.SymCryptShake256Append, .{ &xs.state2, pbData, cbData });
        },
    }
    xs.isReset = false;
}

pub export fn scTestXofImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void {
    scTestXofImpExtract(pImp, pbResult, cbResult, 1);
}

pub export fn scTestXofImpExtract(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u32) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xof_state;
    const ik = imp.imp_kind;
    const wipe: u8 = if (bWipe != 0) 1 else 0;
    const buf2 = c_alloc.alloc(u8, @max(cbResult, 1)) catch @panic("OOM");
    defer c_alloc.free(buf2);
    switch (xs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptShake128Extract", sc.SymCryptShake128Extract, .{ &xs.state1, pbResult, cbResult, wipe });
            callSym(ik, "SymCryptShake128Extract", sc.SymCryptShake128Extract, .{ &xs.state2, buf2.ptr, cbResult, wipe });
        },
        .Shake256 => {
            callSym(ik, "SymCryptShake256Extract", sc.SymCryptShake256Extract, .{ &xs.state1, pbResult, cbResult, wipe });
            callSym(ik, "SymCryptShake256Extract", sc.SymCryptShake256Extract, .{ &xs.state2, buf2.ptr, cbResult, wipe });
        },
    }
    if (!std.mem.eql(u8, pbResult[0..cbResult], buf2[0..cbResult])) @panic("XOF state mismatch");
    xs.isReset = (bWipe != 0);
}

pub export fn scTestXofImpXof(
    pImp: *anyopaque,
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void {
    scTestXofImpInit(pImp);
    scTestXofImpAppend(pImp, pbData, cbData);
    scTestXofImpExtract(pImp, pbResult, cbResult, 1);
}

pub export fn scTestGetCustomizableXofImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.CXof, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestCXofImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.cxof_state.kind) {
        .Shake128 => 168,
        .Shake256 => 136,
    };
}

pub export fn scTestCXofImpInit(
    pImp: *anyopaque,
    pbN: ?[*]const u8,
    cbN: usize,
    pbS: ?[*]const u8,
    cbS: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const cxs = &imp.cxof_state;
    const ik = imp.imp_kind;
    switch (cxs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptCShake128Init", sc.SymCryptCShake128Init, .{ &cxs.state1, pbN, cbN, pbS, cbS });
            callSym(ik, "SymCryptCShake128StateCopy", sc.SymCryptCShake128StateCopy, .{ &cxs.state1, &cxs.state2 });
        },
        .Shake256 => {
            callSym(ik, "SymCryptCShake256Init", sc.SymCryptCShake256Init, .{ &cxs.state1, pbN, cbN, pbS, cbS });
            callSym(ik, "SymCryptCShake256StateCopy", sc.SymCryptCShake256StateCopy, .{ &cxs.state1, &cxs.state2 });
        },
    }
    cxs.isReset = (cbN == 0 and cbS == 0);
}

pub export fn scTestCXofImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const cxs = &imp.cxof_state;
    const ik = imp.imp_kind;
    switch (cxs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptCShake128Append", sc.SymCryptCShake128Append, .{ &cxs.state1, pbData, cbData });
            callSym(ik, "SymCryptCShake128Append", sc.SymCryptCShake128Append, .{ &cxs.state2, pbData, cbData });
        },
        .Shake256 => {
            callSym(ik, "SymCryptCShake256Append", sc.SymCryptCShake256Append, .{ &cxs.state1, pbData, cbData });
            callSym(ik, "SymCryptCShake256Append", sc.SymCryptCShake256Append, .{ &cxs.state2, pbData, cbData });
        },
    }
    cxs.isReset = false;
}

pub export fn scTestCXofImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void {
    scTestCXofImpExtract(pImp, pbResult, cbResult, 1);
}

pub export fn scTestCXofImpExtract(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u32) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const cxs = &imp.cxof_state;
    const ik = imp.imp_kind;
    const wipe: u8 = if (bWipe != 0) 1 else 0;
    const buf2 = c_alloc.alloc(u8, @max(cbResult, 1)) catch @panic("OOM");
    defer c_alloc.free(buf2);
    switch (cxs.kind) {
        .Shake128 => {
            callSym(ik, "SymCryptCShake128Extract", sc.SymCryptCShake128Extract, .{ &cxs.state1, pbResult, cbResult, wipe });
            callSym(ik, "SymCryptCShake128Extract", sc.SymCryptCShake128Extract, .{ &cxs.state2, buf2.ptr, cbResult, wipe });
        },
        .Shake256 => {
            callSym(ik, "SymCryptCShake256Extract", sc.SymCryptCShake256Extract, .{ &cxs.state1, pbResult, cbResult, wipe });
            callSym(ik, "SymCryptCShake256Extract", sc.SymCryptCShake256Extract, .{ &cxs.state2, buf2.ptr, cbResult, wipe });
        },
    }
    if (!std.mem.eql(u8, pbResult[0..cbResult], buf2[0..cbResult])) @panic("CXOF state mismatch");
    cxs.isReset = (bWipe != 0);
}

pub export fn scTestCXofImpXof(
    pImp: *anyopaque,
    pbN: ?[*]const u8,
    cbN: usize,
    pbS: ?[*]const u8,
    cbS: usize,
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const cxs = &imp.cxof_state;
    const ik = imp.imp_kind;
    switch (cxs.kind) {
        .Shake128 => callSym(ik, "SymCryptCShake128", sc.SymCryptCShake128, .{ pbN, cbN, pbS, cbS, pbData, cbData, pbResult, cbResult }),
        .Shake256 => callSym(ik, "SymCryptCShake256", sc.SymCryptCShake256, .{ pbN, cbN, pbS, cbS, pbData, cbData, pbResult, cbResult }),
    }
}

pub export fn scTestGetKmacImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Kmac, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestKmacImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.kmac_state.kind) {
        .Kmac128 => 168,
        .Kmac256 => 136,
    };
}

pub export fn scTestKmacImpInit(
    pImp: *anyopaque,
    pbS: ?[*]const u8,
    cbS: usize,
    pbKey: ?[*]const u8,
    cbKey: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ks = &imp.kmac_state;
    const ik = imp.imp_kind;
    switch (ks.kind) {
        .Kmac128 => {
            _ = callSym(ik, "SymCryptKmac128ExpandKeyEx", sc.SymCryptKmac128ExpandKeyEx, .{ &ks.key1, pbKey, cbKey, pbS, cbS });
            callSym(ik, "SymCryptKmac128KeyCopy", sc.SymCryptKmac128KeyCopy, .{ &ks.key1, &ks.key2 });
            callSym(ik, "SymCryptKmac128Init", sc.SymCryptKmac128Init, .{ &ks.state1, &ks.key1 });
            callSym(ik, "SymCryptKmac128StateCopy", sc.SymCryptKmac128StateCopy, .{ &ks.state1, &ks.key2, &ks.state2 });
        },
        .Kmac256 => {
            _ = callSym(ik, "SymCryptKmac256ExpandKeyEx", sc.SymCryptKmac256ExpandKeyEx, .{ &ks.key1, pbKey, cbKey, pbS, cbS });
            callSym(ik, "SymCryptKmac256KeyCopy", sc.SymCryptKmac256KeyCopy, .{ &ks.key1, &ks.key2 });
            callSym(ik, "SymCryptKmac256Init", sc.SymCryptKmac256Init, .{ &ks.state1, &ks.key1 });
            callSym(ik, "SymCryptKmac256StateCopy", sc.SymCryptKmac256StateCopy, .{ &ks.state1, &ks.key2, &ks.state2 });
        },
    }
    ks.isReset = true;
}

pub export fn scTestKmacImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ks = &imp.kmac_state;
    const ik = imp.imp_kind;
    switch (ks.kind) {
        .Kmac128 => {
            callSym(ik, "SymCryptKmac128Append", sc.SymCryptKmac128Append, .{ &ks.state1, pbData, cbData });
            callSym(ik, "SymCryptKmac128Append", sc.SymCryptKmac128Append, .{ &ks.state2, pbData, cbData });
        },
        .Kmac256 => {
            callSym(ik, "SymCryptKmac256Append", sc.SymCryptKmac256Append, .{ &ks.state1, pbData, cbData });
            callSym(ik, "SymCryptKmac256Append", sc.SymCryptKmac256Append, .{ &ks.state2, pbData, cbData });
        },
    }
    ks.isReset = false;
}

pub export fn scTestKmacImpResult(pImp: *anyopaque, pbOutput: [*]u8, cbOutput: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ks = &imp.kmac_state;
    const ik = imp.imp_kind;
    const buf2 = c_alloc.alloc(u8, @max(cbOutput, 1)) catch @panic("OOM");
    defer c_alloc.free(buf2);
    switch (ks.kind) {
        .Kmac128 => {
            callSym(ik, "SymCryptKmac128ResultEx", sc.SymCryptKmac128ResultEx, .{ &ks.state1, pbOutput, cbOutput });
            callSym(ik, "SymCryptKmac128ResultEx", sc.SymCryptKmac128ResultEx, .{ &ks.state2, buf2.ptr, cbOutput });
        },
        .Kmac256 => {
            callSym(ik, "SymCryptKmac256ResultEx", sc.SymCryptKmac256ResultEx, .{ &ks.state1, pbOutput, cbOutput });
            callSym(ik, "SymCryptKmac256ResultEx", sc.SymCryptKmac256ResultEx, .{ &ks.state2, buf2.ptr, cbOutput });
        },
    }
    if (!std.mem.eql(u8, pbOutput[0..cbOutput], buf2[0..cbOutput])) @panic("KMAC state mismatch");
    ks.isReset = true;
}

pub export fn scTestKmacImpExtract(pImp: *anyopaque, pbOutput: [*]u8, cbOutput: usize, bWipe: u32) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ks = &imp.kmac_state;
    const ik = imp.imp_kind;
    const wipe: u8 = if (bWipe != 0) 1 else 0;
    const buf2 = c_alloc.alloc(u8, @max(cbOutput, 1)) catch @panic("OOM");
    defer c_alloc.free(buf2);
    switch (ks.kind) {
        .Kmac128 => {
            callSym(ik, "SymCryptKmac128Extract", sc.SymCryptKmac128Extract, .{ &ks.state1, pbOutput, cbOutput, wipe });
            callSym(ik, "SymCryptKmac128Extract", sc.SymCryptKmac128Extract, .{ &ks.state2, buf2.ptr, cbOutput, wipe });
        },
        .Kmac256 => {
            callSym(ik, "SymCryptKmac256Extract", sc.SymCryptKmac256Extract, .{ &ks.state1, pbOutput, cbOutput, wipe });
            callSym(ik, "SymCryptKmac256Extract", sc.SymCryptKmac256Extract, .{ &ks.state2, buf2.ptr, cbOutput, wipe });
        },
    }
    if (!std.mem.eql(u8, pbOutput[0..cbOutput], buf2[0..cbOutput])) @panic("KMAC extract mismatch");
    ks.isReset = (bWipe != 0);
}

pub export fn scTestKmacImpMac(
    pImp: *anyopaque,
    pbS: ?[*]const u8,
    cbS: usize,
    pbKey: ?[*]const u8,
    cbKey: usize,
    pbData: ?[*]const u8,
    cbData: usize,
    pbOutput: [*]u8,
    cbOutput: usize,
) callconv(.c) void {
    scTestKmacImpInit(pImp, pbS, cbS, pbKey, cbKey);
    scTestKmacImpAppend(pImp, pbData, cbData);
    scTestKmacImpResult(pImp, pbOutput, cbOutput);
}

pub export fn scTestKmacImpXof(
    pImp: *anyopaque,
    pbS: ?[*]const u8,
    cbS: usize,
    pbKey: ?[*]const u8,
    cbKey: usize,
    pbData: ?[*]const u8,
    cbData: usize,
    pbOutput: [*]u8,
    cbOutput: usize,
) callconv(.c) void {
    scTestKmacImpInit(pImp, pbS, cbS, pbKey, cbKey);
    scTestKmacImpAppend(pImp, pbData, cbData);
    scTestKmacImpExtract(pImp, pbOutput, cbOutput, 1);
}

// ============================================================================
// MAC Implementations
// ============================================================================

fn macResultLen(kind: MacKind) usize {
    return switch (kind) {
        .HmacMd5, .AesCmac, .Poly1305, .RefPoly1305 => 16,
        .Marvin32 => 8,
        .HmacSha1 => 20,
        .HmacSha224, .HmacSha512_224, .HmacSha3_224 => 28,
        .HmacSha256, .HmacSha512_256, .HmacSha3_256 => 32,
        .HmacSha384, .HmacSha3_384 => 48,
        .HmacSha512, .HmacSha3_512 => 64,
    };
}

fn macInputBlockLen(kind: MacKind) usize {
    return switch (kind) {
        .Marvin32 => 4,
        .AesCmac, .Poly1305, .RefPoly1305 => 16,
        .HmacMd5, .HmacSha1, .HmacSha224, .HmacSha256 => 64,
        .HmacSha384, .HmacSha512, .HmacSha512_224, .HmacSha512_256 => 128,
        .HmacSha3_224 => 144,
        .HmacSha3_256 => 136,
        .HmacSha3_384 => 104,
        .HmacSha3_512 => 72,
    };
}

pub export fn scTestGetMacImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Mac, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestMacImpResultLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return macResultLen(imp.mac_state.kind);
}

pub export fn scTestMacImpInputBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return macInputBlockLen(imp.mac_state.kind);
}

pub export fn scTestMacImpInit(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ms = &imp.mac_state;
    const ik = imp.imp_kind;
    ms.has_key = false;
    switch (ms.kind) {
        .RefPoly1305 => {
            if (cbKey != 32) return -1;
            ref_imp.RefPoly1305Init(&ms.ref_poly, pbKey.?);
            ms.has_key = true;
            ms.isReset = true;
            return 0;
        },
        .Poly1305 => {
            if (cbKey != 32) return -1;
            callSym(ik, "SymCryptPoly1305Init", sc.SymCryptPoly1305Init, .{ &ms.state1, pbKey.? });
            callSym(ik, "SymCryptPoly1305Init", sc.SymCryptPoly1305Init, .{ &ms.state2, pbKey.? });
            ms.has_key = true;
            ms.isReset = true;
            return 0;
        },
        .Marvin32 => {
            if (callSym(ik, "SymCryptMarvin32ExpandSeed", sc.SymCryptMarvin32ExpandSeed, .{ &ms.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return -1;
            callSym(ik, "SymCryptMarvin32SeedCopy", sc.SymCryptMarvin32SeedCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptMarvin32Init", sc.SymCryptMarvin32Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptMarvin32StateCopy", sc.SymCryptMarvin32StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
            ms.has_key = true;
            ms.isReset = true;
            return 0;
        },
        .AesCmac => {
            if (callSym(ik, "SymCryptAesCmacExpandKey", sc.SymCryptAesCmacExpandKey, .{ &ms.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return -1;
            callSym(ik, "SymCryptAesCmacKeyCopy", sc.SymCryptAesCmacKeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptAesCmacInit", sc.SymCryptAesCmacInit, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptAesCmacStateCopy", sc.SymCryptAesCmacStateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
            ms.has_key = true;
            ms.isReset = true;
            return 0;
        },
        .HmacMd5 => {
            _ = callSym(ik, "SymCryptHmacMd5ExpandKey", sc.SymCryptHmacMd5ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacMd5KeyCopy", sc.SymCryptHmacMd5KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacMd5Init", sc.SymCryptHmacMd5Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacMd5StateCopy", sc.SymCryptHmacMd5StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha1 => {
            _ = callSym(ik, "SymCryptHmacSha1ExpandKey", sc.SymCryptHmacSha1ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha1KeyCopy", sc.SymCryptHmacSha1KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha1Init", sc.SymCryptHmacSha1Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha1StateCopy", sc.SymCryptHmacSha1StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha224 => {
            _ = callSym(ik, "SymCryptHmacSha224ExpandKey", sc.SymCryptHmacSha224ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha224KeyCopy", sc.SymCryptHmacSha224KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha224Init", sc.SymCryptHmacSha224Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha224StateCopy", sc.SymCryptHmacSha224StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha256 => {
            _ = callSym(ik, "SymCryptHmacSha256ExpandKey", sc.SymCryptHmacSha256ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha256KeyCopy", sc.SymCryptHmacSha256KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha256Init", sc.SymCryptHmacSha256Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha256StateCopy", sc.SymCryptHmacSha256StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha384 => {
            _ = callSym(ik, "SymCryptHmacSha384ExpandKey", sc.SymCryptHmacSha384ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha384KeyCopy", sc.SymCryptHmacSha384KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha384Init", sc.SymCryptHmacSha384Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha384StateCopy", sc.SymCryptHmacSha384StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha512 => {
            _ = callSym(ik, "SymCryptHmacSha512ExpandKey", sc.SymCryptHmacSha512ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha512KeyCopy", sc.SymCryptHmacSha512KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha512Init", sc.SymCryptHmacSha512Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha512StateCopy", sc.SymCryptHmacSha512StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha512_224 => {
            _ = callSym(ik, "SymCryptHmacSha512_224ExpandKey", sc.SymCryptHmacSha512_224ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha512_224KeyCopy", sc.SymCryptHmacSha512_224KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha512_224Init", sc.SymCryptHmacSha512_224Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha512_224StateCopy", sc.SymCryptHmacSha512_224StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha512_256 => {
            _ = callSym(ik, "SymCryptHmacSha512_256ExpandKey", sc.SymCryptHmacSha512_256ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha512_256KeyCopy", sc.SymCryptHmacSha512_256KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha512_256Init", sc.SymCryptHmacSha512_256Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha512_256StateCopy", sc.SymCryptHmacSha512_256StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha3_224 => {
            _ = callSym(ik, "SymCryptHmacSha3_224ExpandKey", sc.SymCryptHmacSha3_224ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha3_224KeyCopy", sc.SymCryptHmacSha3_224KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha3_224Init", sc.SymCryptHmacSha3_224Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha3_224StateCopy", sc.SymCryptHmacSha3_224StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha3_256 => {
            _ = callSym(ik, "SymCryptHmacSha3_256ExpandKey", sc.SymCryptHmacSha3_256ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha3_256KeyCopy", sc.SymCryptHmacSha3_256KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha3_256Init", sc.SymCryptHmacSha3_256Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha3_256StateCopy", sc.SymCryptHmacSha3_256StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha3_384 => {
            _ = callSym(ik, "SymCryptHmacSha3_384ExpandKey", sc.SymCryptHmacSha3_384ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha3_384KeyCopy", sc.SymCryptHmacSha3_384KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha3_384Init", sc.SymCryptHmacSha3_384Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha3_384StateCopy", sc.SymCryptHmacSha3_384StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
        .HmacSha3_512 => {
            _ = callSym(ik, "SymCryptHmacSha3_512ExpandKey", sc.SymCryptHmacSha3_512ExpandKey, .{ &ms.key1, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha3_512KeyCopy", sc.SymCryptHmacSha3_512KeyCopy, .{ &ms.key1, &ms.key2 });
            callSym(ik, "SymCryptHmacSha3_512Init", sc.SymCryptHmacSha3_512Init, .{ &ms.state1, &ms.key1 });
            callSym(ik, "SymCryptHmacSha3_512StateCopy", sc.SymCryptHmacSha3_512StateCopy, .{ &ms.state1, &ms.key2, &ms.state2 });
        },
    }
    ms.has_key = true;
    ms.isReset = true;
    return 0;
}

pub export fn scTestMacImpAppend(pImp: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ms = &imp.mac_state;
    const ik = imp.imp_kind;
    switch (ms.kind) {
        .RefPoly1305 => {
            if (cbData > 0) {
                ref_imp.RefPoly1305Append(&ms.ref_poly, pbData.?, cbData);
            }
        },
        .Poly1305 => {
            callSym(ik, "SymCryptPoly1305Append", sc.SymCryptPoly1305Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptPoly1305Append", sc.SymCryptPoly1305Append, .{ &ms.state2, pbData, cbData });
        },
        .Marvin32 => {
            callSym(ik, "SymCryptMarvin32Append", sc.SymCryptMarvin32Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptMarvin32Append", sc.SymCryptMarvin32Append, .{ &ms.state2, pbData, cbData });
        },
        .AesCmac => {
            callSym(ik, "SymCryptAesCmacAppend", sc.SymCryptAesCmacAppend, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptAesCmacAppend", sc.SymCryptAesCmacAppend, .{ &ms.state2, pbData, cbData });
        },
        .HmacMd5 => {
            callSym(ik, "SymCryptHmacMd5Append", sc.SymCryptHmacMd5Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacMd5Append", sc.SymCryptHmacMd5Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha1 => {
            callSym(ik, "SymCryptHmacSha1Append", sc.SymCryptHmacSha1Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha1Append", sc.SymCryptHmacSha1Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha224 => {
            callSym(ik, "SymCryptHmacSha224Append", sc.SymCryptHmacSha224Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha224Append", sc.SymCryptHmacSha224Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha256 => {
            callSym(ik, "SymCryptHmacSha256Append", sc.SymCryptHmacSha256Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha256Append", sc.SymCryptHmacSha256Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha384 => {
            callSym(ik, "SymCryptHmacSha384Append", sc.SymCryptHmacSha384Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha384Append", sc.SymCryptHmacSha384Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha512 => {
            callSym(ik, "SymCryptHmacSha512Append", sc.SymCryptHmacSha512Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha512Append", sc.SymCryptHmacSha512Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha512_224 => {
            callSym(ik, "SymCryptHmacSha512_224Append", sc.SymCryptHmacSha512_224Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha512_224Append", sc.SymCryptHmacSha512_224Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha512_256 => {
            callSym(ik, "SymCryptHmacSha512_256Append", sc.SymCryptHmacSha512_256Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha512_256Append", sc.SymCryptHmacSha512_256Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha3_224 => {
            callSym(ik, "SymCryptHmacSha3_224Append", sc.SymCryptHmacSha3_224Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha3_224Append", sc.SymCryptHmacSha3_224Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha3_256 => {
            callSym(ik, "SymCryptHmacSha3_256Append", sc.SymCryptHmacSha3_256Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha3_256Append", sc.SymCryptHmacSha3_256Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha3_384 => {
            callSym(ik, "SymCryptHmacSha3_384Append", sc.SymCryptHmacSha3_384Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha3_384Append", sc.SymCryptHmacSha3_384Append, .{ &ms.state2, pbData, cbData });
        },
        .HmacSha3_512 => {
            callSym(ik, "SymCryptHmacSha3_512Append", sc.SymCryptHmacSha3_512Append, .{ &ms.state1, pbData, cbData });
            callSym(ik, "SymCryptHmacSha3_512Append", sc.SymCryptHmacSha3_512Append, .{ &ms.state2, pbData, cbData });
        },
    }
    ms.isReset = false;
}

pub export fn scTestMacImpResult(pImp: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ms = &imp.mac_state;
    const ik = imp.imp_kind;
    const rlen = macResultLen(ms.kind);
    std.debug.assert(cbResult == rlen);
    var buf2: [128]u8 = undefined;
    switch (ms.kind) {
        .RefPoly1305 => {
            ref_imp.RefPoly1305Result(&ms.ref_poly, pbResult);
            ms.isReset = true;
            return;
        },
        .Poly1305 => {
            callSym(ik, "SymCryptPoly1305Result", sc.SymCryptPoly1305Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptPoly1305Result", sc.SymCryptPoly1305Result, .{ &ms.state2, &buf2 });
        },
        .Marvin32 => {
            callSym(ik, "SymCryptMarvin32Result", sc.SymCryptMarvin32Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptMarvin32Result", sc.SymCryptMarvin32Result, .{ &ms.state2, &buf2 });
        },
        .AesCmac => {
            callSym(ik, "SymCryptAesCmacResult", sc.SymCryptAesCmacResult, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptAesCmacResult", sc.SymCryptAesCmacResult, .{ &ms.state2, &buf2 });
        },
        .HmacMd5 => {
            callSym(ik, "SymCryptHmacMd5Result", sc.SymCryptHmacMd5Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacMd5Result", sc.SymCryptHmacMd5Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha1 => {
            callSym(ik, "SymCryptHmacSha1Result", sc.SymCryptHmacSha1Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha1Result", sc.SymCryptHmacSha1Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha224 => {
            callSym(ik, "SymCryptHmacSha224Result", sc.SymCryptHmacSha224Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha224Result", sc.SymCryptHmacSha224Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha256 => {
            callSym(ik, "SymCryptHmacSha256Result", sc.SymCryptHmacSha256Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha256Result", sc.SymCryptHmacSha256Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha384 => {
            callSym(ik, "SymCryptHmacSha384Result", sc.SymCryptHmacSha384Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha384Result", sc.SymCryptHmacSha384Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha512 => {
            callSym(ik, "SymCryptHmacSha512Result", sc.SymCryptHmacSha512Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha512Result", sc.SymCryptHmacSha512Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha512_224 => {
            callSym(ik, "SymCryptHmacSha512_224Result", sc.SymCryptHmacSha512_224Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha512_224Result", sc.SymCryptHmacSha512_224Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha512_256 => {
            callSym(ik, "SymCryptHmacSha512_256Result", sc.SymCryptHmacSha512_256Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha512_256Result", sc.SymCryptHmacSha512_256Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha3_224 => {
            callSym(ik, "SymCryptHmacSha3_224Result", sc.SymCryptHmacSha3_224Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha3_224Result", sc.SymCryptHmacSha3_224Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha3_256 => {
            callSym(ik, "SymCryptHmacSha3_256Result", sc.SymCryptHmacSha3_256Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha3_256Result", sc.SymCryptHmacSha3_256Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha3_384 => {
            callSym(ik, "SymCryptHmacSha3_384Result", sc.SymCryptHmacSha3_384Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha3_384Result", sc.SymCryptHmacSha3_384Result, .{ &ms.state2, &buf2 });
        },
        .HmacSha3_512 => {
            callSym(ik, "SymCryptHmacSha3_512Result", sc.SymCryptHmacSha3_512Result, .{ &ms.state1, pbResult });
            callSym(ik, "SymCryptHmacSha3_512Result", sc.SymCryptHmacSha3_512Result, .{ &ms.state2, &buf2 });
        },
    }
    if (!std.mem.eql(u8, pbResult[0..rlen], buf2[0..rlen])) @panic("MAC state mismatch");
    ms.isReset = true;
}

pub export fn scTestMacImpMac(
    pImp: *anyopaque,
    pbKey: ?[*]const u8,
    cbKey: usize,
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ms = &imp.mac_state;
    const ik = imp.imp_kind;
    if (ms.kind == .RefPoly1305) {
        if (cbKey != 32) return -1;
        std.debug.assert(cbResult == macResultLen(ms.kind));
        var dummy: [1]u8 = .{0};
        ref_imp.RefPoly1305(pbKey.?, if (pbData) |p| p else &dummy, cbData, pbResult);
        return 0;
    }
    if (scTestMacImpInit(pImp, pbKey, cbKey) != 0) return -1;
    std.debug.assert(cbResult == macResultLen(ms.kind));
    switch (ms.kind) {
        .RefPoly1305 => unreachable,
        .Poly1305 => callSym(ik, "SymCryptPoly1305", sc.SymCryptPoly1305, .{ pbKey.?, pbData, cbData, pbResult }),
        .Marvin32 => callSym(ik, "SymCryptMarvin32", sc.SymCryptMarvin32, .{ &ms.key1, pbData, cbData, pbResult }),
        .AesCmac => callSym(ik, "SymCryptAesCmac", sc.SymCryptAesCmac, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacMd5 => callSym(ik, "SymCryptHmacMd5", sc.SymCryptHmacMd5, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha1 => callSym(ik, "SymCryptHmacSha1", sc.SymCryptHmacSha1, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha224 => callSym(ik, "SymCryptHmacSha224", sc.SymCryptHmacSha224, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha256 => callSym(ik, "SymCryptHmacSha256", sc.SymCryptHmacSha256, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha384 => callSym(ik, "SymCryptHmacSha384", sc.SymCryptHmacSha384, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha512 => callSym(ik, "SymCryptHmacSha512", sc.SymCryptHmacSha512, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha512_224 => callSym(ik, "SymCryptHmacSha512_224", sc.SymCryptHmacSha512_224, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha512_256 => callSym(ik, "SymCryptHmacSha512_256", sc.SymCryptHmacSha512_256, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha3_224 => callSym(ik, "SymCryptHmacSha3_224", sc.SymCryptHmacSha3_224, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha3_256 => callSym(ik, "SymCryptHmacSha3_256", sc.SymCryptHmacSha3_256, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha3_384 => callSym(ik, "SymCryptHmacSha3_384", sc.SymCryptHmacSha3_384, .{ &ms.key1, pbData, cbData, pbResult }),
        .HmacSha3_512 => callSym(ik, "SymCryptHmacSha3_512", sc.SymCryptHmacSha3_512, .{ &ms.key1, pbData, cbData, pbResult }),
    }
    return 0;
}

// ============================================================================
// KDF Implementations
// ============================================================================

const KdfArgs = extern struct {
    argType: c_int,
    u: extern union {
        uGeneric: extern struct {
            pbSelector: ?[*]const u8,
            cbSelector: usize,
        },
        uPbkdf2: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            iterationCnt: u64,
        },
        uSp800_108: extern struct {
            pbLabel: ?[*]const u8,
            cbLabel: usize,
            pbContext: ?[*]const u8,
            cbContext: usize,
        },
        uTlsPrf: extern struct {
            pbLabel: ?[*]const u8,
            cbLabel: usize,
            pbSeed: ?[*]const u8,
            cbSeed: usize,
        },
        uHkdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            pbInfo: ?[*]const u8,
            cbInfo: usize,
        },
        uSshKdf: extern struct {
            hashName: ?[*:0]const u8,
            pbHashValue: ?[*]const u8,
            cbHashValue: usize,
            pbSessionId: ?[*]const u8,
            cbSessionId: usize,
            label: u8,
        },
        uSrtpKdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            uKeyDerivationRate: u32,
            uIndex: u64,
            uIndexWidth: u32,
            label: u8,
        },
        uSskdf: extern struct {
            pbSalt: ?[*]const u8,
            cbSalt: usize,
            pbInfo: ?[*]const u8,
            cbInfo: usize,
        },
    },
};

const KdfArgumentGeneric: c_int = 1;
const KdfArgumentPbkdf2: c_int = 2;
const KdfArgumentSp800_108: c_int = 3;
const KdfArgumentTlsPrf: c_int = 4;
const KdfArgumentHkdf: c_int = 5;
const KdfArgumentSshKdf: c_int = 6;
const KdfArgumentSrtpKdf: c_int = 7;
const KdfArgumentSskdf: c_int = 8;

fn getMacResultSize(mode: KdfModeKind) usize {
    return switch (mode) {
        .HmacMd5, .AesCmac => 16,
        .HmacSha1 => 20,
        .HmacSha224, .HmacSha512_224, .HmacSha3_224 => 28,
        .HmacSha256, .HmacSha512_256, .HmacSha3_256, .Kmac128 => 32,
        .HmacSha384, .HmacSha3_384 => 48,
        .HmacSha512, .HmacSha3_512, .Kmac256 => 64,
        else => 32,
    };
}

fn getMacStruct(ik: sc.ImpKind, mode: KdfModeKind) ?*const anyopaque {
    return switch (mode) {
        .HmacMd5 => getSymPtr(ik, "SymCryptHmacMd5Algorithm", sc.SymCryptHmacMd5Algorithm),
        .HmacSha1 => getSymPtr(ik, "SymCryptHmacSha1Algorithm", sc.SymCryptHmacSha1Algorithm),
        .HmacSha224 => getSymPtr(ik, "SymCryptHmacSha224Algorithm", sc.SymCryptHmacSha224Algorithm),
        .HmacSha256 => getSymPtr(ik, "SymCryptHmacSha256Algorithm", sc.SymCryptHmacSha256Algorithm),
        .HmacSha384 => getSymPtr(ik, "SymCryptHmacSha384Algorithm", sc.SymCryptHmacSha384Algorithm),
        .HmacSha512 => getSymPtr(ik, "SymCryptHmacSha512Algorithm", sc.SymCryptHmacSha512Algorithm),
        .HmacSha512_224 => getSymPtr(ik, "SymCryptHmacSha512_224Algorithm", sc.SymCryptHmacSha512_224Algorithm),
        .HmacSha512_256 => getSymPtr(ik, "SymCryptHmacSha512_256Algorithm", sc.SymCryptHmacSha512_256Algorithm),
        .HmacSha3_224 => getSymPtr(ik, "SymCryptHmacSha3_224Algorithm", sc.SymCryptHmacSha3_224Algorithm),
        .HmacSha3_256 => getSymPtr(ik, "SymCryptHmacSha3_256Algorithm", sc.SymCryptHmacSha3_256Algorithm),
        .HmacSha3_384 => getSymPtr(ik, "SymCryptHmacSha3_384Algorithm", sc.SymCryptHmacSha3_384Algorithm),
        .HmacSha3_512 => getSymPtr(ik, "SymCryptHmacSha3_512Algorithm", sc.SymCryptHmacSha3_512Algorithm),
        .AesCmac => getSymPtr(ik, "SymCryptAesCmacAlgorithm", sc.SymCryptAesCmacAlgorithm),
        .Kmac128 => getSymPtr(ik, "SymCryptKmac128Algorithm", sc.SymCryptKmac128Algorithm),
        .Kmac256 => getSymPtr(ik, "SymCryptKmac256Algorithm", sc.SymCryptKmac256Algorithm),
        else => null,
    };
}

fn getHashStruct(ik: sc.ImpKind, mode: KdfModeKind) ?*const anyopaque {
    return switch (mode) {
        .Md5 => getSymPtr(ik, "SymCryptMd5Algorithm", sc.SymCryptMd5Algorithm),
        .Sha1 => getSymPtr(ik, "SymCryptSha1Algorithm", sc.SymCryptSha1Algorithm),
        .Sha224 => getSymPtr(ik, "SymCryptSha224Algorithm", sc.SymCryptSha224Algorithm),
        .Sha256 => getSymPtr(ik, "SymCryptSha256Algorithm", sc.SymCryptSha256Algorithm),
        .Sha384 => getSymPtr(ik, "SymCryptSha384Algorithm", sc.SymCryptSha384Algorithm),
        .Sha512 => getSymPtr(ik, "SymCryptSha512Algorithm", sc.SymCryptSha512Algorithm),
        .Sha512_224 => getSymPtr(ik, "SymCryptSha512_224Algorithm", sc.SymCryptSha512_224Algorithm),
        .Sha512_256 => getSymPtr(ik, "SymCryptSha512_256Algorithm", sc.SymCryptSha512_256Algorithm),
        .Sha3_224 => getSymPtr(ik, "SymCryptSha3_224Algorithm", sc.SymCryptSha3_224Algorithm),
        .Sha3_256 => getSymPtr(ik, "SymCryptSha3_256Algorithm", sc.SymCryptSha3_256Algorithm),
        .Sha3_384 => getSymPtr(ik, "SymCryptSha3_384Algorithm", sc.SymCryptSha3_384Algorithm),
        .Sha3_512 => getSymPtr(ik, "SymCryptSha3_512Algorithm", sc.SymCryptSha3_512Algorithm),
        .Shake128 => getSymPtr(ik, "SymCryptShake128HashAlgorithm", sc.SymCryptShake128HashAlgorithm),
        .Shake256 => getSymPtr(ik, "SymCryptShake256HashAlgorithm", sc.SymCryptShake256HashAlgorithm),
        else => null,
    };
}

pub export fn scTestGetKdfImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Kdf, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestKdfImpDerive(
    pImp: *anyopaque,
    pbKey: ?[*]const u8,
    cbKey: usize,
    pArgs: *const KdfArgs,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ks = &imp.kdf_state;
    const ik = imp.imp_kind;

    var buf1: [1024]u8 = undefined;
    var buf2: [1024]u8 = undefined;
    std.debug.assert(cbDst <= buf1.len);

    switch (ks.kind) {
        .Pbkdf2 => {
            const mac_alg = getMacStruct(ik, ks.mode).?;
            var exp_key: [1024]u8 align(64) = @splat(0);
            var pbSalt: ?[*]const u8 = null;
            var cbSalt: usize = 0;
            var iterationCnt: u64 = 1;
            switch (pArgs.argType) {
                KdfArgumentGeneric => {
                    pbSalt = pArgs.u.uGeneric.pbSelector;
                    cbSalt = pArgs.u.uGeneric.cbSelector;
                    iterationCnt = 1;
                },
                KdfArgumentPbkdf2 => {
                    pbSalt = pArgs.u.uPbkdf2.pbSalt;
                    cbSalt = pArgs.u.uPbkdf2.cbSalt;
                    iterationCnt = pArgs.u.uPbkdf2.iterationCnt;
                },
                else => @panic("Unexpected KdfArgType for Pbkdf2"),
            }
            const scErr1 = callSym(ik, "SymCryptPbkdf2", sc.SymCryptPbkdf2, .{
                mac_alg,
                pbKey,
                cbKey,
                pbSalt,
                cbSalt,
                iterationCnt,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2");
            const scErr2 = callSym(ik, "SymCryptPbkdf2ExpandKey", sc.SymCryptPbkdf2ExpandKey, .{ &exp_key, mac_alg, pbKey, cbKey });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2");
            const scErr3 = callSym(ik, "SymCryptPbkdf2Derive", sc.SymCryptPbkdf2Derive, .{
                &exp_key,
                pbSalt,
                cbSalt,
                iterationCnt,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt PBKDF2");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt PBKDF2 calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .Sp800_108 => {
            const mac_alg = getMacStruct(ik, ks.mode).?;
            var exp_key: [1024]u8 align(64) = @splat(0);
            var pbLabel: ?[*]const u8 = null;
            var cbLabel: usize = 0;
            var pbContext: ?[*]const u8 = null;
            var cbContext: usize = 0;

            switch (pArgs.argType) {
                KdfArgumentGeneric => {
                    pbLabel = null;
                    cbLabel = std.math.maxInt(usize);
                    pbContext = pArgs.u.uGeneric.pbSelector;
                    cbContext = pArgs.u.uGeneric.cbSelector;
                },
                KdfArgumentSp800_108 => {
                    pbLabel = pArgs.u.uSp800_108.pbLabel;
                    cbLabel = pArgs.u.uSp800_108.cbLabel;
                    pbContext = pArgs.u.uSp800_108.pbContext;
                    cbContext = pArgs.u.uSp800_108.cbContext;
                },
                else => @panic("Unexpected KdfArgType for Sp800_108"),
            }
            const scErr1 = callSym(ik, "SymCryptSp800_108", sc.SymCryptSp800_108, .{
                mac_alg,
                pbKey,
                cbKey,
                pbLabel,
                cbLabel,
                pbContext,
                cbContext,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108");
            const scErr2 = callSym(ik, "SymCryptSp800_108ExpandKey", sc.SymCryptSp800_108ExpandKey, .{ &exp_key, mac_alg, pbKey, cbKey });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108");
            const scErr3 = callSym(ik, "SymCryptSp800_108Derive", sc.SymCryptSp800_108Derive, .{
                &exp_key,
                pbLabel,
                cbLabel,
                pbContext,
                cbContext,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt SP800_108");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt SP800_108 calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .TlsPrf1_1 => {
            var exp_key: [1024]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentTlsPrf, "Unknown argument type for TLS PRF 1.1");
            const a = &pArgs.u.uTlsPrf;
            const scErr1 = callSym(ik, "SymCryptTlsPrf1_1", sc.SymCryptTlsPrf1_1, .{
                pbKey,
                cbKey,
                a.pbLabel,
                a.cbLabel,
                a.pbSeed,
                a.cbSeed,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");
            const scErr2 = callSym(ik, "SymCryptTlsPrf1_1ExpandKey", sc.SymCryptTlsPrf1_1ExpandKey, .{ &exp_key, pbKey, cbKey });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");
            const scErr3 = callSym(ik, "SymCryptTlsPrf1_1Derive", sc.SymCryptTlsPrf1_1Derive, .{
                &exp_key,
                a.pbLabel,
                a.cbLabel,
                a.pbSeed,
                a.cbSeed,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.1");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt TLS PRF 1.1 calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .TlsPrf1_2 => {
            const mac_alg = getMacStruct(ik, ks.mode).?;
            var exp_key: [1024]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentTlsPrf, "Unknown argument type for TLS PRF 1.2");
            const a = &pArgs.u.uTlsPrf;
            const scErr1 = callSym(ik, "SymCryptTlsPrf1_2", sc.SymCryptTlsPrf1_2, .{
                mac_alg,
                pbKey,
                cbKey,
                a.pbLabel,
                a.cbLabel,
                a.pbSeed,
                a.cbSeed,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.2");
            const scErr2 = callSym(ik, "SymCryptTlsPrf1_2ExpandKey", sc.SymCryptTlsPrf1_2ExpandKey, .{ &exp_key, mac_alg, pbKey, cbKey });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.2");
            const scErr3 = callSym(ik, "SymCryptTlsPrf1_2Derive", sc.SymCryptTlsPrf1_2Derive, .{
                &exp_key,
                a.pbLabel,
                a.cbLabel,
                a.pbSeed,
                a.cbSeed,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt TLS PRF 1.2");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt TLS PRF 1.2 calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .Hkdf => {
            const mac_alg = getMacStruct(ik, ks.mode).?;
            const prk_len = getMacResultSize(ks.mode);
            var exp_key: [1024]u8 align(64) = @splat(0);
            var rbPrk: [64]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentHkdf, "Unknown argument type for HKDF");
            const a = &pArgs.u.uHkdf;
            const scErr1 = callSym(ik, "SymCryptHkdf", sc.SymCryptHkdf, .{
                mac_alg,
                pbKey,
                cbKey,
                a.pbSalt,
                a.cbSalt,
                a.pbInfo,
                a.cbInfo,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            const scErr2 = callSym(ik, "SymCryptHkdfExpandKey", sc.SymCryptHkdfExpandKey, .{
                &exp_key,
                mac_alg,
                pbKey,
                cbKey,
                a.pbSalt,
                a.cbSalt,
            });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            const scErr3 = callSym(ik, "SymCryptHkdfDerive", sc.SymCryptHkdfDerive, .{
                &exp_key,
                a.pbInfo,
                a.cbInfo,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt HKDF calling versions disagree");

            const scErr4 = callSym(ik, "SymCryptHkdfExtractPrk", sc.SymCryptHkdfExtractPrk, .{
                mac_alg,
                pbKey,
                cbKey,
                a.pbSalt,
                a.cbSalt,
                &rbPrk,
                prk_len,
            });
            mh.check(scErr4 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            const scErr5 = callSym(ik, "SymCryptHkdfPrkExpandKey", sc.SymCryptHkdfPrkExpandKey, .{
                &exp_key,
                mac_alg,
                &rbPrk,
                prk_len,
            });
            mh.check(scErr5 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            const scErr6 = callSym(ik, "SymCryptHkdfDerive", sc.SymCryptHkdfDerive, .{
                &exp_key,
                a.pbInfo,
                a.cbInfo,
                &buf2,
                cbDst,
            });
            mh.check(scErr6 == sc.SYMCRYPT_NO_ERROR, "Error in SymCrypt HKDF");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt HKDF calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .SshKdf => {
            const hash_alg = getHashStruct(ik, ks.mode).?;
            var exp_key: [1024]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentSshKdf, "Unknown argument type for SSH-KDF");
            const a = &pArgs.u.uSshKdf;
            const scErr1 = callSym(ik, "SymCryptSshKdfExpandKey", sc.SymCryptSshKdfExpandKey, .{ &exp_key, hash_alg, pbKey, cbKey });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdfExpandKey");
            const scErr2 = callSym(ik, "SymCryptSshKdfDerive", sc.SymCryptSshKdfDerive, .{
                &exp_key,
                a.pbHashValue,
                a.cbHashValue,
                a.label,
                a.pbSessionId,
                a.cbSessionId,
                &buf1,
                cbDst,
            });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdfDerive");
            const scErr3 = callSym(ik, "SymCryptSshKdf", sc.SymCryptSshKdf, .{
                hash_alg,
                pbKey,
                cbKey,
                a.pbHashValue,
                a.cbHashValue,
                a.label,
                a.pbSessionId,
                a.cbSessionId,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSshKdf");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt SSH-KDF calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .SrtpKdf => {
            var exp_key: [1024]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentSrtpKdf, "Unknown argument type for SRTP-KDF");
            const a = &pArgs.u.uSrtpKdf;
            const indexWidth: u32 = if (a.label < 3) 48 else 32;
            const scErr1 = callSym(ik, "SymCryptSrtpKdfExpandKey", sc.SymCryptSrtpKdfExpandKey, .{ &exp_key, pbKey, cbKey });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdfExpandKey");
            const scErr2 = callSym(ik, "SymCryptSrtpKdfDerive", sc.SymCryptSrtpKdfDerive, .{
                &exp_key,
                a.pbSalt,
                a.cbSalt,
                a.uKeyDerivationRate,
                a.uIndex,
                indexWidth,
                a.label,
                &buf1,
                cbDst,
            });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdfDerive");
            const scErr3 = callSym(ik, "SymCryptSrtpKdf", sc.SymCryptSrtpKdf, .{
                pbKey,
                cbKey,
                a.pbSalt,
                a.cbSalt,
                a.uKeyDerivationRate,
                a.uIndex,
                indexWidth,
                a.label,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSrtpKdf");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt SRTP-KDF calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .SskdfMac => {
            const mac_alg = getMacStruct(ik, ks.mode).?;
            var exp_salt: [1024]u8 align(64) = @splat(0);
            mh.check(pArgs.argType == KdfArgumentSskdf, "Unknown argument type for SSKDF");
            const a = &pArgs.u.uSskdf;
            const scErr1 = callSym(ik, "SymCryptSskdfMac", sc.SymCryptSskdfMac, .{
                mac_alg,
                0,
                pbKey,
                cbKey,
                a.pbSalt,
                a.cbSalt,
                a.pbInfo,
                a.cbInfo,
                &buf1,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMac");
            const scErr2 = callSym(ik, "SymCryptSskdfMacExpandSalt", sc.SymCryptSskdfMacExpandSalt, .{
                &exp_salt,
                mac_alg,
                a.pbSalt,
                a.cbSalt,
            });
            mh.check(scErr2 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMacExpandSalt");
            const scErr3 = callSym(ik, "SymCryptSskdfMacDerive", sc.SymCryptSskdfMacDerive, .{
                &exp_salt,
                0,
                pbKey,
                cbKey,
                a.pbInfo,
                a.cbInfo,
                &buf2,
                cbDst,
            });
            mh.check(scErr3 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfMacDerive");
            mh.check(std.mem.eql(u8, buf1[0..cbDst], buf2[0..cbDst]), "SymCrypt SSKDF calling versions disagree");
            @memcpy(pbDst[0..cbDst], buf1[0..cbDst]);
        },
        .SskdfHash => {
            const hash_alg = getHashStruct(ik, ks.mode).?;
            mh.check(pArgs.argType == KdfArgumentSskdf, "Unknown argument type for SSKDF");
            const a = &pArgs.u.uSskdf;
            const scErr1 = callSym(ik, "SymCryptSskdfHash", sc.SymCryptSskdfHash, .{
                hash_alg,
                0,
                pbKey,
                cbKey,
                a.pbInfo,
                a.cbInfo,
                pbDst,
                cbDst,
            });
            mh.check(scErr1 == sc.SYMCRYPT_NO_ERROR, "Error in SymCryptSskdfHash");
        },
    }
}

// ============================================================================
// BlockCipher Implementations
// ============================================================================

fn bcCoreBlockLen(alg: BcAlgKind) usize {
    return switch (alg) {
        .Aes => 16,
        .Des, .Des2, .TripleDes, .Desx, .Rc2 => 8,
    };
}

fn bcBlockCipherPtr(ik: sc.ImpKind, alg: BcAlgKind) *const anyopaque {
    return switch (alg) {
        .Aes => getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?,
        .Des => getSymPtr(ik, "SymCryptDesBlockCipher", sc.SymCryptDesBlockCipher).?,
        .Des2, .TripleDes => getSymPtr(ik, "SymCrypt3DesBlockCipher", sc.SymCrypt3DesBlockCipher).?,
        .Desx => getSymPtr(ik, "SymCryptDesxBlockCipher", sc.SymCryptDesxBlockCipher).?,
        .Rc2 => getSymPtr(ik, "SymCryptRc2BlockCipher", sc.SymCryptRc2BlockCipher).?,
    };
}

pub export fn scTestGetBlockCipherImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.BlockCipher, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestBlockCipherCoreBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return bcCoreBlockLen(imp.bc_state.alg);
}

pub export fn scTestBlockCipherMsgBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.bc_state.mode) {
        .Cfb => mh.g_modeCfbShiftParam,
        else => bcCoreBlockLen(imp.bc_state.alg),
    };
}

pub export fn scTestBlockCipherChainBlockLen(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.bc_state.mode) {
        .Ecb => 0,
        else => bcCoreBlockLen(imp.bc_state.alg),
    };
}

pub export fn scTestBlockCipherSetKey(
    pImp: *anyopaque,
    pbKey: ?[*]const u8,
    cbKey: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const bs = &imp.bc_state;
    const ik = imp.imp_kind;

    const rc2EffectiveKeyLength = mh.g_rc2EffectiveKeyLength;

    switch (bs.alg) {
        .Aes => {
            if (callSym(ik, "SymCryptAesExpandKey", sc.SymCryptAesExpandKey, .{ &bs.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
        .Des => {
            if (callSym(ik, "SymCryptDesExpandKey", sc.SymCryptDesExpandKey, .{ &bs.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
        .Des2 => {
            if (cbKey != 16) return sc.STATUS_NOT_SUPPORTED;
            if (callSym(ik, "SymCrypt3DesExpandKey", sc.SymCrypt3DesExpandKey, .{ &bs.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
        .TripleDes => {
            if (cbKey != 24) return sc.STATUS_NOT_SUPPORTED;
            if (callSym(ik, "SymCrypt3DesExpandKey", sc.SymCrypt3DesExpandKey, .{ &bs.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
        .Desx => {
            if (callSym(ik, "SymCryptDesxExpandKey", sc.SymCryptDesxExpandKey, .{ &bs.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
        .Rc2 => {
            const eff_bits: u32 = if (rc2EffectiveKeyLength == 0) @intCast(8 * cbKey) else rc2EffectiveKeyLength;
            if (callSym(ik, "SymCryptRc2ExpandKeyEx", sc.SymCryptRc2ExpandKeyEx, .{ &bs.key1, pbKey, cbKey, eff_bits }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
        },
    }
    return 0;
}

fn doBcOp(
    imp: *AlgImp,
    key_ptr: *const anyopaque,
    is_encrypt: bool,
    pbChain: ?[*]u8,
    cbChain: usize,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) void {
    const bs = &imp.bc_state;
    const ik = imp.imp_kind;
    const core_len = bcCoreBlockLen(bs.alg);
    const bc_ptr = bcBlockCipherPtr(ik, bs.alg);

    switch (bs.mode) {
        .Ecb => {
            std.debug.assert(cbChain == 0);
            if (is_encrypt) {
                callSym(ik, "SymCryptEcbEncrypt", sc.SymCryptEcbEncrypt, .{ bc_ptr, key_ptr, pbSrc, pbDst, cbData });
            } else {
                callSym(ik, "SymCryptEcbDecrypt", sc.SymCryptEcbDecrypt, .{ bc_ptr, key_ptr, pbSrc, pbDst, cbData });
            }
        },
        .Cbc => {
            std.debug.assert(cbChain == core_len);
            if (is_encrypt) {
                callSym(ik, "SymCryptCbcEncrypt", sc.SymCryptCbcEncrypt, .{ bc_ptr, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            } else {
                callSym(ik, "SymCryptCbcDecrypt", sc.SymCryptCbcDecrypt, .{ bc_ptr, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            }
        },
        .Cfb => {
            std.debug.assert(cbChain == core_len);
            if (is_encrypt) {
                callSym(ik, "SymCryptCfbEncrypt", sc.SymCryptCfbEncrypt, .{ bc_ptr, mh.g_modeCfbShiftParam, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            } else {
                callSym(ik, "SymCryptCfbDecrypt", sc.SymCryptCfbDecrypt, .{ bc_ptr, mh.g_modeCfbShiftParam, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            }
        },
        .CtrMsb32 => {
            std.debug.assert(cbChain == core_len);
            callSym(ik, "SymCryptCtrMsb32", sc.SymCryptCtrMsb32, .{ bc_ptr, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
        },
        .CtrMsb64 => {
            std.debug.assert(cbChain == core_len);
            if (bs.alg == .Aes) {
                callSym(ik, "SymCryptAesCtrMsb64", sc.SymCryptAesCtrMsb64, .{ key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            } else {
                callSym(ik, "SymCryptCtrMsb64", sc.SymCryptCtrMsb64, .{ bc_ptr, key_ptr, pbChain.?, pbSrc, pbDst, cbData });
            }
        },
        .CtrLsb64 => {
            std.debug.assert(cbChain == core_len);
            var i: usize = 0;
            var ks_block: [16]u8 = undefined;
            while (i + core_len <= cbData) : (i += core_len) {
                doBcOp(imp, key_ptr, true, null, 0, pbChain, &ks_block, core_len);
                for (0..core_len) |j| {
                    pbDst[i + j] = pbSrc.?[i + j] ^ ks_block[j];
                }
                const pCtr: *align(1) u64 = @ptrCast(pbChain.?[0..8]);
                pCtr.* = std.mem.littleToNative(u64, std.mem.nativeToLittle(u64, pCtr.*) +% 1);
            }
        },
    }
}

pub export fn scTestBlockCipherEncrypt(
    pImp: *anyopaque,
    pbChain: ?[*]u8,
    cbChain: usize,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    doBcOp(imp, &imp.bc_state.key1, true, pbChain, cbChain, pbSrc, pbDst, cbData);
}

pub export fn scTestBlockCipherDecrypt(
    pImp: *anyopaque,
    pbChain: ?[*]u8,
    cbChain: usize,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    doBcOp(imp, &imp.bc_state.key1, false, pbChain, cbChain, pbSrc, pbDst, cbData);
}

// ============================================================================
// AuthEnc Implementations (CCM, GCM, ChaCha20Poly1305)
// ============================================================================

const AUTHENC_FLAG_PARTIALDATA: u32 = 1;
const STATUS_AUTH_TAG_MISMATCH: i32 = @bitCast(@as(u32, 0xC000A002));

pub export fn scTestGetAuthEncImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.AuthEnc, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestAuthEncGetNonceSizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.authenc_state.kind) {
        .Ccm => blk: {
            var count: usize = 0;
            for (7..14) |s| {
                if (count < maxSizes) {
                    outSizes[count] = s;
                    count += 1;
                }
            }
            break :blk count;
        },
        .Gcm => blk: {
            var count: usize = 0;
            for (1..257) |s| {
                if (count < maxSizes) {
                    outSizes[count] = s;
                    count += 1;
                }
            }
            break :blk count;
        },
        .ChaCha20Poly1305 => blk: {
            if (maxSizes >= 1) outSizes[0] = 12;
            break :blk 1;
        },
    };
}

pub export fn scTestAuthEncGetTagSizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.authenc_state.kind) {
        .Ccm => blk: {
            const tags = [_]usize{ 4, 6, 8, 10, 12, 14, 16 };
            const n = @min(tags.len, maxSizes);
            @memcpy(outSizes[0..n], tags[0..n]);
            break :blk n;
        },
        .Gcm => blk: {
            var count: usize = 0;
            for (12..17) |s| {
                if (count < maxSizes) {
                    outSizes[count] = s;
                    count += 1;
                }
            }
            break :blk count;
        },
        .ChaCha20Poly1305 => blk: {
            if (maxSizes >= 1) outSizes[0] = 16;
            break :blk 1;
        },
    };
}

pub export fn scTestAuthEncGetKeySizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.authenc_state.kind) {
        .Ccm, .Gcm => blk: {
            const ks = [_]usize{ 16, 24, 32 };
            const n = @min(ks.len, maxSizes);
            @memcpy(outSizes[0..n], ks[0..n]);
            break :blk n;
        },
        .ChaCha20Poly1305 => blk: {
            if (maxSizes >= 1) outSizes[0] = 32;
            break :blk 1;
        },
    };
}

pub export fn scTestAuthEncSetKey(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const aes = &imp.authenc_state;
    const ik = imp.imp_kind;
    aes.inComputation = false;
    switch (aes.kind) {
        .Ccm => {
            if (callSym(ik, "SymCryptAesExpandKey", sc.SymCryptAesExpandKey, .{ &aes.key, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return -1;
            return 0;
        },
        .Gcm => {
            const bc_ptr = getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?;
            if (callSym(ik, "SymCryptGcmExpandKey", sc.SymCryptGcmExpandKey, .{ &aes.key, bc_ptr, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return -1;
            var key2: [4096]u8 align(64) = @splat(0);
            callSym(ik, "SymCryptGcmKeyCopy", sc.SymCryptGcmKeyCopy, .{ &aes.key, &key2 });
            callSym(ik, "SymCryptGcmKeyCopy", sc.SymCryptGcmKeyCopy, .{ &key2, &aes.key });
            return 0;
        },
        .ChaCha20Poly1305 => {
            if (cbKey != 32) return -1;
            @memcpy(aes.key_bytes[0..32], pbKey.?[0..32]);
            aes.key_len = 32;
            return 0;
        },
    }
}

pub export fn scTestAuthEncSetTotalCbData(pImp: *anyopaque, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    imp.authenc_state.totalCbData = cbData;
}

pub export fn scTestAuthEncEncrypt(
    pImp: *anyopaque,
    pbNonce: ?[*]const u8,
    cbNonce: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
    pbTag: ?[*]u8,
    cbTag: usize,
    flags: u32,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const aes = &imp.authenc_state;
    const ik = imp.imp_kind;

    switch (aes.kind) {
        .Ccm => {
            const bc_ptr = getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?;
            if (callSym(ik, "SymCryptCcmValidateParameters", sc.SymCryptCcmValidateParameters, .{
                bc_ptr,
                cbNonce,
                cbAuthData,
                if ((flags & AUTHENC_FLAG_PARTIALDATA) != 0) aes.totalCbData else cbData,
                cbTag,
            }) != sc.SYMCRYPT_NO_ERROR) return -1;

            if ((flags & AUTHENC_FLAG_PARTIALDATA) == 0) {
                callSym(ik, "SymCryptCcmEncrypt", sc.SymCryptCcmEncrypt, .{
                    bc_ptr,
                    &aes.key,
                    pbNonce,
                    cbNonce,
                    pbAuthData,
                    cbAuthData,
                    pbSrc,
                    pbDst,
                    cbData,
                    pbTag.?,
                    cbTag,
                });
            } else {
                if (!aes.inComputation) {
                    callSym(ik, "SymCryptCcmInit", sc.SymCryptCcmInit, .{
                        &aes.state1,
                        bc_ptr,
                        &aes.key,
                        pbNonce,
                        cbNonce,
                        pbAuthData,
                        cbAuthData,
                        aes.totalCbData,
                        cbTag,
                    });
                    aes.inComputation = true;
                }
                callSym(ik, "SymCryptCcmEncryptPart", sc.SymCryptCcmEncryptPart, .{ &aes.state1, pbSrc, pbDst, cbData });
                if (pbTag) |tag| {
                    callSym(ik, "SymCryptCcmEncryptFinal", sc.SymCryptCcmEncryptFinal, .{ &aes.state1, tag, cbTag });
                    aes.inComputation = false;
                }
            }
            return 0;
        },
        .Gcm => {
            const bc_ptr = getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?;
            if (callSym(ik, "SymCryptGcmValidateParameters", sc.SymCryptGcmValidateParameters, .{
                bc_ptr,
                cbNonce,
                cbAuthData,
                cbData,
                cbTag,
            }) != sc.SYMCRYPT_NO_ERROR) return -1;

            if ((flags & AUTHENC_FLAG_PARTIALDATA) == 0) {
                callSym(ik, "SymCryptGcmEncrypt", sc.SymCryptGcmEncrypt, .{
                    &aes.key,
                    pbNonce,
                    cbNonce,
                    pbAuthData,
                    cbAuthData,
                    pbSrc,
                    pbDst,
                    cbData,
                    pbTag.?,
                    cbTag,
                });
            } else {
                if (!aes.inComputation) {
                    callSym(ik, "SymCryptGcmInit", sc.SymCryptGcmInit, .{ &aes.state1, &aes.key, pbNonce, cbNonce });
                    callSym(ik, "SymCryptGcmAuthPart", sc.SymCryptGcmAuthPart, .{ &aes.state1, pbAuthData, cbAuthData });
                    aes.inComputation = true;
                }
                callSym(ik, "SymCryptGcmEncryptPart", sc.SymCryptGcmEncryptPart, .{ &aes.state1, pbSrc, pbDst, cbData });
                if (pbTag) |tag| {
                    callSym(ik, "SymCryptGcmEncryptFinal", sc.SymCryptGcmEncryptFinal, .{ &aes.state1, tag, cbTag });
                    aes.inComputation = false;
                }
            }
            return 0;
        },
        .ChaCha20Poly1305 => {
            if ((flags & AUTHENC_FLAG_PARTIALDATA) != 0) return -1;
            if (cbNonce != 12 or cbTag != 16) return -1;
            callSym(ik, "SymCryptChaCha20Poly1305Encrypt", sc.SymCryptChaCha20Poly1305Encrypt, .{
                &aes.key_bytes,
                aes.key_len,
                pbNonce,
                cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbData,
                pbTag.?,
                cbTag,
            });
            return 0;
        },
    }
}

pub export fn scTestAuthEncDecrypt(
    pImp: *anyopaque,
    pbNonce: ?[*]const u8,
    cbNonce: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
    pbTag: ?[*]const u8,
    cbTag: usize,
    flags: u32,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const aes = &imp.authenc_state;
    const ik = imp.imp_kind;

    switch (aes.kind) {
        .Ccm => {
            const bc_ptr = getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?;
            if (callSym(ik, "SymCryptCcmValidateParameters", sc.SymCryptCcmValidateParameters, .{
                bc_ptr,
                cbNonce,
                cbAuthData,
                if ((flags & AUTHENC_FLAG_PARTIALDATA) != 0) aes.totalCbData else cbData,
                cbTag,
            }) != sc.SYMCRYPT_NO_ERROR) return -1;

            if ((flags & AUTHENC_FLAG_PARTIALDATA) == 0) {
                const scError = callSym(ik, "SymCryptCcmDecrypt", sc.SymCryptCcmDecrypt, .{
                    bc_ptr,
                    &aes.key,
                    pbNonce,
                    cbNonce,
                    pbAuthData,
                    cbAuthData,
                    pbSrc,
                    pbDst,
                    cbData,
                    pbTag.?,
                    cbTag,
                });
                return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
            } else {
                if (!aes.inComputation) {
                    callSym(ik, "SymCryptCcmInit", sc.SymCryptCcmInit, .{
                        &aes.state1,
                        bc_ptr,
                        &aes.key,
                        pbNonce,
                        cbNonce,
                        pbAuthData,
                        cbAuthData,
                        aes.totalCbData,
                        cbTag,
                    });
                    aes.inComputation = true;
                }
                callSym(ik, "SymCryptCcmDecryptPart", sc.SymCryptCcmDecryptPart, .{ &aes.state1, pbSrc, pbDst, cbData });
                if (pbTag) |tag| {
                    aes.inComputation = false;
                    const scError = callSym(ik, "SymCryptCcmDecryptFinal", sc.SymCryptCcmDecryptFinal, .{ &aes.state1, tag, cbTag });
                    return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
                }
                return 0;
            }
        },
        .Gcm => {
            const bc_ptr = getSymPtr(ik, "SymCryptAesBlockCipher", sc.SymCryptAesBlockCipher).?;
            if (callSym(ik, "SymCryptGcmValidateParameters", sc.SymCryptGcmValidateParameters, .{
                bc_ptr,
                cbNonce,
                cbAuthData,
                cbData,
                cbTag,
            }) != sc.SYMCRYPT_NO_ERROR) return -1;

            if ((flags & AUTHENC_FLAG_PARTIALDATA) == 0) {
                const scError = callSym(ik, "SymCryptGcmDecrypt", sc.SymCryptGcmDecrypt, .{
                    &aes.key,
                    pbNonce,
                    cbNonce,
                    pbAuthData,
                    cbAuthData,
                    pbSrc,
                    pbDst,
                    cbData,
                    pbTag.?,
                    cbTag,
                });
                return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
            } else {
                if (!aes.inComputation) {
                    callSym(ik, "SymCryptGcmInit", sc.SymCryptGcmInit, .{ &aes.state1, &aes.key, pbNonce, cbNonce });
                    callSym(ik, "SymCryptGcmAuthPart", sc.SymCryptGcmAuthPart, .{ &aes.state1, pbAuthData, cbAuthData });
                    aes.inComputation = true;
                }
                callSym(ik, "SymCryptGcmDecryptPart", sc.SymCryptGcmDecryptPart, .{ &aes.state1, pbSrc, pbDst, cbData });
                if (pbTag) |tag| {
                    aes.inComputation = false;
                    const scError = callSym(ik, "SymCryptGcmDecryptFinal", sc.SymCryptGcmDecryptFinal, .{ &aes.state1, tag, cbTag });
                    return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
                }
                return 0;
            }
        },
        .ChaCha20Poly1305 => {
            if ((flags & AUTHENC_FLAG_PARTIALDATA) != 0) return -1;
            if (cbNonce != 12 or cbTag != 16) return -1;
            const scError = callSym(ik, "SymCryptChaCha20Poly1305Decrypt", sc.SymCryptChaCha20Poly1305Decrypt, .{
                &aes.key_bytes,
                aes.key_len,
                pbNonce,
                cbNonce,
                pbAuthData,
                cbAuthData,
                pbSrc,
                pbDst,
                cbData,
                pbTag.?,
                cbTag,
            });
            return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
        },
    }
}

// ============================================================================
// StreamCipher Implementations (RC4, ChaCha20)
// ============================================================================

pub export fn scTestGetStreamCipherImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.StreamCipher, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestStreamCipherGetNonceSizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.stream_state.kind) {
        .Rc4 => 0,
        .ChaCha20 => blk: {
            if (maxSizes >= 1) outSizes[0] = 12;
            break :blk 1;
        },
    };
}

pub export fn scTestStreamCipherGetKeySizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.stream_state.kind) {
        .Rc4 => blk: {
            var count: usize = 0;
            for (1..257) |s| {
                if (count < maxSizes) {
                    outSizes[count] = s;
                    count += 1;
                }
            }
            break :blk count;
        },
        .ChaCha20 => blk: {
            if (maxSizes >= 1) outSizes[0] = 32;
            break :blk 1;
        },
    };
}

pub export fn scTestStreamCipherSetKey(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ss = &imp.stream_state;
    const ik = imp.imp_kind;
    switch (ss.kind) {
        .Rc4 => {
            if (callSym(ik, "SymCryptRc4Init", sc.SymCryptRc4Init, .{ &ss.state1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return -1;
            return 0;
        },
        .ChaCha20 => {
            if (cbKey != 32) return -1;
            @memcpy(ss.key_buf[0..32], pbKey.?[0..32]);
            ss.key_len = 32;
            @memset(&ss.nonce_buf, 0);
            _ = callSym(ik, "SymCryptChaCha20Init", sc.SymCryptChaCha20Init, .{ &ss.state1, &ss.key_buf, 32, &ss.nonce_buf, 12, 0 });
            return 0;
        },
    }
}

pub export fn scTestStreamCipherSetNonce(pImp: *anyopaque, pbNonce: ?[*]const u8, cbNonce: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ss = &imp.stream_state;
    const ik = imp.imp_kind;
    switch (ss.kind) {
        .Rc4 => return if (cbNonce == 0) 0 else -1,
        .ChaCha20 => {
            if (cbNonce != 12) return -1;
            @memcpy(ss.nonce_buf[0..12], pbNonce.?[0..12]);
            if (callSym(ik, "SymCryptChaCha20Init", sc.SymCryptChaCha20Init, .{ &ss.state1, &ss.key_buf, ss.key_len, pbNonce, cbNonce, 0 }) != sc.SYMCRYPT_NO_ERROR) return -1;
            return 0;
        },
    }
}

pub export fn scTestStreamCipherIsRandomAccess(pImp: *const anyopaque) callconv(.c) u32 {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.stream_state.kind) {
        .Rc4 => 0,
        .ChaCha20 => 1,
    };
}

pub export fn scTestStreamCipherSetOffset(pImp: *anyopaque, offset: u64) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ss = &imp.stream_state;
    const ik = imp.imp_kind;
    if (ss.kind == .ChaCha20) {
        callSym(ik, "SymCryptChaCha20SetOffset", sc.SymCryptChaCha20SetOffset, .{ &ss.state1, offset });
    }
}

pub export fn scTestStreamCipherEncrypt(pImp: *anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ss = &imp.stream_state;
    const ik = imp.imp_kind;
    switch (ss.kind) {
        .Rc4 => callSym(ik, "SymCryptRc4Crypt", sc.SymCryptRc4Crypt, .{ &ss.state1, pbSrc.?, pbDst, cbData }),
        .ChaCha20 => callSym(ik, "SymCryptChaCha20Crypt", sc.SymCryptChaCha20Crypt, .{ &ss.state1, pbSrc.?, pbDst, cbData }),
    }
}

// ============================================================================
// RNG SP800-90 (AesCtrDrbg, AesCtrF142, DynamicRandom)
// ============================================================================

pub export fn scTestGetRngSp800_90Imps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.RngSp800_90, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestRngSp800_90Instantiate(pImp: *anyopaque, pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ik = imp.imp_kind;
    switch (imp.rng_state.kind) {
        .Drbg => {
            const scError = callSym(ik, "SymCryptRngAesInstantiate", sc.SymCryptRngAesInstantiate, .{ &imp.rng_state.state1, pbEntropy, cbEntropy });
            return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else -1;
        },
        .F142 => {
            const scError = callSym(ik, "SymCryptRngAesFips140_2Instantiate", sc.SymCryptRngAesFips140_2Instantiate, .{ &imp.rng_state.state1, pbEntropy, cbEntropy });
            return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else -1;
        },
        .DynamicRandom => {
            if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, "SymCryptProvideEntropy", env.SCTEST_DYNSYM_FUNCTION_PTR)) |ptr| {
                const FnPtr = *const fn (?[*]const u8, usize) callconv(.c) void;
                const fn_ptr: FnPtr = @ptrCast(@alignCast(ptr));
                fn_ptr(pbEntropy, cbEntropy);
            }
            return 0;
        },
    }
}

pub export fn scTestRngSp800_90Reseed(pImp: *anyopaque, pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ik = imp.imp_kind;
    switch (imp.rng_state.kind) {
        .Drbg => {
            const scError = callSym(ik, "SymCryptRngAesReseed", sc.SymCryptRngAesReseed, .{ &imp.rng_state.state1, pbEntropy, cbEntropy });
            return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else -1;
        },
        .F142 => {
            const scError = callSym(ik, "SymCryptRngAesFips140_2Reseed", sc.SymCryptRngAesFips140_2Reseed, .{ &imp.rng_state.state1, pbEntropy, cbEntropy });
            return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else -1;
        },
        .DynamicRandom => {
            if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, "SymCryptProvideEntropy", env.SCTEST_DYNSYM_FUNCTION_PTR)) |ptr| {
                const FnPtr = *const fn (?[*]const u8, usize) callconv(.c) void;
                const fn_ptr: FnPtr = @ptrCast(@alignCast(ptr));
                fn_ptr(pbEntropy, cbEntropy);
            }
            return 0;
        },
    }
}

pub export fn scTestRngSp800_90Generate(
    pImp: *anyopaque,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) void {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ik = imp.imp_kind;
    switch (imp.rng_state.kind) {
        .Drbg => callSym(ik, "SymCryptRngAesGenerate", sc.SymCryptRngAesGenerate, .{ &imp.rng_state.state1, pbDst, cbDst }),
        .F142 => callSym(ik, "SymCryptRngAesFips140_2Generate", sc.SymCryptRngAesFips140_2Generate, .{ &imp.rng_state.state1, pbDst, cbDst }),
        .DynamicRandom => {
            if (env.getDynamicSymbolPointerFromString(mh.g_dynamicSymCryptModuleHandle, "SymCryptRandom", env.SCTEST_DYNSYM_FUNCTION_PTR)) |ptr| {
                const FnPtr = *const fn ([*]u8, usize) callconv(.c) void;
                const fn_ptr: FnPtr = @ptrCast(@alignCast(ptr));
                fn_ptr(pbDst, cbDst);
            }
        },
    }
}

// ============================================================================
// XTS Implementations (XtsAes)
// ============================================================================

pub export fn scTestGetXtsImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.Xts, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestXtsSetKey(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, flags: u32) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xts_state;
    const ik = imp.imp_kind;
    const scError = callSym(ik, "SymCryptXtsAesExpandKeyEx", sc.SymCryptXtsAesExpandKeyEx, .{ &xs.key1, pbKey.?, cbKey, flags });
    if (scError == sc.SYMCRYPT_NO_ERROR) {
        callSym(ik, "SymCryptXtsAesKeyCopy", sc.SymCryptXtsAesKeyCopy, .{ &xs.key1, &xs.key2 });
        return 0;
    }
    return sc.STATUS_NOT_SUPPORTED;
}

pub export fn scTestXtsEncrypt(
    pImp: *anyopaque,
    cbDataUnit: usize,
    tweak: u64,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xts_state;
    const ik = imp.imp_kind;
    callSym(ik, "SymCryptXtsAesEncrypt", sc.SymCryptXtsAesEncrypt, .{ &xs.key1, cbDataUnit, tweak, pbSrc.?, pbDst, cbData });
    return 0;
}

pub export fn scTestXtsDecrypt(
    pImp: *anyopaque,
    cbDataUnit: usize,
    tweak: u64,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xts_state;
    const ik = imp.imp_kind;
    callSym(ik, "SymCryptXtsAesDecrypt", sc.SymCryptXtsAesDecrypt, .{ &xs.key1, cbDataUnit, tweak, pbSrc.?, pbDst, cbData });
    return 0;
}

pub export fn scTestXtsEncryptWith128bTweak(
    pImp: *anyopaque,
    cbDataUnit: usize,
    pbTweak: ?[*]const u8,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xts_state;
    const ik = imp.imp_kind;
    callSym(ik, "SymCryptXtsAesEncryptWith128bTweak", sc.SymCryptXtsAesEncryptWith128bTweak, .{ &xs.key1, cbDataUnit, pbTweak.?, pbSrc.?, pbDst, cbData });
    return 0;
}

pub export fn scTestXtsDecryptWith128bTweak(
    pImp: *anyopaque,
    cbDataUnit: usize,
    pbTweak: ?[*]const u8,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const xs = &imp.xts_state;
    const ik = imp.imp_kind;
    callSym(ik, "SymCryptXtsAesDecryptWith128bTweak", sc.SymCryptXtsAesDecryptWith128bTweak, .{ &xs.key1, cbDataUnit, pbTweak.?, pbSrc.?, pbDst, cbData });
    return 0;
}

// ============================================================================
// KeyWrap Implementations (AesKw, AesKwp)
// ============================================================================

pub export fn scTestGetKeyWrapImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.KeyWrap, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestKeyWrapGetMinPlaintextSize(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.kw_state.kind) {
        .AesKw => 16,
        .AesKwp => 1,
    };
}

pub export fn scTestKeyWrapGetMaxPlaintextSize(pImp: *const anyopaque) callconv(.c) usize {
    _ = pImp;
    return (@as(usize, 1) << 31) - 8;
}

pub export fn scTestKeyWrapGetPlaintextSizeIncrement(pImp: *const anyopaque) callconv(.c) usize {
    const imp: *const AlgImp = @ptrCast(@alignCast(pImp));
    return switch (imp.kw_state.kind) {
        .AesKw => 8,
        .AesKwp => 1,
    };
}

pub export fn scTestKeyWrapGetKeySizes(pImp: *const anyopaque, outSizes: [*]usize, maxSizes: usize) callconv(.c) usize {
    _ = pImp;
    const ks = [_]usize{ 16, 24, 32 };
    const n = @min(ks.len, maxSizes);
    @memcpy(outSizes[0..n], ks[0..n]);
    return n;
}

pub export fn scTestKeyWrapSetKey(pImp: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const kw = &imp.kw_state;
    const ik = imp.imp_kind;
    if (callSym(ik, "SymCryptAesExpandKey", sc.SymCryptAesExpandKey, .{ &kw.key1, pbKey, cbKey }) != sc.SYMCRYPT_NO_ERROR) return sc.STATUS_NOT_SUPPORTED;
    callSym(ik, "SymCryptAesKeyCopy", sc.SymCryptAesKeyCopy, .{ &kw.key1, &kw.key2 });
    return 0;
}

pub export fn scTestKeyWrapEncrypt(
    pImp: *anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: [*]u8,
    cbDst: usize,
    pcbResult: *usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const kw = &imp.kw_state;
    const ik = imp.imp_kind;
    const scError = switch (kw.kind) {
        .AesKw => callSym(ik, "SymCryptAesKwEncrypt", sc.SymCryptAesKwEncrypt, .{ &kw.key1, pbSrc, cbSrc, pbDst, cbDst, pcbResult }),
        .AesKwp => callSym(ik, "SymCryptAesKwpEncrypt", sc.SymCryptAesKwpEncrypt, .{ &kw.key1, pbSrc, cbSrc, pbDst, cbDst, pcbResult }),
    };
    return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else sc.STATUS_UNSUCCESSFUL;
}

pub export fn scTestKeyWrapDecrypt(
    pImp: *anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: [*]u8,
    cbDst: usize,
    pcbResult: *usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const kw = &imp.kw_state;
    const ik = imp.imp_kind;
    const scError = switch (kw.kind) {
        .AesKw => callSym(ik, "SymCryptAesKwDecrypt", sc.SymCryptAesKwDecrypt, .{ &kw.key1, pbSrc, cbSrc, pbDst, cbDst, pcbResult }),
        .AesKwp => callSym(ik, "SymCryptAesKwpDecrypt", sc.SymCryptAesKwpDecrypt, .{ &kw.key1, pbSrc, cbSrc, pbDst, cbDst, pcbResult }),
    };
    return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else STATUS_AUTH_TAG_MISMATCH;
}

// ============================================================================
// TlsCbcHmac Implementations
// ============================================================================

pub export fn scTestGetTlsCbcHmacImps(
    algNamePtr: [*]const u8,
    algNameLen: usize,
    outImps: [*]*anyopaque,
    maxImps: usize,
) callconv(.c) usize {
    return getImpsByCategory(.TlsCbcHmac, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestTlsCbcHmacVerify(
    pImp: *anyopaque,
    pbKey: ?[*]const u8,
    cbKey: usize,
    pbHeader: ?[*]const u8,
    cbHeader: usize,
    pbData: ?[*]const u8,
    cbData: usize,
) callconv(.c) i32 {
    const imp: *AlgImp = @ptrCast(@alignCast(pImp));
    const ik = imp.imp_kind;
    var exp_key: [1024]u8 align(64) = @splat(0);
    var hmac_state: [512]u8 align(64) = @splat(0);
    const scError = switch (imp.tls_cbc_hmac_state.kind) {
        .Sha1 => blk: {
            _ = callSym(ik, "SymCryptHmacSha1ExpandKey", sc.SymCryptHmacSha1ExpandKey, .{ &exp_key, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha1Init", sc.SymCryptHmacSha1Init, .{ &hmac_state, &exp_key });
            callSym(ik, "SymCryptHmacSha1Append", sc.SymCryptHmacSha1Append, .{ &hmac_state, pbHeader, cbHeader });
            const mac_alg = getSymPtr(ik, "SymCryptHmacSha1Algorithm", sc.SymCryptHmacSha1Algorithm).?;
            break :blk callSym(ik, "SymCryptTlsCbcHmacVerify", sc.SymCryptTlsCbcHmacVerify, .{ mac_alg, &exp_key, &hmac_state, pbData.?, cbData });
        },
        .Sha256 => blk: {
            _ = callSym(ik, "SymCryptHmacSha256ExpandKey", sc.SymCryptHmacSha256ExpandKey, .{ &exp_key, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha256Init", sc.SymCryptHmacSha256Init, .{ &hmac_state, &exp_key });
            callSym(ik, "SymCryptHmacSha256Append", sc.SymCryptHmacSha256Append, .{ &hmac_state, pbHeader, cbHeader });
            const mac_alg = getSymPtr(ik, "SymCryptHmacSha256Algorithm", sc.SymCryptHmacSha256Algorithm).?;
            break :blk callSym(ik, "SymCryptTlsCbcHmacVerify", sc.SymCryptTlsCbcHmacVerify, .{ mac_alg, &exp_key, &hmac_state, pbData.?, cbData });
        },
        .Sha384 => blk: {
            _ = callSym(ik, "SymCryptHmacSha384ExpandKey", sc.SymCryptHmacSha384ExpandKey, .{ &exp_key, pbKey, cbKey });
            callSym(ik, "SymCryptHmacSha384Init", sc.SymCryptHmacSha384Init, .{ &hmac_state, &exp_key });
            callSym(ik, "SymCryptHmacSha384Append", sc.SymCryptHmacSha384Append, .{ &hmac_state, pbHeader, cbHeader });
            const mac_alg = getSymPtr(ik, "SymCryptHmacSha384Algorithm", sc.SymCryptHmacSha384Algorithm).?;
            break :blk callSym(ik, "SymCryptTlsCbcHmacVerify", sc.SymCryptTlsCbcHmacVerify, .{ mac_alg, &exp_key, &hmac_state, pbData.?, cbData });
        },
    };
    return if (scError == sc.SYMCRYPT_NO_ERROR) 0 else sc.STATUS_UNSUCCESSFUL;
}
