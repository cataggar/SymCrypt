// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const builtin = @import("builtin");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const STATUS_SUCCESS: i32 = 0;

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8007;
const SYMCRYPT_NOT_IMPLEMENTED: u32 = 0x800B;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800C;
const SYMCRYPT_BUFFER_TOO_SMALL: u32 = 0x800D;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800E;
const SYMCRYPT_INCOMPATIBLE_FORMAT: u32 = 0x8011;
const SYMCRYPT_VALUE_TOO_LARGE: u32 = 0x8012;

const SYMCRYPT_HPKE_KEM_ID_NULL: u16 = 0x0000;
const SYMCRYPT_HPKE_KEM_ID_DHKEM_P256: u16 = 0x0010;
const SYMCRYPT_HPKE_KEM_ID_DHKEM_P384: u16 = 0x0011;
const SYMCRYPT_HPKE_KEM_ID_DHKEM_P521: u16 = 0x0012;
const SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519: u16 = 0x0020;
const SYMCRYPT_HPKE_KEM_ID_MLKEM_512: u16 = 0x0040;
const SYMCRYPT_HPKE_KEM_ID_MLKEM_768: u16 = 0x0041;
const SYMCRYPT_HPKE_KEM_ID_MLKEM_1024: u16 = 0x0042;
const SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256: u16 = 0x0050;
const SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384: u16 = 0x0051;
const SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519: u16 = 0x647a;

const SYMCRYPT_HPKE_KDF_ID_NULL: u16 = 0x0000;
const SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256: u16 = 0x0001;
const SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384: u16 = 0x0002;
const SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512: u16 = 0x0003;
const SYMCRYPT_HPKE_KDF_ID_SHAKE128: u16 = 0x0010;
const SYMCRYPT_HPKE_KDF_ID_SHAKE256: u16 = 0x0011;

const SYMCRYPT_HPKE_AEAD_ID_NULL: u16 = 0x0000;
const SYMCRYPT_HPKE_AEAD_ID_AESGCM128: u16 = 0x0001;
const SYMCRYPT_HPKE_AEAD_ID_AESGCM256: u16 = 0x0002;
const SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305: u16 = 0x0003;
const SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY: u16 = 0xFFFF;

const SYMCRYPT_HPKEKEY_FORMAT_NULL: u32 = 0;
const SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY: u32 = 1;
const SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY: u32 = 2;

const SYMCRYPT_HPKE_MAX_EXPORT_SIZE: usize = 16384;
const SYMCRYPT_HPKE_MAX_INFO_SIZE: usize = SYMCRYPT_HPKE_MAX_EXPORT_SIZE;
const SYMCRYPT_HPKE_SEQ_LIMIT: u64 = 0xFFFFFFFF00000000;

const SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE: usize = 1665;
const SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE: usize = 32;
const SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE: usize = 12;
const SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE: usize = 16;
const SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE: usize = 64;
const SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE: usize = 128;

pub const SYMCRYPT_HPKE_CIPHERSUITE = extern struct {
    kemId: u16,
    kdfId: u16,
    aeadId: u16,
};

const SYMCRYPT_HPKE_KEM_PARAMS = extern struct {
    kemId: u16,
    cbSharedSecret: u16,
    cbEnc: u16,
    cbPublicKey: u16,
    cbPrivateKey: u16,
};

const SYMCRYPT_HPKE_AEAD_PARAMS = extern struct {
    aeadId: u16,
    cbKey: u16,
    cbNonce: u16,
    cbTag: u16,
};

const SYMCRYPT_GF128_ELEMENT = extern struct {
    ull: [2]u64 align(16),
};

const SYMCRYPT_GHASH_EXPANDED_KEY = if (builtin.cpu.arch == .x86)
    extern struct {
        tableOffset: u32 align(16),
        tableSpace: [(128 + 1) * @sizeOf(SYMCRYPT_GF128_ELEMENT)]u8,
    }
else
    extern struct {
        table: [128]SYMCRYPT_GF128_ELEMENT align(16),
    };

const SYMCRYPT_AES_EXPANDED_KEY = extern struct {
    RoundKey: [29][4][4]u8 align(16),
    lastEncRoundKey: ?*[4][4]u8,
    lastDecRoundKey: ?*[4][4]u8,
    magic: usize,
};

const SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS = extern union {
    aes: SYMCRYPT_AES_EXPANDED_KEY,
};

const SYMCRYPT_GCM_EXPANDED_KEY = extern struct {
    ghashKey: SYMCRYPT_GHASH_EXPANDED_KEY,
    pBlockCipher: ?*const anyopaque,
    blockcipherKey: SYMCRYPT_GCM_SUPPORTED_BLOCKCIPHER_KEYS,
    cbKey: usize,
    abKey: [32]u8,
    magic: usize,
};

const SYMCRYPT_HPKECONTEXT = extern struct {
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE align(16),
    aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS,
    key: [SYMCRYPT_HPKE_AEAD_MAX_KEY_SIZE]u8,
    baseNonce: [SYMCRYPT_HPKE_AEAD_MAX_NONCE_SIZE]u8,
    exporterSecret: [SYMCRYPT_HPKE_KDF_MAX_HASH_SIZE]u8,
    gcmExpandedKey: SYMCRYPT_GCM_EXPANDED_KEY,
    fGcmKeyExpanded: u8,
    seqNum: u64 align(8),
    state: u32,
    magic: usize,
};

const SYMCRYPT_HPKEKEY = opaque {};

extern fn SymCryptHpkekeyAllocate(params: SYMCRYPT_HPKE_CIPHERSUITE) callconv(.c) ?*SYMCRYPT_HPKEKEY;
extern fn SymCryptHpkekeyFree(pkHpkekey: *SYMCRYPT_HPKEKEY) callconv(.c) void;
extern fn SymCryptHpkeSizeofKeyFormatFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    hpkeKeyFormat: u32,
    pcbKeyFormat: *usize,
) callconv(.c) u32;
extern fn SymCryptHpkeSizeofEncapsCiphertextFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pcbEncapsCiphertext: *usize,
) callconv(.c) u32;
extern fn SymCryptHpkeSizeofAeadOverheadFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pcbAeadOverhead: *usize,
) callconv(.c) u32;
fn SymCryptHpkeMinimumDkpIkmSizeFromParams(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pcbMinIkm: *usize,
) u32 {
    var kemParams: SYMCRYPT_HPKE_KEM_PARAMS = undefined;
    var cs = params;
    cs.kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256;
    cs.aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128;
    const scError = SymCryptHpkeValidateCiphersuite(cs, &kemParams, null);
    if (scError != SYMCRYPT_NO_ERROR) {
        return scError;
    }
    pcbMinIkm.* = kemParams.cbSharedSecret;
    return SYMCRYPT_NO_ERROR;
}

extern fn SymCryptHpkekeyGenerate(pkHpkekey: *SYMCRYPT_HPKEKEY, flags: u32) callconv(.c) u32;

const c_SymCryptHpkekeyDerive = @extern(*const fn (
    pbIkm: ?[*]const u8,
    cbIkm: usize,
    pkHpkekey: *SYMCRYPT_HPKEKEY,
    flags: u32,
) callconv(.c) u32, .{ .name = "SymCryptHpkekeyDerive" });

fn SymCryptHpkekeyDerive(
    pkHpkekey: *SYMCRYPT_HPKEKEY,
    pbIkm: ?[*]const u8,
    cbIkm: usize,
    flags: u32,
) u32 {
    if (pbIkm == null) return SYMCRYPT_INVALID_ARGUMENT;
    return c_SymCryptHpkekeyDerive(pbIkm, cbIkm, pkHpkekey, flags);
}

extern fn SymCryptHpkekeySetValue(
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    hpkeKeyFormat: u32,
    flags: u32,
    pkHpkekey: *SYMCRYPT_HPKEKEY,
) callconv(.c) u32;
extern fn SymCryptHpkekeyGetValue(
    pkHpkekey: *const SYMCRYPT_HPKEKEY,
    pbDst: ?[*]u8,
    cbDst: usize,
    hpkeKeyFormat: u32,
    flags: u32,
) callconv(.c) u32;

extern fn SymCryptHpkeContextAllocate(params: SYMCRYPT_HPKE_CIPHERSUITE) callconv(.c) ?*SYMCRYPT_HPKECONTEXT;
extern fn SymCryptHpkeContextFree(pHpkeContext: ?*SYMCRYPT_HPKECONTEXT) callconv(.c) void;

const c_SymCryptHpkeSetupSender = @extern(*const fn (
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
    flags: u32,
) callconv(.c) u32, .{ .name = "SymCryptHpkeSetupSender" });

fn SymCryptHpkeSetupSender(
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
) u32 {
    return c_SymCryptHpkeSetupSender(pHpkeContext, pkRecipient, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbEnc, cbEnc, 0);
}

const c_SymCryptHpkeSetupRecipient = @extern(*const fn (
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    flags: u32,
) callconv(.c) u32, .{ .name = "SymCryptHpkeSetupRecipient" });

fn SymCryptHpkeSetupRecipient(
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
) u32 {
    return c_SymCryptHpkeSetupRecipient(pHpkeContext, pkRecipient, pbEnc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, 0);
}

extern fn SymCryptHpkeSeal(
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
    pu64SeqNumber: ?*u64,
) callconv(.c) u32;
extern fn SymCryptHpkeOpen(
    pHpkeContext: *SYMCRYPT_HPKECONTEXT,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) u32;
extern fn SymCryptHpkeOpenUnordered(
    pHpkeContext: *const SYMCRYPT_HPKECONTEXT,
    u64SeqNumber: u64,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) u32;
extern fn SymCryptHpkeSecretExport(
    pHpkeContext: *const SYMCRYPT_HPKECONTEXT,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbResult: ?[*]u8,
    cbResult: u16,
) callconv(.c) u32;

const c_SymCryptHpkeSealSingleShot = @extern(*const fn (
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
    flags: u32,
) callconv(.c) u32, .{ .name = "SymCryptHpkeSealSingleShot" });

fn SymCryptHpkeSealSingleShot(
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) u32 {
    return c_SymCryptHpkeSealSingleShot(pkRecipient, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbAuthData, cbAuthData, pbSrc, cbSrc, pbEnc, cbEnc, pbDst, cbDst, 0);
}

const c_SymCryptHpkeOpenSingleShot = @extern(*const fn (
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
    flags: u32,
) callconv(.c) u32, .{ .name = "SymCryptHpkeOpenSingleShot" });

fn SymCryptHpkeOpenSingleShot(
    pkRecipient: *const SYMCRYPT_HPKEKEY,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) u32 {
    return c_SymCryptHpkeOpenSingleShot(pkRecipient, pbEnc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbAuthData, cbAuthData, pbSrc, cbSrc, pbDst, cbDst, 0);
}

extern fn SymCryptHpkeValidateCiphersuite(
    params: SYMCRYPT_HPKE_CIPHERSUITE,
    pKemParams: ?*SYMCRYPT_HPKE_KEM_PARAMS,
    pAeadParams: ?*SYMCRYPT_HPKE_AEAD_PARAMS,
) callconv(.c) u32;

extern fn scTestHpkeCount(algName: [*:0]const u8) callconv(.c) usize;
extern fn scTestHpkeCreate(algName: [*:0]const u8, index: usize) callconv(.c) ?*anyopaque;
extern fn scTestHpkeFree(handle: *anyopaque) callconv(.c) void;
extern fn scTestHpkeGetLastError(handle: *anyopaque) callconv(.c) [*:0]const u8;
extern fn scTestHpkeSetKey(
    handle: *anyopaque,
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE,
    format: u32,
    pbKey: ?[*]const u8,
    cbKey: usize,
) callconv(.c) i32;
extern fn scTestHpkeGetKey(
    handle: *anyopaque,
    format: u32,
    pbKey: [*]u8,
    cbKey: usize,
) callconv(.c) i32;
extern fn scTestHpkeDeriveKeyPair(
    handle: *anyopaque,
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE,
    pbIkm: [*]const u8,
    cbIkm: usize,
) callconv(.c) i32;
extern fn scTestHpkeSealSingleShot(
    handle: *anyopaque,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAad: ?[*]const u8,
    cbAad: usize,
    pbPlaintext: ?[*]const u8,
    cbPlaintext: usize,
    pbEnc: [*]u8,
    cbEnc: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) i32;
extern fn scTestHpkeOpenSingleShot(
    handle: *anyopaque,
    pbEnc: [*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAad: ?[*]const u8,
    cbAad: usize,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pbPlaintext: ?[*]u8,
    cbPlaintext: usize,
) callconv(.c) i32;
extern fn scTestHpkeSecretExportSingleShot(
    handle: *anyopaque,
    pbEnc: [*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbExportedValue: [*]u8,
    cbExportedValue: u16,
) callconv(.c) i32;
extern fn scTestHpkeSetupSender(
    handle: *anyopaque,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: [*]u8,
    cbEnc: usize,
) callconv(.c) i32;
extern fn scTestHpkeSetupSenderDeterministic(
    handle: *anyopaque,
    pbRandom: [*]const u8,
    cbRandom: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: [*]u8,
    cbEnc: usize,
) callconv(.c) i32;
extern fn scTestHpkeSetupRecipient(
    handle: *anyopaque,
    pbEnc: [*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
) callconv(.c) i32;
extern fn scTestHpkeSeal(
    handle: *anyopaque,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: [*]u8,
    cbDst: usize,
    pu64SeqNumber: ?*u64,
) callconv(.c) i32;
extern fn scTestHpkeOpen(
    handle: *anyopaque,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: [*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) i32;
extern fn scTestHpkeOpenUnordered(
    handle: *anyopaque,
    u64SeqNumber: u64,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: [*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) i32;
extern fn scTestHpkeSecretExportSender(
    handle: *anyopaque,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbResult: [*]u8,
    cbResult: u16,
) callconv(.c) i32;
extern fn scTestHpkeSecretExportRecipient(
    handle: *anyopaque,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbResult: [*]u8,
    cbResult: u16,
) callconv(.c) i32;
extern fn scTestHpkeEncSize(handle: *anyopaque) callconv(.c) usize;

const g_supportedKemIds = [_]u16{
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
    SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
    SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
    SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
    SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
};

const g_supportedKdfIds = [_]u16{
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
    SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512,
    SYMCRYPT_HPKE_KDF_ID_SHAKE128,
    SYMCRYPT_HPKE_KDF_ID_SHAKE256,
};

const g_supportedAeadIds = [_]u16{
    SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
    SYMCRYPT_HPKE_AEAD_ID_AESGCM256,
    SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305,
};

const HpkeTestCiphersuite = struct {
    name: [:0]const u8,
    cs: SYMCRYPT_HPKE_CIPHERSUITE,
};

const g_rgTestHpkeCiphersuites = [_]HpkeTestCiphersuite{
    // DHKEM(P-256)
    .{ .name = "DHKEM-P256 / HKDF-SHA256 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    .{ .name = "DHKEM-P256 / HKDF-SHA256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "DHKEM-P256 / HKDF-SHA256 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
    // DHKEM(P-384)
    .{ .name = "DHKEM-P384 / HKDF-SHA384 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    .{ .name = "DHKEM-P384 / HKDF-SHA384 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "DHKEM-P384 / HKDF-SHA384 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
    // DHKEM(P-521)
    .{ .name = "DHKEM-P521 / HKDF-SHA512 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P521, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    .{ .name = "DHKEM-P521 / HKDF-SHA512 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P521, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "DHKEM-P521 / HKDF-SHA512 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P521, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
    // DHKEM(X25519)
    .{ .name = "DHKEM-X25519 / HKDF-SHA256 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    .{ .name = "DHKEM-X25519 / HKDF-SHA256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "DHKEM-X25519 / HKDF-SHA256 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
    // ML-KEM-512
    .{ .name = "ML-KEM-512 / SHAKE128 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_512, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE128, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    .{ .name = "ML-KEM-512 / HKDF-SHA256 / AES-128-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_512, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 } },
    // ML-KEM-768
    .{ .name = "ML-KEM-768 / SHAKE256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "ML-KEM-768 / HKDF-SHA256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "ML-KEM-768 / HKDF-SHA256 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
    // ML-KEM-1024
    .{ .name = "ML-KEM-1024 / SHAKE256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_1024, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "ML-KEM-1024 / HKDF-SHA512 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_1024, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA512, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    // Composite ML-KEM
    .{ .name = "MLKEM768-P256 / SHAKE256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "MLKEM768-P256 / HKDF-SHA256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "MLKEM1024-P384 / SHAKE256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "MLKEM1024-P384 / HKDF-SHA384 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "MLKEM768-X25519 / SHAKE256 / AES-256-GCM", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 } },
    .{ .name = "MLKEM768-X25519 / HKDF-SHA256 / ChaCha20Poly1305", .cs = .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 } },
};

const HpkeMultiImp = struct {
    m_handles: std.ArrayListUnmanaged(*anyopaque) = .empty,
    m_comps: std.ArrayListUnmanaged(*anyopaque) = .empty,

    pub fn init(algName: [:0]const u8) HpkeMultiImp {
        var self = HpkeMultiImp{};
        const count = scTestHpkeCount(algName.ptr);
        for (0..count) |i| {
            if (scTestHpkeCreate(algName.ptr, i)) |handle| {
                self.m_handles.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
                self.m_comps.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
            }
        }
        return self;
    }

    pub fn deinit(self: *HpkeMultiImp) void {
        for (self.m_handles.items) |handle| {
            scTestHpkeFree(handle);
        }
        self.m_handles.deinit(std.heap.c_allocator);
        self.m_comps.deinit(std.heap.c_allocator);
    }

    pub fn getLastError(self: *const HpkeMultiImp) []const u8 {
        for (self.m_comps.items) |handle| {
            const err = std.mem.span(scTestHpkeGetLastError(handle));
            if (err.len > 0) return err;
        }
        return "";
    }

    pub fn setKey(
        self: *HpkeMultiImp,
        ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE,
        format: u32,
        pbKey: ?[*]const u8,
        cbKey: usize,
    ) i32 {
        self.m_comps.clearRetainingCapacity();
        for (self.m_handles.items) |handle| {
            if (scTestHpkeSetKey(handle, ciphersuite, format, pbKey, cbKey) == STATUS_SUCCESS) {
                self.m_comps.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
            }
        }
        return if (self.m_comps.items.len == 0) -1 else STATUS_SUCCESS;
    }

    pub fn getKey(self: *HpkeMultiImp, format: u32, pbKey: [*]u8, cbKey: usize) i32 {
        var resKey = rm.ResultMerge.init();
        defer resKey.deinit();

        const buf = std.heap.c_allocator.alloc(u8, cbKey) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeGetKey(handle, format, buf.ptr, cbKey);
            if (status != STATUS_SUCCESS) return status;
            resKey.addResult(handle, buf);
        }
        resKey.getResult(pbKey[0..cbKey]);
        return status;
    }

    pub fn deriveKeyPair(
        self: *HpkeMultiImp,
        ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE,
        pbIkm: [*]const u8,
        cbIkm: usize,
    ) i32 {
        self.m_comps.clearRetainingCapacity();
        for (self.m_handles.items) |handle| {
            if (scTestHpkeDeriveKeyPair(handle, ciphersuite, pbIkm, cbIkm) == STATUS_SUCCESS) {
                self.m_comps.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
            }
        }
        return if (self.m_comps.items.len == 0) -1 else STATUS_SUCCESS;
    }

    pub fn sealSingleShot(
        self: *HpkeMultiImp,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
        pbAad: ?[*]const u8,
        cbAad: usize,
        pbPlaintext: ?[*]const u8,
        cbPlaintext: usize,
        pbEnc: [*]u8,
        cbEnc: usize,
        pbCiphertext: [*]u8,
        cbCiphertext: usize,
    ) i32 {
        if (self.m_comps.items.len == 0) return -1;
        const idx = rng.g_rng.uint32() % self.m_comps.items.len;
        return scTestHpkeSealSingleShot(
            self.m_comps.items[idx],
            pbInfo,
            cbInfo,
            pbPsk,
            cbPsk,
            pbPskId,
            cbPskId,
            pbAad,
            cbAad,
            pbPlaintext,
            cbPlaintext,
            pbEnc,
            cbEnc,
            pbCiphertext,
            cbCiphertext,
        );
    }

    pub fn openSingleShot(
        self: *HpkeMultiImp,
        pbEnc: [*]const u8,
        cbEnc: usize,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
        pbAad: ?[*]const u8,
        cbAad: usize,
        pbCiphertext: [*]const u8,
        cbCiphertext: usize,
        pbPlaintext: ?[*]u8,
        cbPlaintext: usize,
    ) i32 {
        if (self.m_comps.items.len == 0) return -1;

        var resPt = rm.ResultMerge.init();
        defer resPt.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(cbPlaintext, 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbPlaintext > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeOpenSingleShot(
                handle,
                pbEnc,
                cbEnc,
                pbInfo,
                cbInfo,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
                pbAad,
                cbAad,
                pbCiphertext,
                cbCiphertext,
                if (cbPlaintext > 0) buf.ptr else null,
                cbPlaintext,
            );
            if (status != STATUS_SUCCESS) return status;
            if (cbPlaintext > 0) resPt.addResult(handle, buf[0..cbPlaintext]);
        }
        if (cbPlaintext > 0) {
            resPt.getResult(pbPlaintext.?[0..cbPlaintext]);
        }
        return status;
    }

    pub fn secretExportSingleShot(
        self: *HpkeMultiImp,
        pbEnc: [*]const u8,
        cbEnc: usize,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
        pbExporterContext: ?[*]const u8,
        cbExporterContext: usize,
        pbExportedValue: [*]u8,
        cbExportedValue: u16,
    ) i32 {
        if (self.m_comps.items.len == 0) return -1;

        var resVal = rm.ResultMerge.init();
        defer resVal.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(@as(usize, cbExportedValue), 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbExportedValue > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeSecretExportSingleShot(
                handle,
                pbEnc,
                cbEnc,
                pbInfo,
                cbInfo,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
                pbExporterContext,
                cbExporterContext,
                buf.ptr,
                cbExportedValue,
            );
            if (status != STATUS_SUCCESS) return status;
            if (cbExportedValue > 0) resVal.addResult(handle, buf[0..cbExportedValue]);
        }
        if (cbExportedValue > 0) {
            resVal.getResult(pbExportedValue[0..cbExportedValue]);
        }
        return status;
    }

    pub fn setupSender(
        self: *HpkeMultiImp,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
        pbEnc: [*]u8,
        cbEnc: usize,
    ) i32 {
        if (self.m_comps.items.len == 0) return -1;
        const idx = rng.g_rng.uint32() % self.m_comps.items.len;
        const chosen = self.m_comps.items[idx];
        self.m_comps.clearRetainingCapacity();
        self.m_comps.append(std.heap.c_allocator, chosen) catch h.fatal("Out of memory", .{});
        return scTestHpkeSetupSender(
            chosen,
            pbInfo,
            cbInfo,
            pbPsk,
            cbPsk,
            pbPskId,
            cbPskId,
            pbEnc,
            cbEnc,
        );
    }

    pub fn setupSenderDeterministic(
        self: *HpkeMultiImp,
        pbRandom: [*]const u8,
        cbRandom: usize,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
        pbEnc: [*]u8,
        cbEnc: usize,
    ) i32 {
        var resEnc = rm.ResultMerge.init();
        defer resEnc.deinit();

        const buf = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        self.m_comps.clearRetainingCapacity();
        for (self.m_handles.items, 0..) |handle, idx| {
            buf[0] = @intCast((idx + 1) & 0xff);
            if (scTestHpkeSetupSenderDeterministic(
                handle,
                pbRandom,
                cbRandom,
                pbInfo,
                cbInfo,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
                buf.ptr,
                cbEnc,
            ) == STATUS_SUCCESS) {
                self.m_comps.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
                resEnc.addResult(handle, buf);
            }
        }
        if (self.m_comps.items.len == 0) return -1;
        resEnc.getResult(pbEnc[0..cbEnc]);
        return STATUS_SUCCESS;
    }

    pub fn setupRecipient(
        self: *HpkeMultiImp,
        pbEnc: [*]const u8,
        cbEnc: usize,
        pbInfo: ?[*]const u8,
        cbInfo: usize,
        pbPsk: ?[*]const u8,
        cbPsk: usize,
        pbPskId: ?[*]const u8,
        cbPskId: usize,
    ) i32 {
        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items) |handle| {
            status = scTestHpkeSetupRecipient(
                handle,
                pbEnc,
                cbEnc,
                pbInfo,
                cbInfo,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
            );
            if (status != STATUS_SUCCESS) return status;
        }
        return status;
    }

    pub fn seal(
        self: *HpkeMultiImp,
        pbAuthData: ?[*]const u8,
        cbAuthData: usize,
        pbSrc: ?[*]const u8,
        cbSrc: usize,
        pbDst: [*]u8,
        cbDst: usize,
        pu64SeqNumber: ?*u64,
    ) i32 {
        var resCt = rm.ResultMerge.init();
        defer resCt.deinit();

        const buf = std.heap.c_allocator.alloc(u8, cbDst) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeSeal(handle, pbAuthData, cbAuthData, pbSrc, cbSrc, buf.ptr, cbDst, pu64SeqNumber);
            if (status != STATUS_SUCCESS) return status;
            resCt.addResult(handle, buf);
        }
        resCt.getResult(pbDst[0..cbDst]);
        return status;
    }

    pub fn open(
        self: *HpkeMultiImp,
        pbAuthData: ?[*]const u8,
        cbAuthData: usize,
        pbSrc: [*]const u8,
        cbSrc: usize,
        pbDst: ?[*]u8,
        cbDst: usize,
    ) i32 {
        var resPt = rm.ResultMerge.init();
        defer resPt.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(cbDst, 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbDst > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeOpen(
                handle,
                pbAuthData,
                cbAuthData,
                pbSrc,
                cbSrc,
                if (cbDst > 0) buf.ptr else null,
                cbDst,
            );
            if (status != STATUS_SUCCESS) return status;
            if (cbDst > 0) resPt.addResult(handle, buf[0..cbDst]);
        }
        if (cbDst > 0) {
            resPt.getResult(pbDst.?[0..cbDst]);
        }
        return status;
    }

    pub fn openUnordered(
        self: *HpkeMultiImp,
        u64SeqNumber: u64,
        pbAuthData: ?[*]const u8,
        cbAuthData: usize,
        pbSrc: [*]const u8,
        cbSrc: usize,
        pbDst: ?[*]u8,
        cbDst: usize,
    ) i32 {
        var resPt = rm.ResultMerge.init();
        defer resPt.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(cbDst, 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbDst > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeOpenUnordered(
                handle,
                u64SeqNumber,
                pbAuthData,
                cbAuthData,
                pbSrc,
                cbSrc,
                if (cbDst > 0) buf.ptr else null,
                cbDst,
            );
            if (status != STATUS_SUCCESS) return status;
            if (cbDst > 0) resPt.addResult(handle, buf[0..cbDst]);
        }
        if (cbDst > 0) {
            resPt.getResult(pbDst.?[0..cbDst]);
        }
        return status;
    }

    pub fn secretExportSender(
        self: *HpkeMultiImp,
        pbExporterContext: ?[*]const u8,
        cbExporterContext: usize,
        pbResult: [*]u8,
        cbResult: u16,
    ) i32 {
        var resVal = rm.ResultMerge.init();
        defer resVal.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(@as(usize, cbResult), 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbResult > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeSecretExportSender(handle, pbExporterContext, cbExporterContext, buf.ptr, cbResult);
            if (status != STATUS_SUCCESS) return status;
            if (cbResult > 0) resVal.addResult(handle, buf[0..cbResult]);
        }
        if (cbResult > 0) {
            resVal.getResult(pbResult[0..cbResult]);
        }
        return status;
    }

    pub fn secretExportRecipient(
        self: *HpkeMultiImp,
        pbExporterContext: ?[*]const u8,
        cbExporterContext: usize,
        pbResult: [*]u8,
        cbResult: u16,
    ) i32 {
        var resVal = rm.ResultMerge.init();
        defer resVal.deinit();

        const buf = std.heap.c_allocator.alloc(u8, @max(@as(usize, cbResult), 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_comps.items, 0..) |handle, idx| {
            if (cbResult > 0) buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestHpkeSecretExportRecipient(handle, pbExporterContext, cbExporterContext, buf.ptr, cbResult);
            if (status != STATUS_SUCCESS) return status;
            if (cbResult > 0) resVal.addResult(handle, buf[0..cbResult]);
        }
        if (cbResult > 0) {
            resVal.getResult(pbResult[0..cbResult]);
        }
        return status;
    }

    pub fn encSize(self: *const HpkeMultiImp) usize {
        if (self.m_comps.items.len == 0) return 0;
        return scTestHpkeEncSize(self.m_comps.items[0]);
    }
};

fn testHpkeRoundTrip(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    var cbAeadOverhead: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed for {s}", tcs.name);
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbAeadOverhead);
    h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed for {s}", tcs.name);

    const pkRecipient = SymCryptHpkekeyAllocate(cs);
    h.check3(pkRecipient != null, "HpkekeyAllocate failed for {s}", tcs.name);
    defer SymCryptHpkekeyFree(pkRecipient.?);

    scError = SymCryptHpkekeyGenerate(pkRecipient.?, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed for {s}", tcs.name);

    var cbPubKey: usize = 0;
    scError = SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPubKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat(PUBLIC_KEY) failed");

    const pubKeyBlob = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubKeyBlob);
    scError = SymCryptHpkekeyGetValue(pkRecipient.?, pubKeyBlob.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkekeyGetValue(PUBLIC_KEY) failed for {s}", tcs.name);

    const pkSenderView = SymCryptHpkekeyAllocate(cs);
    h.check(pkSenderView != null, "HpkekeyAllocate (sender view) failed");
    defer SymCryptHpkekeyFree(pkSenderView.?);

    scError = SymCryptHpkekeySetValue(pubKeyBlob.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0, pkSenderView.?);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkekeySetValue(PUBLIC_KEY) failed for {s}", tcs.name);

    const info = "SymCrypt HPKE round-trip test info";
    const aad = "associated data";
    const plaintext = "The quick brown fox jumps over the lazy dog.";

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null, "HpkeContextAllocate (sender) failed");
    defer SymCryptHpkeContextFree(pSenderCtx);

    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pRecipientCtx != null, "HpkeContextAllocate (recipient) failed");
    defer SymCryptHpkeContextFree(pRecipientCtx);

    scError = SymCryptHpkeSetupSender(
        pSenderCtx.?,
        pkSenderView.?,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        enc.ptr,
        enc.len,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed for {s}", tcs.name);

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx.?,
        pkRecipient.?,
        enc.ptr,
        enc.len,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed for {s}", tcs.name);

    const cbPlaintext = plaintext.len;
    const cbCiphertext = cbPlaintext + cbAeadOverhead;
    const ciphertext = std.heap.c_allocator.alloc(u8, cbCiphertext) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ciphertext);
    const decrypted = std.heap.c_allocator.alloc(u8, cbPlaintext) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(decrypted);

    var seqNum: u64 = 0xDEAD;
    scError = SymCryptHpkeSeal(
        pSenderCtx.?,
        aad.ptr,
        aad.len,
        plaintext.ptr,
        cbPlaintext,
        ciphertext.ptr,
        cbCiphertext,
        &seqNum,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSeal failed for {s}", tcs.name);
    h.check3(seqNum == 0, "First Seal sequence number should be 0 for {s}", tcs.name);

    scError = SymCryptHpkeOpen(
        pRecipientCtx.?,
        aad.ptr,
        aad.len,
        ciphertext.ptr,
        cbCiphertext,
        decrypted.ptr,
        cbPlaintext,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeOpen failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, decrypted, plaintext), "Plaintext mismatch for {s}", tcs.name);

    const inPlaceBuf = std.heap.c_allocator.alloc(u8, cbCiphertext) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(inPlaceBuf);
    @memcpy(inPlaceBuf[0..cbPlaintext], plaintext);

    scError = SymCryptHpkeSeal(
        pSenderCtx.?,
        aad.ptr,
        aad.len,
        inPlaceBuf.ptr,
        cbPlaintext,
        inPlaceBuf.ptr,
        cbCiphertext,
        &seqNum,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSeal (in-place) failed for {s}", tcs.name);
    h.check3(seqNum == 1, "Second Seal sequence number should be 1 for {s}", tcs.name);

    scError = SymCryptHpkeOpen(
        pRecipientCtx.?,
        aad.ptr,
        aad.len,
        inPlaceBuf.ptr,
        cbCiphertext,
        inPlaceBuf.ptr,
        cbPlaintext,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeOpen (in-place) failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, inPlaceBuf[0..cbPlaintext], plaintext), "In-place plaintext mismatch for {s}", tcs.name);

    @memcpy(inPlaceBuf[0..cbPlaintext], plaintext);
    scError = SymCryptHpkeSeal(
        pSenderCtx.?,
        aad.ptr,
        aad.len,
        inPlaceBuf.ptr,
        cbPlaintext,
        inPlaceBuf.ptr,
        cbCiphertext,
        &seqNum,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSeal (for OpenUnordered in-place) failed for {s}", tcs.name);

    scError = SymCryptHpkeOpenUnordered(
        pRecipientCtx.?,
        seqNum,
        aad.ptr,
        aad.len,
        inPlaceBuf.ptr,
        cbCiphertext,
        inPlaceBuf.ptr,
        cbPlaintext,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeOpenUnordered (in-place) failed for {s}", tcs.name);
    h.check3(
        std.mem.eql(u8, inPlaceBuf[0..cbPlaintext], plaintext),
        "In-place OpenUnordered plaintext mismatch for {s}",
        tcs.name,
    );
}

fn testHpkeMultipleMessages(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    var cbAeadOverhead: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbAeadOverhead);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");

    const pkKey = SymCryptHpkekeyAllocate(cs);
    h.check(pkKey != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkKey.?);

    scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null, "HpkeContextAllocate (sender) failed");
    defer SymCryptHpkeContextFree(pSenderCtx);

    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pRecipientCtx != null, "HpkeContextAllocate (recipient) failed");
    defer SymCryptHpkeContextFree(pRecipientCtx);

    scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, null, 0, null, 0, null, 0, enc.ptr, enc.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed");

    scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, null, 0, null, 0, null, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed");

    const nMessages: usize = 10;
    var ciphertexts: [nMessages][]u8 = undefined;
    var plaintexts: [nMessages][]u8 = undefined;
    var aads: [nMessages][]u8 = undefined;
    var seqNums: [nMessages]u64 = @splat(0);

    defer {
        for (0..nMessages) |i| {
            std.heap.c_allocator.free(ciphertexts[i]);
            std.heap.c_allocator.free(plaintexts[i]);
            std.heap.c_allocator.free(aads[i]);
        }
    }

    for (0..nMessages) |i| {
        const cbPt: usize = i * 17;
        const cbAad: usize = i * 7;

        plaintexts[i] = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
        aads[i] = std.heap.c_allocator.alloc(u8, cbAad) catch h.fatal("Out of memory", .{});
        ciphertexts[i] = std.heap.c_allocator.alloc(u8, cbPt + cbAeadOverhead) catch h.fatal("Out of memory", .{});

        for (0..cbPt) |j| plaintexts[i][j] = rng.g_rng.byte();
        for (0..cbAad) |j| aads[i][j] = rng.g_rng.byte();

        scError = SymCryptHpkeSeal(
            pSenderCtx.?,
            if (cbAad > 0) aads[i].ptr else null,
            cbAad,
            if (cbPt > 0) plaintexts[i].ptr else null,
            cbPt,
            ciphertexts[i].ptr,
            ciphertexts[i].len,
            &seqNums[i],
        );
        h.check4(scError == SYMCRYPT_NO_ERROR, "HpkeSeal #{d} failed for {s}", i, tcs.name);
        h.check4(seqNums[i] == i, "HpkeSeal #{d} seqNum mismatch for {s}", i, tcs.name);
    }

    for (0..nMessages) |i| {
        const cbPt = plaintexts[i].len;
        const decrypted = std.heap.c_allocator.alloc(u8, @max(cbPt, 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(decrypted);

        scError = SymCryptHpkeOpen(
            pRecipientCtx.?,
            if (aads[i].len > 0) aads[i].ptr else null,
            aads[i].len,
            ciphertexts[i].ptr,
            ciphertexts[i].len,
            if (cbPt > 0) decrypted.ptr else null,
            cbPt,
        );
        h.check4(scError == SYMCRYPT_NO_ERROR, "HpkeOpen #{d} failed for {s}", i, tcs.name);
        if (cbPt > 0) {
            h.check4(std.mem.eql(u8, decrypted[0..cbPt], plaintexts[i]), "HpkeOpen #{d} plaintext mismatch for {s}", i, tcs.name);
        }
    }

    var idx: usize = nMessages;
    while (idx > 0) {
        idx -= 1;
        const cbPt = plaintexts[idx].len;
        const decrypted = std.heap.c_allocator.alloc(u8, @max(cbPt, 1)) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(decrypted);

        scError = SymCryptHpkeOpenUnordered(
            pRecipientCtx.?,
            seqNums[idx],
            if (aads[idx].len > 0) aads[idx].ptr else null,
            aads[idx].len,
            ciphertexts[idx].ptr,
            ciphertexts[idx].len,
            if (cbPt > 0) decrypted.ptr else null,
            cbPt,
        );
        h.check4(scError == SYMCRYPT_NO_ERROR, "HpkeOpenUnordered #{d} failed for {s}", idx, tcs.name);
        if (cbPt > 0) {
            h.check4(
                std.mem.eql(u8, decrypted[0..cbPt], plaintexts[idx]),
                "HpkeOpenUnordered #{d} plaintext mismatch for {s}",
                idx,
                tcs.name,
            );
        }
    }
}

fn testHpkePsk(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    var cbAeadOverhead: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbAeadOverhead);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");

    const pkKey = SymCryptHpkekeyAllocate(cs);
    h.check(pkKey != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkKey.?);

    scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    var psk: [32]u8 = undefined;
    for (0..psk.len) |i| psk[i] = rng.g_rng.byte();
    const pskId = "my-psk-identifier-2026";
    const info = "psk-mode-info";
    const plaintext = "PSK mode test message";

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null, "HpkeContextAllocate (sender) failed");
    defer SymCryptHpkeContextFree(pSenderCtx);

    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pRecipientCtx != null, "HpkeContextAllocate (recipient) failed");
    defer SymCryptHpkeContextFree(pRecipientCtx);

    scError = SymCryptHpkeSetupSender(
        pSenderCtx.?,
        pkKey.?,
        info.ptr,
        info.len,
        &psk,
        psk.len,
        pskId.ptr,
        pskId.len,
        enc.ptr,
        enc.len,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender (PSK) failed for {s}", tcs.name);

    scError = SymCryptHpkeSetupRecipient(
        pRecipientCtx.?,
        pkKey.?,
        enc.ptr,
        enc.len,
        info.ptr,
        info.len,
        &psk,
        psk.len,
        pskId.ptr,
        pskId.len,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient (PSK) failed for {s}", tcs.name);

    const cbPt = plaintext.len;
    const cbCt = cbPt + cbAeadOverhead;
    const ct = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ct);
    const decrypted = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(decrypted);

    scError = SymCryptHpkeSeal(pSenderCtx.?, null, 0, plaintext.ptr, cbPt, ct.ptr, cbCt, null);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeSeal (PSK) failed for {s}", tcs.name);

    scError = SymCryptHpkeOpen(pRecipientCtx.?, null, 0, ct.ptr, cbCt, decrypted.ptr, cbPt);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkeOpen (PSK) failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, decrypted, plaintext), "PSK plaintext mismatch for {s}", tcs.name);

    var wrongPsk: [32]u8 = psk;
    wrongPsk[0] ^= 0xFF;

    const pBadRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pBadRecipientCtx != null, "HpkeContextAllocate (bad recipient) failed");
    defer SymCryptHpkeContextFree(pBadRecipientCtx);

    scError = SymCryptHpkeSetupRecipient(
        pBadRecipientCtx.?,
        pkKey.?,
        enc.ptr,
        enc.len,
        info.ptr,
        info.len,
        &wrongPsk,
        wrongPsk.len,
        pskId.ptr,
        pskId.len,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient with wrong PSK should succeed at setup");

    scError = SymCryptHpkeOpen(pBadRecipientCtx.?, null, 0, ct.ptr, cbCt, decrypted.ptr, cbPt);
    h.check3(scError == SYMCRYPT_AUTHENTICATION_FAILURE, "HpkeOpen with wrong PSK should fail for {s}", tcs.name);
}

fn testHpkeSecretExport(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");

    const pkKey = SymCryptHpkekeyAllocate(cs);
    h.check(pkKey != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkKey.?);

    scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null, "HpkeContextAllocate (sender) failed");
    defer SymCryptHpkeContextFree(pSenderCtx);

    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pRecipientCtx != null, "HpkeContextAllocate (recipient) failed");
    defer SymCryptHpkeContextFree(pRecipientCtx);

    scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, null, 0, null, 0, null, 0, enc.ptr, enc.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed");

    scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, null, 0, null, 0, null, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed");

    const exportCtx1 = "exporter context 1";
    const exportCtx2 = "exporter context 2";
    const exportLengths = [_]u16{ 16, 32, 48, 64, 128 };

    for (exportLengths) |L| {
        const senderSecret = std.heap.c_allocator.alloc(u8, L) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(senderSecret);
        const recipientSecret = std.heap.c_allocator.alloc(u8, L) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(recipientSecret);
        const differentCtxSecret = std.heap.c_allocator.alloc(u8, L) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(differentCtxSecret);

        scError = SymCryptHpkeSecretExport(
            pSenderCtx.?,
            exportCtx1.ptr,
            exportCtx1.len,
            senderSecret.ptr,
            L,
        );
        h.check3(scError == SYMCRYPT_NO_ERROR, "SecretExport (sender) failed for {s}", tcs.name);

        scError = SymCryptHpkeSecretExport(
            pRecipientCtx.?,
            exportCtx1.ptr,
            exportCtx1.len,
            recipientSecret.ptr,
            L,
        );
        h.check3(scError == SYMCRYPT_NO_ERROR, "SecretExport (recipient) failed for {s}", tcs.name);

        h.check3(std.mem.eql(u8, senderSecret, recipientSecret), "Exported secrets mismatch for {s}", tcs.name);

        scError = SymCryptHpkeSecretExport(
            pSenderCtx.?,
            exportCtx2.ptr,
            exportCtx2.len,
            differentCtxSecret.ptr,
            L,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport (different context) failed");
        h.check3(
            !std.mem.eql(u8, senderSecret, differentCtxSecret),
            "Different exporter contexts produced identical secrets for {s}",
            tcs.name,
        );
    }

    var emptyCtxSender: [32]u8 = undefined;
    var emptyCtxRecipient: [32]u8 = undefined;
    scError = SymCryptHpkeSecretExport(pSenderCtx.?, null, 0, &emptyCtxSender, emptyCtxSender.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport with empty context failed");
    scError = SymCryptHpkeSecretExport(pRecipientCtx.?, null, 0, &emptyCtxRecipient, emptyCtxRecipient.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport with empty context (recipient) failed");
    h.check(
        std.mem.eql(u8, &emptyCtxSender, &emptyCtxRecipient),
        "Exported secrets with empty context mismatch",
    );
}

fn testHpkeExportOnly() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;

    const exportOnlySuites = [_]SYMCRYPT_HPKE_CIPHERSUITE{
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P384, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY },
    };

    for (exportOnlySuites) |cs| {
        var cbEnc: usize = 0;
        var cbOverhead: usize = 0;
        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed for ExportOnly");

        scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SizeofAeadOverhead should fail for ExportOnly");

        const pkKey = SymCryptHpkekeyAllocate(cs);
        h.check(pkKey != null, "HpkekeyAllocate failed for ExportOnly");
        defer SymCryptHpkekeyFree(pkKey.?);

        scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed for ExportOnly");

        const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(enc);

        const pSenderCtx = SymCryptHpkeContextAllocate(cs);
        h.check(pSenderCtx != null, "HpkeContextAllocate (sender) failed for ExportOnly");
        defer SymCryptHpkeContextFree(pSenderCtx);

        const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
        h.check(pRecipientCtx != null, "HpkeContextAllocate (recipient) failed for ExportOnly");
        defer SymCryptHpkeContextFree(pRecipientCtx);

        scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, null, 0, null, 0, null, 0, enc.ptr, enc.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed for ExportOnly");

        scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, null, 0, null, 0, null, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed for ExportOnly");

        var dummyPt: [16]u8 = @splat(0);
        var dummyCt: [32]u8 = @splat(0);
        scError = SymCryptHpkeSeal(pSenderCtx.?, null, 0, &dummyPt, dummyPt.len, &dummyCt, dummyCt.len, null);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Seal on ExportOnly context must fail");

        scError = SymCryptHpkeOpen(pRecipientCtx.?, null, 0, &dummyCt, dummyCt.len, &dummyPt, dummyPt.len);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Open on ExportOnly context must fail");

        scError = SymCryptHpkeOpenUnordered(pRecipientCtx.?, 0, null, 0, &dummyCt, dummyCt.len, &dummyPt, dummyPt.len);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "OpenUnordered on ExportOnly context must fail");

        const exportCtx = "export-only test";
        var s1: [32]u8 = undefined;
        var s2: [32]u8 = undefined;
        scError = SymCryptHpkeSecretExport(pSenderCtx.?, exportCtx.ptr, exportCtx.len, &s1, s1.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport (sender) failed on ExportOnly");
        scError = SymCryptHpkeSecretExport(pRecipientCtx.?, exportCtx.ptr, exportCtx.len, &s2, s2.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport (recipient) failed on ExportOnly");
        h.check(std.mem.eql(u8, &s1, &s2), "ExportOnly secrets mismatch");
    }
}

fn testHpkekeyImportExport(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbPrivKey: usize = 0;
    var cbPubKey: usize = 0;
    var cbMinIkm: usize = 0;
    scError = SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivKey);
    h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat(PRIVATE_KEY) failed for {s}", tcs.name);
    scError = SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPubKey);
    h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat(PUBLIC_KEY) failed for {s}", tcs.name);
    scError = SymCryptHpkeMinimumDkpIkmSizeFromParams(cs, &cbMinIkm);
    h.check3(scError == SYMCRYPT_NO_ERROR, "MinimumDkpIkmSize failed for {s}", tcs.name);

    const ikm = std.heap.c_allocator.alloc(u8, cbMinIkm) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ikm);
    for (0..cbMinIkm) |i| ikm[i] = rng.g_rng.byte();

    const pkDerived1 = SymCryptHpkekeyAllocate(cs);
    const pkDerived2 = SymCryptHpkekeyAllocate(cs);
    h.check(pkDerived1 != null and pkDerived2 != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkDerived1.?);
    defer SymCryptHpkekeyFree(pkDerived2.?);

    scError = SymCryptHpkekeyDerive(pkDerived1.?, ikm.ptr, ikm.len, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkekeyDerive #1 failed for {s}", tcs.name);
    scError = SymCryptHpkekeyDerive(pkDerived2.?, ikm.ptr, ikm.len, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "HpkekeyDerive #2 failed for {s}", tcs.name);

    const priv1 = std.heap.c_allocator.alloc(u8, cbPrivKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(priv1);
    const priv2 = std.heap.c_allocator.alloc(u8, cbPrivKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(priv2);
    const pub1 = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pub1);
    const pub2 = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pub2);

    scError = SymCryptHpkekeyGetValue(pkDerived1.?, priv1.ptr, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetValue(PRIVATE_KEY) #1 failed for {s}", tcs.name);
    scError = SymCryptHpkekeyGetValue(pkDerived2.?, priv2.ptr, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetValue(PRIVATE_KEY) #2 failed for {s}", tcs.name);
    scError = SymCryptHpkekeyGetValue(pkDerived1.?, pub1.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetValue(PUBLIC_KEY) #1 failed for {s}", tcs.name);
    scError = SymCryptHpkekeyGetValue(pkDerived2.?, pub2.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetValue(PUBLIC_KEY) #2 failed for {s}", tcs.name);

    h.check3(std.mem.eql(u8, priv1, priv2), "Derived private keys differ for {s}", tcs.name);
    h.check3(std.mem.eql(u8, pub1, pub2), "Derived public keys differ for {s}", tcs.name);

    const pkReimported = SymCryptHpkekeyAllocate(cs);
    h.check(pkReimported != null, "HpkekeyAllocate (reimported) failed");
    defer SymCryptHpkekeyFree(pkReimported.?);

    scError = SymCryptHpkekeySetValue(priv1.ptr, cbPrivKey, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, 0, pkReimported.?);
    h.check3(scError == SYMCRYPT_NO_ERROR, "SetValue(PRIVATE_KEY) failed for {s}", tcs.name);

    const pubReimported = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubReimported);
    scError = SymCryptHpkekeyGetValue(pkReimported.?, pubReimported.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0);
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetValue(PUBLIC_KEY) from reimported key failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, pub1, pubReimported), "Public key from reimported private key differs for {s}", tcs.name);

    const pkPubOnly = SymCryptHpkekeyAllocate(cs);
    h.check(pkPubOnly != null, "HpkekeyAllocate (pub only) failed");
    defer SymCryptHpkekeyFree(pkPubOnly.?);

    scError = SymCryptHpkekeySetValue(pub1.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0, pkPubOnly.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "SetValue(PUBLIC_KEY) failed");
}

fn testHpkeSingleShot(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    var cbOverhead: usize = 0;
    var cbPubKey: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");
    scError = SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPubKey);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat(PUBLIC_KEY) failed");

    const pkRecipient = SymCryptHpkekeyAllocate(cs);
    const pkSenderPub = SymCryptHpkekeyAllocate(cs);
    h.check(pkRecipient != null and pkSenderPub != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkRecipient.?);
    defer SymCryptHpkekeyFree(pkSenderPub.?);

    scError = SymCryptHpkekeyGenerate(pkRecipient.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    const pubKey = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubKey);
    scError = SymCryptHpkekeyGetValue(pkRecipient.?, pubKey.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "GetValue(PUBLIC_KEY) failed");
    scError = SymCryptHpkekeySetValue(pubKey.ptr, cbPubKey, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, 0, pkSenderPub.?);
    h.check(scError == SYMCRYPT_NO_ERROR, "SetValue(PUBLIC_KEY) failed");

    const info = "single-shot info";
    const aad = "single-shot aad";
    const pt = "Single-shot plaintext payload";
    const cbPt = pt.len;
    const cbCt = cbPt + cbOverhead;

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);
    const ct = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ct);
    const decrypted = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(decrypted);

    scError = SymCryptHpkeSealSingleShot(
        pkSenderPub.?,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        pt.ptr,
        cbPt,
        enc.ptr,
        cbEnc,
        ct.ptr,
        cbCt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SealSingleShot failed for {s}", tcs.name);

    scError = SymCryptHpkeOpenSingleShot(
        pkRecipient.?,
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "OpenSingleShot failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, decrypted, pt), "SingleShot plaintext mismatch for {s}", tcs.name);

    var psk: [32]u8 = undefined;
    for (0..psk.len) |i| psk[i] = rng.g_rng.byte();
    const pskId = "ss-psk-id";

    scError = SymCryptHpkeSealSingleShot(
        pkSenderPub.?,
        info.ptr,
        info.len,
        &psk,
        psk.len,
        pskId.ptr,
        pskId.len,
        aad.ptr,
        aad.len,
        pt.ptr,
        cbPt,
        enc.ptr,
        cbEnc,
        ct.ptr,
        cbCt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SealSingleShot (PSK) failed for {s}", tcs.name);

    @memset(decrypted, 0);
    scError = SymCryptHpkeOpenSingleShot(
        pkRecipient.?,
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        &psk,
        psk.len,
        pskId.ptr,
        pskId.len,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "OpenSingleShot (PSK) failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, decrypted, pt), "SingleShot (PSK) plaintext mismatch for {s}", tcs.name);

    const inPlaceSS = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(inPlaceSS);
    @memcpy(inPlaceSS[0..cbPt], pt);

    scError = SymCryptHpkeSealSingleShot(
        pkSenderPub.?,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        inPlaceSS.ptr,
        cbPt,
        enc.ptr,
        cbEnc,
        inPlaceSS.ptr,
        cbCt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SealSingleShot (in-place) failed for {s}", tcs.name);

    scError = SymCryptHpkeOpenSingleShot(
        pkRecipient.?,
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        inPlaceSS.ptr,
        cbCt,
        inPlaceSS.ptr,
        cbPt,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "OpenSingleShot (in-place) failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, inPlaceSS[0..cbPt], pt), "SingleShot in-place plaintext mismatch for {s}", tcs.name);

    var dummyOverhead: [SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8 = undefined;
    scError = SymCryptHpkeSealSingleShot(
        pkSenderPub.?,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        null,
        0,
        enc.ptr,
        cbEnc,
        &dummyOverhead,
        cbOverhead,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "SealSingleShot (empty plaintext) failed for {s}", tcs.name);

    scError = SymCryptHpkeOpenSingleShot(
        pkRecipient.?,
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        &dummyOverhead,
        cbOverhead,
        null,
        0,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "OpenSingleShot (empty plaintext) failed for {s}", tcs.name);
}

fn testHpkeDataIntegrity(tcs: HpkeTestCiphersuite) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = tcs.cs;

    var cbEnc: usize = 0;
    var cbOverhead: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");

    const pkKey = SymCryptHpkekeyAllocate(cs);
    h.check(pkKey != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkKey.?);

    scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null and pRecipientCtx != null, "HpkeContextAllocate failed");
    defer SymCryptHpkeContextFree(pSenderCtx);
    defer SymCryptHpkeContextFree(pRecipientCtx);

    const info = "tamper test info";
    const aad = "tamper test aad";
    const pt = "Tamper test plaintext message";
    const cbPt = pt.len;
    const cbCt = cbPt + cbOverhead;

    scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, info.ptr, info.len, null, 0, null, 0, enc.ptr, enc.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed");
    scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, info.ptr, info.len, null, 0, null, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed");

    const ct = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ct);
    const decrypted = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(decrypted);

    var seqNum: u64 = 0;
    scError = SymCryptHpkeSeal(pSenderCtx.?, aad.ptr, aad.len, pt.ptr, cbPt, ct.ptr, cbCt, &seqNum);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSeal failed");

    const tamperedCt = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(tamperedCt);
    @memcpy(tamperedCt, ct);
    const bitIdx = rng.g_rng.uint32() % (cbCt * 8);
    tamperedCt[bitIdx / 8] ^= @as(u8, 1) << @intCast(bitIdx % 8);

    scError = SymCryptHpkeOpenUnordered(
        pRecipientCtx.?,
        seqNum,
        aad.ptr,
        aad.len,
        tamperedCt.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_AUTHENTICATION_FAILURE,
        "Tampered ciphertext did not fail authentication for {s}",
        tcs.name,
    );

    const wrongAad = "wrong aad";
    scError = SymCryptHpkeOpenUnordered(
        pRecipientCtx.?,
        seqNum,
        wrongAad.ptr,
        wrongAad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_AUTHENTICATION_FAILURE,
        "Wrong AAD did not fail authentication for {s}",
        tcs.name,
    );

    scError = SymCryptHpkeOpenUnordered(
        pRecipientCtx.?,
        seqNum + 1,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_AUTHENTICATION_FAILURE,
        "Wrong sequence number did not fail authentication for {s}",
        tcs.name,
    );

    scError = SymCryptHpkeOpen(
        pRecipientCtx.?,
        aad.ptr,
        aad.len,
        tamperedCt.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_AUTHENTICATION_FAILURE,
        "Tampered ciphertext in Open did not fail for {s}",
        tcs.name,
    );

    scError = SymCryptHpkeOpen(
        pRecipientCtx.?,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_NO_ERROR,
        "Valid Open after failed Open should succeed (seqNum not incremented on failure) for {s}",
        tcs.name,
    );
    h.check(std.mem.eql(u8, decrypted, pt), "Plaintext mismatch after recovery");

    pSenderCtx.?.seqNum = SYMCRYPT_HPKE_SEQ_LIMIT - 1;
    pRecipientCtx.?.seqNum = SYMCRYPT_HPKE_SEQ_LIMIT - 1;

    scError = SymCryptHpkeSeal(pSenderCtx.?, aad.ptr, aad.len, pt.ptr, cbPt, ct.ptr, cbCt, &seqNum);
    h.check3(scError == SYMCRYPT_NO_ERROR, "Seal at SEQ_LIMIT - 1 must succeed for {s}", tcs.name);
    h.check3(seqNum == SYMCRYPT_HPKE_SEQ_LIMIT - 1, "Seal seqNum mismatch at SEQ_LIMIT - 1 for {s}", tcs.name);
    h.check3(pSenderCtx.?.seqNum == SYMCRYPT_HPKE_SEQ_LIMIT, "Sender seqNum not incremented to SEQ_LIMIT for {s}", tcs.name);

    scError = SymCryptHpkeSeal(pSenderCtx.?, aad.ptr, aad.len, pt.ptr, cbPt, ct.ptr, cbCt, &seqNum);
    h.check3(scError == SYMCRYPT_INVALID_ARGUMENT, "Seal at SEQ_LIMIT must fail with INVALID_ARGUMENT for {s}", tcs.name);

    @memset(decrypted, 0);
    scError = SymCryptHpkeOpen(pRecipientCtx.?, aad.ptr, aad.len, ct.ptr, cbCt, decrypted.ptr, cbPt);
    h.check3(scError == SYMCRYPT_NO_ERROR, "Open at SEQ_LIMIT - 1 must succeed for {s}", tcs.name);
    h.check(std.mem.eql(u8, decrypted, pt), "Plaintext mismatch at SEQ_LIMIT - 1");
    h.check3(pRecipientCtx.?.seqNum == SYMCRYPT_HPKE_SEQ_LIMIT, "Recipient seqNum not incremented to SEQ_LIMIT for {s}", tcs.name);

    scError = SymCryptHpkeOpen(pRecipientCtx.?, aad.ptr, aad.len, ct.ptr, cbCt, decrypted.ptr, cbPt);
    h.check3(scError == SYMCRYPT_INVALID_ARGUMENT, "Open at SEQ_LIMIT must fail with INVALID_ARGUMENT for {s}", tcs.name);
    h.check3(pRecipientCtx.?.seqNum == SYMCRYPT_HPKE_SEQ_LIMIT, "Recipient seqNum changed after failed Open for {s}", tcs.name);

    scError = SymCryptHpkeOpenUnordered(
        pRecipientCtx.?,
        SYMCRYPT_HPKE_SEQ_LIMIT,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        decrypted.ptr,
        cbPt,
    );
    h.check3(
        scError == SYMCRYPT_INVALID_ARGUMENT,
        "OpenUnordered at SEQ_LIMIT must fail with INVALID_ARGUMENT for {s}",
        tcs.name,
    );
}

fn testHpkeSealValidationFailureDoesNotConsumeSequence() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const cs = SYMCRYPT_HPKE_CIPHERSUITE{
        .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
        .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
    };

    var cbEnc: usize = 0;
    var cbOverhead: usize = 0;
    scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
    scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead);
    h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");

    const pkKey = SymCryptHpkekeyAllocate(cs);
    h.check(pkKey != null, "HpkekeyAllocate failed");
    defer SymCryptHpkekeyFree(pkKey.?);

    scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);

    const pSenderCtx = SymCryptHpkeContextAllocate(cs);
    const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
    h.check(pSenderCtx != null and pRecipientCtx != null, "HpkeContextAllocate failed");
    defer SymCryptHpkeContextFree(pSenderCtx);
    defer SymCryptHpkeContextFree(pRecipientCtx);

    scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, null, 0, null, 0, null, 0, enc.ptr, enc.len);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed");
    scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, null, 0, null, 0, null, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed");

    const pt = "Seal failure must not consume sequence";
    const cbPt = pt.len;
    const cbCt = cbPt + cbOverhead;

    const ct = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ct);
    const decrypted = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(decrypted);

    var seqNum: u64 = 0xDEAD;
    scError = SymCryptHpkeSeal(pSenderCtx.?, null, 0, pt.ptr, cbPt, ct.ptr, cbCt - 1, &seqNum);
    h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Seal with wrong cbDst must fail");
    h.check(pSenderCtx.?.seqNum == 0, "Failed Seal (wrong cbDst) must not increment seqNum");
    h.check(seqNum == 0xDEAD, "Failed Seal should not write the output sequence number");

    scError = SymCryptHpkeSeal(pSenderCtx.?, null, 0, pt.ptr, cbPt, ct.ptr, cbCt, &seqNum);
    h.check(scError == SYMCRYPT_NO_ERROR, "Valid Seal after failed Seals must succeed");
    h.check(seqNum == 0, "Valid Seal must use sequence number 0");
    h.check(pSenderCtx.?.seqNum == 1, "Sender seqNum must be 1 after first valid Seal");

    scError = SymCryptHpkeOpen(pRecipientCtx.?, null, 0, ct.ptr, cbCt, decrypted.ptr, cbPt);
    h.check(scError == SYMCRYPT_NO_ERROR, "Open of message sealed after failed Seals must succeed");
    h.check(std.mem.eql(u8, decrypted, pt), "Plaintext mismatch after failed Seals");
}

const HPKE_MT_NUM_THREADS: usize = 4;
const HPKE_MT_MSGS_PER_THREAD: usize = 32;
const HPKE_MT_TOTAL_MSGS: usize = HPKE_MT_NUM_THREADS * HPKE_MT_MSGS_PER_THREAD;
const HPKE_MT_PT_SIZE: usize = 48;
const HPKE_MT_AAD_SIZE: usize = 16;

const HpkeMtSharedState = struct {
    pkKey: *const SYMCRYPT_HPKEKEY,
    pRecipientCtx: *const SYMCRYPT_HPKECONTEXT,
    cbEnc: usize,
    cbOverhead: usize,
    plaintexts: [HPKE_MT_TOTAL_MSGS][HPKE_MT_PT_SIZE]u8,
    aads: [HPKE_MT_TOTAL_MSGS][HPKE_MT_AAD_SIZE]u8,
    ciphertexts: [HPKE_MT_TOTAL_MSGS][HPKE_MT_PT_SIZE + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8,
    seqNums: [HPKE_MT_TOTAL_MSGS]u64,
};

const HpkeMtWorkerArgs = struct {
    shared: *const HpkeMtSharedState,
    threadIdx: usize,
};

fn hpkeMtWorker(args: HpkeMtWorkerArgs) void {
    const shared = args.shared;
    const cbCt = HPKE_MT_PT_SIZE + shared.cbOverhead;
    const startIdx = args.threadIdx * HPKE_MT_MSGS_PER_THREAD;

    var decrypted: [HPKE_MT_PT_SIZE]u8 = undefined;
    var enc: [SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE]u8 = undefined;
    var ssCt: [HPKE_MT_PT_SIZE + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8 = undefined;
    var exported: [32]u8 = undefined;
    const exportCtx = "mt-export";

    for (0..HPKE_MT_MSGS_PER_THREAD) |i| {
        const msgIdx = startIdx + i;

        var scError = SymCryptHpkeOpenUnordered(
            shared.pRecipientCtx,
            shared.seqNums[msgIdx],
            &shared.aads[msgIdx],
            HPKE_MT_AAD_SIZE,
            &shared.ciphertexts[msgIdx],
            cbCt,
            &decrypted,
            HPKE_MT_PT_SIZE,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Concurrent OpenUnordered failed");
        h.check(
            std.mem.eql(u8, &decrypted, &shared.plaintexts[msgIdx]),
            "Concurrent OpenUnordered plaintext mismatch",
        );

        scError = SymCryptHpkeSecretExport(
            shared.pRecipientCtx,
            exportCtx.ptr,
            exportCtx.len,
            &exported,
            exported.len,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Concurrent SecretExport failed");

        scError = SymCryptHpkeSealSingleShot(
            shared.pkKey,
            null,
            0,
            null,
            0,
            null,
            0,
            &shared.aads[msgIdx],
            HPKE_MT_AAD_SIZE,
            &shared.plaintexts[msgIdx],
            HPKE_MT_PT_SIZE,
            &enc,
            shared.cbEnc,
            &ssCt,
            cbCt,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Concurrent SealSingleShot failed");

        scError = SymCryptHpkeOpenSingleShot(
            shared.pkKey,
            &enc,
            shared.cbEnc,
            null,
            0,
            null,
            0,
            null,
            0,
            &shared.aads[msgIdx],
            HPKE_MT_AAD_SIZE,
            &ssCt,
            cbCt,
            &decrypted,
            HPKE_MT_PT_SIZE,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Concurrent OpenSingleShot failed");
        h.check(
            std.mem.eql(u8, &decrypted, &shared.plaintexts[msgIdx]),
            "Concurrent OpenSingleShot plaintext mismatch",
        );
    }
}

fn testHpkeMultiThread() void {
    const mtSuites = [_]SYMCRYPT_HPKE_CIPHERSUITE{
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128 },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519, .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_CHACHA20POLY1305 },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 },
        .{ .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256, .kdfId = SYMCRYPT_HPKE_KDF_ID_SHAKE256, .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM256 },
    };

    for (mtSuites) |cs| {
        var scError: u32 = SYMCRYPT_NO_ERROR;
        var cbEnc: usize = 0;
        var cbOverhead: usize = 0;
        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
        scError = SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");

        const pkKey = SymCryptHpkekeyAllocate(cs);
        h.check(pkKey != null, "HpkekeyAllocate failed");
        defer SymCryptHpkekeyFree(pkKey.?);

        scError = SymCryptHpkekeyGenerate(pkKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkekeyGenerate failed");

        const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(enc);

        const pSenderCtx = SymCryptHpkeContextAllocate(cs);
        const pRecipientCtx = SymCryptHpkeContextAllocate(cs);
        h.check(pSenderCtx != null and pRecipientCtx != null, "HpkeContextAllocate failed");
        defer SymCryptHpkeContextFree(pSenderCtx);
        defer SymCryptHpkeContextFree(pRecipientCtx);

        scError = SymCryptHpkeSetupSender(pSenderCtx.?, pkKey.?, null, 0, null, 0, null, 0, enc.ptr, enc.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupSender failed");
        scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pkKey.?, enc.ptr, enc.len, null, 0, null, 0, null, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "HpkeSetupRecipient failed");

        const shared = std.heap.c_allocator.create(HpkeMtSharedState) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.destroy(shared);
        shared.pkKey = pkKey.?;
        shared.pRecipientCtx = pRecipientCtx.?;
        shared.cbEnc = cbEnc;
        shared.cbOverhead = cbOverhead;

        const cbCt = HPKE_MT_PT_SIZE + cbOverhead;
        for (0..HPKE_MT_TOTAL_MSGS) |i| {
            for (0..HPKE_MT_PT_SIZE) |j| shared.plaintexts[i][j] = rng.g_rng.byte();
            for (0..HPKE_MT_AAD_SIZE) |j| shared.aads[i][j] = rng.g_rng.byte();

            scError = SymCryptHpkeSeal(
                pSenderCtx.?,
                &shared.aads[i],
                HPKE_MT_AAD_SIZE,
                &shared.plaintexts[i],
                HPKE_MT_PT_SIZE,
                &shared.ciphertexts[i],
                cbCt,
                &shared.seqNums[i],
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "Pre-Seal for MT test failed");
        }

        var threads: [HPKE_MT_NUM_THREADS]std.Thread = undefined;
        for (0..HPKE_MT_NUM_THREADS) |t| {
            threads[t] = std.Thread.spawn(.{}, hpkeMtWorker, .{HpkeMtWorkerArgs{
                .shared = shared,
                .threadIdx = t,
            }}) catch h.fatal("Thread.spawn failed", .{});
        }
        for (0..HPKE_MT_NUM_THREADS) |t| {
            threads[t].join();
        }
    }
}

fn testHpkeErrorCases() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;

    // 1. Invalid ciphersuite should return nullptr
    {
        const badSuite = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = 0xFFFF,
            .kdfId = 0x0001,
            .aeadId = 0x0001,
        };
        const pKey = SymCryptHpkekeyAllocate(badSuite);
        h.check(pKey == null, "Invalid KEM should return nullptr from Allocate");

        const pCtx = SymCryptHpkeContextAllocate(badSuite);
        h.check(pCtx == null, "Invalid KEM should return nullptr from ContextAllocate");
    }

    // 2. Mismatched ciphersuites between context and key
    {
        const suite1 = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        };
        const suite2 = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA384,
            .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        };

        const pKey = SymCryptHpkekeyAllocate(suite1);
        h.check(pKey != null, "Key alloc failed (mismatch)");
        defer SymCryptHpkekeyFree(pKey.?);
        scError = SymCryptHpkekeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "KeyGen failed (mismatch)");

        const pCtx = SymCryptHpkeContextAllocate(suite2);
        h.check(pCtx != null, "Ctx alloc failed (mismatch)");
        defer SymCryptHpkeContextFree(pCtx);

        var enc: [1088]u8 = undefined;
        scError = SymCryptHpkeSetupSender(pCtx.?, pKey.?, null, 0, null, 0, null, 0, &enc, 1088);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "SetupSender with mismatched ciphersuite should fail");
    }

    // 3. PSK without PSK ID should fail
    {
        const suite = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        };

        const pKey = SymCryptHpkekeyAllocate(suite);
        h.check(pKey != null, "Key alloc (PSK validation)");
        defer SymCryptHpkekeyFree(pKey.?);
        scError = SymCryptHpkekeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "KeyGen (PSK validation)");

        const pCtx = SymCryptHpkeContextAllocate(suite);
        h.check(pCtx != null, "Ctx alloc (PSK validation)");
        defer SymCryptHpkeContextFree(pCtx);

        var enc: [1088]u8 = undefined;
        const psk = "some psk";

        scError = SymCryptHpkeSetupSender(pCtx.?, pKey.?, null, 0, psk.ptr, psk.len, null, 0, &enc, 1088);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "PSK without PSK ID should fail");
    }

    // 4. Size query functions
    {
        const suite = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
            .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        };

        var cbEncaps: usize = 0;
        var cbAeadOverhead: usize = 0;

        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(suite, &cbEncaps);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEncapsCiphertext failed");
        h.check(cbEncaps == 1088, "Expected enc size 1088");

        scError = SymCryptHpkeSizeofAeadOverheadFromParams(suite, &cbAeadOverhead);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed");
        h.check(cbAeadOverhead == 16, "Expected AEAD overhead 16");
    }

    // 5. Role enforcement: Seal is sender-only, Open is recipient-only
    {
        const suite = SYMCRYPT_HPKE_CIPHERSUITE{
            .kemId = SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
            .kdfId = SYMCRYPT_HPKE_KDF_ID_HKDF_SHA256,
            .aeadId = SYMCRYPT_HPKE_AEAD_ID_AESGCM128,
        };

        const pKey = SymCryptHpkekeyAllocate(suite);
        h.check(pKey != null, "Key alloc (role)");
        defer SymCryptHpkekeyFree(pKey.?);
        scError = SymCryptHpkekeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "KeyGen (role)");

        var cbEnc: usize = 0;
        scError = SymCryptHpkeSizeofEncapsCiphertextFromParams(suite, &cbEnc);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofEnc (role)");
        var cbTag: usize = 0;
        scError = SymCryptHpkeSizeofAeadOverheadFromParams(suite, &cbTag);
        h.check(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead (role)");

        var enc: [SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE]u8 = undefined;
        h.check(cbEnc <= enc.len, "enc buffer too small (role)");

        const pt = "role enforcement plaintext";
        const cbPt = pt.len;
        var ct: [pt.len + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8 = undefined;
        var dec: [pt.len]u8 = undefined;
        var exported: [32]u8 = undefined;

        const pSenderCtx = SymCryptHpkeContextAllocate(suite);
        h.check(pSenderCtx != null, "Sender ctx alloc (role)");
        defer SymCryptHpkeContextFree(pSenderCtx);
        scError = SymCryptHpkeSetupSender(pSenderCtx.?, pKey.?, null, 0, null, 0, null, 0, &enc, cbEnc);
        h.check(scError == SYMCRYPT_NO_ERROR, "SetupSender (role)");

        scError = SymCryptHpkeSeal(pSenderCtx.?, null, 0, pt.ptr, cbPt, &ct, cbPt + cbTag, null);
        h.check(scError == SYMCRYPT_NO_ERROR, "Seal on sender ctx should succeed (role)");

        scError = SymCryptHpkeOpenUnordered(pSenderCtx.?, 0, null, 0, &ct, cbPt + cbTag, &dec, cbPt);
        h.check(scError == SYMCRYPT_NO_ERROR, "OpenUnordered on sender ctx should succeed (role)");

        scError = SymCryptHpkeOpen(pSenderCtx.?, null, 0, &ct, cbPt + cbTag, &dec, cbPt);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Open on sender ctx must be rejected (role)");

        const pRecipientCtx = SymCryptHpkeContextAllocate(suite);
        h.check(pRecipientCtx != null, "Recipient ctx alloc (role)");
        defer SymCryptHpkeContextFree(pRecipientCtx);
        scError = SymCryptHpkeSetupRecipient(pRecipientCtx.?, pKey.?, &enc, cbEnc, null, 0, null, 0, null, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "SetupRecipient (role)");

        scError = SymCryptHpkeSeal(pRecipientCtx.?, null, 0, pt.ptr, cbPt, &ct, cbPt + cbTag, null);
        h.check(scError == SYMCRYPT_INVALID_ARGUMENT, "Seal on recipient ctx must be rejected (role)");

        scError = SymCryptHpkeOpenUnordered(pRecipientCtx.?, 0, null, 0, &ct, cbPt + cbTag, &dec, cbPt);
        h.check(scError == SYMCRYPT_NO_ERROR, "OpenUnordered on recipient ctx should succeed (role)");

        scError = SymCryptHpkeOpen(pRecipientCtx.?, null, 0, &ct, cbPt + cbTag, &dec, cbPt);
        h.check(scError == SYMCRYPT_NO_ERROR, "Open on recipient ctx should succeed (role)");

        scError = SymCryptHpkeSecretExport(pSenderCtx.?, "x".ptr, 1, &exported, exported.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport on sender ctx (role)");
        scError = SymCryptHpkeSecretExport(pRecipientCtx.?, "x".ptr, 1, &exported, exported.len);
        h.check(scError == SYMCRYPT_NO_ERROR, "SecretExport on recipient ctx (role)");
    }
}

fn testHpkeKat() void {
    var katReader = kat.ZigKatReader.init("kat_hpke.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var hpkeMultiImp = HpkeMultiImp.init("Hpke");
    defer hpkeMultiImp.deinit();

    var currentSuite: SYMCRYPT_HPKE_CIPHERSUITE = .{ .kemId = 0, .kdfId = 0, .aeadId = 0 };
    var bCategoryFound: bool = false;
    var bSetupSeen: bool = false;
    var hasDeterministicSender: bool = false;

    var cSetupRecords: u32 = 0;
    var cEncryptionRecords: u32 = 0;
    var cExportRecords: u32 = 0;

    while (true) {
        katReader.getKatItem(&katItem);
        const line = katItem.line;

        if (katItem.type == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            bCategoryFound = true;
            bSetupSeen = false;
            continue;
        }

        if (katItem.type != kat.KAT_TYPE_DATASET) {
            continue;
        }

        h.check3(bCategoryFound, "HPKE KAT dataset at line {d} has no ciphersuite category!", line);

        if (katItem.isFieldPresent("info")) {
            const mode = katItem.parseInteger("mode");
            h.check3(mode == 0 or mode == 1, "Unsupported HPKE KAT mode at line {d}", line);

            currentSuite.kemId = @intCast(katItem.parseInteger("kem_id"));
            currentSuite.kdfId = @intCast(katItem.parseInteger("kdf_id"));
            currentSuite.aeadId = @intCast(katItem.parseInteger("aead_id"));

            const katInfo = katItem.parseData("info");
            defer std.heap.c_allocator.free(katInfo);
            const katIkmR = katItem.parseData("ikmr");
            defer std.heap.c_allocator.free(katIkmR);
            const katIkmE = katItem.parseData("ikme");
            defer std.heap.c_allocator.free(katIkmE);
            const katPkRm = katItem.parseData("pkrm");
            defer std.heap.c_allocator.free(katPkRm);
            const katEnc = katItem.parseData("enc");
            defer std.heap.c_allocator.free(katEnc);

            var katPsk: ?[]u8 = null;
            defer if (katPsk) |p| std.heap.c_allocator.free(p);
            var katPskId: ?[]u8 = null;
            defer if (katPskId) |p| std.heap.c_allocator.free(p);
            if (mode == 1) {
                katPsk = katItem.parseData("psk");
                katPskId = katItem.parseData("psk_id");
            }

            const pbPsk: ?[*]const u8 = if (katPsk) |p| (if (p.len > 0) p.ptr else null) else null;
            const cbPsk: usize = if (katPsk) |p| p.len else 0;
            const pbPskId: ?[*]const u8 = if (katPskId) |p| (if (p.len > 0) p.ptr else null) else null;
            const cbPskId: usize = if (katPskId) |p| p.len else 0;
            const pbInfo: ?[*]const u8 = if (katInfo.len > 0) katInfo.ptr else null;

            var cbPk: usize = 0;
            const scError = SymCryptHpkeSizeofKeyFormatFromParams(
                currentSuite,
                SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY,
                &cbPk,
            );
            h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofKeyFormat failed at line {d}", line);
            h.check3(cbPk == katPkRm.len, "Public key size mismatch at line {d}", line);

            var status = hpkeMultiImp.deriveKeyPair(currentSuite, katIkmR.ptr, katIkmR.len);
            h.check4(status == STATUS_SUCCESS, "deriveKeyPair failed at line {d}: {s}", line, hpkeMultiImp.getLastError());

            const implPk = std.heap.c_allocator.alloc(u8, cbPk) catch h.fatal("Out of memory", .{});
            defer std.heap.c_allocator.free(implPk);
            status = hpkeMultiImp.getKey(SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, implPk.ptr, cbPk);
            h.check4(status == STATUS_SUCCESS, "getKey(PUBLIC_KEY) failed at line {d}: {s}", line, hpkeMultiImp.getLastError());
            h.check3(std.mem.eql(u8, implPk, katPkRm), "Derived pkRm mismatch at line {d}", line);

            hasDeterministicSender = false;
            const implEnc = std.heap.c_allocator.alloc(u8, katEnc.len) catch h.fatal("Out of memory", .{});
            defer std.heap.c_allocator.free(implEnc);

            status = hpkeMultiImp.setupSenderDeterministic(
                katIkmE.ptr,
                katIkmE.len,
                pbInfo,
                katInfo.len,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
                implEnc.ptr,
                implEnc.len,
            );
            if (status == STATUS_SUCCESS) {
                hasDeterministicSender = true;
                h.check3(std.mem.eql(u8, implEnc, katEnc), "Deterministic enc mismatch at line {d}", line);
            } else {
                status = hpkeMultiImp.deriveKeyPair(currentSuite, katIkmR.ptr, katIkmR.len);
                h.check3(status == STATUS_SUCCESS, "Re-deriveKeyPair failed at line {d}", line);
            }

            status = hpkeMultiImp.setupRecipient(
                katEnc.ptr,
                katEnc.len,
                pbInfo,
                katInfo.len,
                pbPsk,
                cbPsk,
                pbPskId,
                cbPskId,
            );
            h.check4(status == STATUS_SUCCESS, "setupRecipient failed at line {d}: {s}", line, hpkeMultiImp.getLastError());

            bSetupSeen = true;
            cSetupRecords += 1;
            continue;
        }

        if (katItem.isFieldPresent("seq")) {
            h.check3(bSetupSeen, "Encryption record at line {d} without prior setup!", line);

            var cbTag: usize = 0;
            const scError = SymCryptHpkeSizeofAeadOverheadFromParams(currentSuite, &cbTag);
            h.check3(scError == SYMCRYPT_NO_ERROR, "SizeofAeadOverhead failed at line {d}", line);

            const seq: u64 = @intCast(katItem.parseInteger("seq"));
            const katPt = katItem.parseData("pt");
            defer std.heap.c_allocator.free(katPt);
            const katAad = katItem.parseData("aad");
            defer std.heap.c_allocator.free(katAad);
            const katCt = katItem.parseData("ct");
            defer std.heap.c_allocator.free(katCt);

            const cbPlaintext = katCt.len - cbTag;
            h.check3(cbPlaintext == katPt.len, "Plaintext size mismatch at line {d}", line);

            if (hasDeterministicSender) {
                const implCt = std.heap.c_allocator.alloc(u8, katCt.len) catch h.fatal("Out of memory", .{});
                defer std.heap.c_allocator.free(implCt);
                var seqNum: u64 = 0;
                const status = hpkeMultiImp.seal(
                    if (katAad.len > 0) katAad.ptr else null,
                    katAad.len,
                    if (katPt.len > 0) katPt.ptr else null,
                    katPt.len,
                    implCt.ptr,
                    implCt.len,
                    &seqNum,
                );
                h.check4(status == STATUS_SUCCESS, "KAT seal #{d} failed at line {d}", seq, line);
                h.check4(seqNum == seq, "KAT seal #{d} seq mismatch at line {d}", seq, line);
                h.check4(std.mem.eql(u8, implCt, katCt), "KAT seal #{d} ct mismatch at line {d}", seq, line);
            }

            const implPt = std.heap.c_allocator.alloc(u8, @max(cbPlaintext, 1)) catch h.fatal("Out of memory", .{});
            defer std.heap.c_allocator.free(implPt);
            var status = hpkeMultiImp.open(
                if (katAad.len > 0) katAad.ptr else null,
                katAad.len,
                katCt.ptr,
                katCt.len,
                if (cbPlaintext > 0) implPt.ptr else null,
                cbPlaintext,
            );
            h.check5(status == STATUS_SUCCESS, "KAT open #{d} failed at line {d}: {s}", seq, line, hpkeMultiImp.getLastError());
            if (cbPlaintext > 0) {
                h.check4(std.mem.eql(u8, implPt[0..cbPlaintext], katPt), "KAT open #{d} pt mismatch at line {d}", seq, line);
            }

            if (cbPlaintext > 0) @memset(implPt[0..cbPlaintext], 0);
            status = hpkeMultiImp.openUnordered(
                seq,
                if (katAad.len > 0) katAad.ptr else null,
                katAad.len,
                katCt.ptr,
                katCt.len,
                if (cbPlaintext > 0) implPt.ptr else null,
                cbPlaintext,
            );
            h.check4(status == STATUS_SUCCESS, "KAT openUnordered #{d} failed at line {d}", seq, line);
            if (cbPlaintext > 0) {
                h.check4(
                    std.mem.eql(u8, implPt[0..cbPlaintext], katPt),
                    "KAT openUnordered #{d} pt mismatch at line {d}",
                    seq,
                    line,
                );
            }

            cEncryptionRecords += 1;
            continue;
        }

        if (katItem.isFieldPresent("exporter_context")) {
            h.check3(bSetupSeen, "Export record at line {d} without prior setup!", line);

            const katCtx = katItem.parseData("exporter_context");
            defer std.heap.c_allocator.free(katCtx);
            const L = katItem.parseInteger("l");
            const katExpected = katItem.parseData("exported_value");
            defer std.heap.c_allocator.free(katExpected);

            h.check3(L >= 0 and L <= 0xFFFF, "Export L out of range at line {d}", line);
            h.check3(@as(usize, @intCast(L)) == katExpected.len, "Export L mismatch at line {d}", line);

            const cbExport: u16 = @intCast(L);
            const pbExpCtx: ?[*]const u8 = if (katCtx.len > 0) katCtx.ptr else null;

            if (hasDeterministicSender) {
                const senderExp = std.heap.c_allocator.alloc(u8, cbExport) catch h.fatal("Out of memory", .{});
                defer std.heap.c_allocator.free(senderExp);
                const status = hpkeMultiImp.secretExportSender(
                    pbExpCtx,
                    katCtx.len,
                    senderExp.ptr,
                    cbExport,
                );
                h.check3(status == STATUS_SUCCESS, "KAT secretExportSender failed at line {d}", line);
                h.check3(std.mem.eql(u8, senderExp, katExpected), "KAT secretExportSender mismatch at line {d}", line);
            }

            const recipExp = std.heap.c_allocator.alloc(u8, cbExport) catch h.fatal("Out of memory", .{});
            defer std.heap.c_allocator.free(recipExp);
            const status = hpkeMultiImp.secretExportRecipient(
                pbExpCtx,
                katCtx.len,
                recipExp.ptr,
                cbExport,
            );
            h.check4(status == STATUS_SUCCESS, "KAT secretExportRecipient failed at line {d}: {s}", line, hpkeMultiImp.getLastError());
            h.check3(std.mem.eql(u8, recipExp, katExpected), "KAT secretExportRecipient mismatch at line {d}", line);

            cExportRecords += 1;
            continue;
        }

        h.fatal("HPKE KAT record at line {d} has unrecognized format", .{line});
    }

    _ = hpkeMultiImp.setKey(currentSuite, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, null, 0);
}

fn testHpkeMultiImp(tcs: HpkeTestCiphersuite) void {
    const cs = tcs.cs;

    var hpkeMultiImp = HpkeMultiImp.init("Hpke");
    defer hpkeMultiImp.deinit();

    var cbMinIkm: usize = 0;
    var cbEnc: usize = 0;
    var cbOverhead: usize = 0;
    var cbPubKey: usize = 0;
    var cbPrivKey: usize = 0;

    h.check(SymCryptHpkeMinimumDkpIkmSizeFromParams(cs, &cbMinIkm) == SYMCRYPT_NO_ERROR, "?");
    h.check(SymCryptHpkeSizeofEncapsCiphertextFromParams(cs, &cbEnc) == SYMCRYPT_NO_ERROR, "?");
    h.check(SymCryptHpkeSizeofAeadOverheadFromParams(cs, &cbOverhead) == SYMCRYPT_NO_ERROR, "?");
    h.check(SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR, "?");
    h.check(SymCryptHpkeSizeofKeyFormatFromParams(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR, "?");

    const ikm = std.heap.c_allocator.alloc(u8, cbMinIkm) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ikm);
    for (0..cbMinIkm) |i| ikm[i] = rng.g_rng.byte();

    var status = hpkeMultiImp.deriveKeyPair(cs, ikm.ptr, ikm.len);
    h.check4(status == STATUS_SUCCESS, "MultiImp deriveKeyPair failed for {s}: {s}", tcs.name, hpkeMultiImp.getLastError());

    const pubKey = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubKey);
    const privKey = std.heap.c_allocator.alloc(u8, cbPrivKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(privKey);

    status = hpkeMultiImp.getKey(SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, pubKey.ptr, cbPubKey);
    h.check3(status == STATUS_SUCCESS, "MultiImp getKey(PUBLIC_KEY) failed for {s}", tcs.name);
    status = hpkeMultiImp.getKey(SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, privKey.ptr, cbPrivKey);
    h.check3(status == STATUS_SUCCESS, "MultiImp getKey(PRIVATE_KEY) failed for {s}", tcs.name);

    status = hpkeMultiImp.setKey(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, privKey.ptr, cbPrivKey);
    h.check3(status == STATUS_SUCCESS, "MultiImp setKey(PRIVATE_KEY) failed for {s}", tcs.name);

    const info = "multi-imp info";
    const aad = "multi-imp aad";
    const pt = "Multi-implementation HPKE test message";
    const cbPt = pt.len;
    const cbCt = cbPt + cbOverhead;

    const enc = std.heap.c_allocator.alloc(u8, cbEnc) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(enc);
    const ct = std.heap.c_allocator.alloc(u8, cbCt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(ct);
    const opened = std.heap.c_allocator.alloc(u8, cbPt) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(opened);

    status = hpkeMultiImp.sealSingleShot(
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        pt.ptr,
        cbPt,
        enc.ptr,
        cbEnc,
        ct.ptr,
        cbCt,
    );
    h.check3(status == STATUS_SUCCESS, "MultiImp sealSingleShot failed for {s}", tcs.name);

    status = hpkeMultiImp.openSingleShot(
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        aad.ptr,
        aad.len,
        ct.ptr,
        cbCt,
        opened.ptr,
        cbPt,
    );
    h.check3(status == STATUS_SUCCESS, "MultiImp openSingleShot failed for {s}", tcs.name);
    h.check3(std.mem.eql(u8, opened, pt), "MultiImp SingleShot plaintext mismatch for {s}", tcs.name);

    const exportCtx = "multi-imp export";
    var exportedVal: [32]u8 = undefined;
    status = hpkeMultiImp.secretExportSingleShot(
        enc.ptr,
        cbEnc,
        info.ptr,
        info.len,
        null,
        0,
        null,
        0,
        exportCtx.ptr,
        exportCtx.len,
        &exportedVal,
        exportedVal.len,
    );
    h.check3(status == STATUS_SUCCESS, "MultiImp secretExportSingleShot failed for {s}", tcs.name);

    _ = hpkeMultiImp.setKey(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, null, 0);
}

fn testHpkeRandomKat() void {
    const g_katBytes = [_]u8{
        0xda, 0x05, 0x0c, 0x45, 0x20, 0x8a, 0x21, 0xfb,
        0x2f, 0x09, 0x10, 0xc3, 0x72, 0x3b, 0x2b, 0x82,
        0x48, 0x09, 0x45, 0x7f, 0x99, 0x31, 0xe8, 0xc1,
        0x03, 0xca, 0x43, 0x02, 0xb9, 0x0b, 0x62, 0x77,
        0x52, 0x92, 0x4f, 0x23, 0x38, 0x22, 0x57, 0x66,
        0xb3, 0x29, 0xfa, 0x3e, 0x93, 0x5e, 0x24, 0x2d,
        0x8a, 0xca, 0x53, 0x05, 0xbe, 0x03, 0xdd, 0x79,
        0x2a, 0x03, 0x93, 0xfa, 0xa8, 0x94, 0xf0, 0x21,
    };

    const g_expectedResult = [32]u8{
        0x88, 0x25, 0x73, 0x2a, 0xa4, 0xb6, 0x9c, 0xc7,
        0x1c, 0xf0, 0xfa, 0x33, 0x38, 0x3e, 0x8d, 0x2b,
        0xd5, 0x97, 0x37, 0xdb, 0xaf, 0x0a, 0x11, 0x40,
        0x39, 0xba, 0x22, 0xa1, 0xfd, 0x34, 0xfd, 0xe8,
    };

    var katRng: rng.Rng = .{};
    katRng.reset(g_katBytes[0..]);

    const numRuns: usize = 600;
    const maxInputSize: usize = 64;

    var hpkeMultiImp = HpkeMultiImp.init("Hpke");
    defer hpkeMultiImp.deinit();

    var results: std.ArrayListUnmanaged(u8) = .empty;
    defer results.deinit(std.heap.c_allocator);

    var ikmBuf: [SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE]u8 = undefined;
    var encBuf: [SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE]u8 = undefined;
    var infoBuf: [maxInputSize]u8 = undefined;
    var pskBuf: [maxInputSize]u8 = undefined;
    var pskIdBuf: [maxInputSize]u8 = undefined;
    var aadBuf: [maxInputSize]u8 = undefined;
    var ptBuf: [maxInputSize]u8 = undefined;
    var ctBuf: [maxInputSize + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8 = undefined;
    var decryptedBuf: [maxInputSize]u8 = undefined;
    var expCtxBuf: [maxInputSize]u8 = undefined;
    var expValSender: [maxInputSize]u8 = undefined;
    var expValRecip: [maxInputSize]u8 = undefined;

    for (0..numRuns) |_| {
        const kemId = g_supportedKemIds[katRng.sizet(g_supportedKemIds.len)];
        const kdfId = g_supportedKdfIds[katRng.sizet(g_supportedKdfIds.len)];

        const exportOnly = (katRng.byte() % 5) == 0;
        const aeadId: u16 = if (exportOnly)
            SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY
        else
            g_supportedAeadIds[katRng.sizet(g_supportedAeadIds.len)];

        const cs = SYMCRYPT_HPKE_CIPHERSUITE{ .kemId = kemId, .kdfId = kdfId, .aeadId = aeadId };

        var kemParams: SYMCRYPT_HPKE_KEM_PARAMS = undefined;
        var aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS = undefined;
        if (SymCryptHpkeValidateCiphersuite(cs, &kemParams, &aeadParams) != SYMCRYPT_NO_ERROR) {
            continue;
        }

        const cbIkm = kemParams.cbPrivateKey + katRng.sizet(SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE - kemParams.cbPrivateKey + 1);
        katRng.random(ikmBuf[0..cbIkm]);

        var status = hpkeMultiImp.deriveKeyPair(cs, &ikmBuf, cbIkm);
        h.check3(status == STATUS_SUCCESS, "RandomKat deriveKeyPair failed: {s}", hpkeMultiImp.getLastError());

        const pubKey = std.heap.c_allocator.alloc(u8, kemParams.cbPublicKey) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(pubKey);
        status = hpkeMultiImp.getKey(SYMCRYPT_HPKEKEY_FORMAT_PUBLIC_KEY, pubKey.ptr, pubKey.len);
        h.check(status == STATUS_SUCCESS, "RandomKat getKey(PUBLIC_KEY) failed");
        results.appendSlice(std.heap.c_allocator, pubKey) catch h.fatal("Out of memory", .{});

        const privKey = std.heap.c_allocator.alloc(u8, kemParams.cbPrivateKey) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(privKey);
        status = hpkeMultiImp.getKey(SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, privKey.ptr, privKey.len);
        h.check(status == STATUS_SUCCESS, "RandomKat getKey(PRIVATE_KEY) failed");
        results.appendSlice(std.heap.c_allocator, privKey) catch h.fatal("Out of memory", .{});

        const cbInfo = katRng.sizet(maxInputSize);
        if (cbInfo > 0) katRng.random(infoBuf[0..cbInfo]);

        const usePsk = (katRng.byte() & 1) != 0;
        var cbPsk: usize = 0;
        var cbPskId: usize = 0;
        if (usePsk) {
            cbPsk = 32 + katRng.sizet(maxInputSize - 32 + 1);
            cbPskId = 1 + katRng.sizet(maxInputSize);
            katRng.random(pskBuf[0..cbPsk]);
            katRng.random(pskIdBuf[0..cbPskId]);
        }

        var cbRandom: usize = kemParams.cbPrivateKey;
        if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_512 or
            kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_768 or
            kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_1024)
        {
            cbRandom = 32;
        } else if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256 or
            kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519)
        {
            cbRandom = 64;
        } else if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384) {
            cbRandom = 80;
        }

        var randomBuf: [SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE]u8 = undefined;
        katRng.random(randomBuf[0..cbRandom]);

        const cbEnc: usize = kemParams.cbEnc;
        status = hpkeMultiImp.setupSenderDeterministic(
            &randomBuf,
            cbRandom,
            if (cbInfo > 0) &infoBuf else null,
            cbInfo,
            if (usePsk) &pskBuf else null,
            cbPsk,
            if (usePsk) &pskIdBuf else null,
            cbPskId,
            &encBuf,
            cbEnc,
        );
        h.check3(status == STATUS_SUCCESS, "RandomKat setupSenderDeterministic failed: {s}", hpkeMultiImp.getLastError());
        results.appendSlice(std.heap.c_allocator, encBuf[0..cbEnc]) catch h.fatal("Out of memory", .{});

        status = hpkeMultiImp.setupRecipient(
            &encBuf,
            cbEnc,
            if (cbInfo > 0) &infoBuf else null,
            cbInfo,
            if (usePsk) &pskBuf else null,
            cbPsk,
            if (usePsk) &pskIdBuf else null,
            cbPskId,
        );
        h.check3(status == STATUS_SUCCESS, "RandomKat setupRecipient failed: {s}", hpkeMultiImp.getLastError());

        if (!exportOnly) {
            const numEncryptionRuns: usize = 1 + katRng.sizet(5);
            for (0..numEncryptionRuns) |_| {
                const cbAad = katRng.sizet(maxInputSize);
                const cbPt = katRng.sizet(maxInputSize);
                if (cbAad > 0) katRng.random(aadBuf[0..cbAad]);
                if (cbPt > 0) katRng.random(ptBuf[0..cbPt]);

                const cbCt = cbPt + aeadParams.cbTag;
                var seqNum: u64 = 0;

                status = hpkeMultiImp.seal(
                    if (cbAad > 0) &aadBuf else null,
                    cbAad,
                    if (cbPt > 0) &ptBuf else null,
                    cbPt,
                    &ctBuf,
                    cbCt,
                    &seqNum,
                );
                h.check(status == STATUS_SUCCESS, "RandomKat seal failed");
                results.appendSlice(std.heap.c_allocator, ctBuf[0..cbCt]) catch h.fatal("Out of memory", .{});

                status = hpkeMultiImp.open(
                    if (cbAad > 0) &aadBuf else null,
                    cbAad,
                    &ctBuf,
                    cbCt,
                    if (cbPt > 0) &decryptedBuf else null,
                    cbPt,
                );
                h.check(status == STATUS_SUCCESS, "RandomKat open failed");
                if (cbPt > 0) {
                    h.check(std.mem.eql(u8, decryptedBuf[0..cbPt], ptBuf[0..cbPt]), "RandomKat open pt mismatch");
                }
            }
        }

        const numExportRuns: usize = 1 + katRng.sizet(5);
        for (0..numExportRuns) |_| {
            const cbExpCtx = katRng.sizet(maxInputSize);
            const cbExpVal: u16 = @intCast(1 + katRng.sizet(maxInputSize));
            if (cbExpCtx > 0) katRng.random(expCtxBuf[0..cbExpCtx]);

            status = hpkeMultiImp.secretExportSender(
                if (cbExpCtx > 0) &expCtxBuf else null,
                cbExpCtx,
                &expValSender,
                cbExpVal,
            );
            h.check(status == STATUS_SUCCESS, "RandomKat secretExportSender failed");

            status = hpkeMultiImp.secretExportRecipient(
                if (cbExpCtx > 0) &expCtxBuf else null,
                cbExpCtx,
                &expValRecip,
                cbExpVal,
            );
            h.check(status == STATUS_SUCCESS, "RandomKat secretExportRecipient failed");
            h.check(std.mem.eql(u8, expValSender[0..cbExpVal], expValRecip[0..cbExpVal]), "RandomKat export mismatch");

            results.appendSlice(std.heap.c_allocator, expValSender[0..cbExpVal]) catch h.fatal("Out of memory", .{});
        }

        _ = hpkeMultiImp.setKey(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, null, 0);
    }

    var actualResult: [32]u8 = undefined;
    SymCryptSha256(results.items.ptr, results.items.len, &actualResult);
    h.check(
        std.mem.eql(u8, &actualResult, &g_expectedResult),
        "Random KAT cumulative SHA-256 digest mismatch",
    );
}

extern fn SymCryptSha256(pbData: [*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

fn testHpkeRandomCrossCheck() void {
    const numRuns: usize = 50;
    const maxInputSize: usize = 64;

    var hpkeMultiImp = HpkeMultiImp.init("Hpke");
    defer hpkeMultiImp.deinit();

    var ikmBuf: [SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE]u8 = undefined;
    var encBuf: [SYMCRYPT_HPKE_KEM_MAX_ENCAPS_CIPHERTEXT_SIZE]u8 = undefined;
    var infoBuf: [maxInputSize]u8 = undefined;
    var pskBuf: [maxInputSize]u8 = undefined;
    var pskIdBuf: [maxInputSize]u8 = undefined;
    var aadBuf: [maxInputSize]u8 = undefined;
    var ptBuf: [maxInputSize]u8 = undefined;
    var ctBuf: [maxInputSize + SYMCRYPT_HPKE_AEAD_MAX_TAG_SIZE]u8 = undefined;
    var decryptedBuf: [maxInputSize]u8 = undefined;
    var expCtxBuf: [maxInputSize]u8 = undefined;
    var expValSender: [maxInputSize]u8 = undefined;
    var expValRecip: [maxInputSize]u8 = undefined;

    for (0..numRuns) |_| {
        const kemId = g_supportedKemIds[rng.g_rng.sizet(g_supportedKemIds.len)];
        const kdfId = g_supportedKdfIds[rng.g_rng.sizet(g_supportedKdfIds.len)];

        const exportOnly = (rng.g_rng.byte() % 5) == 0;
        const aeadId: u16 = if (exportOnly)
            SYMCRYPT_HPKE_AEAD_ID_EXPORT_ONLY
        else
            g_supportedAeadIds[rng.g_rng.sizet(g_supportedAeadIds.len)];

        const cs = SYMCRYPT_HPKE_CIPHERSUITE{ .kemId = kemId, .kdfId = kdfId, .aeadId = aeadId };

        var kemParams: SYMCRYPT_HPKE_KEM_PARAMS = undefined;
        var aeadParams: SYMCRYPT_HPKE_AEAD_PARAMS = undefined;
        if (SymCryptHpkeValidateCiphersuite(cs, &kemParams, &aeadParams) != SYMCRYPT_NO_ERROR) {
            continue;
        }

        const cbIkm = kemParams.cbPrivateKey + rng.g_rng.sizet(SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE - kemParams.cbPrivateKey + 1);
        rng.g_rng.random(ikmBuf[0..cbIkm]);

        var status = hpkeMultiImp.deriveKeyPair(cs, &ikmBuf, cbIkm);
        h.check(status == STATUS_SUCCESS, "RandomCrossCheck deriveKeyPair failed");

        const cbInfo = rng.g_rng.sizet(maxInputSize);
        if (cbInfo > 0) rng.g_rng.random(infoBuf[0..cbInfo]);

        const usePsk = (rng.g_rng.byte() & 1) != 0;
        var cbPsk: usize = 0;
        var cbPskId: usize = 0;
        if (usePsk) {
            cbPsk = 32 + rng.g_rng.sizet(maxInputSize - 32 + 1);
            cbPskId = 1 + rng.g_rng.sizet(maxInputSize);
            rng.g_rng.random(pskBuf[0..cbPsk]);
            rng.g_rng.random(pskIdBuf[0..cbPskId]);
        }

        const cbEnc: usize = kemParams.cbEnc;
        const useSingleShot = (rng.g_rng.byte() & 1) != 0;

        if (useSingleShot) {
            if (!exportOnly) {
                const cbAad = rng.g_rng.sizet(maxInputSize);
                const cbPt = rng.g_rng.sizet(maxInputSize);
                if (cbAad > 0) rng.g_rng.random(aadBuf[0..cbAad]);
                if (cbPt > 0) rng.g_rng.random(ptBuf[0..cbPt]);
                const cbCt = cbPt + aeadParams.cbTag;

                status = hpkeMultiImp.sealSingleShot(
                    if (cbInfo > 0) &infoBuf else null,
                    cbInfo,
                    if (usePsk) &pskBuf else null,
                    cbPsk,
                    if (usePsk) &pskIdBuf else null,
                    cbPskId,
                    if (cbAad > 0) &aadBuf else null,
                    cbAad,
                    if (cbPt > 0) &ptBuf else null,
                    cbPt,
                    &encBuf,
                    cbEnc,
                    &ctBuf,
                    cbCt,
                );
                h.check(status == STATUS_SUCCESS, "RandomCrossCheck sealSingleShot failed");

                status = hpkeMultiImp.openSingleShot(
                    &encBuf,
                    cbEnc,
                    if (cbInfo > 0) &infoBuf else null,
                    cbInfo,
                    if (usePsk) &pskBuf else null,
                    cbPsk,
                    if (usePsk) &pskIdBuf else null,
                    cbPskId,
                    if (cbAad > 0) &aadBuf else null,
                    cbAad,
                    &ctBuf,
                    cbCt,
                    if (cbPt > 0) &decryptedBuf else null,
                    cbPt,
                );
                h.check(status == STATUS_SUCCESS, "RandomCrossCheck openSingleShot failed");
                if (cbPt > 0) {
                    h.check(std.mem.eql(u8, decryptedBuf[0..cbPt], ptBuf[0..cbPt]), "RandomCrossCheck SingleShot pt mismatch");
                }
            }
        } else {
            status = hpkeMultiImp.setupSender(
                if (cbInfo > 0) &infoBuf else null,
                cbInfo,
                if (usePsk) &pskBuf else null,
                cbPsk,
                if (usePsk) &pskIdBuf else null,
                cbPskId,
                &encBuf,
                cbEnc,
            );
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck setupSender failed");

            // Re-derive key pair so all implementations are back in m_comps for recipient setup
            status = hpkeMultiImp.deriveKeyPair(cs, &ikmBuf, cbIkm);
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck re-deriveKeyPair failed");

            var cbRandom: usize = kemParams.cbPrivateKey;
            if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_512 or
                kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_768 or
                kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM_1024)
            {
                cbRandom = 32;
            } else if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256 or
                kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519)
            {
                cbRandom = 64;
            } else if (kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384) {
                cbRandom = 80;
            }

            var randomBuf: [SYMCRYPT_HPKE_KDF_MAX_IKM_SIZE]u8 = undefined;
            rng.g_rng.random(randomBuf[0..cbRandom]);

            status = hpkeMultiImp.setupSenderDeterministic(
                &randomBuf,
                cbRandom,
                if (cbInfo > 0) &infoBuf else null,
                cbInfo,
                if (usePsk) &pskBuf else null,
                cbPsk,
                if (usePsk) &pskIdBuf else null,
                cbPskId,
                &encBuf,
                cbEnc,
            );
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck setupSenderDeterministic failed");

            status = hpkeMultiImp.setupRecipient(
                &encBuf,
                cbEnc,
                if (cbInfo > 0) &infoBuf else null,
                cbInfo,
                if (usePsk) &pskBuf else null,
                cbPsk,
                if (usePsk) &pskIdBuf else null,
                cbPskId,
            );
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck setupRecipient failed");

            if (!exportOnly) {
                const numMsgs: usize = 1 + rng.g_rng.sizet(4);
                for (0..numMsgs) |_| {
                    const cbAad = rng.g_rng.sizet(maxInputSize);
                    const cbPt = rng.g_rng.sizet(maxInputSize);
                    if (cbAad > 0) rng.g_rng.random(aadBuf[0..cbAad]);
                    if (cbPt > 0) rng.g_rng.random(ptBuf[0..cbPt]);
                    const cbCt = cbPt + aeadParams.cbTag;
                    var seqNum: u64 = 0;

                    status = hpkeMultiImp.seal(
                        if (cbAad > 0) &aadBuf else null,
                        cbAad,
                        if (cbPt > 0) &ptBuf else null,
                        cbPt,
                        &ctBuf,
                        cbCt,
                        &seqNum,
                    );
                    h.check(status == STATUS_SUCCESS, "RandomCrossCheck seal failed");

                    status = hpkeMultiImp.open(
                        if (cbAad > 0) &aadBuf else null,
                        cbAad,
                        &ctBuf,
                        cbCt,
                        if (cbPt > 0) &decryptedBuf else null,
                        cbPt,
                    );
                    h.check(status == STATUS_SUCCESS, "RandomCrossCheck open failed");
                    if (cbPt > 0) {
                        h.check(std.mem.eql(u8, decryptedBuf[0..cbPt], ptBuf[0..cbPt]), "RandomCrossCheck open pt mismatch");
                    }
                }
            }

            const cbExpCtx = rng.g_rng.sizet(maxInputSize);
            const cbExpVal: u16 = @intCast(1 + rng.g_rng.sizet(maxInputSize));
            if (cbExpCtx > 0) rng.g_rng.random(expCtxBuf[0..cbExpCtx]);

            status = hpkeMultiImp.secretExportSender(
                if (cbExpCtx > 0) &expCtxBuf else null,
                cbExpCtx,
                &expValSender,
                cbExpVal,
            );
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck secretExportSender failed");

            status = hpkeMultiImp.secretExportRecipient(
                if (cbExpCtx > 0) &expCtxBuf else null,
                cbExpCtx,
                &expValRecip,
                cbExpVal,
            );
            h.check(status == STATUS_SUCCESS, "RandomCrossCheck secretExportRecipient failed");
            h.check(std.mem.eql(u8, expValSender[0..cbExpVal], expValRecip[0..cbExpVal]), "RandomCrossCheck export mismatch");
        }

        _ = hpkeMultiImp.setKey(cs, SYMCRYPT_HPKEKEY_FORMAT_PRIVATE_KEY, null, 0);
    }
}

pub export fn testHpke() callconv(.c) void {
    var nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak {d} outstanding before testHpke", nOutstandingAllocs);

    if (!h.isAlgorithmPresent("Hpke", 1)) {
        return;
    }

    h.ziprint("    HPKE\n", .{});

    for (g_rgTestHpkeCiphersuites) |tcs| {
        testHpkeRoundTrip(tcs);
        testHpkeMultipleMessages(tcs);
        testHpkePsk(tcs);
        testHpkeSecretExport(tcs);
        testHpkekeyImportExport(tcs);
        testHpkeSingleShot(tcs);
        testHpkeDataIntegrity(tcs);
        testHpkeMultiImp(tcs);
    }

    testHpkeExportOnly();
    testHpkeSealValidationFailureDoesNotConsumeSequence();
    testHpkeMultiThread();
    testHpkeErrorCases();
    testHpkeKat();
    testHpkeRandomKat();
    testHpkeRandomCrossCheck();

    h.ziprint("\n", .{});

    nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak {d} outstanding after testHpke", nOutstandingAllocs);
}
