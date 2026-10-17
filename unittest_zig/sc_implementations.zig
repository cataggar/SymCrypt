// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");

const check = h.check;

pub const SYMCRYPT_NO_ERROR: u32 = 0;
pub const SYMCRYPT_AUTHENTICATION_FAILURE: u32 = 0x8007;
pub const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800E;

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));
pub const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

pub const DynamicSymbolType = enum(u32) {
    function_ptr = 1,
    data_ptr = 2,
    array = 3,
};

pub const SYMCRYPT_OID = extern struct {
    cbOID: u32,
    pbOID: [*]const u8,
};

pub const ImpKind = enum {
    sc,
    sc_static,
    sc_dynamic,

    pub fn name(self: ImpKind) []const u8 {
        return switch (self) {
            .sc => "SymCrypt",
            .sc_static => "SymCryptStatic",
            .sc_dynamic => "SymCryptDynamic",
        };
    }

    pub fn nameZ(self: ImpKind) [*:0]const u8 {
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

pub const SYMCRYPT_MD2_STATE_EXPORT_SIZE: usize = 80;
pub const SYMCRYPT_MD4_STATE_EXPORT_SIZE: usize = 116;
pub const SYMCRYPT_MD5_STATE_EXPORT_SIZE: usize = 116;
pub const SYMCRYPT_SHA1_STATE_EXPORT_SIZE: usize = 120;
pub const SYMCRYPT_SHA224_STATE_EXPORT_SIZE: usize = 132;
pub const SYMCRYPT_SHA256_STATE_EXPORT_SIZE: usize = 132;
pub const SYMCRYPT_SHA384_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_224_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_SHA512_256_STATE_EXPORT_SIZE: usize = 236;
pub const SYMCRYPT_KECCAK_STATE_EXPORT_SIZE: usize = 234;
pub const SYMCRYPT_SHA3_224_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_256_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_384_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHA3_512_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHAKE128_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;
pub const SYMCRYPT_SHAKE256_STATE_EXPORT_SIZE: usize = SYMCRYPT_KECCAK_STATE_EXPORT_SIZE;

pub extern fn SymCryptWipe(pbData: ?[*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptEqual(pb1: ?[*]const u8, pb2: ?[*]const u8, cb: usize) callconv(.c) u8;

// Global algorithm / blockcipher / seed pointers
pub extern const SymCryptMd2Algorithm: *const anyopaque;
pub extern const SymCryptMd4Algorithm: *const anyopaque;
pub extern const SymCryptMd5Algorithm: *const anyopaque;
pub extern const SymCryptSha1Algorithm: *const anyopaque;
pub extern const SymCryptSha224Algorithm: *const anyopaque;
pub extern const SymCryptSha256Algorithm: *const anyopaque;
pub extern const SymCryptSha384Algorithm: *const anyopaque;
pub extern const SymCryptSha512Algorithm: *const anyopaque;
pub extern const SymCryptSha512_224Algorithm: *const anyopaque;
pub extern const SymCryptSha512_256Algorithm: *const anyopaque;
pub extern const SymCryptSha3_224Algorithm: *const anyopaque;
pub extern const SymCryptSha3_256Algorithm: *const anyopaque;
pub extern const SymCryptSha3_384Algorithm: *const anyopaque;
pub extern const SymCryptSha3_512Algorithm: *const anyopaque;
pub extern const SymCryptShake128HashAlgorithm: *const anyopaque;
pub extern const SymCryptShake256HashAlgorithm: *const anyopaque;

pub extern const SymCryptHmacMd5Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha1Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha224Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha256Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha384Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha512Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha512_224Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha512_256Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha3_224Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha3_256Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha3_384Algorithm: *const anyopaque;
pub extern const SymCryptHmacSha3_512Algorithm: *const anyopaque;
pub extern const SymCryptAesCmacAlgorithm: *const anyopaque;
pub extern const SymCryptMarvin32Algorithm: *const anyopaque;
pub extern const SymCryptKmac128Algorithm: *const anyopaque;
pub extern const SymCryptKmac256Algorithm: *const anyopaque;
pub extern const SymCryptMarvin32DefaultSeed: *const anyopaque;

pub extern const SymCryptAesBlockCipher: *const anyopaque;
pub extern const SymCryptDesBlockCipher: *const anyopaque;
pub extern const SymCrypt3DesBlockCipher: *const anyopaque;
pub extern const SymCryptDesxBlockCipher: *const anyopaque;
pub extern const SymCryptRc2BlockCipher: *const anyopaque;

// Hashes
pub extern fn SymCryptMd2Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd2Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptMd2Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd2StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd2(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd2StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd2StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptMd4Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd4Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptMd4Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd4StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd4(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd4StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd4StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptMd5Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd5Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptMd5Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd5StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMd5(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd5StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptMd5StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha1Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha1Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha1Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha1StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha1(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha1StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha1StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha224Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha224StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha224(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha224StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha224StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha256Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha256StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha256StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha384Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha384Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha384Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha384StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha384(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha384StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha384StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha512Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha512Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha512_224Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512_224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha512_224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_224StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512_224(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_224StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_224StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha512_256Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512_256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha512_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha512_256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_256StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha512_256StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha3_224Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha3_224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_224StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_224(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_224StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_224StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha3_256Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha3_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_256StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_256StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha3_384Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_384Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha3_384Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_384StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_384(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_384StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_384StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptSha3_512Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_512Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptSha3_512Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_512StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptSha3_512(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_512StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptSha3_512StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

// Parallel Hash
pub extern fn SymCryptParallelSha256Init(pStates: *anyopaque, nStates: usize) callconv(.c) void;
pub extern fn SymCryptParallelSha256Process(pStates: *anyopaque, nStates: usize, pOperations: *const anyopaque, nOperations: usize, pbScratch: [*]u8, cbScratch: usize) callconv(.c) u32;
pub extern fn SymCryptParallelSha384Init(pStates: *anyopaque, nStates: usize) callconv(.c) void;
pub extern fn SymCryptParallelSha384Process(pStates: *anyopaque, nStates: usize, pOperations: *const anyopaque, nOperations: usize, pbScratch: [*]u8, cbScratch: usize) callconv(.c) u32;
pub extern fn SymCryptParallelSha512Init(pStates: *anyopaque, nStates: usize) callconv(.c) void;
pub extern fn SymCryptParallelSha512Process(pStates: *anyopaque, nStates: usize, pOperations: *const anyopaque, nOperations: usize, pbScratch: [*]u8, cbScratch: usize) callconv(.c) u32;

// XOF / Shake
pub extern fn SymCryptShake128Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptShake128Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptShake128Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptShake128Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptShake128StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptShake128(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
pub extern fn SymCryptShake128StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptShake128StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

pub extern fn SymCryptShake256Init(pState: *anyopaque) callconv(.c) void;
pub extern fn SymCryptShake256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptShake256Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptShake256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptShake256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptShake256(pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
pub extern fn SymCryptShake256StateExport(pState: *const anyopaque, pbBlob: [*]u8) callconv(.c) void;
pub extern fn SymCryptShake256StateImport(pState: *anyopaque, pbBlob: [*]const u8) callconv(.c) u32;

// cSHAKE
pub extern fn SymCryptCShake128Init(pState: *anyopaque, pbFunctionName: ?[*]const u8, cbFunctionName: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize) callconv(.c) void;
pub extern fn SymCryptCShake128Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCShake128Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptCShake128Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptCShake128StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptCShake128(pbFunctionName: ?[*]const u8, cbFunctionName: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

pub extern fn SymCryptCShake256Init(pState: *anyopaque, pbFunctionName: ?[*]const u8, cbFunctionName: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize) callconv(.c) void;
pub extern fn SymCryptCShake256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCShake256Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptCShake256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptCShake256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptCShake256(pbFunctionName: ?[*]const u8, cbFunctionName: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

// KMAC
pub extern fn SymCryptKmac128ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptKmac128ExpandKeyEx(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize) callconv(.c) u32;
pub extern fn SymCryptKmac128KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac128Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac128Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptKmac128Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptKmac128Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptKmac128ResultEx(pState: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
pub extern fn SymCryptKmac128StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac128(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptKmac128Ex(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

pub extern fn SymCryptKmac256ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptKmac256ExpandKeyEx(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbCustomizationString: ?[*]const u8, cbCustomizationString: usize) callconv(.c) u32;
pub extern fn SymCryptKmac256KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac256Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptKmac256Extract(pState: *anyopaque, pbResult: [*]u8, cbResult: usize, bWipe: u8) callconv(.c) void;
pub extern fn SymCryptKmac256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptKmac256ResultEx(pState: *anyopaque, pbResult: [*]u8, cbResult: usize) callconv(.c) void;
pub extern fn SymCryptKmac256StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptKmac256(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptKmac256Ex(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) void;

// MACs
pub extern fn SymCryptHmacMd5ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacMd5KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacMd5Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacMd5Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacMd5Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacMd5StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacMd5(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha1ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha1KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha1Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha1Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha1Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha1StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha1(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha224ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha224KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha224Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha224StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha224(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha256ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha256KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha256Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha256StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha256(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha384ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha384KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha384Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha384Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha384Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha384StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha384(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha512ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha512KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha512Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha512StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha512_224ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha512_224KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_224Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha512_224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha512_224StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_224(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha512_256ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha512_256KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_256Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha512_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha512_256StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha512_256(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha3_224ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha3_224KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_224Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_224Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha3_224Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha3_224StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_224(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha3_256ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha3_256KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_256Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha3_256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha3_256StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_256(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha3_384ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha3_384KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_384Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_384Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha3_384Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha3_384StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_384(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptHmacSha3_512ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptHmacSha3_512KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_512Init(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_512Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptHmacSha3_512Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptHmacSha3_512StateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptHmacSha3_512(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptAesCmacExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptAesCmacKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptAesCmacInit(pState: *anyopaque, pExpandedKey: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptAesCmacAppend(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesCmacResult(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptAesCmacStateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptAesCmac(pExpandedKey: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptMarvin32ExpandSeed(pExpandedSeed: *anyopaque, pbSeed: ?[*]const u8, cbSeed: usize) callconv(.c) u32;
pub extern fn SymCryptMarvin32SeedCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMarvin32Init(pState: *anyopaque, pExpandedSeed: *const anyopaque) callconv(.c) void;
pub extern fn SymCryptMarvin32Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptMarvin32Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptMarvin32StateCopy(pSrc: *const anyopaque, pExpandedSeed: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptMarvin32(pExpandedSeed: *const anyopaque, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

pub extern fn SymCryptPoly1305Init(pState: *anyopaque, pbKey: ?[*]const u8) callconv(.c) void;
pub extern fn SymCryptPoly1305Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptPoly1305Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
pub extern fn SymCryptPoly1305(pbKey: ?[*]const u8, pbData: ?[*]const u8, cbData: usize, pbResult: [*]u8) callconv(.c) void;

// KDFs
pub extern fn SymCryptPbkdf2ExpandKey(pExpandedKey: *anyopaque, macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptPbkdf2Derive(pExpandedKey: *const anyopaque, pbSalt: ?[*]const u8, cbSalt: usize, iterationCnt: u64, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;
pub extern fn SymCryptPbkdf2(macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbSalt: ?[*]const u8, cbSalt: usize, iterationCnt: u64, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;

pub extern fn SymCryptSp800_108ExpandKey(pExpandedKey: *anyopaque, macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptSp800_108Derive(pExpandedKey: *const anyopaque, pbLabel: ?[*]const u8, cbLabel: usize, pbContext: ?[*]const u8, cbContext: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;
pub extern fn SymCryptSp800_108(macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbLabel: ?[*]const u8, cbLabel: usize, pbContext: ?[*]const u8, cbContext: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;

pub extern fn SymCryptTlsPrf1_1ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptTlsPrf1_1Derive(pExpandedKey: *const anyopaque, pbLabel: ?[*]const u8, cbLabel: usize, pbSeed: ?[*]const u8, cbSeed: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;
pub extern fn SymCryptTlsPrf1_1(pbKey: ?[*]const u8, cbKey: usize, pbLabel: ?[*]const u8, cbLabel: usize, pbSeed: ?[*]const u8, cbSeed: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;

pub extern fn SymCryptTlsPrf1_2ExpandKey(pExpandedKey: *anyopaque, macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptTlsPrf1_2Derive(pExpandedKey: *const anyopaque, pbLabel: ?[*]const u8, cbLabel: usize, pbSeed: ?[*]const u8, cbSeed: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;
pub extern fn SymCryptTlsPrf1_2(macAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbLabel: ?[*]const u8, cbLabel: usize, pbSeed: ?[*]const u8, cbSeed: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;

pub extern fn SymCryptHkdfExpandKey(pExpandedKey: *anyopaque, macAlgorithm: *const anyopaque, pbIkm: ?[*]const u8, cbIkm: usize, pbSalt: ?[*]const u8, cbSalt: usize) callconv(.c) u32;
pub extern fn SymCryptHkdfExtractPrk(macAlgorithm: *const anyopaque, pbIkm: ?[*]const u8, cbIkm: usize, pbSalt: ?[*]const u8, cbSalt: usize, pbPrk: [*]u8, cbPrk: usize) callconv(.c) u32;
pub extern fn SymCryptHkdfPrkExpandKey(pExpandedKey: *anyopaque, macAlgorithm: *const anyopaque, pbPrk: [*]const u8, cbPrk: usize) callconv(.c) u32;
pub extern fn SymCryptHkdfDerive(pExpandedKey: *const anyopaque, pbInfo: ?[*]const u8, cbInfo: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;
pub extern fn SymCryptHkdf(macAlgorithm: *const anyopaque, pbIkm: ?[*]const u8, cbIkm: usize, pbSalt: ?[*]const u8, cbSalt: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbResult: [*]u8, cbResult: usize) callconv(.c) u32;

pub extern fn SymCryptSshKdfExpandKey(pExpandedKey: *anyopaque, hashAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptSshKdfDerive(pExpandedKey: *const anyopaque, pbHashValue: ?[*]const u8, cbHashValue: usize, label: u8, pbSessionId: ?[*]const u8, cbSessionId: usize, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;
pub extern fn SymCryptSshKdf(hashAlgorithm: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbHashValue: ?[*]const u8, cbHashValue: usize, label: u8, pbSessionId: ?[*]const u8, cbSessionId: usize, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;

pub extern fn SymCryptSrtpKdfExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptSrtpKdfDerive(pExpandedKey: *const anyopaque, pbSalt: ?[*]const u8, cbSalt: usize, uKeyDerivationRate: u32, uIndex: u64, uIndexWidth: u32, label: u8, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;
pub extern fn SymCryptSrtpKdf(pbKey: ?[*]const u8, cbKey: usize, pbSalt: ?[*]const u8, cbSalt: usize, uKeyDerivationRate: u32, uIndex: u64, uIndexWidth: u32, label: u8, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;

pub extern fn SymCryptSskdfMacExpandSalt(pExpandedSalt: *anyopaque, macAlgorithm: *const anyopaque, pbSalt: ?[*]const u8, cbSalt: usize) callconv(.c) u32;
pub extern fn SymCryptSskdfMacDerive(pExpandedSalt: *const anyopaque, cbExpansionLen: usize, pbKey: ?[*]const u8, cbKey: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;
pub extern fn SymCryptSskdfMac(macAlgorithm: *const anyopaque, cbExpansionLen: usize, pbKey: ?[*]const u8, cbKey: usize, pbSalt: ?[*]const u8, cbSalt: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;
pub extern fn SymCryptSskdfHash(hashAlgorithm: *const anyopaque, cbExpansionLen: usize, pbKey: ?[*]const u8, cbKey: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbOutput: [*]u8, cbOutput: usize) callconv(.c) u32;

// Block Ciphers
pub extern fn SymCryptAesExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptAesKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptAesEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptAesDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptAesEcbEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesEcbDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesCbcEncrypt(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesCbcDecrypt(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesCtrMsb32(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptAesCtrMsb64(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

pub extern fn SymCryptDesExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptDesKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptDesEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptDesDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;

pub extern fn SymCrypt3DesExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCrypt3DesKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCrypt3DesEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCrypt3DesDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;

pub extern fn SymCryptDesxExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptDesxKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptDesxEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptDesxDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;

pub extern fn SymCryptRc2ExpandKey(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptRc2ExpandKeyEx(pExpandedKey: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, EffectiveKeyLength: u32) callconv(.c) u32;
pub extern fn SymCryptRc2KeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptRc2Encrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptRc2Decrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8) callconv(.c) void;
pub extern fn SymCryptRc2CbcEncrypt(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptRc2CbcDecrypt(pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

pub extern fn SymCryptEcbEncrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptEcbDecrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCbcEncrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCbcDecrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCfbEncrypt(pBlockCipher: *const anyopaque, cbShift: usize, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCfbDecrypt(pBlockCipher: *const anyopaque, cbShift: usize, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCtrMsb32(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCtrMsb64(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbChainingValue: [*]u8, pbSrc: ?[*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

// AuthEnc (CCM / GCM / ChaCha20Poly1305)
pub extern fn SymCryptCcmValidateParameters(pBlockCipher: *const anyopaque, cbNonce: usize, cbAuthData: u64, cbData: u64, cbTag: usize) callconv(.c) u32;
pub extern fn SymCryptCcmInit(pState: *anyopaque, pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, cbData: u64, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptCcmEncryptPart(pState: *anyopaque, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCcmDecryptPart(pState: *anyopaque, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptCcmEncryptFinal(pState: *anyopaque, pbTag: [*]u8, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptCcmDecryptFinal(pState: *anyopaque, pbTag: [*]const u8, cbTag: usize) callconv(.c) u32;
pub extern fn SymCryptCcmStateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptCcmEncrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]u8, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptCcmDecrypt(pBlockCipher: *const anyopaque, pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]const u8, cbTag: usize) callconv(.c) u32;

pub extern fn SymCryptGcmValidateParameters(pBlockCipher: *const anyopaque, cbNonce: usize, cbAuthData: u64, cbData: u64, cbTag: usize) callconv(.c) u32;
pub extern fn SymCryptGcmExpandKey(pExpandedKey: *anyopaque, pBlockCipher: *const anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptGcmKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptGcmInit(pState: *anyopaque, pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize) callconv(.c) void;
pub extern fn SymCryptGcmStateCopy(pSrc: *const anyopaque, pExpandedKey: ?*const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptGcmAuthPart(pState: *anyopaque, pbAuthData: ?[*]const u8, cbAuthData: usize) callconv(.c) void;
pub extern fn SymCryptGcmEncryptPart(pState: *anyopaque, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptGcmDecryptPart(pState: *anyopaque, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptGcmEncryptFinal(pState: *anyopaque, pbTag: [*]u8, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptGcmDecryptFinal(pState: *anyopaque, pbTag: [*]const u8, cbTag: usize) callconv(.c) u32;
pub extern fn SymCryptGcmEncrypt(pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]u8, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptGcmDecrypt(pExpandedKey: *const anyopaque, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]const u8, cbTag: usize) callconv(.c) u32;

pub extern fn SymCryptChaCha20Poly1305Encrypt(pbKey: ?[*]const u8, cbKey: usize, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]u8, cbTag: usize) callconv(.c) void;
pub extern fn SymCryptChaCha20Poly1305Decrypt(pbKey: ?[*]const u8, cbKey: usize, pbNonce: ?[*]const u8, cbNonce: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, pbDst: ?[*]u8, cbData: usize, pbTag: [*]const u8, cbTag: usize) callconv(.c) u32;

// Stream Ciphers
pub extern fn SymCryptRc4Init(pState: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptRc4Crypt(pState: *anyopaque, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

pub extern fn SymCryptChaCha20Init(pState: *anyopaque, pbKey: ?[*]const u8, cbKey: usize, pbNonce: ?[*]const u8, cbNonce: usize, offset: u64) callconv(.c) u32;
pub extern fn SymCryptChaCha20SetOffset(pState: *anyopaque, offset: u64) callconv(.c) void;
pub extern fn SymCryptChaCha20Crypt(pState: *anyopaque, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

// RNG
pub extern fn SymCryptRngAesInstantiate(pState: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptRngAesReseed(pState: *anyopaque, pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) u32;
pub extern fn SymCryptRngAesGenerate(pState: *anyopaque, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptRngAesUninstantiate(pState: *anyopaque) callconv(.c) void;

pub extern fn SymCryptRngAesFips140_2Instantiate(pState: *anyopaque, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptRngAesFips140_2Reseed(pState: *anyopaque, pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) u32;
pub extern fn SymCryptRngAesFips140_2Generate(pState: *anyopaque, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptRngAesFips140_2Uninstantiate(pState: *anyopaque) callconv(.c) void;

pub extern fn SymCryptProvideEntropy(pbEntropy: ?[*]const u8, cbEntropy: usize) callconv(.c) void;
pub extern fn SymCryptRandom(pbRandom: [*]u8, cbRandom: usize) callconv(.c) void;

// XTS-AES
pub extern fn SymCryptXtsAesExpandKey(pExpandedKey: *anyopaque, pbKey: [*]const u8, cbKey: usize) callconv(.c) u32;
pub extern fn SymCryptXtsAesExpandKeyEx(pExpandedKey: *anyopaque, pbKey: [*]const u8, cbKey: usize, flags: u32) callconv(.c) u32;
pub extern fn SymCryptXtsAesKeyCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;
pub extern fn SymCryptXtsAesEncrypt(pExpandedKey: *const anyopaque, cbDataUnit: usize, tweak: u64, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesDecrypt(pExpandedKey: *const anyopaque, cbDataUnit: usize, tweak: u64, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesEncryptWith128bTweak(pExpandedKey: *const anyopaque, cbDataUnit: usize, pbTweak: [*]const u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesDecryptWith128bTweak(pExpandedKey: *const anyopaque, cbDataUnit: usize, pbTweak: [*]const u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesEncryptDataUnit(pExpandedKey: *const anyopaque, pbTweakBlock: [*]u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesDecryptDataUnit(pExpandedKey: *const anyopaque, pbTweakBlock: [*]u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesEncryptDataUnitEx(pExpandedKey: *const anyopaque, pbTweakBlock: [*]const u8, pbScratch: [*]u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;
pub extern fn SymCryptXtsAesDecryptDataUnitEx(pExpandedKey: *const anyopaque, pbTweakBlock: [*]const u8, pbScratch: [*]u8, pbSrc: [*]const u8, pbDst: [*]u8, cbData: usize) callconv(.c) void;

// AES-KW / AES-KWP
pub extern fn SymCryptAesKwEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) u32;
pub extern fn SymCryptAesKwDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) u32;
pub extern fn SymCryptAesKwpEncrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) u32;
pub extern fn SymCryptAesKwpDecrypt(pExpandedKey: *const anyopaque, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: [*]u8, cbDst: usize, pcbResult: *usize) callconv(.c) u32;

// TLS-CBC-HMAC
pub extern fn SymCryptTlsCbcHmacVerify(pMacAlgorithm: *const anyopaque, pExpandedKey: *const anyopaque, pState: *anyopaque, pbData: [*]const u8, cbData: usize) callconv(.c) u32;

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
        return SymCryptRngAesInstantiate(pState, &entropy, entropy.len);
    } else {
        pExpandedKey.useDerivationFunction = pbKey[0];
        return SymCryptRngAesInstantiate(pState, pbKey + 1, cbKey - 1);
    }
}

pub export fn SymCryptAesCtrDrbgReseed(
    pExpandedKey: *SYMCRYPT_RNG_AES_EXPANDED_KEY,
    pState: *anyopaque,
    pbEntropy: [*]const u8,
    cbEntropy: usize,
) callconv(.c) void {
    _ = pExpandedKey;
    _ = SymCryptRngAesReseed(pState, pbEntropy, cbEntropy);
}

pub export fn SymCryptAesCtrDrbgGenerate(
    pExpandedKey: *SYMCRYPT_RNG_AES_EXPANDED_KEY,
    pState: *anyopaque,
    pbSrc: ?[*]const u8,
    pbDst: [*]u8,
    cbData: usize,
) callconv(.c) void {
    _ = pExpandedKey;
    _ = pbSrc;
    SymCryptRngAesGenerate(pState, pbDst, cbData);
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
