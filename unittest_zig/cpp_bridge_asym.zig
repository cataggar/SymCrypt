//
// cpp_bridge_asym.zig
// Asymmetric, post-quantum, HBS, and HPKE implementation states and C-ABI bridges
// ported from unittest/lib/cpp_bridge.cpp and unittest/lib/sc_imp_pattern.cpp.
//

const std = @import("std");
const types = @import("symcrypt_types");
const h = @import("main_harness.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");
const sc_imp = @import("sc_implementations.zig");
const bridge = @import("cpp_bridge.zig");

const SYMCRYPT_NO_ERROR: i32 = 0;
const SYMCRYPT_AUTHENTICATION_FAILURE: i32 = 0x8007;
const SYMCRYPT_NOT_IMPLEMENTED: i32 = 0x800B;
const SYMCRYPT_INVALID_BLOB: i32 = 0x800C;
const SYMCRYPT_BUFFER_TOO_SMALL: i32 = 0x800D;
const SYMCRYPT_INVALID_ARGUMENT: i32 = 0x800E;
const SYMCRYPT_MEMORY_ALLOCATION_FAILURE: i32 = 0x800F;
const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE: i32 = 0x8010;
const SYMCRYPT_INCOMPATIBLE_FORMAT: i32 = 0x8011;
const SYMCRYPT_VALUE_TOO_LARGE: i32 = 0x8012;
const SYMCRYPT_SESSION_REPLAY_FAILURE: i32 = 0x8013;
const SYMCRYPT_HBS_NO_OTS_KEYS_LEFT: i32 = 0x8014;
const SYMCRYPT_HBS_PUBLIC_ROOT_MISMATCH: i32 = 0x8015;

const STATUS_SUCCESS: i32 = 0;
const STATUS_BUFFER_OVERFLOW: i32 = @bitCast(@as(u32, 0x80000005));
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));
const STATUS_INVALID_PARAMETER: i32 = @bitCast(@as(u32, 0xC000000D));
const STATUS_INVALID_SIGNATURE: i32 = @bitCast(@as(u32, 0xC000A000));
const STATUS_UNSUCCESSFUL: i32 = @bitCast(@as(u32, 0xC0000001));

const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: u32 = 2;
const SYMCRYPT_FLAG_KEY_NO_FIPS: u32 = 0x100;
const SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION: u32 = 0x200;
const SYMCRYPT_FLAG_RSAKEY_SIGN: u32 = 0x1000;
const SYMCRYPT_FLAG_RSAKEY_ENCRYPT: u32 = 0x2000;
const SYMCRYPT_RSAKEY_FIPS_MIN_BITSIZE_MODULUS: u32 = 2048;
const SYMCRYPT_FLAG_RSA_PKCS1_NO_ASN1: u32 = 0x01;
const SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID: u32 = 0x02;
const SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT: u32 = 0x04;

const SYMCRYPT_FLAG_DLKEY_PRIVATE_MOD_P: u32 = 0x100;
const SYMCRYPT_FLAG_DLKEY_DSA: u32 = 0x1000;
const SYMCRYPT_FLAG_DLKEY_DH: u32 = 0x2000;

extern fn SymCryptCallbackAlloc(cb: usize) callconv(.c) ?*anyopaque;
extern fn SymCryptCallbackFree(p: ?*anyopaque) callconv(.c) void;
extern fn SymCryptWipe(pbData: [*]u8, cbData: usize) callconv(.c) void;

const RSAKEY_MAXKEYSIZE = 1024;
pub const RSAKEY_TESTBLOB = extern struct {
    nBitsModulus: u32,
    u64PubExp: u64,
    cbModulus: u32,
    cbPrime1: u32,
    cbPrime2: u32,
    abModulus: [RSAKEY_MAXKEYSIZE]u8,
    abPrime1: [RSAKEY_MAXKEYSIZE]u8,
    abPrime2: [RSAKEY_MAXKEYSIZE]u8,
    abPrivateExp: [RSAKEY_MAXKEYSIZE]u8,
    pcstrSource: ?[*:0]const u8,
    u64Line: i64,
};

const DLKEY_MAXKEYSIZE = 1024;
pub const DLGROUP_TESTBLOB = extern struct {
    nBitsP: u32,
    cbPrimeP: u32,
    cbPrimeQ: u32,
    fipsStandard: u32,
    pHashAlgorithm: ?*const anyopaque,
    cbSeed: u32,
    genCounter: u32,
    fHasPrimeQ: u8,
    isSafePrimeGroup: u8,
    pcstrHashAlgName: ?[*:0]const u8,
    abPrimeP: [DLKEY_MAXKEYSIZE]u8,
    abPrimeQ: [DLKEY_MAXKEYSIZE]u8,
    abGenG: [DLKEY_MAXKEYSIZE]u8,
    abSeed: [DLKEY_MAXKEYSIZE]u8,
};

pub const DLKEY_TESTBLOB = extern struct {
    pGroup: *const DLGROUP_TESTBLOB,
    nBitsPriv: u32,
    cbPrivKey: u32,
    abPubKey: [DLKEY_MAXKEYSIZE]u8,
    abPrivKey: [DLKEY_MAXKEYSIZE]u8,
    fPrivateModP: u32,
};

const SYMCRYPT_TEST_MLDSA_MAX_KEY_SIZE = 4896;
const SYMCRYPT_TEST_COMPOSITE_MLDSA_MAX_KEY_SIZE = 2689;

pub const MLDSAKEY_TESTBLOB = extern struct {
    params: u32,
    format: u32,
    abKeyBlob: [SYMCRYPT_TEST_MLDSA_MAX_KEY_SIZE]u8,
    cbKeyBlob: usize,
};

pub const COMPOSITE_MLDSAKEY_TESTBLOB = extern struct {
    params: u32,
    format: u32,
    abKeyBlob: [SYMCRYPT_TEST_COMPOSITE_MLDSA_MAX_KEY_SIZE]u8,
    cbKeyBlob: usize,
};

pub const PQDSAKEY_TESTBLOB = extern union {
    mlDsakey: MLDSAKEY_TESTBLOB,
    compositeMlDsakey: COMPOSITE_MLDSAKEY_TESTBLOB,
};

// ============================================================================
// Extern SymCrypt Asymmetric / PQ / HBS / HPKE symbols
// ============================================================================

const SYMCRYPT_RSA_PARAMS = extern struct {
    version: u32,
    nBitsOfModulus: u32,
    nPrimes: u32,
    nPubExp: u32,
};

extern const SymCryptMd5OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha1OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha224OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha256OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha384OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha512OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha512_224OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha512_256OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha3_224OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha3_256OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha3_384OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptSha3_512OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptShake128OidList: [2]sc_imp.SYMCRYPT_OID;
extern const SymCryptShake256OidList: [2]sc_imp.SYMCRYPT_OID;

extern const SymCryptMd2Algorithm: *const anyopaque;
extern const SymCryptMd4Algorithm: *const anyopaque;
extern const SymCryptMd5Algorithm: *const anyopaque;
extern const SymCryptSha1Algorithm: *const anyopaque;
extern const SymCryptSha224Algorithm: *const anyopaque;
extern const SymCryptSha256Algorithm: *const anyopaque;
extern const SymCryptSha384Algorithm: *const anyopaque;
extern const SymCryptSha512Algorithm: *const anyopaque;
extern const SymCryptSha512_224Algorithm: *const anyopaque;
extern const SymCryptSha512_256Algorithm: *const anyopaque;
extern const SymCryptSha3_224Algorithm: *const anyopaque;
extern const SymCryptSha3_256Algorithm: *const anyopaque;
extern const SymCryptSha3_384Algorithm: *const anyopaque;
extern const SymCryptSha3_512Algorithm: *const anyopaque;

extern fn SymCryptRsakeyAllocate(pParams: *const SYMCRYPT_RSA_PARAMS, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptRsakeyFree(pkRsakey: *anyopaque) callconv(.c) void;
extern fn SymCryptRsakeySetValue(
    pbModulus: [*]const u8,
    cbModulus: usize,
    pu64PubExp: ?*const u64,
    nPubExp: u32,
    ppbPrimes: ?[*]const [*]const u8,
    pcbPrimes: ?[*]const usize,
    nPrimes: u32,
    numFormat: u32,
    flags: u32,
    pkRsakey: *anyopaque,
) callconv(.c) i32;
extern fn SymCryptRsakeySetValueFromPrivateExponent(
    pbModulus: [*]const u8,
    cbModulus: usize,
    u64PubExp: u64,
    pbPrivateExponent: [*]const u8,
    cbPrivateExponent: usize,
    numFormat: u32,
    flags: u32,
    pkRsakey: *anyopaque,
) callconv(.c) i32;
extern fn SymCryptRsakeySizeofModulus(pkRsakey: *const anyopaque) callconv(.c) u32;
extern fn SymCryptRsaRawEncrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    numFormat: u32,
    flags: u32,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) i32;
extern fn SymCryptRsaRawDecrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    numFormat: u32,
    flags: u32,
    pbDst: [*]u8,
    cbDst: usize,
) callconv(.c) i32;
extern fn SymCryptRsaPkcs1Encrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    flags: u32,
    numFormat: u32,
    pbDst: [*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaPkcs1Decrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    numFormat: u32,
    flags: u32,
    pbDst: ?[*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaOaepEncrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pHashAlgorithm: *const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    flags: u32,
    numFormat: u32,
    pbDst: [*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaOaepDecrypt(
    pkRsakey: *const anyopaque,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    numFormat: u32,
    pHashAlgorithm: *const anyopaque,
    pbLabel: ?[*]const u8,
    cbLabel: usize,
    flags: u32,
    pbDst: [*]u8,
    cbDst: usize,
    pcbDst: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaPkcs1Sign(
    pkRsakey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    pHashOIDs: ?[*]const sc_imp.SYMCRYPT_OID,
    nOIDCount: usize,
    flags: u32,
    numFormat: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
    pcbSignature: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaPkcs1Verify(
    pkRsakey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    pbSignature: ?[*]const u8,
    cbSignature: usize,
    numFormat: u32,
    pHashOIDs: ?[*]const sc_imp.SYMCRYPT_OID,
    nOIDCount: usize,
    flags: u32,
) callconv(.c) i32;
extern fn SymCryptRsaPssSign(
    pkRsakey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    pHashAlgorithm: *const anyopaque,
    cbSalt: usize,
    flags: u32,
    numFormat: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
    pcbSignature: *usize,
) callconv(.c) i32;
extern fn SymCryptRsaPssVerify(
    pkRsakey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    pbSignature: ?[*]const u8,
    cbSignature: usize,
    numFormat: u32,
    pHashAlgorithm: *const anyopaque,
    cbSalt: usize,
    flags: u32,
) callconv(.c) i32;

extern fn SymCryptDlgroupAllocate(nBitsOfP: u32, nBitsOfQ: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptDlgroupFree(pgDlgroup: *anyopaque) callconv(.c) void;
extern fn SymCryptDlgroupSetValue(
    pbPrimeP: [*]const u8,
    cbPrimeP: usize,
    pbPrimeQ: ?[*]const u8,
    cbPrimeQ: usize,
    pbGenG: [*]const u8,
    cbGenG: usize,
    numFormat: u32,
    pHashAlgorithm: ?*const anyopaque,
    pbSeed: ?[*]const u8,
    cbSeed: usize,
    genCounter: u32,
    fipsStandard: u32,
    pgDlgroup: *anyopaque,
) callconv(.c) i32;
extern fn SymCryptDlkeyAllocate(pgDlgroup: *const anyopaque) callconv(.c) ?*anyopaque;
extern fn SymCryptDlkeyFree(pkDlkey: *anyopaque) callconv(.c) void;
extern fn SymCryptDlkeySetValue(
    pbPrivateKey: ?[*]const u8,
    cbPrivateKey: usize,
    pbPublicKey: ?[*]const u8,
    cbPublicKey: usize,
    numFormat: u32,
    flags: u32,
    pkDlkey: *anyopaque,
) callconv(.c) i32;
extern fn SymCryptDlkeySetPrivateKeyLength(pkDlkey: *anyopaque, nBitsPriv: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptDhSecretAgreement(
    pkPrivate: *const anyopaque,
    pkPublic: *const anyopaque,
    numFormat: u32,
    flags: u32,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) i32;
extern fn SymCryptDsaSign(
    pkDlkey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    numFormat: u32,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) i32;
extern fn SymCryptDsaVerify(
    pkDlkey: *const anyopaque,
    pbHashValue: ?[*]const u8,
    cbHashValue: usize,
    pbSignature: ?[*]const u8,
    cbSignature: usize,
    numFormat: u32,
    flags: u32,
) callconv(.c) i32;

const SYMCRYPT_XMSS_PARAMS = extern struct {
    hash: ?*const anyopaque align(16),
    id: u32,
    cbHashOutput: u32,
    nWinternitzWidth: u32,
    nTotalTreeHeight: u32,
    nLayers: u32,
    cbPrefix: u32,
    len1: u32,
    len2: u32,
    len: u32,
    nLayerHeight: u32,
    cbIdx: u32,
    nLeftShift32: u32,
    Reserved: [16]u8,
};

const SYMCRYPT_LMS_PARAMS = extern struct {
    lmsAlgID: u32 align(16),
    lmsOtsAlgID: u32,
    pLmsHashFunction: ?*const anyopaque,
    nTreeHeight: u32,
    cbHashOutput: u32,
    nWinternitzChainWidth: u32,
    nByteStringCount: u32,
    nChecksumLShiftBits: u32,
};

extern fn SymCryptXmssParamsFromAlgId(id: u32, pParams: *SYMCRYPT_XMSS_PARAMS) callconv(.c) i32;
extern fn SymCryptXmssMtParamsFromAlgId(id: u32, pParams: *SYMCRYPT_XMSS_PARAMS) callconv(.c) i32;
extern fn SymCryptXmssSizeofSignatureFromParams(pParams: *const SYMCRYPT_XMSS_PARAMS) callconv(.c) usize;
extern fn SymCryptXmssSizeofKeyBlobFromParams(pParams: *const SYMCRYPT_XMSS_PARAMS, keyType: u32, pcbKey: *usize) callconv(.c) i32;
extern fn SymCryptXmsskeyAllocate(pParams: *const SYMCRYPT_XMSS_PARAMS, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptXmsskeyFree(pKey: *anyopaque) callconv(.c) void;
extern fn SymCryptXmsskeyGenerate(pKey: *anyopaque, flags: u32) callconv(.c) i32;
extern fn SymCryptXmsskeySetValue(pbSrc: [*]const u8, cbSrc: usize, keyType: u32, flags: u32, pKey: *anyopaque) callconv(.c) i32;
extern fn SymCryptXmsskeyGetValue(pKey: *const anyopaque, keyType: u32, flags: u32, pbDst: [*]u8, cbDst: usize) callconv(.c) i32;
extern fn SymCryptXmssSign(pKey: *anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, flags: u32, pbSig: [*]u8, cbSig: usize) callconv(.c) i32;
extern fn SymCryptXmssVerify(pKey: *const anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, flags: u32, pbSig: [*]const u8, cbSig: usize) callconv(.c) i32;

extern fn SymCryptLmsParamsFromAlgId(algId: u32, otsAlgId: u32, pParams: *SYMCRYPT_LMS_PARAMS) callconv(.c) i32;
extern fn SymCryptLmsSizeofSignatureFromParams(pParams: *const SYMCRYPT_LMS_PARAMS) callconv(.c) usize;
extern fn SymCryptLmsSizeofKeyBlobFromParams(pParams: *const SYMCRYPT_LMS_PARAMS, keyType: u32, pcbKey: *usize) callconv(.c) i32;
extern fn SymCryptLmskeyAllocate(pParams: *const SYMCRYPT_LMS_PARAMS, flags: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptLmskeyFree(pKey: *anyopaque) callconv(.c) void;
extern fn SymCryptLmskeyGenerate(pKey: *anyopaque, flags: u32) callconv(.c) i32;
extern fn SymCryptLmskeySetValue(pbSrc: [*]const u8, cbSrc: usize, keyType: u32, flags: u32, pKey: *anyopaque) callconv(.c) i32;
extern fn SymCryptLmskeyGetValue(pKey: *const anyopaque, keyType: u32, flags: u32, pbDst: [*]u8, cbDst: usize) callconv(.c) i32;
extern fn SymCryptLmsSign(pKey: *anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, flags: u32, pbSig: [*]u8, cbSig: usize) callconv(.c) i32;
extern fn SymCryptLmsVerify(pKey: *const anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, flags: u32, pbSig: [*]const u8, cbSig: usize) callconv(.c) i32;

extern fn SymCryptMlKemkeyAllocate(params: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptMlKemkeyFree(pkMlKemkey: *anyopaque) callconv(.c) void;
extern fn SymCryptMlKemkeyGenerate(pkMlKemkey: *anyopaque, flags: u32) callconv(.c) i32;
extern fn SymCryptMlKemkeySetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, flags: u32, pkMlKemkey: *anyopaque) callconv(.c) i32;
extern fn SymCryptMlKemkeyGetValue(pkMlKemkey: *const anyopaque, pbDst: [*]u8, cbDst: usize, format: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptMlKemEncapsulate(pkMlKemkey: *const anyopaque, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) i32;
extern fn SymCryptMlKemEncapsulateEx(pkMlKemkey: *const anyopaque, pbRandom: [*]const u8, cbRandom: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) i32;
extern fn SymCryptMlKemDecapsulate(pkMlKemkey: *const anyopaque, pbCiphertext: [*]const u8, cbCiphertext: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize) callconv(.c) i32;

extern fn SymCryptCompositeMlKemkeyAllocate(params: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptCompositeMlKemkeyFree(pkCompositeMlKemkey: *anyopaque) callconv(.c) void;
extern fn SymCryptCompositeMlKemkeyGenerate(pkCompositeMlKemkey: *anyopaque, flags: u32) callconv(.c) i32;
extern fn SymCryptCompositeMlKemkeySetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, flags: u32, pkCompositeMlKemkey: *anyopaque) callconv(.c) i32;
extern fn SymCryptCompositeMlKemkeyGetValue(pkCompositeMlKemkey: *const anyopaque, pbDst: [*]u8, cbDst: usize, format: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptCompositeMlKemEncapsulate(pkCompositeMlKemkey: *const anyopaque, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) i32;
extern fn SymCryptCompositeMlKemEncapsulateEx(pkCompositeMlKemkey: *const anyopaque, pbMlKemRandom: [*]const u8, cbMlKemRandom: usize, pbTraditionalRandom: [*]const u8, cbTraditionalRandom: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) i32;
extern fn SymCryptCompositeMlKemDecapsulate(pkCompositeMlKemkey: *const anyopaque, pbCiphertext: [*]const u8, cbCiphertext: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize) callconv(.c) i32;

extern fn SymCryptMlDsakeyAllocate(params: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptMlDsakeyFree(pkMlDsakey: *anyopaque) callconv(.c) void;
extern fn SymCryptMlDsakeySetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, flags: u32, pkMlDsakey: *anyopaque) callconv(.c) i32;
extern fn SymCryptMlDsakeyGetValue(pkMlDsakey: *const anyopaque, pbDst: [*]u8, cbDst: usize, format: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptMlDsaSign(pkMlDsakey: *const anyopaque, pbInput: ?[*]const u8, cbInput: usize, pbContext: ?[*]const u8, cbContext: usize, flags: u32, pbSignature: [*]u8, cbSignature: usize) callconv(.c) i32;
extern fn SymCryptExternalMuMlDsaSign(pkMlDsakey: *const anyopaque, pbMu: [*]const u8, cbMu: usize, flags: u32, pbSignature: [*]u8, cbSignature: usize) callconv(.c) i32;
extern fn SymCryptHashMlDsaSign(pkMlDsakey: *const anyopaque, hashId: u32, pbHash: ?[*]const u8, cbHash: usize, pbContext: ?[*]const u8, cbContext: usize, flags: u32, pbSignature: [*]u8, cbSignature: usize) callconv(.c) i32;
extern fn SymCryptMlDsaSignEx(pkMlDsakey: *const anyopaque, pbInput: ?[*]const u8, cbInput: usize, pbContext: ?[*]const u8, cbContext: usize, pbHashOid: ?[*]const u8, cbHashOid: usize, pbRandom: ?[*]const u8, cbRandom: usize, flags: u32, pbSignature: [*]u8, cbSignature: usize) callconv(.c) i32;
extern fn SymCryptMlDsaVerify(pkMlDsakey: *const anyopaque, pbInput: ?[*]const u8, cbInput: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]const u8, cbSignature: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptExternalMuMlDsaVerify(pkMlDsakey: *const anyopaque, pbMu: [*]const u8, cbMu: usize, pbSignature: [*]const u8, cbSignature: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptHashMlDsaVerify(pkMlDsakey: *const anyopaque, hashId: u32, pbHash: ?[*]const u8, cbHash: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]const u8, cbSignature: usize, flags: u32) callconv(.c) i32;

extern fn SymCryptCompositeMlDsakeyAllocate(params: u32) callconv(.c) ?*anyopaque;
extern fn SymCryptCompositeMlDsakeyFree(pkCompositeMlDsakey: *anyopaque) callconv(.c) void;
extern fn SymCryptCompositeMlDsakeySetValue(pbSrc: [*]const u8, cbSrc: usize, format: u32, flags: u32, pkCompositeMlDsakey: *anyopaque) callconv(.c) i32;
extern fn SymCryptCompositeMlDsakeyGetValue(pkCompositeMlDsakey: *const anyopaque, pbDst: [*]u8, cbDst: usize, format: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptCompositeMlDsaSign(pkCompositeMlDsakey: *const anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, pbContext: ?[*]const u8, cbContext: usize, flags: u32, pbSignature: [*]u8, cbSignature: usize, pcbResult: ?*usize) callconv(.c) i32;
extern fn SymCryptCompositeMlDsaVerify(pkCompositeMlDsakey: *const anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]const u8, cbSignature: usize, flags: u32) callconv(.c) i32;

pub const SYMCRYPT_HPKE_CIPHERSUITE = extern struct {
    kemId: u16,
    kdfId: u16,
    aeadId: u16,
};

pub const SYMCRYPT_HPKE_KEM_PARAMS = extern struct {
    kemId: u16,
    cbSharedSecret: u16,
    cbEnc: u16,
    cbPublicKey: u16,
    cbPrivateKey: u16,
};

pub const SYMCRYPT_HPKE_AEAD_PARAMS = extern struct {
    aeadId: u16,
    cbKey: u16,
    cbNonce: u16,
    cbTag: u16,
};

pub const SYMCRYPT_HPKEKEY = extern struct {
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE align(16),
    kemParams: SYMCRYPT_HPKE_KEM_PARAMS,
    pKemKeyData: ?*anyopaque,
    magic: usize,
};

pub const SYMCRYPT_HPKECONTEXT = opaque {};

extern fn SymCryptHpkekeyAllocate(params: SYMCRYPT_HPKE_CIPHERSUITE) callconv(.c) ?*SYMCRYPT_HPKEKEY;
extern fn SymCryptHpkekeyFree(pkHpkekey: *SYMCRYPT_HPKEKEY) callconv(.c) void;
extern fn SymCryptHpkeSizeofKeyFormatFromParams(params: SYMCRYPT_HPKE_CIPHERSUITE, hpkeKeyFormat: u32, pcbKeyFormat: *usize) callconv(.c) i32;
extern fn SymCryptHpkeSizeofEncapsCiphertextFromParams(params: SYMCRYPT_HPKE_CIPHERSUITE, pcbEncapsCiphertext: *usize) callconv(.c) i32;
extern fn SymCryptHpkeSizeofAeadOverheadFromParams(params: SYMCRYPT_HPKE_CIPHERSUITE, pcbAeadOverhead: *usize) callconv(.c) i32;
extern fn SymCryptHpkekeyGenerate(pkHpkekey: *SYMCRYPT_HPKEKEY, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkekeyDerive(pbIkm: ?[*]const u8, cbIkm: usize, pkHpkekey: *SYMCRYPT_HPKEKEY, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkekeySetValue(pbSrc: ?[*]const u8, cbSrc: usize, hpkeKeyFormat: u32, flags: u32, pkHpkekey: *SYMCRYPT_HPKEKEY) callconv(.c) i32;
extern fn SymCryptHpkekeyGetValue(pkHpkekey: *const SYMCRYPT_HPKEKEY, pbDst: ?[*]u8, cbDst: usize, hpkeKeyFormat: u32, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkeContextAllocate(params: SYMCRYPT_HPKE_CIPHERSUITE) callconv(.c) ?*SYMCRYPT_HPKECONTEXT;
extern fn SymCryptHpkeContextFree(pHpkeContext: ?*SYMCRYPT_HPKECONTEXT) callconv(.c) void;
extern fn SymCryptHpkeSetupSender(pHpkeContext: *SYMCRYPT_HPKECONTEXT, pkRecipient: *const SYMCRYPT_HPKEKEY, pbInfo: ?[*]const u8, cbInfo: usize, pbPsk: ?[*]const u8, cbPsk: usize, pbPskId: ?[*]const u8, cbPskId: usize, pbEnc: ?[*]u8, cbEnc: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkeSetupRecipient(pHpkeContext: *SYMCRYPT_HPKECONTEXT, pkRecipient: *const SYMCRYPT_HPKEKEY, pbEnc: ?[*]const u8, cbEnc: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbPsk: ?[*]const u8, cbPsk: usize, pbPskId: ?[*]const u8, cbPskId: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkeSeal(pHpkeContext: *SYMCRYPT_HPKECONTEXT, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: ?[*]u8, cbDst: usize, pu64SeqNumber: ?*u64) callconv(.c) i32;
extern fn SymCryptHpkeOpen(pHpkeContext: *SYMCRYPT_HPKECONTEXT, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: ?[*]u8, cbDst: usize) callconv(.c) i32;
extern fn SymCryptHpkeOpenUnordered(pHpkeContext: *const SYMCRYPT_HPKECONTEXT, u64SeqNumber: u64, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: ?[*]u8, cbDst: usize) callconv(.c) i32;
extern fn SymCryptHpkeSecretExport(pHpkeContext: *const SYMCRYPT_HPKECONTEXT, pbExporterContext: ?[*]const u8, cbExporterContext: usize, pbResult: ?[*]u8, cbResult: u16) callconv(.c) i32;
extern fn SymCryptHpkeSealSingleShot(pkRecipient: *const SYMCRYPT_HPKEKEY, pbInfo: ?[*]const u8, cbInfo: usize, pbPsk: ?[*]const u8, cbPsk: usize, pbPskId: ?[*]const u8, cbPskId: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, cbSrc: usize, pbEnc: ?[*]u8, cbEnc: usize, pbDst: ?[*]u8, cbDst: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkeOpenSingleShot(pkRecipient: *const SYMCRYPT_HPKEKEY, pbEnc: ?[*]const u8, cbEnc: usize, pbInfo: ?[*]const u8, cbInfo: usize, pbPsk: ?[*]const u8, cbPsk: usize, pbPskId: ?[*]const u8, cbPskId: usize, pbAuthData: ?[*]const u8, cbAuthData: usize, pbSrc: ?[*]const u8, cbSrc: usize, pbDst: ?[*]u8, cbDst: usize, flags: u32) callconv(.c) i32;
extern fn SymCryptHpkeValidateCiphersuite(params: SYMCRYPT_HPKE_CIPHERSUITE, pKemParams: ?*SYMCRYPT_HPKE_KEM_PARAMS, pAeadParams: ?*SYMCRYPT_HPKE_AEAD_PARAMS) callconv(.c) i32;
extern fn SymCryptHpkeDhkemEncapsulateEx(pkRecipientKey: *const SYMCRYPT_HPKEKEY, pbIkmE: ?[*]const u8, cbIkmE: usize, pbSharedSecret: [*]u8, cbSharedSecret: u16, pbEnc: [*]u8, cbEnc: usize) callconv(.c) i32;
extern fn SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(ecurveId: u32, numFormat: u32, pbSeed: [*]const u8, cbSeed: usize, pbScalar: [*]u8, cbScalar: usize) callconv(.c) i32;
extern fn SymCryptHpkeFinishSetup(pHpkeContext: *SYMCRYPT_HPKECONTEXT, role: u32, pbInfo: ?[*]const u8, cbInfo: usize, pbPsk: ?[*]const u8, cbPsk: usize, pbPskId: ?[*]const u8, cbPskId: usize, pbSharedSecret: [*]const u8, cbSharedSecret: u16) callconv(.c) i32;

// ============================================================================
// Helper: Hash Name -> SymCryptHashAlgorithm / OidList
// ============================================================================

fn getSymCryptHashAlgorithm(imp_kind: sc_imp.ImpKind, pcstrHashAlgName: ?[*:0]const u8) ?*const anyopaque {
    const name_c = pcstrHashAlgName orelse return null;
    const name = std.mem.span(name_c);
    if (std.mem.eql(u8, name, "MD2")) return bridge.getSymPtr(imp_kind, "SymCryptMd2Algorithm", SymCryptMd2Algorithm);
    if (std.mem.eql(u8, name, "MD4")) return bridge.getSymPtr(imp_kind, "SymCryptMd4Algorithm", SymCryptMd4Algorithm);
    if (std.mem.eql(u8, name, "MD5")) return bridge.getSymPtr(imp_kind, "SymCryptMd5Algorithm", SymCryptMd5Algorithm);
    if (std.mem.eql(u8, name, "SHA1")) return bridge.getSymPtr(imp_kind, "SymCryptSha1Algorithm", SymCryptSha1Algorithm);
    if (std.mem.eql(u8, name, "SHA224")) return bridge.getSymPtr(imp_kind, "SymCryptSha224Algorithm", SymCryptSha224Algorithm);
    if (std.mem.eql(u8, name, "SHA256")) return bridge.getSymPtr(imp_kind, "SymCryptSha256Algorithm", SymCryptSha256Algorithm);
    if (std.mem.eql(u8, name, "SHA384")) return bridge.getSymPtr(imp_kind, "SymCryptSha384Algorithm", SymCryptSha384Algorithm);
    if (std.mem.eql(u8, name, "SHA512")) return bridge.getSymPtr(imp_kind, "SymCryptSha512Algorithm", SymCryptSha512Algorithm);
    if (std.mem.eql(u8, name, "SHA512-224")) return bridge.getSymPtr(imp_kind, "SymCryptSha512_224Algorithm", SymCryptSha512_224Algorithm);
    if (std.mem.eql(u8, name, "SHA512-256")) return bridge.getSymPtr(imp_kind, "SymCryptSha512_256Algorithm", SymCryptSha512_256Algorithm);
    if (std.mem.eql(u8, name, "SHA3-224")) return bridge.getSymPtr(imp_kind, "SymCryptSha3_224Algorithm", SymCryptSha3_224Algorithm);
    if (std.mem.eql(u8, name, "SHA3-256")) return bridge.getSymPtr(imp_kind, "SymCryptSha3_256Algorithm", SymCryptSha3_256Algorithm);
    if (std.mem.eql(u8, name, "SHA3-384")) return bridge.getSymPtr(imp_kind, "SymCryptSha3_384Algorithm", SymCryptSha3_384Algorithm);
    if (std.mem.eql(u8, name, "SHA3-512")) return bridge.getSymPtr(imp_kind, "SymCryptSha3_512Algorithm", SymCryptSha3_512Algorithm);
    h.check(false, "Unknown hash algorithm name");
    return null;
}

fn getSymCryptOidList(imp_kind: sc_imp.ImpKind, pcstrHashAlgName: ?[*:0]const u8, pCount: *usize) ?[*]const sc_imp.SYMCRYPT_OID {
    const name_c = pcstrHashAlgName orelse {
        pCount.* = 0;
        return null;
    };
    const name = std.mem.span(name_c);
    if (std.mem.eql(u8, name, "MD5")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptMd5OidList", &SymCryptMd5OidList)));
    }
    if (std.mem.eql(u8, name, "SHA1")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha1OidList", &SymCryptSha1OidList)));
    }
    if (std.mem.eql(u8, name, "SHA224")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha224OidList", &SymCryptSha224OidList)));
    }
    if (std.mem.eql(u8, name, "SHA256")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha256OidList", &SymCryptSha256OidList)));
    }
    if (std.mem.eql(u8, name, "SHA384")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha384OidList", &SymCryptSha384OidList)));
    }
    if (std.mem.eql(u8, name, "SHA512")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha512OidList", &SymCryptSha512OidList)));
    }
    if (std.mem.eql(u8, name, "SHA512-224")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha512_224OidList", &SymCryptSha512_224OidList)));
    }
    if (std.mem.eql(u8, name, "SHA512-256")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha512_256OidList", &SymCryptSha512_256OidList)));
    }
    if (std.mem.eql(u8, name, "SHA3-224")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha3_224OidList", &SymCryptSha3_224OidList)));
    }
    if (std.mem.eql(u8, name, "SHA3-256")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha3_256OidList", &SymCryptSha3_256OidList)));
    }
    if (std.mem.eql(u8, name, "SHA3-384")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha3_384OidList", &SymCryptSha3_384OidList)));
    }
    if (std.mem.eql(u8, name, "SHA3-512")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptSha3_512OidList", &SymCryptSha3_512OidList)));
    }
    if (std.mem.eql(u8, name, "SHAKE128")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptShake128OidList", &SymCryptShake128OidList)));
    }
    if (std.mem.eql(u8, name, "SHAKE256")) {
        pCount.* = 2;
        return @ptrCast(@alignCast(bridge.getSymArrayPtr(imp_kind, "SymCryptShake256OidList", &SymCryptShake256OidList)));
    }
    h.check(false, "Unknown hash OID name");
    return null;
}

// ============================================================================
// RsaSign & RsaEnc
// ============================================================================

pub const RsaState = struct {
    pKey: ?*anyopaque = null,

    pub fn deinit(self: *RsaState, imp_kind: sc_imp.ImpKind) void {
        if (self.pKey) |k| {
            bridge.callSym(imp_kind, "SymCryptRsakeyFree", SymCryptRsakeyFree, .{k});
            self.pKey = null;
        }
    }
};

fn symCryptRsaKeyFromTestBlob(imp_kind: sc_imp.ImpKind, pcKeyBlob: *const RSAKEY_TESTBLOB, allowflag: u32) ?*anyopaque {
    var params = SYMCRYPT_RSA_PARAMS{
        .version = 1,
        .nBitsOfModulus = pcKeyBlob.nBitsModulus,
        .nPrimes = 2,
        .nPubExp = 1,
    };
    const pKey = bridge.callSym(imp_kind, "SymCryptRsakeyAllocate", SymCryptRsakeyAllocate, .{ &params, 0 }) orelse {
        h.check(false, "Failed to allocate RSA key");
        return null;
    };
    var flags = allowflag;
    if (pcKeyBlob.nBitsModulus < 2048) {
        flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
    }
    var ppPrimes = [2][*]const u8{ &pcKeyBlob.abPrime1, &pcKeyBlob.abPrime2 };
    var cbPrimes = [2]usize{ @intCast(pcKeyBlob.cbPrime1), @intCast(pcKeyBlob.cbPrime2) };
    const scError: i32 = if ((rng.g_rng.byte() & 1) != 0)
        bridge.callSym(imp_kind, "SymCryptRsakeySetValue", SymCryptRsakeySetValue, .{
            @as([*]const u8, &pcKeyBlob.abModulus),
            @as(usize, @intCast(pcKeyBlob.cbModulus)),
            &pcKeyBlob.u64PubExp,
            1,
            &ppPrimes,
            &cbPrimes,
            2,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            flags,
            pKey,
        })
    else
        bridge.callSym(imp_kind, "SymCryptRsakeySetValueFromPrivateExponent", SymCryptRsakeySetValueFromPrivateExponent, .{
            @as([*]const u8, &pcKeyBlob.abModulus),
            @as(usize, @intCast(pcKeyBlob.cbModulus)),
            pcKeyBlob.u64PubExp,
            @as([*]const u8, &pcKeyBlob.abPrivateExp),
            @as(usize, @intCast(pcKeyBlob.cbModulus)),
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            flags,
            pKey,
        });
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to import SymCrypt RSA key");
    return pKey;
}

fn rsaSetKey(imp: *bridge.AlgImp, pcKeyBlob: ?*const RSAKEY_TESTBLOB, allowflag: u32) i32 {
    if (imp.rsa_state.pKey) |k| {
        bridge.callSym(imp.imp_kind, "SymCryptRsakeyFree", SymCryptRsakeyFree, .{k});
        imp.rsa_state.pKey = null;
    }
    if (pcKeyBlob) |blob| {
        imp.rsa_state.pKey = symCryptRsaKeyFromTestBlob(imp.imp_kind, blob, allowflag);
    }
    return STATUS_SUCCESS;
}

pub export fn scTestRsaSignImpSetKey(pImp: *anyopaque, pcKeyBlob: ?*const RSAKEY_TESTBLOB) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    return rsaSetKey(imp, pcKeyBlob, SYMCRYPT_FLAG_RSAKEY_SIGN);
}

pub export fn scTestRsaSignImpSign(pImp: *anyopaque, pbHash: ?[*]const u8, cbHash: usize, pcstrHashAlgName: ?[*:0]const u8, u32Other: u32, pbSig: [*]u8, cbSig: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const pKey = imp.rsa_state.pKey.?;
    var cbSigRes: usize = 0;
    if (std.mem.eql(u8, imp.algorithm_name, "RsaSignPkcs1")) {
        var nOIDCount: usize = 0;
        const pOids = getSymCryptOidList(imp.imp_kind, pcstrHashAlgName, &nOIDCount);
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPkcs1Sign", SymCryptRsaPkcs1Sign, .{
            pKey,
            pbHash,
            cbHash,
            pOids,
            nOIDCount,
            u32Other,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSig,
            cbSig,
            &cbSigRes,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Error in RsaPkcs1Sign");
        const modSize = bridge.callSym(imp.imp_kind, "SymCryptRsakeySizeofModulus", SymCryptRsakeySizeofModulus, .{pKey});
        h.check(cbSigRes == modSize, "Wrong signature length");
        return STATUS_SUCCESS;
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaSignPss")) {
        const pHash = getSymCryptHashAlgorithm(imp.imp_kind, pcstrHashAlgName).?;
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPssSign", SymCryptRsaPssSign, .{
            pKey,
            pbHash,
            cbHash,
            pHash,
            u32Other,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbSig,
            cbSig,
            &cbSigRes,
        });
        const modSize = bridge.callSym(imp.imp_kind, "SymCryptRsakeySizeofModulus", SymCryptRsakeySizeofModulus, .{pKey});
        h.check((scError == SYMCRYPT_NO_ERROR and cbSigRes == modSize) or (scError != SYMCRYPT_NO_ERROR and cbSigRes == 0), "Wrong signature length");
        if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS;
        if (scError == SYMCRYPT_INVALID_ARGUMENT) return STATUS_INVALID_PARAMETER;
        h.check(false, "Unexpected error in SymCryptRsaPssSign");
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_NOT_SUPPORTED;
}

pub export fn scTestRsaSignImpVerify(pImp: *anyopaque, pbHash: ?[*]const u8, cbHash: usize, pbSig: ?[*]const u8, cbSig: usize, pcstrHashAlgName: ?[*:0]const u8, u32Other: u32) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const pKey = imp.rsa_state.pKey.?;
    if (std.mem.eql(u8, imp.algorithm_name, "RsaSignPkcs1")) {
        var nOIDCount: usize = 0;
        const pOids = getSymCryptOidList(imp.imp_kind, pcstrHashAlgName, &nOIDCount);
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPkcs1Verify", SymCryptRsaPkcs1Verify, .{
            pKey,
            pbHash,
            cbHash,
            pbSig,
            cbSig,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pOids,
            nOIDCount,
            u32Other | (if (pOids == null) @as(u32, 0) else SYMCRYPT_FLAG_RSA_PKCS1_OPTIONAL_HASH_OID),
        });
        return switch (scError) {
            SYMCRYPT_NO_ERROR => STATUS_SUCCESS,
            SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE => STATUS_INVALID_SIGNATURE,
            SYMCRYPT_INVALID_ARGUMENT => STATUS_INVALID_PARAMETER,
            else => blk: {
                h.check(false, "Error in RsaPkcs1Verify");
                break :blk STATUS_UNSUCCESSFUL;
            },
        };
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaSignPss")) {
        const pHash = getSymCryptHashAlgorithm(imp.imp_kind, pcstrHashAlgName).?;
        var scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{
            pKey,
            pbHash,
            cbHash,
            pbSig,
            cbSig,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pHash,
            u32Other,
            0,
        });
        if (scError == SYMCRYPT_NO_ERROR) {
            var scErr2 = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{ pKey, pbHash, cbHash, pbSig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pHash, u32Other + 1, 0 });
            h.check(scErr2 != SYMCRYPT_NO_ERROR, "Corner case test failure in SymCryptRsaPssVerify (1)");
            if (u32Other > 0) {
                scErr2 = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{ pKey, pbHash, cbHash, pbSig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pHash, u32Other - 1, 0 });
                h.check(scErr2 != SYMCRYPT_NO_ERROR, "Corner case test failure in SymCryptRsaPssVerify (2)");
            }
            scErr2 = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{ pKey, pbHash, cbHash, pbSig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pHash, u32Other, SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT });
            h.check(scErr2 == SYMCRYPT_NO_ERROR, "Corner case test failure in SymCryptRsaPssVerify (3)");
            scErr2 = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{ pKey, pbHash, cbHash, pbSig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pHash, 0, SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT });
            h.check(scErr2 == SYMCRYPT_NO_ERROR, "Corner case test failure in SymCryptRsaPssVerify (4)");
            scErr2 = bridge.callSym(imp.imp_kind, "SymCryptRsaPssVerify", SymCryptRsaPssVerify, .{ pKey, pbHash, cbHash, pbSig, cbSig, SYMCRYPT_NUMBER_FORMAT_MSB_FIRST, pHash, u32Other + 1, SYMCRYPT_FLAG_RSA_PSS_VERIFY_WITH_MINIMUM_SALT });
            h.check(scErr2 != SYMCRYPT_NO_ERROR, "Corner case test failure in SymCryptRsaPssVerify (5)");
            scError = SYMCRYPT_NO_ERROR;
        }
        return switch (scError) {
            SYMCRYPT_NO_ERROR => STATUS_SUCCESS,
            SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, SYMCRYPT_INVALID_ARGUMENT => STATUS_INVALID_PARAMETER,
            else => blk: {
                h.check(false, "Error in RsaPssVerify");
                break :blk STATUS_UNSUCCESSFUL;
            },
        };
    }
    return STATUS_NOT_SUPPORTED;
}

pub export fn scTestRsaEncImpSetKey(pImp: *anyopaque, pcKeyBlob: ?*const RSAKEY_TESTBLOB) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    return rsaSetKey(imp, pcKeyBlob, SYMCRYPT_FLAG_RSAKEY_ENCRYPT);
}

pub export fn scTestRsaEncImpEncrypt(pImp: *anyopaque, pbMsg: ?[*]const u8, cbMsg: usize, pcstrHashAlgName: ?[*:0]const u8, pbLabel: ?[*]const u8, cbLabel: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const pKey = imp.rsa_state.pKey.?;
    if (std.mem.eql(u8, imp.algorithm_name, "RsaEncRaw")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaRawEncrypt", SymCryptRsaRawEncrypt, .{
            pKey,
            pbMsg,
            cbMsg,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbCiphertext,
            cbCiphertext,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to encrypt using raw RSA");
        return STATUS_SUCCESS;
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaEncPkcs1")) {
        var cbRes: usize = 0;
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPkcs1Encrypt", SymCryptRsaPkcs1Encrypt, .{
            pKey,
            pbMsg,
            cbMsg,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbCiphertext,
            cbCiphertext,
            &cbRes,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaPkcs1Encrypt failed");
        h.check(cbRes == cbCiphertext, "Wrong encryption length");
        return STATUS_SUCCESS;
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaEncOaep")) {
        var cbRes: usize = 0;
        const pHash = getSymCryptHashAlgorithm(imp.imp_kind, pcstrHashAlgName).?;
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaOaepEncrypt", SymCryptRsaOaepEncrypt, .{
            pKey,
            pbMsg,
            cbMsg,
            pHash,
            pbLabel,
            cbLabel,
            0,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pbCiphertext,
            cbCiphertext,
            &cbRes,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptRsaOaepEncrypt failed");
        h.check(cbRes == cbCiphertext, "Wrong encryption length");
        return STATUS_SUCCESS;
    }
    return STATUS_NOT_SUPPORTED;
}

pub export fn scTestRsaEncImpDecrypt(pImp: *anyopaque, pbCiphertext: ?[*]const u8, cbCiphertext: usize, pcstrHashAlgName: ?[*:0]const u8, pbLabel: ?[*]const u8, cbLabel: usize, pbMsg: ?[*]u8, cbMsg: usize, pcbMsg: *usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const pKey = imp.rsa_state.pKey.?;
    if (std.mem.eql(u8, imp.algorithm_name, "RsaEncRaw")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaRawDecrypt", SymCryptRsaRawDecrypt, .{
            pKey,
            pbCiphertext,
            cbCiphertext,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbMsg.?,
            cbMsg,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to decrypt using raw RSA");
        pcbMsg.* = bridge.callSym(imp.imp_kind, "SymCryptRsakeySizeofModulus", SymCryptRsakeySizeofModulus, .{pKey});
        return STATUS_SUCCESS;
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaEncPkcs1")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaPkcs1Decrypt", SymCryptRsaPkcs1Decrypt, .{
            pKey,
            pbCiphertext,
            cbCiphertext,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            0,
            pbMsg,
            cbMsg,
            pcbMsg,
        });
        return switch (scError) {
            SYMCRYPT_NO_ERROR => STATUS_SUCCESS,
            SYMCRYPT_INVALID_ARGUMENT => STATUS_INVALID_PARAMETER,
            SYMCRYPT_BUFFER_TOO_SMALL => STATUS_BUFFER_OVERFLOW,
            else => blk: {
                h.check(false, "Unexpected error in SymCryptRsaPkcs1Decrypt");
                break :blk STATUS_UNSUCCESSFUL;
            },
        };
    } else if (std.mem.eql(u8, imp.algorithm_name, "RsaEncOaep")) {
        const pHash = getSymCryptHashAlgorithm(imp.imp_kind, pcstrHashAlgName).?;
        const scError = bridge.callSym(imp.imp_kind, "SymCryptRsaOaepDecrypt", SymCryptRsaOaepDecrypt, .{
            pKey,
            pbCiphertext,
            cbCiphertext,
            SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
            pHash,
            pbLabel,
            cbLabel,
            0,
            pbMsg.?,
            cbMsg,
            pcbMsg,
        });
        return switch (scError) {
            SYMCRYPT_NO_ERROR => STATUS_SUCCESS,
            SYMCRYPT_INVALID_ARGUMENT => STATUS_INVALID_PARAMETER,
            SYMCRYPT_BUFFER_TOO_SMALL => STATUS_BUFFER_OVERFLOW,
            else => blk: {
                h.check(false, "Unexpected error in SymCryptRsaOaepDecrypt");
                break :blk STATUS_UNSUCCESSFUL;
            },
        };
    }
    return STATUS_NOT_SUPPORTED;
}

// ============================================================================
// Dh & Dsa
// ============================================================================

pub const DlState = struct {
    pGroup: ?*anyopaque = null,
    pKey: ?*anyopaque = null,

    pub fn deinit(self: *DlState, imp_kind: sc_imp.ImpKind) void {
        if (self.pKey) |k| {
            bridge.callSym(imp_kind, "SymCryptDlkeyFree", SymCryptDlkeyFree, .{k});
            self.pKey = null;
        }
        if (self.pGroup) |g| {
            bridge.callSym(imp_kind, "SymCryptDlgroupFree", SymCryptDlgroupFree, .{g});
            self.pGroup = null;
        }
    }
};

fn symCryptDlGroupFromTestBlob(imp_kind: sc_imp.ImpKind, pBlob: *const DLGROUP_TESTBLOB) ?*anyopaque {
    const pGroup = bridge.callSym(imp_kind, "SymCryptDlgroupAllocate", SymCryptDlgroupAllocate, .{ pBlob.nBitsP, 8 * pBlob.cbPrimeQ }) orelse {
        h.check(false, "Failed to allocate DL group");
        return null;
    };
    const pbQ: ?[*]const u8 = if (pBlob.cbPrimeQ == 0) null else &pBlob.abPrimeQ;
    const cbQ: usize = @intCast(pBlob.cbPrimeQ);
    const pHash = getSymCryptHashAlgorithm(imp_kind, pBlob.pcstrHashAlgName);
    const pbSeed: ?[*]const u8 = if (pBlob.cbSeed == 0) null else &pBlob.abSeed;
    const cbSeed: usize = @intCast(pBlob.cbSeed);

    const scError = bridge.callSym(imp_kind, "SymCryptDlgroupSetValue", SymCryptDlgroupSetValue, .{
        @as([*]const u8, &pBlob.abPrimeP),
        @as(usize, @intCast(pBlob.cbPrimeP)),
        pbQ,
        cbQ,
        @as([*]const u8, &pBlob.abGenG),
        @as(usize, @intCast(pBlob.cbPrimeP)),
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        pHash,
        pbSeed,
        cbSeed,
        pBlob.genCounter,
        pBlob.fipsStandard,
        pGroup,
    });
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set DL group");
    return pGroup;
}

pub export fn scTestDlgroupObjectFromTestBlob(pBlob: *const DLGROUP_TESTBLOB) callconv(.c) ?*anyopaque {
    return symCryptDlGroupFromTestBlob(.sc, pBlob);
}

fn symCryptDlKeyFromTestBlob(imp_kind: sc_imp.ImpKind, pGroup: *anyopaque, pBlob: *const DLKEY_TESTBLOB, algFlags: u32, setPrivate: bool) ?*anyopaque {
    const pRes = bridge.callSym(imp_kind, "SymCryptDlkeyAllocate", SymCryptDlkeyAllocate, .{pGroup}) orelse {
        h.check(false, "Failed to allocate DL key");
        return null;
    };

    const randByte = rng.g_rng.byte();
    var flags: u32 = algFlags;
    var pbPrivKey: ?[*]const u8 = null;
    var cbPrivKey: usize = 0;
    var pbPubKey: ?[*]const u8 = null;
    var cbPubKey: usize = 0;

    if (pBlob.pGroup.fHasPrimeQ == 0 or
        pBlob.fPrivateModP != 0 or
        (algFlags == SYMCRYPT_FLAG_DLKEY_DH and pBlob.pGroup.isSafePrimeGroup == 0) or
        (algFlags == SYMCRYPT_FLAG_DLKEY_DSA and pBlob.pGroup.isSafePrimeGroup != 0) or
        (randByte & 0x1) != 0)
    {
        flags |= SYMCRYPT_FLAG_KEY_NO_FIPS;
        if ((randByte & 0x2) != 0) {
            flags |= SYMCRYPT_FLAG_DLKEY_DSA;
            flags |= SYMCRYPT_FLAG_DLKEY_DH;
        }
    }

    if (setPrivate or (randByte & 0x4) != 0) {
        pbPrivKey = &pBlob.abPrivKey;
        cbPrivKey = pBlob.cbPrivKey;

        if (pBlob.nBitsPriv != 0) {
            const scError = bridge.callSym(imp_kind, "SymCryptDlkeySetPrivateKeyLength", SymCryptDlkeySetPrivateKeyLength, .{ pRes, pBlob.nBitsPriv, 0 });
            h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptDlkeySetPrivateKeyLength failed");
        }
    }

    if ((flags & SYMCRYPT_FLAG_KEY_NO_FIPS) != 0 and (randByte & 0x8) != 0) {
        flags |= SYMCRYPT_FLAG_KEY_MINIMAL_VALIDATION;
    }

    if (!setPrivate) {
        pbPubKey = &pBlob.abPubKey;
        cbPubKey = pBlob.pGroup.cbPrimeP;
    }

    const scError = bridge.callSym(imp_kind, "SymCryptDlkeySetValue", SymCryptDlkeySetValue, .{
        pbPrivKey,
        cbPrivKey,
        pbPubKey,
        cbPubKey,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        flags,
        pRes,
    });
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set DL key");
    return pRes;
}

fn dlSetKey(imp: *bridge.AlgImp, pcKeyBlob: ?*const DLKEY_TESTBLOB, allowflag: u32) i32 {
    if (imp.dl_state.pKey) |k| {
        bridge.callSym(imp.imp_kind, "SymCryptDlkeyFree", SymCryptDlkeyFree, .{k});
        imp.dl_state.pKey = null;
    }
    if (imp.dl_state.pGroup) |g| {
        bridge.callSym(imp.imp_kind, "SymCryptDlgroupFree", SymCryptDlgroupFree, .{g});
        imp.dl_state.pGroup = null;
    }
    if (pcKeyBlob) |blob| {
        if (imp.imp_kind == .sc_dynamic and blob.nBitsPriv != 0 and !bridge.hasSym("SymCryptDlkeySetPrivateKeyLength")) {
            return STATUS_NOT_SUPPORTED;
        }
        imp.dl_state.pGroup = symCryptDlGroupFromTestBlob(imp.imp_kind, blob.pGroup);
        imp.dl_state.pKey = symCryptDlKeyFromTestBlob(imp.imp_kind, imp.dl_state.pGroup.?, blob, allowflag, true);
        h.check(imp.dl_state.pGroup != null and imp.dl_state.pKey != null, "?");
    }
    return STATUS_SUCCESS;
}

pub export fn scTestDhImpSetKey(pImp: *anyopaque, pcKeyBlob: ?*const DLKEY_TESTBLOB) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    return dlSetKey(imp, pcKeyBlob, SYMCRYPT_FLAG_DLKEY_DH);
}

pub export fn scTestDhImpSharedSecret(pImp: *anyopaque, pcPubkey: *const DLKEY_TESTBLOB, pbSecret: [*]u8, cbSecret: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const pPub = symCryptDlKeyFromTestBlob(imp.imp_kind, imp.dl_state.pGroup.?, pcPubkey, SYMCRYPT_FLAG_DLKEY_DH, false).?;
    defer bridge.callSym(imp.imp_kind, "SymCryptDlkeyFree", SymCryptDlkeyFree, .{pPub});

    const scError = bridge.callSym(imp.imp_kind, "SymCryptDhSecretAgreement", SymCryptDhSecretAgreement, .{
        imp.dl_state.pKey.?,
        pPub,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        pbSecret,
        cbSecret,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestDsaImpSetKey(pImp: *anyopaque, pcKeyBlob: ?*const DLKEY_TESTBLOB) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    return dlSetKey(imp, pcKeyBlob, SYMCRYPT_FLAG_DLKEY_DSA);
}

pub export fn scTestDsaImpSign(pImp: *anyopaque, pbHash: ?[*]const u8, cbHash: usize, pbSig: [*]u8, cbSig: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = bridge.callSym(imp.imp_kind, "SymCryptDsaSign", SymCryptDsaSign, .{
        imp.dl_state.pKey.?,
        pbHash,
        cbHash,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
        pbSig,
        cbSig,
    });
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to sign using DSA");
    return STATUS_SUCCESS;
}

pub export fn scTestDsaImpVerify(pImp: *anyopaque, pbHash: ?[*]const u8, cbHash: usize, pbSig: ?[*]const u8, cbSig: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = bridge.callSym(imp.imp_kind, "SymCryptDsaVerify", SymCryptDsaVerify, .{
        imp.dl_state.pKey.?,
        pbHash,
        cbHash,
        pbSig,
        cbSig,
        SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        0,
    });
    if (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) return STATUS_INVALID_SIGNATURE;
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to verify using DSA");
    return STATUS_SUCCESS;
}

// ============================================================================
// Hbs (Xmss & Lms)
// ============================================================================

const SYMCRYPT_XMSSKEY_TYPE_NONE: u32 = 0;
const SYMCRYPT_XMSSKEY_TYPE_PUBLIC: u32 = 1;
const SYMCRYPT_XMSSKEY_TYPE_PRIVATE: u32 = 2;
const SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT: u32 = 1;
const SYMCRYPT_LMSKEY_TYPE_NONE: u32 = 0;
const SYMCRYPT_LMSKEY_TYPE_PUBLIC: u32 = 1;
const SYMCRYPT_LMSKEY_TYPE_PRIVATE: u32 = 2;
const SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT: u32 = 1;

pub const HbsState = struct {
    pKey: ?*anyopaque = null,

    pub fn deinit(self: *HbsState, imp_kind: sc_imp.ImpKind, alg_name: []const u8) void {
        if (self.pKey) |k| {
            if (std.mem.eql(u8, alg_name, "Xmss")) {
                bridge.callSym(imp_kind, "SymCryptXmsskeyFree", SymCryptXmsskeyFree, .{k});
            } else {
                bridge.callSym(imp_kind, "SymCryptLmskeyFree", SymCryptLmskeyFree, .{k});
            }
            self.pKey = null;
        }
    }
};

fn hbsImpSetKey(
    imp: *bridge.AlgImp,
    algId: u32,
    otsAlgId: u32,
    fMultitree: c_int,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    fVerify: c_int,
) i32 {
    imp.hbs_state.deinit(imp.imp_kind, imp.algorithm_name);
    const src = pbSrc orelse return STATUS_SUCCESS;

    if (std.mem.eql(u8, imp.algorithm_name, "Xmss")) {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptXmsskeyAllocate")) return STATUS_NOT_SUPPORTED;
        var params: SYMCRYPT_XMSS_PARAMS = std.mem.zeroes(SYMCRYPT_XMSS_PARAMS);
        var scError: i32 = SYMCRYPT_NO_ERROR;
        if (fMultitree != 0) {
            scError = bridge.callSym(imp.imp_kind, "SymCryptXmssMtParamsFromAlgId", SymCryptXmssMtParamsFromAlgId, .{ algId, &params });
        } else {
            scError = bridge.callSym(imp.imp_kind, "SymCryptXmssParamsFromAlgId", SymCryptXmssParamsFromAlgId, .{ algId, &params });
        }
        if (scError != SYMCRYPT_NO_ERROR) return STATUS_NOT_SUPPORTED;

        imp.hbs_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptXmsskeyAllocate", SymCryptXmsskeyAllocate, .{ &params, 0 });
        h.check(imp.hbs_state.pKey != null, "Cannot allocate XMSS key");

        var cbPublicKey: usize = 0;
        var cbPrivateKey: usize = 0;
        var keyType: u32 = SYMCRYPT_XMSSKEY_TYPE_NONE;
        scError = bridge.callSym(imp.imp_kind, "SymCryptXmssSizeofKeyBlobFromParams", SymCryptXmssSizeofKeyBlobFromParams, .{ &params, SYMCRYPT_XMSSKEY_TYPE_PUBLIC, &cbPublicKey });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptXmssSizeofKeyBlobFromParams failed");
        if (cbSrc == cbPublicKey) keyType = SYMCRYPT_XMSSKEY_TYPE_PUBLIC;

        scError = bridge.callSym(imp.imp_kind, "SymCryptXmssSizeofKeyBlobFromParams", SymCryptXmssSizeofKeyBlobFromParams, .{ &params, SYMCRYPT_XMSSKEY_TYPE_PRIVATE, &cbPrivateKey });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptXmssSizeofKeyBlobFromParams failed");
        if (cbSrc == cbPrivateKey) keyType = SYMCRYPT_XMSSKEY_TYPE_PRIVATE;

        const flags: u32 = if (fVerify != 0) SYMCRYPT_FLAG_XMSSKEY_VERIFY_ROOT else 0;
        scError = bridge.callSym(imp.imp_kind, "SymCryptXmsskeySetValue", SymCryptXmsskeySetValue, .{ src, cbSrc, keyType, flags, imp.hbs_state.pKey.? });
        h.check(scError == SYMCRYPT_NO_ERROR, "XMSS key initialization error");
        return STATUS_SUCCESS;
    } else {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptLmskeyAllocate")) return STATUS_NOT_SUPPORTED;
        var params: SYMCRYPT_LMS_PARAMS = std.mem.zeroes(SYMCRYPT_LMS_PARAMS);
        var scError = bridge.callSym(imp.imp_kind, "SymCryptLmsParamsFromAlgId", SymCryptLmsParamsFromAlgId, .{ algId, otsAlgId, &params });
        if (scError != SYMCRYPT_NO_ERROR) return STATUS_NOT_SUPPORTED;

        imp.hbs_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptLmskeyAllocate", SymCryptLmskeyAllocate, .{ &params, 0 });
        h.check(imp.hbs_state.pKey != null, "Cannot allocate LMS key");

        var cbPublicKey: usize = 0;
        var cbPrivateKey: usize = 0;
        var keyType: u32 = SYMCRYPT_LMSKEY_TYPE_NONE;
        scError = bridge.callSym(imp.imp_kind, "SymCryptLmsSizeofKeyBlobFromParams", SymCryptLmsSizeofKeyBlobFromParams, .{ &params, SYMCRYPT_LMSKEY_TYPE_PUBLIC, &cbPublicKey });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptLmsSizeofKeyBlobFromParams failed");
        if (cbSrc == cbPublicKey) keyType = SYMCRYPT_LMSKEY_TYPE_PUBLIC;

        scError = bridge.callSym(imp.imp_kind, "SymCryptLmsSizeofKeyBlobFromParams", SymCryptLmsSizeofKeyBlobFromParams, .{ &params, SYMCRYPT_LMSKEY_TYPE_PRIVATE, &cbPrivateKey });
        h.check(scError == SYMCRYPT_NO_ERROR, "SymCryptLmsSizeofKeyBlobFromParams failed");
        if (cbSrc == cbPrivateKey) keyType = SYMCRYPT_LMSKEY_TYPE_PRIVATE;

        const flags: u32 = if (fVerify != 0) SYMCRYPT_FLAG_LMSKEY_VERIFY_ROOT else 0;
        scError = bridge.callSym(imp.imp_kind, "SymCryptLmskeySetValue", SymCryptLmskeySetValue, .{ src, cbSrc, keyType, flags, imp.hbs_state.pKey.? });
        h.check(scError == SYMCRYPT_NO_ERROR, "LMS key initialization error");
        return STATUS_SUCCESS;
    }
}

fn hbsImpVerify(imp: *bridge.AlgImp, pbMsg: ?[*]const u8, cbMsg: usize, pbSig: [*]const u8, cbSig: usize) i32 {
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "Xmss"))
        bridge.callSym(imp.imp_kind, "SymCryptXmssVerify", SymCryptXmssVerify, .{ imp.hbs_state.pKey.?, pbMsg, cbMsg, 0, pbSig, cbSig })
    else
        bridge.callSym(imp.imp_kind, "SymCryptLmsVerify", SymCryptLmsVerify, .{ imp.hbs_state.pKey.?, pbMsg, cbMsg, 0, pbSig, cbSig });
    return switch (scError) {
        SYMCRYPT_NO_ERROR => STATUS_SUCCESS,
        SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE => STATUS_INVALID_SIGNATURE,
        SYMCRYPT_INVALID_ARGUMENT => STATUS_INVALID_PARAMETER,
        else => blk: {
            h.check(false, "Unexpected error in HBS verify");
            break :blk STATUS_UNSUCCESSFUL;
        },
    };
}

fn hbsImpSign(imp: *bridge.AlgImp, pbMsg: ?[*]const u8, cbMsg: usize, pbSig: [*]u8, cbSig: usize) i32 {
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "Xmss"))
        bridge.callSym(imp.imp_kind, "SymCryptXmssSign", SymCryptXmssSign, .{ imp.hbs_state.pKey.?, pbMsg, cbMsg, 0, pbSig, cbSig })
    else
        bridge.callSym(imp.imp_kind, "SymCryptLmsSign", SymCryptLmsSign, .{ imp.hbs_state.pKey.?, pbMsg, cbMsg, 0, pbSig, cbSig });
    h.check(scError == SYMCRYPT_NO_ERROR, "HBS sign failed");
    return STATUS_SUCCESS;
}

const ScTestHbsMultiImp = struct {
    imps: [16]*bridge.AlgImp = undefined,
    n_imps: usize = 0,
    comps: [16]*bridge.AlgImp = undefined,
    n_comps: usize = 0,
};

pub export fn scTestHbsMultiImpCreate(algName: [*:0]const u8) callconv(.c) ?*anyopaque {
    const p = std.heap.c_allocator.create(ScTestHbsMultiImp) catch return null;
    p.* = .{};
    var raw: [16]*anyopaque = undefined;
    const count = bridge.getImpsByCategory(.Hbs, std.mem.span(algName), &raw, raw.len);
    p.n_imps = count;
    for (0..count) |i| {
        p.imps[i] = @ptrCast(@alignCast(raw[i]));
    }
    return p;
}

pub export fn scTestHbsMultiImpDestroy(pMultiVoid: ?*anyopaque) callconv(.c) void {
    const p: *ScTestHbsMultiImp = @ptrCast(@alignCast(pMultiVoid orelse return));
    std.heap.c_allocator.destroy(p);
}

pub export fn scTestHbsMultiImpGetCount(pMultiVoid: *const anyopaque) callconv(.c) usize {
    const p: *const ScTestHbsMultiImp = @ptrCast(@alignCast(pMultiVoid));
    return p.n_imps;
}

pub export fn scTestHbsImpSetKey(
    pMultiVoid: *anyopaque,
    algId: u32,
    otsAlgId: u32,
    fMultitree: c_int,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    fVerifyRoot: c_int,
) callconv(.c) i32 {
    const p: *ScTestHbsMultiImp = @ptrCast(@alignCast(pMultiVoid));
    p.n_comps = 0;
    for (p.imps[0..p.n_imps]) |imp| {
        if (hbsImpSetKey(imp, algId, otsAlgId, fMultitree, pbSrc, cbSrc, fVerifyRoot) == STATUS_SUCCESS) {
            p.comps[p.n_comps] = imp;
            p.n_comps += 1;
        }
    }
    return if (p.n_comps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
}

pub export fn scTestHbsImpVerify(
    pMultiVoid: *anyopaque,
    pbMsg: ?[*]const u8,
    cbMsg: usize,
    flags: u32,
    pbSig: [*]const u8,
    cbSig: usize,
) callconv(.c) i32 {
    _ = flags;
    const p: *ScTestHbsMultiImp = @ptrCast(@alignCast(pMultiVoid));
    var res = rm.ResultMerge.init();
    for (p.comps[0..p.n_comps]) |imp| {
        const status = hbsImpVerify(imp, pbMsg, cbMsg, pbSig, cbSig);
        var b: [4]u8 = undefined;
        std.mem.writeInt(i32, &b, status, .big);
        res.addResult(imp, &b);
    }
    var b: [4]u8 = undefined;
    res.getResult(&b);
    return std.mem.readInt(i32, &b, .big);
}

pub export fn scTestHbsImpSign(
    pMultiVoid: *anyopaque,
    pbMsg: ?[*]const u8,
    cbMsg: usize,
    flags: u32,
    pbSig: [*]u8,
    cbSig: usize,
) callconv(.c) i32 {
    _ = flags;
    const p: *ScTestHbsMultiImp = @ptrCast(@alignCast(pMultiVoid));
    var res = rm.ResultMerge.init();
    const buf = std.heap.c_allocator.alloc(u8, cbSig) catch return STATUS_UNSUCCESSFUL;
    defer std.heap.c_allocator.free(buf);
    for (p.comps[0..p.n_comps]) |imp| {
        SymCryptWipe(buf.ptr, cbSig);
        const status = hbsImpSign(imp, pbMsg, cbMsg, buf.ptr, cbSig);
        h.check(status == STATUS_SUCCESS, "Signature generation error");
        res.addResult(imp, buf[0..cbSig]);
    }
    res.getResult(pbSig[0..cbSig]);
    return STATUS_SUCCESS;
}

// ============================================================================
// Kem (MlKem & CompositeMlKem)
// ============================================================================

const MLKEMKEY_TESTBLOB = extern struct {
    params: u32 = 0,
    format: u32 = 0,
    abKeyBlob: [3168]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

const COMPOSITE_MLKEMKEY_TESTBLOB = extern struct {
    params: u32 = 0,
    format: u32 = 0,
    abKeyBlob: [1665]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

pub const KemState = struct {
    pKey: ?*anyopaque = null,

    pub fn deinit(self: *KemState, imp_kind: sc_imp.ImpKind, alg_name: []const u8) void {
        if (self.pKey) |k| {
            if (std.mem.eql(u8, alg_name, "MlKem")) {
                bridge.callSym(imp_kind, "SymCryptMlKemkeyFree", SymCryptMlKemkeyFree, .{k});
            } else {
                bridge.callSym(imp_kind, "SymCryptCompositeMlKemkeyFree", SymCryptCompositeMlKemkeyFree, .{k});
            }
            self.pKey = null;
        }
    }
};

const ScTestKemMultiImp = struct {
    imps: [16]*bridge.AlgImp = undefined,
    n_imps: usize = 0,
    n_error_kat_failure: u64 = 0,
};

pub export fn scTestKemMultiImpCreate(algName: [*:0]const u8) callconv(.c) ?*anyopaque {
    const p = std.heap.c_allocator.create(ScTestKemMultiImp) catch return null;
    p.* = .{};
    var raw: [16]*anyopaque = undefined;
    const count = bridge.getImpsByCategory(.Kem, std.mem.span(algName), &raw, raw.len);
    p.n_imps = count;
    for (0..count) |i| {
        p.imps[i] = @ptrCast(@alignCast(raw[i]));
    }
    return p;
}

pub export fn scTestKemMultiImpDestroy(pMultiVoid: ?*anyopaque) callconv(.c) void {
    const p: *ScTestKemMultiImp = @ptrCast(@alignCast(pMultiVoid orelse return));
    for (p.imps[0..p.n_imps]) |imp| {
        imp.n_error_kat_failure += p.n_error_kat_failure;
    }
    std.heap.c_allocator.destroy(p);
}

pub export fn scTestKemMultiImpGetCount(pMultiVoid: *const anyopaque) callconv(.c) usize {
    const p: *const ScTestKemMultiImp = @ptrCast(@alignCast(pMultiVoid));
    return p.n_imps;
}

pub export fn scTestKemMultiImpGetImp(pMultiVoid: *anyopaque, idx: usize) callconv(.c) *anyopaque {
    const p: *ScTestKemMultiImp = @ptrCast(@alignCast(pMultiVoid));
    return p.imps[idx];
}

pub export fn scTestKemMultiImpGetImpName(pMultiVoid: *anyopaque, idx: usize) callconv(.c) [*:0]const u8 {
    const p: *ScTestKemMultiImp = @ptrCast(@alignCast(pMultiVoid));
    return p.imps[idx].implementation_name.ptr;
}

pub export fn scTestKemMultiImpAddKatError(pMultiVoid: *anyopaque, nErrorKatFailure: i64) callconv(.c) void {
    const p: *ScTestKemMultiImp = @ptrCast(@alignCast(pMultiVoid));
    if (nErrorKatFailure > 0) {
        p.n_error_kat_failure += @intCast(nErrorKatFailure);
    }
}

const STATUS_SUCCESS_U32: u32 = 0;
const STATUS_UNSUCCESSFUL_U32: u32 = 0xC0000001;
const STATUS_NOT_SUPPORTED_U32: u32 = 0xC00000BB;
const STATUS_INVALID_SIGNATURE_U32: u32 = 0xC000A000;
const SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED: u32 = 1;

pub export fn scTestKemImpSetKeyFromTestBlob(
    pImp: *anyopaque,
    pcbTestKeyBlob: ?[*]const u8,
    cbTestKeyBlob: usize,
    canDecapsulate: c_int,
) callconv(.c) u32 {
    _ = canDecapsulate;
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    imp.kem_state.deinit(imp.imp_kind, imp.algorithm_name);
    const rawBlob = pcbTestKeyBlob orelse return STATUS_SUCCESS_U32;
    if (std.mem.eql(u8, imp.algorithm_name, "MlKem")) {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptMlKemkeyAllocate")) return STATUS_NOT_SUPPORTED_U32;
        h.check(cbTestKeyBlob == @sizeOf(MLKEMKEY_TESTBLOB), "Invalid key blob size");
        const blob: *const MLKEMKEY_TESTBLOB = @ptrCast(@alignCast(rawBlob));
        imp.kem_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptMlKemkeyAllocate", SymCryptMlKemkeyAllocate, .{blob.params});
        h.check(imp.kem_state.pKey != null, "Failed to allocate SymCrypt ML-KEM key");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptMlKemkeySetValue", SymCryptMlKemkeySetValue, .{
            &blob.abKeyBlob,
            blob.cbKeyBlob,
            blob.format,
            0,
            imp.kem_state.pKey.?,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to import SymCrypt ML-KEM key");
        return STATUS_SUCCESS_U32;
    } else {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptCompositeMlKemkeyAllocate")) return STATUS_NOT_SUPPORTED_U32;
        h.check(cbTestKeyBlob == @sizeOf(COMPOSITE_MLKEMKEY_TESTBLOB), "Invalid key blob size");
        const blob: *const COMPOSITE_MLKEMKEY_TESTBLOB = @ptrCast(@alignCast(rawBlob));
        imp.kem_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemkeyAllocate", SymCryptCompositeMlKemkeyAllocate, .{blob.params});
        h.check(imp.kem_state.pKey != null, "Failed to allocate SymCrypt Composite ML-KEM key");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemkeySetValue", SymCryptCompositeMlKemkeySetValue, .{
            &blob.abKeyBlob,
            blob.cbKeyBlob,
            blob.format,
            0,
            imp.kem_state.pKey.?,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to import SymCrypt Composite ML-KEM key");
        return STATUS_SUCCESS_U32;
    }
}

pub export fn scTestKemImpGetBlobFromKey(pImp: *anyopaque, keyFormat: u32, pbBlob: [*]u8, cbBlob: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlKem"))
        bridge.callSym(imp.imp_kind, "SymCryptMlKemkeyGetValue", SymCryptMlKemkeyGetValue, .{ imp.kem_state.pKey.?, pbBlob, cbBlob, keyFormat, 0 })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemkeyGetValue", SymCryptCompositeMlKemkeyGetValue, .{ imp.kem_state.pKey.?, pbBlob, cbBlob, keyFormat, 0 });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestKemImpEncapsulate(pImp: *anyopaque, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlKem"))
        bridge.callSym(imp.imp_kind, "SymCryptMlKemEncapsulate", SymCryptMlKemEncapsulate, .{ imp.kem_state.pKey.?, pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemEncapsulate", SymCryptCompositeMlKemEncapsulate, .{ imp.kem_state.pKey.?, pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestKemImpEncapsulateEx(pImp: *anyopaque, pbRandom: [*]const u8, cbRandom: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize, pbCiphertext: [*]u8, cbCiphertext: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlKem"))
        bridge.callSym(imp.imp_kind, "SymCryptMlKemEncapsulateEx", SymCryptMlKemEncapsulateEx, .{ imp.kem_state.pKey.?, pbRandom, cbRandom, pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemEncapsulateEx", SymCryptCompositeMlKemEncapsulateEx, .{ imp.kem_state.pKey.?, pbRandom, 32, pbRandom + 32, cbRandom - 32, pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestKemImpDecapsulate(pImp: *anyopaque, pbCiphertext: [*]const u8, cbCiphertext: usize, pbAgreedSecret: [*]u8, cbAgreedSecret: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlKem"))
        bridge.callSym(imp.imp_kind, "SymCryptMlKemDecapsulate", SymCryptMlKemDecapsulate, .{ imp.kem_state.pKey.?, pbCiphertext, cbCiphertext, pbAgreedSecret, cbAgreedSecret })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlKemDecapsulate", SymCryptCompositeMlKemDecapsulate, .{ imp.kem_state.pKey.?, pbCiphertext, cbCiphertext, pbAgreedSecret, cbAgreedSecret });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

// ============================================================================
// PqDsa (MlDsa & CompositeMlDsa)
// ============================================================================

pub const PqDsaState = struct {
    pKey: ?*anyopaque = null,

    pub fn deinit(self: *PqDsaState, imp_kind: sc_imp.ImpKind, alg_name: []const u8) void {
        if (self.pKey) |k| {
            if (std.mem.eql(u8, alg_name, "MlDsa")) {
                bridge.callSym(imp_kind, "SymCryptMlDsakeyFree", SymCryptMlDsakeyFree, .{k});
            } else {
                bridge.callSym(imp_kind, "SymCryptCompositeMlDsakeyFree", SymCryptCompositeMlDsakeyFree, .{k});
            }
            self.pKey = null;
        }
    }
};

pub export fn scTestPqDsaCount(algName: [*:0]const u8) callconv(.c) usize {
    var raw: [16]*anyopaque = undefined;
    return bridge.getImpsByCategory(.PqDsa, std.mem.span(algName), &raw, raw.len);
}

pub export fn scTestPqDsaCreate(algName: [*:0]const u8, index: usize) callconv(.c) ?*anyopaque {
    var raw: [16]*anyopaque = undefined;
    const count = bridge.getImpsByCategory(.PqDsa, std.mem.span(algName), &raw, raw.len);
    return if (index < count) raw[index] else null;
}

pub export fn scTestPqDsaFree(handle: ?*anyopaque) callconv(.c) void {
    if (handle) |h_ptr| {
        const imp: *bridge.AlgImp = @ptrCast(@alignCast(h_ptr));
        imp.pqdsa_state.deinit(imp.imp_kind, imp.algorithm_name);
    }
}

pub export fn scTestPqDsaSetKey(handle: *anyopaque, pcKeyBlob: ?*const PQDSAKEY_TESTBLOB) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    imp.pqdsa_state.deinit(imp.imp_kind, imp.algorithm_name);
    const blob = pcKeyBlob orelse return STATUS_SUCCESS_U32;
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptMlDsakeyAllocate")) return STATUS_NOT_SUPPORTED_U32;
        imp.pqdsa_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptMlDsakeyAllocate", SymCryptMlDsakeyAllocate, .{blob.mlDsakey.params});
        h.check(imp.pqdsa_state.pKey != null, "Failed to allocate SymCrypt ML-DSA key");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptMlDsakeySetValue", SymCryptMlDsakeySetValue, .{
            &blob.mlDsakey.abKeyBlob,
            blob.mlDsakey.cbKeyBlob,
            blob.mlDsakey.format,
            0,
            imp.pqdsa_state.pKey.?,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to import SymCrypt ML-DSA key");
        return STATUS_SUCCESS_U32;
    } else {
        if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptCompositeMlDsakeyAllocate")) return STATUS_NOT_SUPPORTED_U32;
        imp.pqdsa_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsakeyAllocate", SymCryptCompositeMlDsakeyAllocate, .{blob.compositeMlDsakey.params});
        h.check(imp.pqdsa_state.pKey != null, "Failed to allocate SymCrypt Composite ML-DSA key");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsakeySetValue", SymCryptCompositeMlDsakeySetValue, .{
            &blob.compositeMlDsakey.abKeyBlob,
            blob.compositeMlDsakey.cbKeyBlob,
            blob.compositeMlDsakey.format,
            0,
            imp.pqdsa_state.pKey.?,
        });
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to import SymCrypt Composite ML-DSA key");
        return STATUS_SUCCESS_U32;
    }
}

pub export fn scTestPqDsaGetBlobFromKey(handle: *anyopaque, keyFormat: u32, pbBlob: [*]u8, cbBlob: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlDsa"))
        bridge.callSym(imp.imp_kind, "SymCryptMlDsakeyGetValue", SymCryptMlDsakeyGetValue, .{ imp.pqdsa_state.pKey.?, pbBlob, cbBlob, keyFormat, 0 })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsakeyGetValue", SymCryptCompositeMlDsakeyGetValue, .{ imp.pqdsa_state.pKey.?, pbBlob, cbBlob, keyFormat, 0 });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestPqDsaSign(handle: *anyopaque, pbInput: ?[*]const u8, cbInput: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]u8, cbSignature: usize, pcbResult: ?*usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        h.check(pcbResult == null, "pcbResult is not intended for AlgMlDsa");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptMlDsaSign", SymCryptMlDsaSign, .{ imp.pqdsa_state.pKey.?, pbInput, cbInput, pbContext, cbContext, 0, pbSignature, cbSignature });
        return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
    } else {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsaSign", SymCryptCompositeMlDsaSign, .{ imp.pqdsa_state.pKey.?, pbInput, cbInput, pbContext, cbContext, 0, pbSignature, cbSignature, pcbResult });
        return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
    }
}

pub export fn scTestPqDsaSignExternalMu(handle: *anyopaque, pbMu: [*]const u8, cbMu: usize, pbSignature: [*]u8, cbSignature: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptExternalMuMlDsaSign", SymCryptExternalMuMlDsaSign, .{ imp.pqdsa_state.pKey.?, pbMu, cbMu, 0, pbSignature, cbSignature });
        return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
    } else {
        return STATUS_UNSUCCESSFUL_U32;
    }
}

pub export fn scTestPqDsaSignHash(handle: *anyopaque, hashAlgId: u32, pbHash: ?[*]const u8, cbHash: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]u8, cbSignature: usize, pcbResult: ?*usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        h.check(pcbResult == null, "pcbResult is not intended for AlgMlDsa");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptHashMlDsaSign", SymCryptHashMlDsaSign, .{ imp.pqdsa_state.pKey.?, hashAlgId, pbHash, cbHash, pbContext, cbContext, 0, pbSignature, cbSignature });
        return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
    } else {
        h.check(hashAlgId == 0, "hashId is not intended for AlgCompositeMlDsa");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsaSign", SymCryptCompositeMlDsaSign, .{ imp.pqdsa_state.pKey.?, pbHash, cbHash, pbContext, cbContext, SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED, pbSignature, cbSignature, pcbResult });
        return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
    }
}

pub export fn scTestPqDsaSignEx(
    handle: *anyopaque,
    hashId: u32,
    pbInput: ?[*]const u8,
    cbInput: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbRandom: ?[*]const u8,
    cbRandom: usize,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (!std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        return STATUS_UNSUCCESSFUL_U32;
    }
    if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptMlDsaSignEx")) {
        return STATUS_NOT_SUPPORTED_U32;
    }
    var pbHashOid: ?[*]const u8 = null;
    var cbHashOid: usize = 0;
    if (hashId != 0) {
        const oid: *const sc_imp.SYMCRYPT_OID = switch (hashId) {
            1 => &SymCryptSha256OidList[1],
            2 => &SymCryptSha384OidList[1],
            3 => &SymCryptSha512OidList[1],
            4 => &SymCryptSha512_256OidList[1],
            5 => &SymCryptSha3_256OidList[1],
            6 => &SymCryptSha3_384OidList[1],
            7 => &SymCryptSha3_512OidList[1],
            8 => &SymCryptShake128OidList[1],
            9 => &SymCryptShake256OidList[1],
            10 => &SymCryptSha224OidList[1],
            11 => &SymCryptSha512_224OidList[1],
            12 => &SymCryptSha3_224OidList[1],
            else => blk: {
                h.check(false, "Unknown hash algorithm ID");
                break :blk &SymCryptSha256OidList[1];
            },
        };
        pbHashOid = oid.pbOID;
        cbHashOid = oid.cbOID;
    }
    const scError = bridge.callSym(imp.imp_kind, "SymCryptMlDsaSignEx", SymCryptMlDsaSignEx, .{ imp.pqdsa_state.pKey.?, pbInput, cbInput, pbContext, cbContext, pbHashOid, cbHashOid, pbRandom, cbRandom, flags, pbSignature, cbSignature });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS_U32 else STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestPqDsaVerify(handle: *anyopaque, pbMessage: ?[*]const u8, cbMessage: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]const u8, cbSignature: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    const scError = if (std.mem.eql(u8, imp.algorithm_name, "MlDsa"))
        bridge.callSym(imp.imp_kind, "SymCryptMlDsaVerify", SymCryptMlDsaVerify, .{ imp.pqdsa_state.pKey.?, pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature, 0 })
    else
        bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsaVerify", SymCryptCompositeMlDsaVerify, .{ imp.pqdsa_state.pKey.?, pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature, 0 });
    if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS_U32;
    if (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) return STATUS_INVALID_SIGNATURE_U32;
    h.check(false, "Unexpected SymCrypt error in PqDsaVerify");
    return STATUS_UNSUCCESSFUL_U32;
}

pub export fn scTestPqDsaVerifyExternalMu(handle: *anyopaque, pbMu: [*]const u8, cbMu: usize, pbSignature: [*]const u8, cbSignature: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptExternalMuMlDsaVerify", SymCryptExternalMuMlDsaVerify, .{ imp.pqdsa_state.pKey.?, pbMu, cbMu, pbSignature, cbSignature, 0 });
        if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS_U32;
        if (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) return STATUS_INVALID_SIGNATURE_U32;
        h.check(false, "Unexpected SymCrypt error in PqDsaVerifyExternalMu");
        return STATUS_UNSUCCESSFUL_U32;
    } else {
        return STATUS_UNSUCCESSFUL_U32;
    }
}

pub export fn scTestPqDsaVerifyHash(handle: *anyopaque, hashAlgId: u32, pbHash: ?[*]const u8, cbHash: usize, pbContext: ?[*]const u8, cbContext: usize, pbSignature: [*]const u8, cbSignature: usize) callconv(.c) u32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    if (std.mem.eql(u8, imp.algorithm_name, "MlDsa")) {
        const scError = bridge.callSym(imp.imp_kind, "SymCryptHashMlDsaVerify", SymCryptHashMlDsaVerify, .{ imp.pqdsa_state.pKey.?, hashAlgId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature, 0 });
        if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS_U32;
        if (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) return STATUS_INVALID_SIGNATURE_U32;
        h.check(false, "Unexpected SymCrypt error in PqDsaVerifyHash");
        return STATUS_UNSUCCESSFUL_U32;
    } else {
        h.check(hashAlgId == 0, "hashId is not intended for AlgCompositeMlDsa");
        const scError = bridge.callSym(imp.imp_kind, "SymCryptCompositeMlDsaVerify", SymCryptCompositeMlDsaVerify, .{ imp.pqdsa_state.pKey.?, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature, SYMCRYPT_FLAG_COMPOSITE_MLDSA_PREHASHED });
        if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS_U32;
        if (scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE) return STATUS_INVALID_SIGNATURE_U32;
        h.check(false, "Unexpected SymCrypt error in CompositeMlDsaVerifyHash");
        return STATUS_UNSUCCESSFUL_U32;
    }
}

// ============================================================================
// Hpke
// ============================================================================

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

const SYMCRYPT_CACHED_ECURVE_ID_NIST_P256: u32 = 0;
const SYMCRYPT_CACHED_ECURVE_ID_NIST_P384: u32 = 1;
const SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519: u32 = 2;

const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: u32 = 1;
const SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM: usize = 32;
const SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE: usize = 64;
const SYMCRYPT_HPKE_CONTEXT_STATE_SENDER: u32 = 1;

pub const HpkeState = struct {
    pKey: ?*SYMCRYPT_HPKEKEY = null,
    pSenderCtx: ?*SYMCRYPT_HPKECONTEXT = null,
    pRecipientCtx: ?*SYMCRYPT_HPKECONTEXT = null,
    ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE = .{ .kemId = 0, .kdfId = 0, .aeadId = 0 },

    pub fn deinit(self: *HpkeState, imp_kind: sc_imp.ImpKind) void {
        if (self.pSenderCtx) |c| {
            bridge.callSym(imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{c});
            self.pSenderCtx = null;
        }
        if (self.pRecipientCtx) |c| {
            bridge.callSym(imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{c});
            self.pRecipientCtx = null;
        }
        if (self.pKey) |k| {
            bridge.callSym(imp_kind, "SymCryptHpkekeyFree", SymCryptHpkekeyFree, .{k});
            self.pKey = null;
        }
    }
};

pub export fn scTestHpkeCount(algName: [*:0]const u8) callconv(.c) usize {
    var raw: [16]*anyopaque = undefined;
    return bridge.getImpsByCategory(.Hpke, std.mem.span(algName), &raw, raw.len);
}

pub export fn scTestHpkeCreate(algName: [*:0]const u8, index: usize) callconv(.c) ?*anyopaque {
    var raw: [16]*anyopaque = undefined;
    const count = bridge.getImpsByCategory(.Hpke, std.mem.span(algName), &raw, raw.len);
    return if (index < count) raw[index] else null;
}

pub export fn scTestHpkeFree(handle: ?*anyopaque) callconv(.c) void {
    if (handle) |h_ptr| {
        const imp: *bridge.AlgImp = @ptrCast(@alignCast(h_ptr));
        imp.hpke_state.deinit(imp.imp_kind);
    }
}

pub export fn scTestHpkeGetLastError(handle: *anyopaque) callconv(.c) [*:0]const u8 {
    _ = handle;
    return "";
}

pub export fn scTestHpkeSetKey(handle: *anyopaque, ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE, format: u32, pbKey: ?[*]const u8, cbKey: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    imp.hpke_state.deinit(imp.imp_kind);
    const pb = pbKey orelse return STATUS_SUCCESS;
    if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptHpkekeyAllocate")) return STATUS_NOT_SUPPORTED;
    imp.hpke_state.ciphersuite = ciphersuite;
    imp.hpke_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptHpkekeyAllocate", SymCryptHpkekeyAllocate, .{ciphersuite});
    if (imp.hpke_state.pKey == null) return STATUS_NOT_SUPPORTED;

    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkekeySetValue", SymCryptHpkekeySetValue, .{ pb, cbKey, format, 0, imp.hpke_state.pKey.? });
    if (scError != SYMCRYPT_NO_ERROR) {
        bridge.callSym(imp.imp_kind, "SymCryptHpkekeyFree", SymCryptHpkekeyFree, .{imp.hpke_state.pKey.?});
        imp.hpke_state.pKey = null;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeGetKey(handle: *anyopaque, format: u32, pbKey: ?[*]u8, cbKey: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE getKey called without key");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkekeyGetValue", SymCryptHpkekeyGetValue, .{ imp.hpke_state.pKey.?, pbKey, cbKey, format, 0 });
    h.check(scError == SYMCRYPT_NO_ERROR, "HPKE getKey failed");
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeDeriveKeyPair(handle: *anyopaque, ciphersuite: SYMCRYPT_HPKE_CIPHERSUITE, pbIkm: ?[*]const u8, cbIkm: usize) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    imp.hpke_state.deinit(imp.imp_kind);
    if (imp.imp_kind == .sc_dynamic and !bridge.hasSym("SymCryptHpkekeyAllocate")) return STATUS_NOT_SUPPORTED;
    imp.hpke_state.ciphersuite = ciphersuite;
    imp.hpke_state.pKey = bridge.callSym(imp.imp_kind, "SymCryptHpkekeyAllocate", SymCryptHpkekeyAllocate, .{ciphersuite});
    if (imp.hpke_state.pKey == null) return STATUS_NOT_SUPPORTED;

    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkekeyDerive", SymCryptHpkekeyDerive, .{ pbIkm, cbIkm, imp.hpke_state.pKey.?, 0 });
    if (scError != SYMCRYPT_NO_ERROR) {
        bridge.callSym(imp.imp_kind, "SymCryptHpkekeyFree", SymCryptHpkekeyFree, .{imp.hpke_state.pKey.?});
        imp.hpke_state.pKey = null;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeSealSingleShot(
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
    pbEnc: ?[*]u8,
    cbEnc: usize,
    pbCiphertext: ?[*]u8,
    cbCiphertext: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE seal called without key");
    var cbTag: usize = 0;
    var scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSizeofAeadOverheadFromParams", SymCryptHpkeSizeofAeadOverheadFromParams, .{ imp.hpke_state.ciphersuite, &cbTag });
    h.check(scError == SYMCRYPT_NO_ERROR, "HPKE: SizeofAeadOverhead failed");
    h.check(cbPlaintext + cbTag == cbCiphertext, "HPKE: AeadOverhead calculation went wrong");

    scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSealSingleShot", SymCryptHpkeSealSingleShot, .{
        imp.hpke_state.pKey.?,
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
        0,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeOpenSingleShot(
    handle: *anyopaque,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbAad: ?[*]const u8,
    cbAad: usize,
    pbCiphertext: ?[*]const u8,
    cbCiphertext: usize,
    pbPlaintext: ?[*]u8,
    cbPlaintext: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE open called without key");
    var cbTag: usize = 0;
    var scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSizeofAeadOverheadFromParams", SymCryptHpkeSizeofAeadOverheadFromParams, .{ imp.hpke_state.ciphersuite, &cbTag });
    h.check(scError == SYMCRYPT_NO_ERROR, "HPKE: SizeofAeadOverhead failed");
    h.check(cbPlaintext + cbTag == cbCiphertext, "HPKE: AeadOverhead calculation went wrong");

    scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeOpenSingleShot", SymCryptHpkeOpenSingleShot, .{
        imp.hpke_state.pKey.?,
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
        pbPlaintext,
        cbPlaintext,
        0,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeSecretExportSingleShot(
    handle: *anyopaque,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbExportedValue: ?[*]u8,
    cbExportedValue: u16,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE secretExport called without key");
    const pCtx = bridge.callSym(imp.imp_kind, "SymCryptHpkeContextAllocate", SymCryptHpkeContextAllocate, .{imp.hpke_state.ciphersuite}) orelse {
        h.check(false, "HPKE secretExport: context alloc failed");
        return STATUS_UNSUCCESSFUL;
    };
    defer bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{pCtx});

    var scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSetupRecipient", SymCryptHpkeSetupRecipient, .{
        pCtx,
        imp.hpke_state.pKey.?,
        pbEnc,
        cbEnc,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        0,
    });
    if (scError != SYMCRYPT_NO_ERROR) return STATUS_UNSUCCESSFUL;

    scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSecretExport", SymCryptHpkeSecretExport, .{
        pCtx,
        pbExporterContext,
        cbExporterContext,
        pbExportedValue,
        cbExportedValue,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeSetupSender(
    handle: *anyopaque,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE setupSender called without key");
    if (imp.hpke_state.pSenderCtx) |c| {
        bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{c});
        imp.hpke_state.pSenderCtx = null;
    }
    imp.hpke_state.pSenderCtx = bridge.callSym(imp.imp_kind, "SymCryptHpkeContextAllocate", SymCryptHpkeContextAllocate, .{imp.hpke_state.ciphersuite});
    h.check(imp.hpke_state.pSenderCtx != null, "HPKE setupSender: context alloc failed");

    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSetupSender", SymCryptHpkeSetupSender, .{
        imp.hpke_state.pSenderCtx.?,
        imp.hpke_state.pKey.?,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        pbEnc,
        cbEnc,
        0,
    });
    if (scError != SYMCRYPT_NO_ERROR) {
        bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{imp.hpke_state.pSenderCtx.?});
        imp.hpke_state.pSenderCtx = null;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeSetupSenderDeterministic(
    handle: *anyopaque,
    pbRandom: ?[*]const u8,
    cbRandom: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
    pbEnc: ?[*]u8,
    cbEnc: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE setupSenderDeterministic called without key");
    if (imp.hpke_state.pSenderCtx) |c| {
        bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{c});
        imp.hpke_state.pSenderCtx = null;
    }
    if (imp.imp_kind == .sc_dynamic) return STATUS_NOT_SUPPORTED;

    var kemParams: SYMCRYPT_HPKE_KEM_PARAMS = undefined;
    var scError = SymCryptHpkeValidateCiphersuite(imp.hpke_state.ciphersuite, &kemParams, null);
    h.check(scError == SYMCRYPT_NO_ERROR, "HPKE setupSenderDeterministic: ValidateCiphersuite failed");

    const cbSharedSecret = kemParams.cbSharedSecret;
    var abSharedSecret: [SYMCRYPT_HPKE_KEM_MAX_SHARED_SECRET_SIZE]u8 = undefined;
    defer SymCryptWipe(&abSharedSecret, abSharedSecret.len);
    h.check(cbSharedSecret <= abSharedSecret.len, "HPKE setupSenderDeterministic: shared secret too large");

    const pKey = imp.hpke_state.pKey.?;
    switch (pKey.ciphersuite.kemId) {
        SYMCRYPT_HPKE_KEM_ID_DHKEM_P256,
        SYMCRYPT_HPKE_KEM_ID_DHKEM_P384,
        SYMCRYPT_HPKE_KEM_ID_DHKEM_P521,
        SYMCRYPT_HPKE_KEM_ID_DHKEM_X25519,
        => {
            scError = SymCryptHpkeDhkemEncapsulateEx(pKey, pbRandom, cbRandom, &abSharedSecret, cbSharedSecret, pbEnc.?, cbEnc);
        },
        SYMCRYPT_HPKE_KEM_ID_MLKEM_512,
        SYMCRYPT_HPKE_KEM_ID_MLKEM_768,
        SYMCRYPT_HPKE_KEM_ID_MLKEM_1024,
        => {
            scError = SymCryptMlKemEncapsulateEx(pKey.pKemKeyData.?, pbRandom.?, cbRandom, &abSharedSecret, cbSharedSecret, pbEnc.?, cbEnc);
        },
        SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256,
        SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384,
        SYMCRYPT_HPKE_KEM_ID_MLKEM768_X25519,
        => blk: {
            var curveId: u32 = SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519;
            var numFormat: u32 = SYMCRYPT_NUMBER_FORMAT_LSB_FIRST;
            var cbScalar: usize = 32;
            var abScalar: [48]u8 = undefined;
            defer SymCryptWipe(&abScalar, abScalar.len);

            if (pKey.ciphersuite.kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM768_P256) {
                curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P256;
                numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
                cbScalar = 32;
            } else if (pKey.ciphersuite.kemId == SYMCRYPT_HPKE_KEM_ID_MLKEM1024_P384) {
                curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P384;
                numFormat = SYMCRYPT_NUMBER_FORMAT_MSB_FIRST;
                cbScalar = 48;
            }

            if (cbRandom < SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM + cbScalar) {
                scError = SYMCRYPT_INVALID_ARGUMENT;
                break :blk;
            }

            scError = SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
                curveId,
                numFormat,
                pbRandom.? + SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM,
                cbRandom - SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM,
                &abScalar,
                cbScalar,
            );
            if (scError != SYMCRYPT_NO_ERROR) break :blk;

            scError = SymCryptCompositeMlKemEncapsulateEx(
                pKey.pKemKeyData.?,
                pbRandom.?,
                SYMCRYPT_MLKEM_SIZEOF_ENCAPS_RANDOM,
                &abScalar,
                cbScalar,
                &abSharedSecret,
                cbSharedSecret,
                pbEnc.?,
                cbEnc,
            );
        },
        else => {
            scError = SYMCRYPT_NOT_IMPLEMENTED;
        },
    }

    if (scError != SYMCRYPT_NO_ERROR) {
        return if (scError == SYMCRYPT_NOT_IMPLEMENTED) STATUS_NOT_SUPPORTED else STATUS_UNSUCCESSFUL;
    }

    imp.hpke_state.pSenderCtx = SymCryptHpkeContextAllocate(imp.hpke_state.ciphersuite);
    h.check(imp.hpke_state.pSenderCtx != null, "HPKE setupSenderDeterministic: context alloc failed");

    scError = SymCryptHpkeFinishSetup(
        imp.hpke_state.pSenderCtx.?,
        SYMCRYPT_HPKE_CONTEXT_STATE_SENDER,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        &abSharedSecret,
        cbSharedSecret,
    );
    if (scError != SYMCRYPT_NO_ERROR) {
        SymCryptHpkeContextFree(imp.hpke_state.pSenderCtx.?);
        imp.hpke_state.pSenderCtx = null;
        return STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeSetupRecipient(
    handle: *anyopaque,
    pbEnc: ?[*]const u8,
    cbEnc: usize,
    pbInfo: ?[*]const u8,
    cbInfo: usize,
    pbPsk: ?[*]const u8,
    cbPsk: usize,
    pbPskId: ?[*]const u8,
    cbPskId: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE setupRecipient called without key");
    if (imp.hpke_state.pRecipientCtx) |c| {
        bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{c});
        imp.hpke_state.pRecipientCtx = null;
    }
    imp.hpke_state.pRecipientCtx = bridge.callSym(imp.imp_kind, "SymCryptHpkeContextAllocate", SymCryptHpkeContextAllocate, .{imp.hpke_state.ciphersuite});
    h.check(imp.hpke_state.pRecipientCtx != null, "HPKE setupRecipient: context alloc failed");

    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSetupRecipient", SymCryptHpkeSetupRecipient, .{
        imp.hpke_state.pRecipientCtx.?,
        imp.hpke_state.pKey.?,
        pbEnc,
        cbEnc,
        pbInfo,
        cbInfo,
        pbPsk,
        cbPsk,
        pbPskId,
        cbPskId,
        0,
    });
    if (scError != SYMCRYPT_NO_ERROR) {
        bridge.callSym(imp.imp_kind, "SymCryptHpkeContextFree", SymCryptHpkeContextFree, .{imp.hpke_state.pRecipientCtx.?});
        imp.hpke_state.pRecipientCtx = null;
        return if (scError == SYMCRYPT_NOT_IMPLEMENTED) STATUS_NOT_SUPPORTED else STATUS_UNSUCCESSFUL;
    }
    return STATUS_SUCCESS;
}

pub export fn scTestHpkeSeal(
    handle: *anyopaque,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
    pu64SeqNumber: ?*u64,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pSenderCtx != null, "HPKE seal called without sender context");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSeal", SymCryptHpkeSeal, .{
        imp.hpke_state.pSenderCtx.?,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbSrc,
        pbDst,
        cbDst,
        pu64SeqNumber,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeOpen(
    handle: *anyopaque,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pRecipientCtx != null, "HPKE open called without recipient context");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeOpen", SymCryptHpkeOpen, .{
        imp.hpke_state.pRecipientCtx.?,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbSrc,
        pbDst,
        cbDst,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeOpenUnordered(
    handle: *anyopaque,
    u64SeqNumber: u64,
    pbAuthData: ?[*]const u8,
    cbAuthData: usize,
    pbSrc: ?[*]const u8,
    cbSrc: usize,
    pbDst: ?[*]u8,
    cbDst: usize,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pRecipientCtx != null, "HPKE openUnordered called without recipient context");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeOpenUnordered", SymCryptHpkeOpenUnordered, .{
        imp.hpke_state.pRecipientCtx.?,
        u64SeqNumber,
        pbAuthData,
        cbAuthData,
        pbSrc,
        cbSrc,
        pbDst,
        cbDst,
    });
    if (scError == SYMCRYPT_NO_ERROR) return STATUS_SUCCESS;
    return if (scError == SYMCRYPT_NOT_IMPLEMENTED) STATUS_NOT_SUPPORTED else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeSecretExportSender(
    handle: *anyopaque,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbResult: ?[*]u8,
    cbResult: u16,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pSenderCtx != null, "HPKE secretExportSender called without sender context");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSecretExport", SymCryptHpkeSecretExport, .{
        imp.hpke_state.pSenderCtx.?,
        pbExporterContext,
        cbExporterContext,
        pbResult,
        cbResult,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeSecretExportRecipient(
    handle: *anyopaque,
    pbExporterContext: ?[*]const u8,
    cbExporterContext: usize,
    pbResult: ?[*]u8,
    cbResult: u16,
) callconv(.c) i32 {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pRecipientCtx != null, "HPKE secretExportRecipient called without recipient context");
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSecretExport", SymCryptHpkeSecretExport, .{
        imp.hpke_state.pRecipientCtx.?,
        pbExporterContext,
        cbExporterContext,
        pbResult,
        cbResult,
    });
    return if (scError == SYMCRYPT_NO_ERROR) STATUS_SUCCESS else STATUS_UNSUCCESSFUL;
}

pub export fn scTestHpkeEncSize(handle: *anyopaque) callconv(.c) usize {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(handle));
    h.check(imp.hpke_state.pKey != null, "HPKE encSize called without key");
    var cbEnc: usize = 0;
    const scError = bridge.callSym(imp.imp_kind, "SymCryptHpkeSizeofEncapsCiphertextFromParams", SymCryptHpkeSizeofEncapsCiphertextFromParams, .{ imp.hpke_state.ciphersuite, &cbEnc });
    h.check(scError == SYMCRYPT_NO_ERROR, "HPKE encSize failed");
    return cbEnc;
}

// ============================================================================
// Asymmetric Implementation Queries & Struct Accessors
// ============================================================================

pub export fn scTestGetRsaSignImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.RsaSign, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestGetRsaEncImps(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.RsaEnc, algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestGetDhImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Dh, "", outImps, maxImps);
}

pub export fn scTestGetDsaImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Dsa, "", outImps, maxImps);
}

pub export fn scTestGetEcurveImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Ecurve, "", outImps, maxImps);
}

pub export fn scTestGetPqKemImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Kem, "", outImps, maxImps);
}

pub export fn scTestGetPqDsaImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.PqDsa, "", outImps, maxImps);
}

pub export fn scTestGetHbsImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Hbs, "", outImps, maxImps);
}

pub export fn scTestGetHpkeImps(outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getImpsByCategory(.Hpke, "", outImps, maxImps);
}

pub export fn scTestGetAllImplementations(algNamePtr: [*]const u8, algNameLen: usize, outImps: [*]*anyopaque, maxImps: usize) callconv(.c) usize {
    return bridge.getAllImpsByName(algNamePtr[0..algNameLen], outImps, maxImps);
}

pub export fn scTestImpIncResults(pImp: *anyopaque) callconv(.c) void {
    const imp: *bridge.AlgImp = @ptrCast(@alignCast(pImp));
    imp.n_results += 1;
}

pub export fn scTestDlgroupNBitsOfP(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.nBitsOfP;
}

pub export fn scTestDlgroupNBitsOfQ(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.nBitsOfQ;
}

pub export fn scTestDlgroupNMinBitsPriv(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.nMinBitsPriv;
}

pub export fn scTestDlgroupNDefaultBitsPriv(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.nDefaultBitsPriv;
}

pub export fn scTestDlgroupCbPrimeP(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.cbPrimeP;
}

pub export fn scTestDlgroupCbPrimeQ(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.cbPrimeQ;
}

pub export fn scTestDlgroupFHasPrimeQ(pDlgroup: *const anyopaque) callconv(.c) u32 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.fHasPrimeQ;
}

pub export fn scTestDlgroupSetFHasPrimeQ(pDlgroup: *anyopaque, val: u32) callconv(.c) void {
    const g: *types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    g.fHasPrimeQ = @intCast(val);
}

pub export fn scTestDlgroupIsSafePrimeGroup(pDlgroup: *const anyopaque) callconv(.c) u8 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.isSafePrimeGroup;
}

pub export fn scTestDlgroupIsSafePrime(pDlgroup: *const anyopaque) callconv(.c) u8 {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return g.isSafePrimeGroup;
}

pub export fn scTestDlgroupSetIsSafePrimeGroup(pDlgroup: *anyopaque, val: u8) callconv(.c) void {
    const g: *types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    g.isSafePrimeGroup = val;
}

pub export fn scTestDlgroupPmP(pDlgroup: *const anyopaque) callconv(.c) *anyopaque {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return @ptrCast(g.pmP);
}

pub export fn scTestDlgroupPmQ(pDlgroup: *const anyopaque) callconv(.c) ?*anyopaque {
    const g: *const types.SYMCRYPT_DLGROUP = @ptrCast(@alignCast(pDlgroup));
    return if (g.pmQ) |p| @ptrCast(p) else null;
}

pub export fn scTestDlkeyFHasPrivateKey(pDlkey: *const anyopaque) callconv(.c) u32 {
    const k: *const types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    return k.fHasPrivateKey;
}

pub export fn scTestDlkeySetFAlgorithmInfo(pDlkey: *anyopaque, val: u32) callconv(.c) void {
    const k: *types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    k.fAlgorithmInfo = val;
}

pub export fn scTestDlkeyNBitsPriv(pDlkey: *const anyopaque) callconv(.c) u32 {
    const k: *const types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    return k.nBitsPriv;
}

pub export fn scTestDlkeyFPrivateModQ(pDlkey: *const anyopaque) callconv(.c) u32 {
    const k: *const types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    return k.fPrivateModQ;
}

pub export fn scTestDlkeyPiPrivateKey(pDlkey: *const anyopaque) callconv(.c) ?*anyopaque {
    const k: *const types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    return if (k.piPrivateKey) |p| @ptrCast(p) else null;
}

pub export fn scTestDlkeyPePublicKey(pDlkey: *const anyopaque) callconv(.c) *anyopaque {
    const k: *const types.SYMCRYPT_DLKEY = @ptrCast(@alignCast(pDlkey));
    return @ptrCast(k.pePublicKey);
}

pub fn registerAsymAlgs(imp_kind: sc_imp.ImpKind) void {
    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptRsakeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .RsaEnc, "RsaEncRaw", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .RsaEnc, "RsaEncPkcs1", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .RsaEnc, "RsaEncOaep", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .RsaSign, "RsaSignPkcs1", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .RsaSign, "RsaSignPss", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "RsakeySetValue", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "RsakeySetValueFromPrivateExponent", "");
    }

    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptDlkeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Dh, "Dh", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .Dsa, "Dsa", "");
    }

    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptXmsskeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Hbs, "Xmss", "");
    }
    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptLmskeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Hbs, "Lms", "");
    }

    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptMlKemkeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Kem, "MlKem", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "MlKemkeySetValue", "");
    }
    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptCompositeMlKemkeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Kem, "CompositeMlKem", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "CompositeMlKemkeySetValue", "");
    }

    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptMlDsakeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .PqDsa, "MlDsa", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "MlDsakeySetValue", "");
    }
    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptCompositeMlDsakeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .PqDsa, "CompositeMlDsa", "");
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, "CompositeMlDsakeySetValue", "");
    }

    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptHpkekeyAllocate")) {
        _ = bridge.maybeCreateAlgImp(imp_kind, .Hpke, "Hpke", "");
    }

    const ec_algs = [_][:0]const u8{
        "EcurveAllocateAndFree",
        "EckeySetRandom",
        "EcpointSetZero",
        "EcpointSetDistinguished",
        "EcpointSetRandom",
        "EcpointIsEqual",
        "EcpointIsZero",
        "EcpointOnCurve",
        "EcpointAdd",
        "EcpointAddDiffNz",
        "EcpointDouble",
        "EcpointScalarMul",
        "EcdsaSign",
        "EcdsaVerify",
        "Ecdh",
        "EckeySetValue",
    };
    if (imp_kind != .sc_dynamic or bridge.hasSym("SymCryptEcurveAllocate")) {
        for (ec_algs) |name| {
            _ = bridge.maybeCreateAlgImp(imp_kind, .Ecurve, name, "");
        }
    }

    const perf_only_algs = [_][:0]const u8{
        "IntAdd",
        "IntSub",
        "IntMul",
        "IntSquare",
        "IntDivMod",
        "ModAdd",
        "ModSub",
        "ModMul",
        "ModSquare",
        "ModInv",
        "ModExp",
        "ScsTable",
        "TrialDivision",
        "TrialDivisionContext",
        "TlsHandshake",
        "DeveloperTest",
    };
    for (perf_only_algs) |name| {
        _ = bridge.maybeCreateAlgImp(imp_kind, .PerfOnly, name, "");
    }
}

pub fn deinitAsymAlgImp(imp: *bridge.AlgImp) void {
    imp.rsa_state.deinit(imp.imp_kind);
    imp.dl_state.deinit(imp.imp_kind);
    imp.hbs_state.deinit(imp.imp_kind, imp.algName);
    imp.kem_state.deinit(imp.imp_kind, imp.algName);
    imp.pqdsa_state.deinit(imp.imp_kind, imp.algName);
    imp.hpke_state.deinit(imp.imp_kind);
}

pub export fn scTestRsakeySetAlgorithmInfo(pKey: *anyopaque, flags: u32) callconv(.c) void {
    const k: *types.SYMCRYPT_RSAKEY = @ptrCast(@alignCast(pKey));
    k.fAlgorithmInfo = flags;
}

pub export fn scTestScratchBytesForRsaOaep(hashAlgorithm: *const anyopaque, nBytesOAEP: usize) callconv(.c) usize {
    const h_alg: *const types.SYMCRYPT_HASH = @ptrCast(@alignCast(hashAlgorithm));
    return types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_OAEP(h_alg, nBytesOAEP);
}

pub export fn scTestScratchBytesForRsaPkcs1(nBytesPKCS1: usize) callconv(.c) usize {
    return types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_PKCS1(nBytesPKCS1);
}

pub export fn scTestScratchBytesForRsaPss(hashAlgorithm: *const anyopaque, nBytesMessage: usize, nBytesPSS: usize) callconv(.c) usize {
    const h_alg: *const types.SYMCRYPT_HASH = @ptrCast(@alignCast(hashAlgorithm));
    return types.SYMCRYPT_INTERNAL_SCRATCH_BYTES_FOR_RSA_PSS(h_alg, nBytesMessage, nBytesPSS);
}

pub export fn scTestScratchBytesForIntDivMod(nSrcDigits: u32, nDivisorDigits: u32) callconv(.c) u32 {
    return types.SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD(nSrcDigits, nDivisorDigits);
}

extern fn SymCryptSha256Init(pState: *anyopaque) callconv(.c) void;
extern fn SymCryptSha256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void;
extern fn SymCryptSha256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void;
extern fn SymCryptSha256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void;

pub export fn scTestSha256Algorithm() callconv(.c) *const anyopaque {
    return SymCryptSha256Algorithm;
}

pub export fn scTestSha256StateSize() callconv(.c) usize {
    return 128;
}

pub export fn scTestSha256Init(pState: *anyopaque) callconv(.c) void {
    SymCryptSha256Init(pState);
}

pub export fn scTestSha256Append(pState: *anyopaque, pbData: ?[*]const u8, cbData: usize) callconv(.c) void {
    SymCryptSha256Append(pState, pbData, cbData);
}

pub export fn scTestSha256Result(pState: *anyopaque, pbResult: [*]u8) callconv(.c) void {
    SymCryptSha256Result(pState, pbResult);
}

pub export fn scTestSha256StateCopy(pSrc: *const anyopaque, pDst: *anyopaque) callconv(.c) void {
    SymCryptSha256StateCopy(pSrc, pDst);
}

