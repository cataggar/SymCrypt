// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const STATUS_SUCCESS: i32 = 0;
const STATUS_INVALID_SIGNATURE: i32 = @bitCast(@as(u32, 0xC000A000));

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800C;
const SYMCRYPT_INVALID_ARGUMENT: u32 = 0x800E;
const SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE: u32 = 0x8010;
const SYMCRYPT_INCOMPATIBLE_FORMAT: u32 = 0x8011;

const SYMCRYPT_MLDSA_PARAMS_NULL: u32 = 0;
const SYMCRYPT_MLDSA_PARAMS_MLDSA44: u32 = 1;
const SYMCRYPT_MLDSA_PARAMS_MLDSA65: u32 = 2;
const SYMCRYPT_MLDSA_PARAMS_MLDSA87: u32 = 3;

const SYMCRYPT_MLDSAKEY_FORMAT_NULL: u32 = 0;
const SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED: u32 = 1;
const SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY: u32 = 2;
const SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY: u32 = 3;

const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_NULL: u32 = 0;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256: u32 = 1;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512: u32 = 2;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512: u32 = 3;
const SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512: u32 = 4;

const SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL: u32 = 0;
const SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY: u32 = 1;
const SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY: u32 = 2;

const SYMCRYPT_PQDSA_HASH_ID_NULL: u32 = 0;
const SYMCRYPT_PQDSA_HASH_ID_SHA256: u32 = 1;
const SYMCRYPT_PQDSA_HASH_ID_SHA384: u32 = 2;
const SYMCRYPT_PQDSA_HASH_ID_SHA512: u32 = 3;
const SYMCRYPT_PQDSA_HASH_ID_SHA512_256: u32 = 4;
const SYMCRYPT_PQDSA_HASH_ID_SHA3_256: u32 = 5;
const SYMCRYPT_PQDSA_HASH_ID_SHA3_384: u32 = 6;
const SYMCRYPT_PQDSA_HASH_ID_SHA3_512: u32 = 7;
const SYMCRYPT_PQDSA_HASH_ID_SHAKE128: u32 = 8;
const SYMCRYPT_PQDSA_HASH_ID_SHAKE256: u32 = 9;
const SYMCRYPT_PQDSA_HASH_ID_SHA224: u32 = 10;
const SYMCRYPT_PQDSA_HASH_ID_SHA512_224: u32 = 11;
const SYMCRYPT_PQDSA_HASH_ID_SHA3_224: u32 = 12;

const SYMCRYPT_FLAG_MLDSA_EXTERNALMU: u32 = 0x1;

const SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS: usize = 256;
const SYMCRYPT_MLDSA_Q: u32 = 8380417;
const SYMCRYPT_MLDSA_R_LOG2: u6 = 32;
const SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS: u32 = 13;

const SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE: usize = 32;
const SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE: usize = 64;
const SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE: usize = 32;
const SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE: usize = 32;
const SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE: usize = 32;
const SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH: usize = 255;
const SYMCRYPT_SHAKE256_RESULT_SIZE: usize = 64;
const SYMCRYPT_SHA512_RESULT_SIZE: usize = 64;

const SYMCRYPT_MLDSA_VECTOR_MAX_LENGTH: usize = 8;
const SYMCRYPT_MLDSA_MATRIX_MAX_NROWS: usize = 8;
const SYMCRYPT_MLDSA_MATRIX_MAX_NCOLS: usize = 7;

const SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA87: usize = 4896;
const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA44: usize = 2420;
const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65: usize = 3309;
const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA87: usize = 4627;

const SYMCRYPT_COMPOSITE_MLDSA_PRIVATE_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512: usize = 64;
const SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512: usize = 2689;

const SYMCRYPT_MLDSA_POLYELEMENT = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]u32,
};

const SYMCRYPT_MLDSA_VECTOR = extern struct {
    nElems: u8,
    cbTotalSize: u32,
};

const SYMCRYPT_MLDSA_MATRIX = extern struct {
    nRows: u8,
    nCols: u8,
    cbTotalSize: u32,
};

const SYMCRYPT_MLDSA_INTERNAL_PARAMS = extern struct {
    params: u32,
    cbPolyElement: u32,
    cbRowVector: u32,
    cbColVector: u32,
    cbMatrix: u32,
    nRows: u8,
    nCols: u8,
    privateKeyRange: u8,
    encodedCoefficientBitLength: u8,
    nChallengeNonZeroCoeffs: u8,
    nHintNonZeroCoeffs: u8,
    maskCoefficientRangeLog2: u8,
    commitmentModulus: u8,
    decomposeR1Factor: u32,
    commitmentRoundingRange: u32,
    w1EncodeCoefficientBitLength: u32,
    cbCommitmentHash: u32,
    cbEncodedPrivateKey: u32,
    cbEncodedPublicKey: u32,
    cbEncodedSignature: u32,
};

const SYMCRYPT_MLDSAKEY = opaque {};
const SYMCRYPT_COMPOSITE_MLDSAKEY = opaque {};

pub const MLDSAKEY_TESTBLOB = extern struct {
    params: u32 = SYMCRYPT_MLDSA_PARAMS_NULL,
    format: u32 = SYMCRYPT_MLDSAKEY_FORMAT_NULL,
    abKeyBlob: [SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA87]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

pub const COMPOSITE_MLDSAKEY_TESTBLOB = extern struct {
    params: u32 = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_NULL,
    format: u32 = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_NULL,
    abKeyBlob: [SYMCRYPT_COMPOSITE_MLDSA_PUBLIC_KEY_SIZE_MLDSA87_ECDSA_P384_SHA512]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

pub const PQDSAKEY_TESTBLOB = extern union {
    mlDsakey: MLDSAKEY_TESTBLOB,
    compositeMlDsakey: COMPOSITE_MLDSAKEY_TESTBLOB,
};

const SYMCRYPT_TEST_MLDSA_PARAMS = struct {
    pszParamsName: [:0]const u8,
    params: u32,
};

const rgTestMlDsaParams = [_]SYMCRYPT_TEST_MLDSA_PARAMS{
    .{
        .pszParamsName = "ML-DSA-44",
        .params = SYMCRYPT_MLDSA_PARAMS_MLDSA44,
    },
    .{
        .pszParamsName = "ML-DSA-65",
        .params = SYMCRYPT_MLDSA_PARAMS_MLDSA65,
    },
    .{
        .pszParamsName = "ML-DSA-87",
        .params = SYMCRYPT_MLDSA_PARAMS_MLDSA87,
    },
};

const SYMCRYPT_TEST_COMPOSITE_MLDSA_PARAMS = struct {
    pszParamsName: [:0]const u8,
    params: u32,
    cbMlDsaSignature: usize,
};

const rgTestCompositeMlDsaParams = [_]SYMCRYPT_TEST_COMPOSITE_MLDSA_PARAMS{
    .{
        .pszParamsName = "MLDSA44-ECDSA-P256-SHA256",
        .params = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256,
        .cbMlDsaSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA44,
    },
    .{
        .pszParamsName = "MLDSA65-ECDSA-P256-SHA512",
        .params = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512,
        .cbMlDsaSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65,
    },
    .{
        .pszParamsName = "MLDSA65-ECDSA-P384-SHA512",
        .params = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512,
        .cbMlDsaSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65,
    },
    .{
        .pszParamsName = "MLDSA87-ECDSA-P384-SHA512",
        .params = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512,
        .cbMlDsaSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA87,
    },
};

extern const SymCryptMlDsaInternalParams44: SYMCRYPT_MLDSA_INTERNAL_PARAMS;
extern const SymCryptMlDsaInternalParams65: SYMCRYPT_MLDSA_INTERNAL_PARAMS;
extern const SymCryptMlDsaInternalParams87: SYMCRYPT_MLDSA_INTERNAL_PARAMS;

extern const SymCryptSha256Algorithm: ?*const anyopaque;
extern const SymCryptSha512Algorithm: ?*const anyopaque;

extern fn SymCryptHash(
    pHash: ?*const anyopaque,
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void;

extern fn SymCryptShake256(
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
    cbResult: usize,
) callconv(.c) void;

extern fn SymCryptSha512(
    pbData: ?[*]const u8,
    cbData: usize,
    pbResult: [*]u8,
) callconv(.c) void;

extern fn SymCryptMlDsaGetInternalParamsFromParams(
    params: u32,
    pInternalParams: *?*const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
) callconv(.c) u32;
extern fn SymCryptMlDsaSizeofKeyFormatFromParams(params: u32, format: u32, pcbKeyFormat: *usize) callconv(.c) u32;
extern fn SymCryptMlDsaSizeofSignatureFromParams(params: u32, pcbSignature: *usize) callconv(.c) u32;
extern fn SymCryptMlDsakeyAllocate(params: u32) callconv(.c) ?*SYMCRYPT_MLDSAKEY;
extern fn SymCryptMlDsakeyFree(pkMlDsakey: *SYMCRYPT_MLDSAKEY) callconv(.c) void;
extern fn SymCryptMlDsakeyGenerate(pkMlDsakey: *SYMCRYPT_MLDSAKEY, flags: u32) callconv(.c) u32;
extern fn SymCryptMlDsakeySetValue(
    pbSrc: [*]const u8,
    cbSrc: usize,
    mlDsakeyFormat: u32,
    flags: u32,
    pkMlDsakey: *SYMCRYPT_MLDSAKEY,
) callconv(.c) u32;
extern fn SymCryptMlDsakeyGetValue(
    pkMlDsakey: *const SYMCRYPT_MLDSAKEY,
    pbDst: [*]u8,
    cbDst: usize,
    mlDsakeyFormat: u32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptMlDsaSign(
    pkMlDsakey: *const SYMCRYPT_MLDSAKEY,
    pbMessage: ?[*]const u8,
    cbMessage: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) u32;
extern fn SymCryptMlDsaVerify(
    pkMlDsakey: *const SYMCRYPT_MLDSAKEY,
    pbMessage: ?[*]const u8,
    cbMessage: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
    flags: u32,
) callconv(.c) u32;

extern fn SymCryptWipe(pbData: ?*anyopaque, cbData: usize) callconv(.c) void;
extern fn SymCryptMlDsaMontReduce(a: u64) callconv(.c) u32;
extern fn SymCryptMlDsaMontMul(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMlDsaModAdd(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMlDsaModSub(a: u32, b: u32) callconv(.c) u32;
extern fn SymCryptMlDsaPolyElementCreate(pbBuffer: [*]u8, cbBuffer: usize) callconv(.c) ?*SYMCRYPT_MLDSA_POLYELEMENT;
extern fn SymCryptMlDsaPolyElementSetZero(peDst: *SYMCRYPT_MLDSA_POLYELEMENT) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementNTT(peSrc: *SYMCRYPT_MLDSA_POLYELEMENT) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementINTT(peSrc: *SYMCRYPT_MLDSA_POLYELEMENT) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementMulR(peSrc: *SYMCRYPT_MLDSA_POLYELEMENT) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementMontMul(
    peSrc1: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peDst: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementAdd(
    peSrc1: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peDst: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementSub(
    peSrc1: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peDst: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsaPower2Round(r: u32, puR1: *u32, puR0: *u32) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementPower2Round(
    peSrc: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peDst1: *SYMCRYPT_MLDSA_POLYELEMENT,
    peDst0: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementEncode(
    peSrc: *const SYMCRYPT_MLDSA_POLYELEMENT,
    nBitsPerCoefficient: u32,
    signedCoefficientBound: u32,
    pbDst: [*]u8,
) callconv(.c) void;
extern fn SymCryptMlDsaPolyElementDecode(
    pbSrc: [*]const u8,
    nBitsPerCoefficient: u32,
    signedCoefficientBound: u32,
    peDst: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) u32;
extern fn SymCryptMlDsaSampleInBall(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbCommitmentHash: [*]const u8,
    cbCommitmentHash: usize,
    peChallenge: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) u32;

extern fn SymCryptMlDsaVectorCreate(pbBuffer: [*]u8, cbBuffer: u32, nElems: u8) callconv(.c) ?*SYMCRYPT_MLDSA_VECTOR;
extern fn SymCryptMlDsaVectorCopy(pvSrc: *const SYMCRYPT_MLDSA_VECTOR, pvDst: *SYMCRYPT_MLDSA_VECTOR) callconv(.c) void;
extern fn SymCryptMlDsaVectorSetZero(pvDst: *SYMCRYPT_MLDSA_VECTOR) callconv(.c) void;
extern fn SymCryptMlDsaVectorAdd(
    pvSrc1: *const SYMCRYPT_MLDSA_VECTOR,
    pvSrc2: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorSub(
    pvSrc1: *const SYMCRYPT_MLDSA_VECTOR,
    pvSrc2: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorPolyElementMontMul(
    pvSrc1: *const SYMCRYPT_MLDSA_VECTOR,
    peSrc2: *const SYMCRYPT_MLDSA_POLYELEMENT,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorNTT(pvSrc: *SYMCRYPT_MLDSA_VECTOR) callconv(.c) void;
extern fn SymCryptMlDsaVectorINTT(pvSrc: *SYMCRYPT_MLDSA_VECTOR) callconv(.c) void;
extern fn SymCryptMlDsaVectorPower2Round(
    pvSrc: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst1: *SYMCRYPT_MLDSA_VECTOR,
    pvDst0: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorHighBits(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorLowBits(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorInfinityNorm(pvSrc: *const SYMCRYPT_MLDSA_VECTOR) callconv(.c) u32;
extern fn SymCryptMlDsaVectorEncode(
    pvSrc: *const SYMCRYPT_MLDSA_VECTOR,
    nBitsPerCoefficient: u32,
    signedCoefficientBound: u32,
    pbDst: [*]u8,
) callconv(.c) void;
extern fn SymCryptMlDsaVectorDecode(
    pbSrc: [*]const u8,
    nBitsPerCoefficient: u32,
    signedCoefficientBound: u32,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) u32;
extern fn SymCryptMlDsaMatrixCreate(
    pbBuffer: [*]u8,
    cbBuffer: u32,
    nRows: u8,
    nCols: u8,
) callconv(.c) ?*SYMCRYPT_MLDSA_MATRIX;
extern fn SymCryptMlDsaMatrixVectorMontMul(
    pmSrc1: *const SYMCRYPT_MLDSA_MATRIX,
    pvSrc2: *const SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
    peTmp: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsakeyComputeT(
    pmA: *const SYMCRYPT_MLDSA_MATRIX,
    pvs1: *const SYMCRYPT_MLDSA_VECTOR,
    pvs2: *const SYMCRYPT_MLDSA_VECTOR,
    pvt0: *SYMCRYPT_MLDSA_VECTOR,
    pvt1: *SYMCRYPT_MLDSA_VECTOR,
    pvTmp: *SYMCRYPT_MLDSA_VECTOR,
    peTmp: *SYMCRYPT_MLDSA_POLYELEMENT,
) callconv(.c) void;
extern fn SymCryptMlDsaMakeHint(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvWMinusCs2: *SYMCRYPT_MLDSA_VECTOR,
    pvWMinusCs2PlusCt0: *SYMCRYPT_MLDSA_VECTOR,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
    nBitsSet: *u32,
) callconv(.c) void;
extern fn SymCryptMlDsaUseHint(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvHint: *const SYMCRYPT_MLDSA_VECTOR,
    pvCommitment: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) void;
extern fn SymCryptMlDsaHintBitPack(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: *const SYMCRYPT_MLDSA_VECTOR,
    pbDst: [*]u8,
) callconv(.c) void;
extern fn SymCryptMlDsaHintBitUnpack(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbSrc: [*]const u8,
    pvDst: *SYMCRYPT_MLDSA_VECTOR,
) callconv(.c) u32;

extern fn SymCryptCompositeMlDsaSizeofKeyFormatFromParams(params: u32, format: u32, pcbKeyFormat: *usize) callconv(.c) u32;
extern fn SymCryptCompositeMlDsaSizeofSignatureFromParams(params: u32, pcbSignature: *usize) callconv(.c) u32;
extern fn SymCryptCompositeMlDsakeyAllocate(params: u32) callconv(.c) ?*SYMCRYPT_COMPOSITE_MLDSAKEY;
extern fn SymCryptCompositeMlDsakeyFree(pkCompositeMlDsakey: *SYMCRYPT_COMPOSITE_MLDSAKEY) callconv(.c) void;
extern fn SymCryptCompositeMlDsakeyGenerate(pkCompositeMlDsakey: *SYMCRYPT_COMPOSITE_MLDSAKEY, flags: u32) callconv(.c) u32;
extern fn SymCryptCompositeMlDsakeyGetValue(
    pkCompositeMlDsakey: *const SYMCRYPT_COMPOSITE_MLDSAKEY,
    pbDst: [*]u8,
    cbDst: usize,
    compositeMlDsakeyFormat: u32,
    flags: u32,
) callconv(.c) u32;

extern fn scTestPqDsaCount(algName: [*:0]const u8) callconv(.c) usize;
extern fn scTestPqDsaCreate(algName: [*:0]const u8, index: usize) callconv(.c) ?*anyopaque;
extern fn scTestPqDsaFree(handle: *anyopaque) callconv(.c) void;
extern fn scTestPqDsaSetKey(
    handle: *anyopaque,
    pcKeyBlob: ?*const PQDSAKEY_TESTBLOB,
) callconv(.c) i32;
extern fn scTestPqDsaGetBlobFromKey(
    handle: *anyopaque,
    keyFormat: u32,
    pbBlob: [*]u8,
    cbBlob: usize,
) callconv(.c) i32;
extern fn scTestPqDsaSign(
    handle: *anyopaque,
    pbMessage: ?[*]const u8,
    cbMessage: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbSignature: [*]u8,
    cbSignature: usize,
    pcbResult: ?*usize,
) callconv(.c) i32;
extern fn scTestPqDsaSignExternalMu(
    handle: *anyopaque,
    pbMu: [*]const u8,
    cbMu: usize,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) i32;
extern fn scTestPqDsaSignHash(
    handle: *anyopaque,
    hashId: u32,
    pbHash: ?[*]const u8,
    cbHash: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbSignature: [*]u8,
    cbSignature: usize,
    pcbResult: ?*usize,
) callconv(.c) i32;
extern fn scTestPqDsaSignEx(
    handle: *anyopaque,
    hashId: u32,
    pbInput: ?[*]const u8,
    cbInput: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbRandom: [*]const u8,
    cbRandom: usize,
    flags: u32,
    pbSignature: [*]u8,
    cbSignature: usize,
) callconv(.c) i32;
extern fn scTestPqDsaVerify(
    handle: *anyopaque,
    pbMessage: ?[*]const u8,
    cbMessage: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
) callconv(.c) i32;
extern fn scTestPqDsaVerifyExternalMu(
    handle: *anyopaque,
    pbMu: [*]const u8,
    cbMu: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
) callconv(.c) i32;
extern fn scTestPqDsaVerifyHash(
    handle: *anyopaque,
    hashId: u32,
    pbHash: ?[*]const u8,
    cbHash: usize,
    pbContext: ?[*]const u8,
    cbContext: usize,
    pbSignature: [*]const u8,
    cbSignature: usize,
) callconv(.c) i32;

inline fn sizeofPolyElement() u32 {
    return @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT);
}

inline fn sizeofVector(nElems: u32) u32 {
    return @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (nElems * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
}

inline fn sizeofMatrix(nRows: u32, nCols: u32) u32 {
    return @sizeOf(SYMCRYPT_MLDSA_MATRIX) + (nRows * nCols * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
}

inline fn vectorElement(row: usize, pVector: *SYMCRYPT_MLDSA_VECTOR) *SYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]u8 = @ptrCast(pVector);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (row * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

inline fn vectorElementConst(row: usize, pVector: *const SYMCRYPT_MLDSA_VECTOR) *const SYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]const u8 = @ptrCast(pVector);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (row * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

inline fn matrixElement(row: usize, col: usize, pMatrix: *SYMCRYPT_MLDSA_MATRIX) *SYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]u8 = @ptrCast(pMatrix);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_MATRIX) + ((row * @as(usize, pMatrix.nCols) + col) * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

inline fn sizeofEncodedVector(pVector: *const SYMCRYPT_MLDSA_VECTOR, nBitsPerCoeff: u32) usize {
    return (@as(usize, pVector.nElems) * SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS * @as(usize, nBitsPerCoeff)) / 8;
}

inline fn mask32Lt(a: u32, b: u32) u32 {
    return @bitCast(@as(i32, @intCast((@as(i64, a) - @as(i64, b)) >> 32)));
}

inline fn symCryptMlDsaModPlusMinus(r: u32, modulus: u32) i32 {
    const halfModulus: u32 = modulus >> 1;
    const subtractionMask: u32 = mask32Lt(halfModulus, r);
    return @bitCast(r -% (modulus & subtractionMask));
}

inline fn symCryptMlDsaSignedCoefficientModQ(coefficient: i32) u32 {
    const negMask: u32 = @bitCast(coefficient >> 31);
    const coeffBits: u32 = @bitCast(coefficient);
    return coeffBits +% (SYMCRYPT_MLDSA_Q & negMask);
}

inline fn symCryptMlDsaPolyElementInfinityNorm(peSrc: *const SYMCRYPT_MLDSA_POLYELEMENT) u32 {
    var norm: u32 = 0;
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        const currSigned: i32 = symCryptMlDsaModPlusMinus(peSrc.coeffs[i], SYMCRYPT_MLDSA_Q);
        const currBits: u32 = @bitCast(currSigned);
        const negBits: u32 = @bitCast(-%currSigned);
        const negMask: u32 = @bitCast(currSigned >> 31);
        const absCurr: u32 = (currBits & ~negMask) | (negBits & negMask);
        const ltMask: u32 = mask32Lt(norm, absCurr);
        norm = (norm & ~ltMask) | (absCurr & ltMask);
    }
    return norm;
}

inline fn symCryptMlDsaDecompose(
    pParams: *const SYMCRYPT_MLDSA_INTERNAL_PARAMS,
    r: u32,
    puR1: ?*u32,
    puR0: ?*u32,
) void {
    const rdiv128: u32 = (r + 127) >> 7;
    var r1: u32 = (rdiv128 * pParams.decomposeR1Factor + (1 << 23)) >> 24;
    const mask: u32 = mask32Lt(r1, pParams.commitmentModulus);
    r1 &= mask;

    var r0: i32 = @bitCast(r -% (r1 * 2 * pParams.commitmentRoundingRange));
    const qHalf: i32 = (SYMCRYPT_MLDSA_Q - 1) >> 1;
    const subQMask: i32 = (qHalf -% r0) >> 31;
    r0 -%= subQMask & @as(i32, SYMCRYPT_MLDSA_Q);
    const r0ModQ: u32 = symCryptMlDsaSignedCoefficientModQ(r0);

    if (puR1) |p1| p1.* = r1;
    if (puR0) |p0| p0.* = r0ModQ;
}

const PqDsaMultiImp = struct {
    m_handles: std.ArrayListUnmanaged(*anyopaque) = .empty,

    pub fn init(algName: [:0]const u8) PqDsaMultiImp {
        var self = PqDsaMultiImp{};
        const count = scTestPqDsaCount(algName.ptr);
        for (0..count) |i| {
            if (scTestPqDsaCreate(algName.ptr, i)) |handle| {
                self.m_handles.append(std.heap.c_allocator, handle) catch h.fatal("Out of memory", .{});
            }
        }
        return self;
    }

    pub fn deinit(self: *PqDsaMultiImp) void {
        for (self.m_handles.items) |handle| {
            scTestPqDsaFree(handle);
        }
        self.m_handles.deinit(std.heap.c_allocator);
    }

    pub fn setKey(self: *PqDsaMultiImp, pcKeyBlob: ?*const PQDSAKEY_TESTBLOB) i32 {
        var nSuccess: usize = 0;
        for (self.m_handles.items) |handle| {
            if (scTestPqDsaSetKey(handle, pcKeyBlob) == STATUS_SUCCESS) {
                nSuccess += 1;
            }
        }
        return if (nSuccess > 0) STATUS_SUCCESS else -1;
    }

    pub fn getBlobFromKey(self: *PqDsaMultiImp, keyFormat: u32, pbBlob: [*]u8, cbBlob: usize) i32 {
        var resBlob = rm.ResultMerge.init();
        defer resBlob.deinit();

        const buf = std.heap.c_allocator.alloc(u8, cbBlob) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = STATUS_SUCCESS;
        for (self.m_handles.items, 0..) |handle, idx| {
            buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestPqDsaGetBlobFromKey(handle, keyFormat, buf.ptr, cbBlob);
            if (status != STATUS_SUCCESS) {
                return status;
            }
            resBlob.addResult(handle, buf);
        }
        resBlob.getResult(pbBlob[0..cbBlob]);
        return status;
    }

    pub fn sign(
        self: *PqDsaMultiImp,
        pbMessage: ?[*]const u8,
        cbMessage: usize,
        pbContext: ?[*]const u8,
        cbContext: usize,
        pbSignature: [*]u8,
        cbSignature: usize,
        pcbResult: ?*usize,
    ) i32 {
        var status: i32 = -1;
        for (self.m_handles.items) |handle| {
            status = scTestPqDsaSign(handle, pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature, pcbResult);
            if (status < 0) break;
        }
        return status;
    }

    pub fn signExternalMu(
        self: *PqDsaMultiImp,
        pbMu: [*]const u8,
        cbMu: usize,
        pbSignature: [*]u8,
        cbSignature: usize,
    ) i32 {
        var status: i32 = -1;
        for (self.m_handles.items) |handle| {
            status = scTestPqDsaSignExternalMu(handle, pbMu, cbMu, pbSignature, cbSignature);
            if (status < 0) break;
        }
        return status;
    }

    pub fn signHash(
        self: *PqDsaMultiImp,
        hashId: u32,
        pbHash: ?[*]const u8,
        cbHash: usize,
        pbContext: ?[*]const u8,
        cbContext: usize,
        pbSignature: [*]u8,
        cbSignature: usize,
        pcbResult: ?*usize,
    ) i32 {
        var status: i32 = -1;
        for (self.m_handles.items) |handle| {
            status = scTestPqDsaSignHash(handle, hashId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature, pcbResult);
            if (status < 0) break;
        }
        return status;
    }

    pub fn signEx(
        self: *PqDsaMultiImp,
        hashId: u32,
        pbInput: ?[*]const u8,
        cbInput: usize,
        pbContext: ?[*]const u8,
        cbContext: usize,
        pbRandom: [*]const u8,
        cbRandom: usize,
        flags: u32,
        pbSignature: [*]u8,
        cbSignature: usize,
    ) i32 {
        var resSig = rm.ResultMerge.init();
        defer resSig.deinit();

        const buf = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(buf);

        var status: i32 = -1;
        for (self.m_handles.items, 0..) |handle, idx| {
            buf[0] = @intCast((idx + 1) & 0xff);
            status = scTestPqDsaSignEx(handle, hashId, pbInput, cbInput, pbContext, cbContext, pbRandom, cbRandom, flags, buf.ptr, cbSignature);
            if (status < 0) return status;
            resSig.addResult(handle, buf);
        }
        resSig.getResult(pbSignature[0..cbSignature]);
        return status;
    }

    pub fn verify(
        self: *PqDsaMultiImp,
        pbMessage: ?[*]const u8,
        cbMessage: usize,
        pbContext: ?[*]const u8,
        cbContext: usize,
        pbSignature: [*]const u8,
        cbSignature: usize,
    ) i32 {
        var resStatus = rm.ResultMerge.init();
        defer resStatus.deinit();

        for (self.m_handles.items) |handle| {
            const st = scTestPqDsaVerify(handle, pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature);
            resStatus.addResult(handle, std.mem.asBytes(&st));
        }

        var status: i32 = -1;
        resStatus.getResult(std.mem.asBytes(&status));
        return status;
    }

    pub fn verifyExternalMu(
        self: *PqDsaMultiImp,
        pbMu: [*]const u8,
        cbMu: usize,
        pbSignature: [*]const u8,
        cbSignature: usize,
    ) i32 {
        var resStatus = rm.ResultMerge.init();
        defer resStatus.deinit();

        for (self.m_handles.items) |handle| {
            const st = scTestPqDsaVerifyExternalMu(handle, pbMu, cbMu, pbSignature, cbSignature);
            resStatus.addResult(handle, std.mem.asBytes(&st));
        }

        var status: i32 = -1;
        resStatus.getResult(std.mem.asBytes(&status));
        return status;
    }

    pub fn verifyHash(
        self: *PqDsaMultiImp,
        hashId: u32,
        pbHash: ?[*]const u8,
        cbHash: usize,
        pbContext: ?[*]const u8,
        cbContext: usize,
        pbSignature: [*]const u8,
        cbSignature: usize,
    ) i32 {
        var resStatus = rm.ResultMerge.init();
        defer resStatus.deinit();

        for (self.m_handles.items) |handle| {
            const st = scTestPqDsaVerifyHash(handle, hashId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature);
            resStatus.addResult(handle, std.mem.asBytes(&st));
        }

        var status: i32 = -1;
        resStatus.getResult(std.mem.asBytes(&status));
        return status;
    }
};

const MLDSA_ZETA_BITREV = [256]u32{
    1,       4808194, 3765607, 3761513, 5178923, 5496691, 5234739, 5178987,
    7778734, 3542485, 2682288, 2129892, 3764867, 7375178, 557458,  7159240,
    5010068, 4317364, 2663378, 6705802, 4855975, 7946292, 676590,  7044481,
    5152541, 1714295, 2453983, 1460718, 7737789, 4795319, 2815639, 2283733,
    3602218, 3182878, 2740543, 4793971, 5269599, 2101410, 3704823, 1159875,
    394148,  928749,  1095468, 4874037, 2071829, 4361428, 3241972, 2156050,
    3415069, 1759347, 7562881, 4805951, 3756790, 6444618, 6663429, 4430364,
    5483103, 3192354, 556856,  3870317, 2917338, 1853806, 3345963, 1858416,
    3073009, 1277625, 5744944, 3852015, 4183372, 5157610, 5258977, 8106357,
    2508980, 2028118, 1937570, 4564692, 2811291, 5396636, 7270901, 4158088,
    1528066, 482649,  1148858, 5418153, 7814814, 169688,  2462444, 5046034,
    4213992, 4892034, 1987814, 5183169, 1736313, 235407,  5130263, 3258457,
    5801164, 1787943, 5989328, 6125690, 3482206, 4197502, 7080401, 6018354,
    7062739, 2461387, 3035980, 621164,  3901472, 7153756, 2925816, 3374250,
    1356448, 5604662, 2683270, 5601629, 4912752, 2312838, 7727142, 7921254,
    348812,  8052569, 1011223, 6026202, 4561790, 6458164, 6143691, 1744507,
    1753,    6444997, 5720892, 6924527, 2660408, 6600190, 8321269, 2772600,
    1182243, 87208,   636927,  4415111, 4423672, 6084020, 5095502, 4663471,
    8352605, 822541,  1009365, 5926272, 6400920, 1596822, 4423473, 4620952,
    6695264, 4969849, 2678278, 4611469, 4829411, 635956,  8129971, 5925040,
    4234153, 6607829, 2192938, 6653329, 2387513, 4768667, 8111961, 5199961,
    3747250, 2296099, 1239911, 4541938, 3195676, 2642980, 1254190, 8368000,
    2998219, 141835,  8291116, 2513018, 7025525, 613238,  7070156, 6161950,
    7921677, 6458423, 4040196, 4908348, 2039144, 6500539, 7561656, 6201452,
    6757063, 2105286, 6006015, 6346610, 586241,  7200804, 527981,  5637006,
    6903432, 1994046, 2491325, 6987258, 507927,  7192532, 7655613, 6545891,
    5346675, 8041997, 2647994, 3009748, 5767564, 4148469, 749577,  4357667,
    3980599, 2569011, 6764887, 1723229, 1665318, 2028038, 1163598, 5011144,
    3994671, 8368538, 7009900, 3020393, 3363542, 214880,  545376,  7609976,
    3105558, 7277073, 508145,  7826699, 860144,  3430436, 140244,  6866265,
    6195333, 3123762, 2358373, 6187330, 5365997, 6663603, 2926054, 7987710,
    8077412, 3531229, 4405932, 4606686, 1900052, 7598542, 1054478, 7648983,
};

const MLDSA_ZETA_BITREV_NEGATIVE = [256]u32{
    8380416, 3572223, 4614810, 4618904, 3201494, 2883726, 3145678, 3201430,
    601683,  4837932, 5698129, 6250525, 4615550, 1005239, 7822959, 1221177,
    3370349, 4063053, 5717039, 1674615, 3524442, 434125,  7703827, 1335936,
    3227876, 6666122, 5926434, 6919699, 642628,  3585098, 5564778, 6096684,
    4778199, 5197539, 5639874, 3586446, 3110818, 6279007, 4675594, 7220542,
    7986269, 7451668, 7284949, 3506380, 6308588, 4018989, 5138445, 6224367,
    4965348, 6621070, 817536,  3574466, 4623627, 1935799, 1716988, 3950053,
    2897314, 5188063, 7823561, 4510100, 5463079, 6526611, 5034454, 6522001,
    5307408, 7102792, 2635473, 4528402, 4197045, 3222807, 3121440, 274060,
    5871437, 6352299, 6442847, 3815725, 5569126, 2983781, 1109516, 4222329,
    6852351, 7897768, 7231559, 2962264, 565603,  8210729, 5917973, 3334383,
    4166425, 3488383, 6392603, 3197248, 6644104, 8145010, 3250154, 5121960,
    2579253, 6592474, 2391089, 2254727, 4898211, 4182915, 1300016, 2362063,
    1317678, 5919030, 5344437, 7759253, 4478945, 1226661, 5454601, 5006167,
    7023969, 2775755, 5697147, 2778788, 3467665, 6067579, 653275,  459163,
    8031605, 327848,  7369194, 2354215, 3818627, 1922253, 2236726, 6635910,
    8378664, 1935420, 2659525, 1455890, 5720009, 1780227, 59148,   5607817,
    7198174, 8293209, 7743490, 3965306, 3956745, 2296397, 3284915, 3716946,
    27812,   7557876, 7371052, 2454145, 1979497, 6783595, 3956944, 3759465,
    1685153, 3410568, 5702139, 3768948, 3551006, 7744461, 250446,  2455377,
    4146264, 1772588, 6187479, 1727088, 5992904, 3611750, 268456,  3180456,
    4633167, 6084318, 7140506, 3838479, 5184741, 5737437, 7126227, 12417,
    5382198, 8238582, 89301,   5867399, 1354892, 7767179, 1310261, 2218467,
    458740,  1921994, 4340221, 3472069, 6341273, 1879878, 818761,  2178965,
    1623354, 6275131, 2374402, 2033807, 7794176, 1179613, 7852436, 2743411,
    1476985, 6386371, 5889092, 1393159, 7872490, 1187885, 724804,  1834526,
    3033742, 338420,  5732423, 5370669, 2612853, 4231948, 7630840, 4022750,
    4399818, 5811406, 1615530, 6657188, 6715099, 6352379, 7216819, 3369273,
    4385746, 11879,   1370517, 5360024, 5016875, 8165537, 7835041, 770441,
    5274859, 1103344, 7872272, 553718,  7520273, 4949981, 8240173, 1514152,
    2185084, 5256655, 6022044, 2193087, 3014420, 1716814, 5454363, 392707,
    303005,  4849188, 3974485, 3773731, 6480365, 781875,  7325939, 731434,
};

fn testSymCryptMlDsaPolyElementEqual(
    peA: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peB: *const SYMCRYPT_MLDSA_POLYELEMENT,
) bool {
    return std.mem.eql(u32, &peA.coeffs, &peB.coeffs);
}

fn testSymCryptMlDsaNaivePolyMul(
    peA: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peB: *const SYMCRYPT_MLDSA_POLYELEMENT,
    peResult: *SYMCRYPT_MLDSA_POLYELEMENT,
) void {
    @memset(&peResult.coeffs, 0);

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            const a: u64 = peA.coeffs[i];
            const b: u64 = peB.coeffs[j];
            const ab: u32 = @intCast((a * b) % SYMCRYPT_MLDSA_Q);

            const idx = (i + j) % SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS;
            var c: u32 = peResult.coeffs[idx];

            if (i + j < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) {
                c += ab;
            } else {
                if (ab > c) {
                    c += SYMCRYPT_MLDSA_Q - ab;
                } else {
                    c -= ab;
                }
            }

            c %= SYMCRYPT_MLDSA_Q;
            peResult.coeffs[idx] = c;
        }
    }
}

fn testSymCryptMlDsaModulo(a: i64) u32 {
    var r: i32 = @intCast(@rem(a, @as(i64, SYMCRYPT_MLDSA_Q)));
    if (r < 0) {
        r += @intCast(SYMCRYPT_MLDSA_Q);
    }
    return @intCast(r);
}

fn testSymCryptMlDsaMatrixSetElement(
    peSrc: *const SYMCRYPT_MLDSA_POLYELEMENT,
    row: usize,
    col: usize,
    pmDst: *SYMCRYPT_MLDSA_MATRIX,
) void {
    const peDst = matrixElement(row, col, pmDst);
    peDst.* = peSrc.*;
}

fn testSymCryptMlDsaPolyElementNTT(peSrc: *SYMCRYPT_MLDSA_POLYELEMENT) void {
    var k: usize = 0;
    var len: usize = 128;
    while (len >= 1) : (len /= 2) {
        var start: usize = 0;
        while (start < 256) : (start += 2 * len) {
            k += 1;
            const twiddleFactor: i64 = MLDSA_ZETA_BITREV[k];
            for (start..start + len) |j| {
                const t: u32 = testSymCryptMlDsaModulo(twiddleFactor * @as(i64, peSrc.coeffs[j + len]));
                peSrc.coeffs[j + len] = testSymCryptMlDsaModulo(@as(i64, peSrc.coeffs[j]) + SYMCRYPT_MLDSA_Q - t);
                peSrc.coeffs[j] = testSymCryptMlDsaModulo(@as(i64, peSrc.coeffs[j]) + t);
            }
        }
    }
}

fn testSymCryptMlDsaPolyElementINTT(peSrc: *SYMCRYPT_MLDSA_POLYELEMENT) void {
    var k: usize = 256;
    var len: usize = 1;
    while (len < 256) : (len *= 2) {
        var start: usize = 0;
        while (start < 256) : (start += 2 * len) {
            k -= 1;
            const twiddleFactor: i64 = MLDSA_ZETA_BITREV_NEGATIVE[k];
            for (start..start + len) |j| {
                const t: u32 = peSrc.coeffs[j];
                peSrc.coeffs[j] = testSymCryptMlDsaModulo(@as(i64, t) + peSrc.coeffs[j + len]);
                peSrc.coeffs[j + len] = testSymCryptMlDsaModulo(@as(i64, t) + SYMCRYPT_MLDSA_Q - peSrc.coeffs[j + len]);
                peSrc.coeffs[j + len] = testSymCryptMlDsaModulo(twiddleFactor * @as(i64, peSrc.coeffs[j + len]));
            }
        }
    }

    for (0..256) |j| {
        peSrc.coeffs[j] = testSymCryptMlDsaModulo(@as(i64, 8347681) * peSrc.coeffs[j]);
    }
}

fn testMlDsaPolyArithmetic() void {
    const elementCount = 9;
    const cbPolyBuf = @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT) * elementCount;
    const rawBuf = cb.SymCryptCallbackAlloc(cbPolyBuf) orelse {
        h.check(false, "SymCryptCallbackAlloc failed\n");
        unreachable;
    };
    const polyBuf: [*]u8 = @ptrCast(rawBuf);
    defer {
        SymCryptWipe(polyBuf, cbPolyBuf);
        cb.SymCryptCallbackFree(rawBuf);
    }

    var peElements: [elementCount]*SYMCRYPT_MLDSA_POLYELEMENT = undefined;
    for (0..elementCount) |i| {
        peElements[i] = SymCryptMlDsaPolyElementCreate(
            polyBuf + i * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT),
            @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT),
        ) orelse {
            h.check(false, "SymCryptMlDsaPolyElementCreate failed");
            unreachable;
        };
    }

    const peZero = peElements[0];
    const peOne = peElements[1];
    const peOneNtt = peElements[2];
    const peA = peElements[3];
    const peB = peElements[4];
    const peC = peElements[5];
    const peD = peElements[6];
    const peE = peElements[7];
    const peF = peElements[8];

    SymCryptMlDsaPolyElementSetZero(peZero);
    SymCryptMlDsaPolyElementSetZero(peOne);
    SymCryptMlDsaPolyElementSetZero(peOneNtt);

    peOne.coeffs[0] = 1;
    peOneNtt.coeffs[0] = 1;

    SymCryptMlDsaPolyElementNTT(peZero);
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        h.check(peZero.coeffs[i] == 0, "NTT(0) != 0");
    }

    SymCryptMlDsaPolyElementINTT(peZero);
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        h.check(peZero.coeffs[i] == 0, "INTT(0) != 0");
    }

    SymCryptMlDsaPolyElementNTT(peOneNtt);
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        h.check(peOneNtt.coeffs[i] == 1, "NTT({1, 0, 0, ...}) != {1, 1, 1, ...}");
    }

    peC.* = peOneNtt.*;

    SymCryptMlDsaPolyElementINTT(peC);
    h.check(peC.coeffs[0] == 1, "INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    for (1..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        h.check(peC.coeffs[i] == 0, "INTT(NTT({1, 1, 1, ...})) != {1, 0, 0, ...}");
    }

    SymCryptMlDsaPolyElementAdd(peZero, peZero, peC);
    h.check(testSymCryptMlDsaPolyElementEqual(peZero, peC), "(0 + 0) != 0");

    SymCryptMlDsaPolyElementAdd(peOne, peZero, peC);
    h.check(testSymCryptMlDsaPolyElementEqual(peOne, peC), "(1 + 0) != 1");

    SymCryptMlDsaPolyElementMulR(peOneNtt);

    SymCryptMlDsaPolyElementMontMul(peOneNtt, peOneNtt, peC);
    h.check(testSymCryptMlDsaPolyElementEqual(peOneNtt, peC), "NTT poly mul (1, 1) != 1");

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peOneNtt.coeffs[i] = SymCryptMlDsaMontReduce(peOneNtt.coeffs[i]);
        h.check(peOneNtt.coeffs[i] == 1, "Montgomery reduction of peOneNtt did not yield original value");
    }

    SymCryptMlDsaPolyElementMontMul(peOneNtt, peZero, peC);
    h.check(testSymCryptMlDsaPolyElementEqual(peZero, peC), "NTT poly mul (1, 0) != 0");

    SymCryptMlDsaPolyElementMontMul(peZero, peZero, peC);
    h.check(testSymCryptMlDsaPolyElementEqual(peZero, peC), "NTT poly mul (0, 0) != 0");

    for (0..10000) |_| {
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            peA.coeffs[j] = rng.g_rng.uint32() % SYMCRYPT_MLDSA_Q;
            peB.coeffs[j] = rng.g_rng.uint32() % SYMCRYPT_MLDSA_Q;
        }

        peD.* = peA.*;
        peE.* = peB.*;

        SymCryptMlDsaPolyElementMulR(peD);
        SymCryptMlDsaPolyElementNTT(peD);
        SymCryptMlDsaPolyElementNTT(peE);

        SymCryptMlDsaPolyElementMontMul(peD, peE, peF);
        SymCryptMlDsaPolyElementINTT(peF);

        testSymCryptMlDsaNaivePolyMul(peA, peB, peC);
        h.check(testSymCryptMlDsaPolyElementEqual(peC, peF), "Naive poly mul (A, B) != NTT poly mul (A, B)");
    }

    const loopLimit: u32 = 100;
    const offsetA: u32 = rng.g_rng.uint32() % SYMCRYPT_MLDSA_Q;
    const offsetB: u32 = rng.g_rng.uint32() % SYMCRYPT_MLDSA_Q;

    for (0..loopLimit) |i_idx| {
        const i: u32 = @intCast(i_idx);
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |k_idx| {
            const k: u32 = @intCast(k_idx);
            peA.coeffs[k_idx] = (offsetA + (i * SYMCRYPT_MLDSA_Q / loopLimit) + k) % SYMCRYPT_MLDSA_Q;
        }

        SymCryptMlDsaPolyElementAdd(peA, peZero, peC);
        h.check(testSymCryptMlDsaPolyElementEqual(peA, peC), "(A + 0) != A");

        SymCryptMlDsaPolyElementAdd(peZero, peA, peC);
        h.check(testSymCryptMlDsaPolyElementEqual(peA, peC), "(0 + A) != A");

        peD.* = peA.*;
        peE.* = peA.*;

        SymCryptMlDsaPolyElementNTT(peD);
        testSymCryptMlDsaPolyElementNTT(peE);
        h.check(testSymCryptMlDsaPolyElementEqual(peD, peE), "Naive NTT(A) != NTT(A)");

        peF.* = peD.*;

        SymCryptMlDsaPolyElementINTT(peF);
        testSymCryptMlDsaPolyElementINTT(peE);
        h.check(testSymCryptMlDsaPolyElementEqual(peF, peE), "Naive INTT(Naive NTT(A)) != INTT(NTT(A))");
        h.check(testSymCryptMlDsaPolyElementEqual(peA, peF), "INTT(NTT(A)) != A");

        peF.* = peD.*;
        SymCryptMlDsaPolyElementMulR(peF);
        SymCryptMlDsaPolyElementMontMul(peF, peZero, peF);
        h.check(testSymCryptMlDsaPolyElementEqual(peZero, peF), "INTT((NTT(A) * R) * 0 ./ R) != 0");

        peF.* = peD.*;
        SymCryptMlDsaPolyElementMulR(peF);
        SymCryptMlDsaPolyElementMontMul(peF, peOneNtt, peC);
        h.check(testSymCryptMlDsaPolyElementEqual(peC, peD), "(NTT(A) * R) * 1)  != NTT(A)");

        for (0..loopLimit) |j_idx| {
            const j: u32 = @intCast(j_idx);
            for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |k_idx| {
                const k: u32 = @intCast(k_idx);
                peB.coeffs[k_idx] = (offsetB + (j * SYMCRYPT_MLDSA_Q / loopLimit) + 3 * k) % SYMCRYPT_MLDSA_Q;
            }

            SymCryptMlDsaPolyElementAdd(peA, peB, peC);
            SymCryptMlDsaPolyElementAdd(peB, peA, peD);
            h.check(testSymCryptMlDsaPolyElementEqual(peC, peD), "A + B != B + A");

            peD.* = peA.*;
            peE.* = peB.*;

            SymCryptMlDsaPolyElementNTT(peD);
            SymCryptMlDsaPolyElementNTT(peE);

            SymCryptMlDsaPolyElementAdd(peD, peE, peF);
            SymCryptMlDsaPolyElementINTT(peF);
            h.check(testSymCryptMlDsaPolyElementEqual(peC, peF), "INTT(NTT(A) + NTT(B)) != A + B");

            SymCryptMlDsaPolyElementMulR(peD);
            SymCryptMlDsaPolyElementMontMul(peD, peE, peF);
            SymCryptMlDsaPolyElementINTT(peF);

            testSymCryptMlDsaNaivePolyMul(peA, peB, peC);
            h.check(testSymCryptMlDsaPolyElementEqual(peC, peF), "Naive poly mul (A, B) != NTT poly mul (A, B)");
        }
    }
}

fn testMlDsaMatrixVectorArithmetic() void {
    const pParams = &SymCryptMlDsaInternalParams44;

    const polyCount = 5;
    const cbPolyBuf: usize = @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT) * polyCount;
    const rawPolyBuf = cb.SymCryptCallbackAlloc(cbPolyBuf) orelse {
        h.check(false, "SymCryptCallbackAlloc failed\n");
        unreachable;
    };
    const polyBuf: [*]u8 = @ptrCast(rawPolyBuf);
    defer {
        SymCryptWipe(polyBuf, cbPolyBuf);
        cb.SymCryptCallbackFree(rawPolyBuf);
    }

    var peElements: [polyCount]*SYMCRYPT_MLDSA_POLYELEMENT = undefined;
    for (0..polyCount) |i| {
        peElements[i] = SymCryptMlDsaPolyElementCreate(
            polyBuf + i * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT),
            @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT),
        ) orelse {
            h.check(false, "SymCryptMlDsaPolyElementCreate failed");
            unreachable;
        };
    }

    const peZero = peElements[0];
    const peOne = peElements[1];
    const peOneNttTimesR = peElements[2];
    const peSrc = peElements[3];

    SymCryptMlDsaPolyElementSetZero(peZero);
    SymCryptMlDsaPolyElementSetZero(peOne);
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peOne.coeffs[i] = 1;
    }

    SymCryptMlDsaPolyElementSetZero(peOneNttTimesR);
    peOneNttTimesR.coeffs[0] = 1;
    SymCryptMlDsaPolyElementNTT(peOneNttTimesR);
    SymCryptMlDsaPolyElementMulR(peOneNttTimesR);

    const vectorCount = 4;
    const cbVectorBuf: usize = @as(usize, pParams.cbRowVector) * vectorCount;
    const rawVecBuf = cb.SymCryptCallbackAlloc(cbVectorBuf) orelse {
        h.check(false, "SymCryptCallbackAlloc failed\n");
        unreachable;
    };
    const vectorBuf: [*]u8 = @ptrCast(rawVecBuf);
    defer {
        SymCryptWipe(vectorBuf, cbVectorBuf);
        cb.SymCryptCallbackFree(rawVecBuf);
    }

    var pvVectors: [vectorCount]*SYMCRYPT_MLDSA_VECTOR = undefined;
    for (0..vectorCount) |i| {
        pvVectors[i] = SymCryptMlDsaVectorCreate(
            vectorBuf + i * pParams.cbRowVector,
            pParams.cbRowVector,
            pParams.nRows,
        ) orelse {
            h.check(false, "SymCryptMlDsaVectorCreate failed");
            unreachable;
        };
    }

    const pvZero = pvVectors[0];
    const pvOne = pvVectors[1];
    const pvDst = pvVectors[3];

    SymCryptMlDsaVectorSetZero(pvZero);
    SymCryptMlDsaVectorSetZero(pvOne);

    for (0..4) |i| {
        const peTmp = vectorElement(i, pvOne);
        peTmp.* = peOneNttTimesR.*;
    }

    const cbMatrixBuf: usize = pParams.cbMatrix;
    const rawMatBuf = cb.SymCryptCallbackAlloc(cbMatrixBuf) orelse {
        h.check(false, "SymCryptCallbackAlloc failed\n");
        unreachable;
    };
    const matrixBuf: [*]u8 = @ptrCast(rawMatBuf);
    defer {
        SymCryptWipe(matrixBuf, cbMatrixBuf);
        cb.SymCryptCallbackFree(rawMatBuf);
    }

    SymCryptWipe(matrixBuf, cbMatrixBuf);

    const pmMatrix = SymCryptMlDsaMatrixCreate(
        matrixBuf,
        pParams.cbMatrix,
        pParams.nRows,
        pParams.nCols,
    ) orelse {
        h.check(false, "SymCryptMlDsaMatrixCreate failed");
        unreachable;
    };

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvZero, pvDst, peSrc);
    for (0..4) |i| {
        h.check(testSymCryptMlDsaPolyElementEqual(vectorElement(i, pvDst), peZero), "0 matrix * 0 vector != 0 vector");
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvOne, pvDst, peSrc);
    for (0..4) |i| {
        h.check(testSymCryptMlDsaPolyElementEqual(vectorElement(i, pvDst), peZero), "0 matrix * 1 vector != 0 vector");
    }

    for (0..4) |i| {
        testSymCryptMlDsaMatrixSetElement(peOneNttTimesR, i, i, pmMatrix);
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvZero, pvDst, peSrc);
    for (0..4) |i| {
        h.check(testSymCryptMlDsaPolyElementEqual(vectorElement(i, pvDst), peZero), "I matrix * 0 vector != 0 vector");
    }

    SymCryptMlDsaMatrixVectorMontMul(pmMatrix, pvOne, pvDst, peSrc);
    for (0..4) |i| {
        h.check(testSymCryptMlDsaPolyElementEqual(vectorElement(i, pvDst), peOneNttTimesR), "I matrix * 1 vector != 1 vector");
    }
}

fn testMlDsaRandom() void {
    var status: i32 = STATUS_SUCCESS;
    var scError: u32 = SYMCRYPT_NO_ERROR;

    var mlDsaImp = PqDsaMultiImp.init("MlDsa");
    defer mlDsaImp.deinit();

    var keyBlob: PQDSAKEY_TESTBLOB = .{ .mlDsakey = .{} };
    var pKeyBlob = &keyBlob.mlDsakey;
    var pKey: ?*SYMCRYPT_MLDSAKEY = null;

    const message = std.heap.c_allocator.alloc(u8, 64) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(message);
    const context = std.heap.c_allocator.alloc(u8, 32) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(context);
    const mu = std.heap.c_allocator.alloc(u8, SYMCRYPT_SHAKE256_RESULT_SIZE) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(mu);
    const hash = std.heap.c_allocator.alloc(u8, SYMCRYPT_SHA512_RESULT_SIZE) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(hash);

    var pubKeyHash: [SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE]u8 = undefined;

    for (0..message.len) |i| message[i] = rng.g_rng.byte();
    for (0..context.len) |i| context[i] = rng.g_rng.byte();

    const rgParams = [_]*const SYMCRYPT_MLDSA_INTERNAL_PARAMS{
        &SymCryptMlDsaInternalParams44,
        &SymCryptMlDsaInternalParams65,
        &SymCryptMlDsaInternalParams87,
    };

    for (rgParams) |pParams| {
        const signature = std.heap.c_allocator.alloc(u8, pParams.cbEncodedSignature) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(signature);
        const muSignature = std.heap.c_allocator.alloc(u8, pParams.cbEncodedSignature) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(muSignature);
        const hashSignature = std.heap.c_allocator.alloc(u8, pParams.cbEncodedSignature) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(hashSignature);
        const pubKeyBlob = std.heap.c_allocator.alloc(u8, pParams.cbEncodedPublicKey) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(pubKeyBlob);
        const privKeyBlob = std.heap.c_allocator.alloc(u8, pParams.cbEncodedPrivateKey) catch h.fatal("Out of memory", .{});
        defer std.heap.c_allocator.free(privKeyBlob);

        for (0..100) |_| {
            pKeyBlob.params = pParams.params;
            pKeyBlob.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
            pKeyBlob.cbKeyBlob = SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE;
            for (0..pKeyBlob.cbKeyBlob) |k| {
                pKeyBlob.abKeyBlob[k] = rng.g_rng.byte();
            }

            status = mlDsaImp.setKey(&keyBlob);
            h.check(status >= 0, "Failed to set key with random seed");

            status = mlDsaImp.getBlobFromKey(SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, privKeyBlob.ptr, privKeyBlob.len);
            h.check(status >= 0, "Failed to get private key");

            status = mlDsaImp.getBlobFromKey(SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, pubKeyBlob.ptr, pubKeyBlob.len);
            h.check(status >= 0, "Failed to get public key");

            SymCryptShake256(pubKeyBlob.ptr, pubKeyBlob.len, &pubKeyHash, pubKeyHash.len);

            const muInputSize = SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE + 2 + context.len + message.len;
            const muInput = std.heap.c_allocator.alloc(u8, muInputSize) catch h.fatal("Out of memory", .{});
            defer std.heap.c_allocator.free(muInput);

            @memcpy(muInput[0..SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE], &pubKeyHash);
            muInput[SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE] = 0;
            muInput[SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE + 1] = @intCast(context.len);
            @memcpy(muInput[SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE + 2 .. SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE + 2 + context.len], context);
            @memcpy(muInput[SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE + 2 + context.len ..], message);

            SymCryptShake256(muInput.ptr, muInput.len, mu.ptr, mu.len);
            SymCryptSha512(message.ptr, message.len, hash.ptr);

            pKey = SymCryptMlDsakeyAllocate(pParams.params);
            h.check(pKey != null, "Failed to allocate key");

            scError = SymCryptMlDsakeySetValue(
                &pKeyBlob.abKeyBlob,
                pKeyBlob.cbKeyBlob,
                pKeyBlob.format,
                0,
                pKey.?,
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set key");

            scError = SymCryptMlDsakeySetValue(
                pubKeyBlob.ptr,
                pubKeyBlob.len,
                SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY,
                0,
                pKey.?,
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set public key");

            scError = SymCryptMlDsakeyGetValue(
                pKey.?,
                privKeyBlob.ptr,
                privKeyBlob.len,
                SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
                0,
            );
            h.check(scError == SYMCRYPT_INCOMPATIBLE_FORMAT, "Successfully exported private key from public key?");

            scError = SymCryptMlDsakeyGetValue(
                pKey.?,
                &pKeyBlob.abKeyBlob,
                pKeyBlob.cbKeyBlob,
                SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
            );
            h.check(scError == SYMCRYPT_INCOMPATIBLE_FORMAT, "Successfully exported seed from public key?");

            scError = SymCryptMlDsakeySetValue(
                privKeyBlob.ptr,
                privKeyBlob.len,
                SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
                0,
                pKey.?,
            );
            h.check(scError == SYMCRYPT_NO_ERROR, "Failed to set private key");

            scError = SymCryptMlDsakeyGetValue(
                pKey.?,
                &pKeyBlob.abKeyBlob,
                pKeyBlob.cbKeyBlob,
                SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED,
                0,
            );
            h.check(scError == SYMCRYPT_INCOMPATIBLE_FORMAT, "Successfully exported seed from private key?");

            SymCryptMlDsakeyFree(pKey.?);
            pKey = null;

            status = mlDsaImp.sign(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
                null,
            );
            h.check(status >= 0, "Failed to sign");

            status = mlDsaImp.signExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to sign External Mu");

            status = mlDsaImp.signHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
                null,
            );
            h.check(status >= 0, "Failed to sign hash");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status >= 0, "Failed to verify with full key from seed");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with full key from seed via regular verify");

            status = mlDsaImp.verifyExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with full key from seed");

            status = mlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
            );
            h.check(status >= 0, "Failed to verify hash with full key from seed");

            pKeyBlob.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
            pKeyBlob.cbKeyBlob = privKeyBlob.len;
            @memcpy(pKeyBlob.abKeyBlob[0..privKeyBlob.len], privKeyBlob);

            status = mlDsaImp.setKey(&keyBlob);
            h.check(status >= 0, "Failed to set private key");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status >= 0, "Failed to verify with private key");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with private key via regular verify");

            status = mlDsaImp.verifyExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with private key");

            status = mlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
            );
            h.check(status >= 0, "Failed to verify hash with private key");

            status = mlDsaImp.sign(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
                null,
            );
            h.check(status >= 0, "Failed to sign with private key");

            status = mlDsaImp.signExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to sign External Mu with private key");

            status = mlDsaImp.signHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
                null,
            );
            h.check(status >= 0, "Failed to sign hash with private key");

            pKeyBlob.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
            pKeyBlob.cbKeyBlob = pubKeyBlob.len;
            @memcpy(pKeyBlob.abKeyBlob[0..pubKeyBlob.len], pubKeyBlob);

            status = mlDsaImp.setKey(&keyBlob);
            h.check(status >= 0, "Failed to set public key");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status >= 0, "Failed to verify with public key");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with public key via regular verify");

            status = mlDsaImp.verifyExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status >= 0, "Failed to verify External Mu signature with public key");

            status = mlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
            );
            h.check(status >= 0, "Failed to verify hash with public key");

            const t = rng.g_rng.uint32();
            const bit: u8 = @as(u8, 1) << @intCast(t % 8);
            signature[(t / 8) % signature.len] ^= bit;
            muSignature[(t / 8) % muSignature.len] ^= bit;
            hashSignature[(t / 8) % hashSignature.len] ^= bit;

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered signature verified successfully?");

            status = mlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered External Mu signature verified successfully?");

            status = mlDsaImp.verifyExternalMu(
                mu.ptr,
                mu.len,
                muSignature.ptr,
                muSignature.len,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered External Mu signature verified successfully?");

            status = mlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_SHA512,
                hash.ptr,
                hash.len,
                context.ptr,
                context.len,
                hashSignature.ptr,
                hashSignature.len,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered hash signature verified successfully?");
        }
    }

    status = mlDsaImp.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testMlDsaNegative() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    const pParams = &SymCryptMlDsaInternalParams44;
    const privateKeyBlob = std.heap.c_allocator.alloc(u8, pParams.cbEncodedPrivateKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(privateKeyBlob);
    const signature = std.heap.c_allocator.alloc(u8, pParams.cbEncodedSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);

    const pKey = SymCryptMlDsakeyAllocate(SYMCRYPT_MLDSA_PARAMS_MLDSA44);
    h.check(pKey != null, "Failed to allocate key");
    defer SymCryptMlDsakeyFree(pKey.?);

    scError = SymCryptMlDsakeyGenerate(pKey.?, 0);
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate key");

    scError = SymCryptMlDsaSign(
        pKey.?,
        null,
        0,
        null,
        0,
        0,
        signature.ptr,
        signature.len,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to sign");

    const badInfinityNorm: u32 = @as(u32, pParams.nChallengeNonZeroCoeffs) * pParams.privateKeyRange;
    const commitOffset: usize = pParams.cbCommitmentHash;
    var newVal = std.mem.readInt(u32, signature[commitOffset..][0..4], .little);
    const maskShift: u5 = @intCast(pParams.maskCoefficientRangeLog2 + 1);
    newVal &= ~((@as(u32, 1) << maskShift) - 1);
    newVal |= badInfinityNorm;
    std.mem.writeInt(u32, signature[commitOffset..][0..4], newVal, .little);

    scError = SymCryptMlDsaVerify(
        pKey.?,
        null,
        0,
        null,
        0,
        signature.ptr,
        signature.len,
        0,
    );
    h.check(scError == SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE, "Invalid signature verified successfully");

    scError = SymCryptMlDsakeyGetValue(
        pKey.?,
        privateKeyBlob.ptr,
        privateKeyBlob.len,
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
        0,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get private key");

    const offset: usize =
        SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE +
        SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE +
        SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE +
        (rng.g_rng.uint32() % (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS * 3));

    privateKeyBlob[offset] = 0xFF;

    scError = SymCryptMlDsakeySetValue(
        privateKeyBlob.ptr,
        privateKeyBlob.len,
        SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY,
        0,
        pKey.?,
    );
    h.check(scError == SYMCRYPT_INVALID_BLOB, "Imported invalid private key");
}

fn testMlDsaKeyGen(
    pPqDsaImplementation: *PqDsaMultiImp,
    params: u32,
    katSeed: []const u8,
    katPubKey: []const u8,
    katPrivKey: []const u8,
    line: i64,
) void {
    var status: i32 = STATUS_SUCCESS;
    var keyBlob: PQDSAKEY_TESTBLOB = .{ .mlDsakey = .{} };
    var cbPubKey: usize = 0;
    var cbPrivKey: usize = 0;

    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size",
    );
    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size",
    );

    h.check4(katSeed.len == SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE, "Invalid seed size {d} at line {d}", katSeed.len, line);
    h.check4(katPubKey.len == cbPubKey, "Invalid public key size {d} at line {d}", katPubKey.len, line);
    h.check4(katPrivKey.len == cbPrivKey, "Invalid private key size {d} at line {d}", katPrivKey.len, line);

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED;
    keyBlob.mlDsakey.cbKeyBlob = katSeed.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katSeed.len], katSeed);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set key at line {d}", line);

    const pubKey = std.heap.c_allocator.alloc(u8, cbPubKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubKey);
    const privKey = std.heap.c_allocator.alloc(u8, cbPrivKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(privKey);

    status = pPqDsaImplementation.getBlobFromKey(SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, pubKey.ptr, cbPubKey);
    h.check3(status >= 0, "Failed to get public key at line {d}", line);
    h.check3(std.mem.eql(u8, pubKey, katPubKey), "Public key mismatch at line {d}", line);

    status = pPqDsaImplementation.getBlobFromKey(SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, privKey.ptr, cbPrivKey);
    h.check3(status >= 0, "Failed to get private key at line {d}", line);
    h.check3(std.mem.eql(u8, privKey, katPrivKey), "Private key mismatch at line {d}", line);

    status = pPqDsaImplementation.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testMlDsaSignVerify(
    pPqDsaImplementation: *PqDsaMultiImp,
    params: u32,
    katRnd: []const u8,
    katPrivKey: []const u8,
    katPubKey: []const u8,
    katMsg: []const u8,
    katSig: []const u8,
    katCtx: []const u8,
    line: i64,
) void {
    var status: i32 = STATUS_SUCCESS;
    var keyBlob: PQDSAKEY_TESTBLOB = .{ .mlDsakey = .{} };
    var cbPrivKey: usize = 0;
    var cbPubKey: usize = 0;
    var cbSig: usize = 0;

    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size",
    );
    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size",
    );
    h.check(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size",
    );

    h.check4(katPrivKey.len == cbPrivKey, "Invalid private key size {d} at line {d}", katPrivKey.len, line);
    h.check4(katPubKey.len == cbPubKey, "Invalid public key size {d} at line {d}", katPubKey.len, line);
    h.check4(katRnd.len == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size {d} at line {d}", katRnd.len, line);
    h.check4(katCtx.len <= SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH, "Invalid context size {d} at line {d}", katCtx.len, line);
    h.check4(katSig.len == cbSig, "Invalid signature size {d} at line {d}", katSig.len, line);

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPrivKey.len], katPrivKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set private key at line {d}", line);

    const signature = std.heap.c_allocator.alloc(u8, cbSig) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);

    status = pPqDsaImplementation.signEx(
        SYMCRYPT_PQDSA_HASH_ID_NULL,
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        katRnd.ptr,
        katRnd.len,
        0,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Signing failed at line {d}", line);
    h.check3(std.mem.eql(u8, signature, katSig), "Signature mismatch at line {d}", line);

    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPubKey.len], katPubKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set public key at line {d}", line);

    status = pPqDsaImplementation.verify(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Verification failed at line {d}", line);

    status = pPqDsaImplementation.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testExternalMuMlDsaSignVerify(
    pPqDsaImplementation: *PqDsaMultiImp,
    params: u32,
    katRnd: []const u8,
    katPrivKey: []const u8,
    katPubKey: []const u8,
    katMu: []const u8,
    katSig: []const u8,
    line: i64,
) void {
    var status: i32 = STATUS_SUCCESS;
    var keyBlob: PQDSAKEY_TESTBLOB = .{ .mlDsakey = .{} };
    var cbPrivKey: usize = 0;
    var cbPubKey: usize = 0;
    var cbSig: usize = 0;

    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size",
    );
    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size",
    );
    h.check(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size",
    );

    h.check4(katPrivKey.len == cbPrivKey, "Invalid private key size {d} at line {d}", katPrivKey.len, line);
    h.check4(katPubKey.len == cbPubKey, "Invalid public key size {d} at line {d}", katPubKey.len, line);
    h.check4(katRnd.len == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size {d} at line {d}", katRnd.len, line);
    h.check4(katMu.len == SYMCRYPT_SHAKE256_RESULT_SIZE, "Invalid mu size {d} at line {d}", katMu.len, line);
    h.check4(katSig.len == cbSig, "Invalid signature size {d} at line {d}", katSig.len, line);

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPrivKey.len], katPrivKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set private key at line {d}", line);

    const signature = std.heap.c_allocator.alloc(u8, cbSig) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);

    status = pPqDsaImplementation.signEx(
        SYMCRYPT_PQDSA_HASH_ID_NULL,
        katMu.ptr,
        katMu.len,
        null,
        0,
        katRnd.ptr,
        katRnd.len,
        SYMCRYPT_FLAG_MLDSA_EXTERNALMU,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Signing failed at line {d}", line);
    h.check3(std.mem.eql(u8, signature, katSig), "Signature mismatch at line {d}", line);

    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPubKey.len], katPubKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set public key at line {d}", line);

    status = pPqDsaImplementation.verifyExternalMu(
        katMu.ptr,
        katMu.len,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Verification failed at line {d}", line);

    status = pPqDsaImplementation.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testHashMlDsaSignVerify(
    pPqDsaImplementation: *PqDsaMultiImp,
    params: u32,
    katRnd: []const u8,
    katPrivKey: []const u8,
    katPubKey: []const u8,
    katHash: []const u8,
    katHashAlg: []const u8,
    katSig: []const u8,
    katCtx: []const u8,
    line: i64,
) void {
    var status: i32 = STATUS_SUCCESS;
    var keyBlob: PQDSAKEY_TESTBLOB = .{ .mlDsakey = .{} };
    var cbPrivKey: usize = 0;
    var cbPubKey: usize = 0;
    var cbSig: usize = 0;
    var hashId: u32 = SYMCRYPT_PQDSA_HASH_ID_NULL;

    const HashAlgEntry = struct {
        name: []const u8,
        id: u32,
    };
    const hashAlgs = [_]HashAlgEntry{
        .{ .name = "sha224", .id = SYMCRYPT_PQDSA_HASH_ID_SHA224 },
        .{ .name = "sha256", .id = SYMCRYPT_PQDSA_HASH_ID_SHA256 },
        .{ .name = "sha384", .id = SYMCRYPT_PQDSA_HASH_ID_SHA384 },
        .{ .name = "sha512", .id = SYMCRYPT_PQDSA_HASH_ID_SHA512 },
        .{ .name = "sha512_224", .id = SYMCRYPT_PQDSA_HASH_ID_SHA512_224 },
        .{ .name = "sha512_256", .id = SYMCRYPT_PQDSA_HASH_ID_SHA512_256 },
        .{ .name = "sha3_224", .id = SYMCRYPT_PQDSA_HASH_ID_SHA3_224 },
        .{ .name = "sha3_256", .id = SYMCRYPT_PQDSA_HASH_ID_SHA3_256 },
        .{ .name = "sha3_384", .id = SYMCRYPT_PQDSA_HASH_ID_SHA3_384 },
        .{ .name = "sha3_512", .id = SYMCRYPT_PQDSA_HASH_ID_SHA3_512 },
        .{ .name = "shake_128", .id = SYMCRYPT_PQDSA_HASH_ID_SHAKE128 },
        .{ .name = "shake_256", .id = SYMCRYPT_PQDSA_HASH_ID_SHAKE256 },
    };

    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size",
    );
    h.check(
        SymCryptMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size",
    );
    h.check(
        SymCryptMlDsaSizeofSignatureFromParams(params, &cbSig) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size",
    );

    h.check4(katPrivKey.len == cbPrivKey, "Invalid private key size {d} at line {d}", katPrivKey.len, line);
    h.check4(katPubKey.len == cbPubKey, "Invalid public key size {d} at line {d}", katPubKey.len, line);
    h.check4(katRnd.len == SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE, "Invalid random size {d} at line {d}", katRnd.len, line);
    h.check4(katCtx.len <= SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH, "Invalid context size {d} at line {d}", katCtx.len, line);
    h.check4(katSig.len == cbSig, "Invalid signature size {d} at line {d}", katSig.len, line);

    for (hashAlgs) |ha| {
        if (std.mem.eql(u8, katHashAlg, ha.name)) {
            hashId = ha.id;
            break;
        }
    }
    h.check4(hashId != SYMCRYPT_PQDSA_HASH_ID_NULL, "Unknown hash algorithm {s} at line {d}", katHashAlg, line);

    keyBlob.mlDsakey.params = params;
    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPrivKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPrivKey.len], katPrivKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set private key at line {d}", line);

    const signature = std.heap.c_allocator.alloc(u8, cbSig) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);

    status = pPqDsaImplementation.signEx(
        hashId,
        if (katHash.len > 0) katHash.ptr else null,
        katHash.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        katRnd.ptr,
        katRnd.len,
        0,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Signing failed at line {d}", line);
    h.check3(std.mem.eql(u8, signature, katSig), "Signature mismatch at line {d}", line);

    keyBlob.mlDsakey.format = SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY;
    keyBlob.mlDsakey.cbKeyBlob = katPubKey.len;
    @memcpy(keyBlob.mlDsakey.abKeyBlob[0..katPubKey.len], katPubKey);

    status = pPqDsaImplementation.setKey(&keyBlob);
    h.check3(status >= 0, "Failed to set public key at line {d}", line);

    status = pPqDsaImplementation.verifyHash(
        hashId,
        if (katHash.len > 0) katHash.ptr else null,
        katHash.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Verification failed at line {d}", line);

    status = pPqDsaImplementation.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testMlDsaKats() void {
    var katReader = kat.ZigKatReader.init("kat_pqdsa.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "";
    var params: u32 = SYMCRYPT_MLDSA_PARAMS_NULL;
    var cKeyGen: u32 = 0;
    var cSignReg: u32 = 0;
    var cSignMu: u32 = 0;
    var cSignHash: u32 = 0;

    var pqDsaMultiImp = PqDsaMultiImp.init("MlDsa");
    defer pqDsaMultiImp.deinit();

    while (true) {
        katReader.getKatItem(&katItem);
        const line = katItem.line;

        if (katItem.type == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
            sep = ", ";

            var bParamsFound = false;
            for (rgTestMlDsaParams) |tp| {
                if (std.mem.eql(u8, katItem.categoryName, tp.pszParamsName)) {
                    params = tp.params;
                    bParamsFound = true;
                    break;
                }
            }
            h.check3(bParamsFound, "PQDSA header at line {d} specifies unknown ML-DSA params!", line);
        }

        if (katItem.type == kat.KAT_TYPE_DATASET) {
            if (katItem.isFieldPresent("seed")) {
                h.check3(katItem.dataItems.items.len == 3, "Wrong number of items in ML-DSA KeyGen record at line {d}", line);

                const katSeed = katItem.parseData("seed");
                defer std.heap.c_allocator.free(katSeed);
                const katPubKey = katItem.parseData("pk");
                defer std.heap.c_allocator.free(katPubKey);
                const katPrivKey = katItem.parseData("sk");
                defer std.heap.c_allocator.free(katPrivKey);

                testMlDsaKeyGen(&pqDsaMultiImp, params, katSeed, katPubKey, katPrivKey, line);
                cKeyGen += 1;
                continue;
            } else if (katItem.isFieldPresent("mu")) {
                h.check3(katItem.dataItems.items.len == 5, "Wrong number of items in External Mu ML-DSA Sign/Verify record at line {d}", line);

                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                const katPubKey = katItem.parseData("pk");
                defer std.heap.c_allocator.free(katPubKey);
                const katPrivKey = katItem.parseData("sk");
                defer std.heap.c_allocator.free(katPrivKey);
                const katMu = katItem.parseData("mu");
                defer std.heap.c_allocator.free(katMu);
                const katSig = katItem.parseData("sig");
                defer std.heap.c_allocator.free(katSig);

                testExternalMuMlDsaSignVerify(&pqDsaMultiImp, params, katRnd, katPrivKey, katPubKey, katMu, katSig, line);
                cSignMu += 1;
                continue;
            } else if (katItem.isFieldPresent("hash")) {
                h.check3(
                    katItem.dataItems.items.len == 6 or katItem.dataItems.items.len == 7,
                    "Wrong number of items in HashML-DSA Sign/Verify record at line {d}",
                    line,
                );

                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                const katPubKey = katItem.parseData("pk");
                defer std.heap.c_allocator.free(katPubKey);
                const katPrivKey = katItem.parseData("sk");
                defer std.heap.c_allocator.free(katPrivKey);
                const katHash = katItem.parseData("hash");
                defer std.heap.c_allocator.free(katHash);
                const katHashAlg = katItem.parseData("hashalg");
                defer std.heap.c_allocator.free(katHashAlg);
                const katSig = katItem.parseData("sig");
                defer std.heap.c_allocator.free(katSig);

                var katCtx: ?[]u8 = null;
                defer if (katCtx) |c| std.heap.c_allocator.free(c);
                if (katItem.isFieldPresent("ctx")) {
                    katCtx = katItem.parseData("ctx");
                }

                testHashMlDsaSignVerify(&pqDsaMultiImp, params, katRnd, katPrivKey, katPubKey, katHash, katHashAlg, katSig, katCtx orelse &.{}, line);
                cSignHash += 1;
                continue;
            } else if (katItem.isFieldPresent("rnd")) {
                h.check3(
                    katItem.dataItems.items.len == 5 or katItem.dataItems.items.len == 6,
                    "Wrong number of items in ML-DSA Sign/Verify record at line {d}",
                    line,
                );

                const katRnd = katItem.parseData("rnd");
                defer std.heap.c_allocator.free(katRnd);
                const katPubKey = katItem.parseData("pk");
                defer std.heap.c_allocator.free(katPubKey);
                const katPrivKey = katItem.parseData("sk");
                defer std.heap.c_allocator.free(katPrivKey);
                const katMsg = katItem.parseData("msg");
                defer std.heap.c_allocator.free(katMsg);
                const katSig = katItem.parseData("sig");
                defer std.heap.c_allocator.free(katSig);

                var katCtx: ?[]u8 = null;
                defer if (katCtx) |c| std.heap.c_allocator.free(c);
                if (katItem.isFieldPresent("ctx")) {
                    katCtx = katItem.parseData("ctx");
                }

                testMlDsaSignVerify(&pqDsaMultiImp, params, katRnd, katPrivKey, katPubKey, katMsg, katSig, katCtx orelse &.{}, line);
                cSignReg += 1;
                continue;
            }

            h.fatal("Unknown data record at line {d}", .{line});
        }
    }

    h.ziprint("\n        Total samples: {d} KeyGen, {d} Sign, {d} SignExternalMu, {d} SignHash\n", .{ cKeyGen, cSignReg, cSignMu, cSignHash });
}

fn testPqDsaMlDsa() void {
    var nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak {d} outstanding", nOutstandingAllocs);

    if (!h.isAlgorithmPresent("MlDsa", 1)) {
        return;
    }

    h.ziprint("    ML-DSA arithmetic\n", .{});
    testMlDsaPolyArithmetic();
    testMlDsaMatrixVectorArithmetic();

    h.ziprint("    ML-DSA\n", .{});
    testMlDsaRandom();
    testMlDsaNegative();
    testMlDsaKats();

    nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak, {d} outstanding", nOutstandingAllocs);
}

fn testPqDsaCompositeMlDsaFunctionalDo(
    pCompositeMlDsaImp: *PqDsaMultiImp,
    testParams: SYMCRYPT_TEST_COMPOSITE_MLDSA_PARAMS,
) void {
    var status: i32 = STATUS_SUCCESS;
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var keyBlob: PQDSAKEY_TESTBLOB = .{ .compositeMlDsakey = .{} };
    var pKeyBlob = &keyBlob.compositeMlDsakey;

    var cbPrivateKey: usize = 0;
    var cbPublicKey: usize = 0;
    var cbSignature: usize = 0;
    var cbSignatureResult: usize = 0;
    var cbPreHashSignatureResult: usize = 0;
    var cbMessageHash: usize = 0;
    var pHashAlgorithm: ?*const anyopaque = null;

    switch (testParams.params) {
        SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA44_ECDSA_P256_SHA256 => {
            cbMessageHash = 32;
            pHashAlgorithm = SymCryptSha256Algorithm;
        },
        SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P256_SHA512,
        SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA65_ECDSA_P384_SHA512,
        SYMCRYPT_COMPOSITE_MLDSA_PARAMS_MLDSA87_ECDSA_P384_SHA512,
        => {
            cbMessageHash = 64;
            pHashAlgorithm = SymCryptSha512Algorithm;
        },
        else => h.check(false, "Invalid Composite ML-DSA params"),
    }

    scError = SymCryptCompositeMlDsaSizeofKeyFormatFromParams(
        testParams.params,
        SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
        &cbPrivateKey,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get private key size");

    scError = SymCryptCompositeMlDsaSizeofKeyFormatFromParams(
        testParams.params,
        SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY,
        &cbPublicKey,
    );
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get public key size");

    scError = SymCryptCompositeMlDsaSizeofSignatureFromParams(testParams.params, &cbSignature);
    h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get signature size");

    const message = std.heap.c_allocator.alloc(u8, 64) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(message);
    const messageHash = std.heap.c_allocator.alloc(u8, cbMessageHash) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(messageHash);
    const context = std.heap.c_allocator.alloc(u8, 32) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(context);

    const privKeyBuf = std.heap.c_allocator.alloc(u8, cbPrivateKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(privKeyBuf);
    const pubKeyBuf = std.heap.c_allocator.alloc(u8, cbPublicKey) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(pubKeyBuf);

    const signature = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);
    const signatureWithTamperedMlDsa = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signatureWithTamperedMlDsa);
    const signatureWithTamperedEcDsa = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signatureWithTamperedEcDsa);
    const signatureWithTamperedEcDsaHeader = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signatureWithTamperedEcDsaHeader);
    const preHashSignature = std.heap.c_allocator.alloc(u8, cbSignature) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(preHashSignature);

    for (0..message.len) |i| message[i] = rng.g_rng.byte();
    SymCryptHash(pHashAlgorithm, message.ptr, message.len, messageHash.ptr, messageHash.len);
    for (0..context.len) |i| context[i] = rng.g_rng.byte();

    for (0..100) |_| {
        const pKey = SymCryptCompositeMlDsakeyAllocate(testParams.params);
        h.check(pKey != null, "Failed to allocate key");
        defer SymCryptCompositeMlDsakeyFree(pKey.?);

        scError = SymCryptCompositeMlDsakeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate key");

        scError = SymCryptCompositeMlDsakeyGetValue(
            pKey.?,
            privKeyBuf.ptr,
            privKeyBuf.len,
            SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
            0,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get private key");

        scError = SymCryptCompositeMlDsakeyGetValue(
            pKey.?,
            pubKeyBuf.ptr,
            pubKeyBuf.len,
            SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY,
            0,
        );
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get public key");

        pKeyBlob.params = testParams.params;
        pKeyBlob.format = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY;
        pKeyBlob.cbKeyBlob = privKeyBuf.len;
        @memcpy(pKeyBlob.abKeyBlob[0..privKeyBuf.len], privKeyBuf);

        status = pCompositeMlDsaImp.setKey(&keyBlob);
        h.check(status >= 0, "Failed to set key");

        const formatsToCheck = [_]u32{
            SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY,
            SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY,
        };

        for (formatsToCheck) |format| {
            switch (format) {
                SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY => {
                    status = pCompositeMlDsaImp.getBlobFromKey(format, privKeyBuf.ptr, privKeyBuf.len);
                    h.check(status >= 0, "Failed to get private key");
                    pKeyBlob.cbKeyBlob = privKeyBuf.len;
                    @memcpy(pKeyBlob.abKeyBlob[0..privKeyBuf.len], privKeyBuf);
                },
                SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY => {
                    status = pCompositeMlDsaImp.getBlobFromKey(format, pubKeyBuf.ptr, pubKeyBuf.len);
                    h.check(status >= 0, "Failed to get public key");
                    pKeyBlob.cbKeyBlob = pubKeyBuf.len;
                    @memcpy(pKeyBlob.abKeyBlob[0..pubKeyBuf.len], pubKeyBuf);
                },
                else => unreachable,
            }

            pKeyBlob.format = format;
            status = pCompositeMlDsaImp.setKey(&keyBlob);
            h.check(status >= 0, "Failed to set key");

            if (format != SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY) {
                status = pCompositeMlDsaImp.sign(
                    message.ptr,
                    message.len,
                    context.ptr,
                    context.len,
                    signature.ptr,
                    signature.len,
                    &cbSignatureResult,
                );
                h.check(status >= 0, "Failed to sign message");
                h.check(cbSignatureResult <= cbSignature, "Resulting signature length exceeds maximum!");

                status = pCompositeMlDsaImp.signHash(
                    SYMCRYPT_PQDSA_HASH_ID_NULL,
                    messageHash.ptr,
                    messageHash.len,
                    context.ptr,
                    context.len,
                    preHashSignature.ptr,
                    preHashSignature.len,
                    &cbPreHashSignatureResult,
                );
                h.check(status >= 0, "Failed to sign hash");
                h.check(cbPreHashSignatureResult <= cbSignature, "Resulting pre-hash signature length exceeds maximum!");
            }

            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status >= 0, "Failed to verify message");

            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                preHashSignature.ptr,
                preHashSignature.len,
            );
            h.check(status >= 0, "Failed to verify message");

            status = pCompositeMlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_NULL,
                messageHash.ptr,
                messageHash.len,
                context.ptr,
                context.len,
                signature.ptr,
                signature.len,
            );
            h.check(status >= 0, "Failed to verify hash");

            status = pCompositeMlDsaImp.verifyHash(
                SYMCRYPT_PQDSA_HASH_ID_NULL,
                messageHash.ptr,
                messageHash.len,
                context.ptr,
                context.len,
                preHashSignature.ptr,
                preHashSignature.len,
            );
            h.check(status >= 0, "Failed to verify hash");

            if (cbSignatureResult < cbSignature) {
                status = pCompositeMlDsaImp.verify(
                    message.ptr,
                    message.len,
                    context.ptr,
                    context.len,
                    signature.ptr,
                    cbSignatureResult,
                );
                h.check(status >= 0, "Failed to verify message");

                status = pCompositeMlDsaImp.verifyHash(
                    SYMCRYPT_PQDSA_HASH_ID_NULL,
                    messageHash.ptr,
                    messageHash.len,
                    context.ptr,
                    context.len,
                    signature.ptr,
                    cbSignatureResult,
                );
                h.check(status >= 0, "Failed to verify hash");
            }

            if (cbPreHashSignatureResult < cbSignature) {
                status = pCompositeMlDsaImp.verify(
                    message.ptr,
                    message.len,
                    context.ptr,
                    context.len,
                    preHashSignature.ptr,
                    cbPreHashSignatureResult,
                );
                h.check(status >= 0, "Failed to verify message");

                status = pCompositeMlDsaImp.verifyHash(
                    SYMCRYPT_PQDSA_HASH_ID_NULL,
                    messageHash.ptr,
                    messageHash.len,
                    context.ptr,
                    context.len,
                    preHashSignature.ptr,
                    cbPreHashSignatureResult,
                );
                h.check(status >= 0, "Failed to verify hash");
            }
        }

        const t = rng.g_rng.uint32();
        const xorBit: u8 = @as(u8, 1) << @intCast(t % 8);
        const mldsaIndex: usize = (t / 8) % testParams.cbMlDsaSignature;
        const ecdsaIndex: usize = testParams.cbMlDsaSignature + ((t / 8) % (cbSignatureResult - testParams.cbMlDsaSignature));
        const ecdsaHeaderIndex: usize = testParams.cbMlDsaSignature + ((t / 8) % 2);
        const trailingDataIndex: usize = if (cbSignatureResult < cbSignature)
            (cbSignatureResult + ((t / 8) % (cbSignature - cbSignatureResult)))
        else
            0;

        @memcpy(signatureWithTamperedMlDsa, signature);
        @memcpy(signatureWithTamperedEcDsa, signature);
        @memcpy(signatureWithTamperedEcDsaHeader, signature);

        signatureWithTamperedMlDsa[mldsaIndex] ^= xorBit;
        signatureWithTamperedEcDsa[ecdsaIndex] ^= xorBit;
        signatureWithTamperedEcDsaHeader[ecdsaHeaderIndex] ^= xorBit;

        status = pCompositeMlDsaImp.verify(
            message.ptr,
            message.len,
            context.ptr,
            context.len,
            signatureWithTamperedMlDsa.ptr,
            cbSignature,
        );
        h.check(status == STATUS_INVALID_SIGNATURE, "Tampered ML-DSA signature verified successfully?");

        status = pCompositeMlDsaImp.verify(
            message.ptr,
            message.len,
            context.ptr,
            context.len,
            signatureWithTamperedEcDsa.ptr,
            cbSignature,
        );
        h.check(status == STATUS_INVALID_SIGNATURE, "Tampered EC-DSA signature verified successfully?");

        status = pCompositeMlDsaImp.verify(
            message.ptr,
            message.len,
            context.ptr,
            context.len,
            signatureWithTamperedEcDsaHeader.ptr,
            cbSignature,
        );
        h.check(status == STATUS_INVALID_SIGNATURE, "Tampered EC-DSA signature header verified successfully?");

        if (cbSignatureResult < cbSignature) {
            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signatureWithTamperedMlDsa.ptr,
                cbSignatureResult,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered ML-DSA signature verified successfully?");

            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signatureWithTamperedEcDsa.ptr,
                cbSignatureResult,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered EC-DSA signature verified successfully?");

            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signatureWithTamperedEcDsaHeader.ptr,
                cbSignatureResult,
            );
            h.check(status == STATUS_INVALID_SIGNATURE, "Tampered EC-DSA signature header verified successfully?");

            signature[trailingDataIndex] ^= xorBit;

            status = pCompositeMlDsaImp.verify(
                message.ptr,
                message.len,
                context.ptr,
                context.len,
                signature.ptr,
                cbSignature,
            );
            h.check(status >= 0, "Tampered trailing data caused verification failure?");
        }
    }

    status = pCompositeMlDsaImp.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testPqDsaCompositeMlDsaFunctional() void {
    var compositeMlDsaImp = PqDsaMultiImp.init("CompositeMlDsa");
    defer compositeMlDsaImp.deinit();

    for (rgTestCompositeMlDsaParams) |testParams| {
        h.zprint("        {s}\n", .{testParams.pszParamsName});
        testPqDsaCompositeMlDsaFunctionalDo(&compositeMlDsaImp, testParams);
    }
}

fn testPqDsaCompositeMlDsaKatSignVerify(
    pPqDsaImplementation: *PqDsaMultiImp,
    params: u32,
    katPubKey: []const u8,
    katPrivKey: []const u8,
    katMsg: []const u8,
    katCtx: []const u8,
    katSig: []const u8,
    line: i64,
) void {
    var status: i32 = STATUS_SUCCESS;
    var pubKeyBlob: PQDSAKEY_TESTBLOB = .{ .compositeMlDsakey = .{} };
    var privKeyBlob: PQDSAKEY_TESTBLOB = .{ .compositeMlDsakey = .{} };
    var cbPubKey: usize = 0;
    var cbPrivKey: usize = 0;
    var cbSigMax: usize = 0;
    var cbResult: usize = 0;

    h.check(
        SymCryptCompositeMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY, &cbPrivKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected private key size",
    );
    h.check(
        SymCryptCompositeMlDsaSizeofKeyFormatFromParams(params, SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY, &cbPubKey) == SYMCRYPT_NO_ERROR,
        "Failed to get expected public key size",
    );
    h.check(
        SymCryptCompositeMlDsaSizeofSignatureFromParams(params, &cbSigMax) == SYMCRYPT_NO_ERROR,
        "Failed to get expected signature size",
    );

    h.check4(katPrivKey.len == cbPrivKey, "Invalid private key size {d} at line {d}", katPrivKey.len, line);
    h.check4(katPubKey.len == cbPubKey, "Invalid public key size {d} at line {d}", katPubKey.len, line);
    h.check4(katSig.len <= cbSigMax, "Invalid signature size {d} at line {d}", katSig.len, line);

    const signature = std.heap.c_allocator.alloc(u8, cbSigMax) catch h.fatal("Out of memory", .{});
    defer std.heap.c_allocator.free(signature);

    pubKeyBlob.compositeMlDsakey.params = params;
    pubKeyBlob.compositeMlDsakey.format = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PUBLIC_KEY;
    pubKeyBlob.compositeMlDsakey.cbKeyBlob = katPubKey.len;
    @memcpy(pubKeyBlob.compositeMlDsakey.abKeyBlob[0..katPubKey.len], katPubKey);

    privKeyBlob.compositeMlDsakey.params = params;
    privKeyBlob.compositeMlDsakey.format = SYMCRYPT_COMPOSITE_MLDSAKEY_FORMAT_PRIVATE_KEY;
    privKeyBlob.compositeMlDsakey.cbKeyBlob = katPrivKey.len;
    @memcpy(privKeyBlob.compositeMlDsakey.abKeyBlob[0..katPrivKey.len], katPrivKey);

    status = pPqDsaImplementation.setKey(&privKeyBlob);
    h.check3(status >= 0, "Failed to set private key at line {d}", line);

    status = pPqDsaImplementation.verify(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        katSig.ptr,
        katSig.len,
    );
    h.check3(status >= 0, "Verify with private key failed at line {d}", line);

    status = pPqDsaImplementation.sign(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        signature.ptr,
        signature.len,
        &cbResult,
    );
    h.check3(status >= 0, "Sign failed at line {d}", line);

    status = pPqDsaImplementation.verify(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Verify with private key failed at line {d}", line);

    status = pPqDsaImplementation.setKey(&pubKeyBlob);
    h.check3(status >= 0, "Failed to set public key at line {d}", line);

    status = pPqDsaImplementation.verify(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        signature.ptr,
        signature.len,
    );
    h.check3(status >= 0, "Verify with public key failed at line {d}", line);

    status = pPqDsaImplementation.verify(
        if (katMsg.len > 0) katMsg.ptr else null,
        katMsg.len,
        if (katCtx.len > 0) katCtx.ptr else null,
        katCtx.len,
        katSig.ptr,
        katSig.len,
    );
    h.check3(status >= 0, "Verify with public key failed at line {d}", line);

    status = pPqDsaImplementation.setKey(null);
    h.check(status >= 0, "Failed to free key");
}

fn testPqDsaCompositeMlDsaKat() void {
    var katReader = kat.ZigKatReader.init("kat_composite_mldsa.dat");
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "";
    var params: u32 = SYMCRYPT_COMPOSITE_MLDSA_PARAMS_NULL;
    var cCompositeMlDsaSignVerifySamples: u32 = 0;
    var cCompositeMlDsaSignVerifyWithContextSamples: u32 = 0;

    var compositeMlDsaImp = PqDsaMultiImp.init("CompositeMlDsa");
    defer compositeMlDsaImp.deinit();

    while (true) {
        katReader.getKatItem(&katItem);
        const line = katItem.line;

        if (katItem.type == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            h.ziprint("{s}{s}", .{ sep, katItem.categoryName });
            sep = ", ";

            var bParamsFound = false;
            for (rgTestCompositeMlDsaParams) |tp| {
                if (std.mem.eql(u8, katItem.categoryName, tp.pszParamsName)) {
                    params = tp.params;
                    bParamsFound = true;
                    break;
                }
            }
            h.check3(bParamsFound, "Composite-ML-DSA header at line {d} specifies unknown params!", line);
        }

        if (katItem.type == kat.KAT_TYPE_DATASET) {
            h.check3(katItem.dataItems.items.len == 6, "Wrong number of items in record at line {d}", line);
            h.check3(katItem.isFieldPresent("pk"), "Missing pk in record at line {d}", line);
            h.check3(katItem.isFieldPresent("sk"), "Missing sk from record at line {d}", line);
            h.check3(katItem.isFieldPresent("msg"), "Missing msg from record at line {d}", line);
            h.check3(katItem.isFieldPresent("ctx"), "Missing ctx from record at line {d}", line);
            h.check3(katItem.isFieldPresent("sig"), "Missing sig from record at line {d}", line);
            h.check3(katItem.isFieldPresent("sigwithctx"), "Missing sigwithctx from record at line {d}", line);

            const katPubKey = katItem.parseData("pk");
            defer std.heap.c_allocator.free(katPubKey);
            const katPrivKey = katItem.parseData("sk");
            defer std.heap.c_allocator.free(katPrivKey);
            const katMsg = katItem.parseData("msg");
            defer std.heap.c_allocator.free(katMsg);
            const katCtx = katItem.parseData("ctx");
            defer std.heap.c_allocator.free(katCtx);
            const katSig = katItem.parseData("sig");
            defer std.heap.c_allocator.free(katSig);
            const katSigWithCtx = katItem.parseData("sigwithctx");
            defer std.heap.c_allocator.free(katSigWithCtx);

            testPqDsaCompositeMlDsaKatSignVerify(
                &compositeMlDsaImp,
                params,
                katPubKey,
                katPrivKey,
                katMsg,
                &.{},
                katSig,
                line,
            );
            cCompositeMlDsaSignVerifySamples += 1;

            testPqDsaCompositeMlDsaKatSignVerify(
                &compositeMlDsaImp,
                params,
                katPubKey,
                katPrivKey,
                katMsg,
                katCtx,
                katSigWithCtx,
                line,
            );
            cCompositeMlDsaSignVerifyWithContextSamples += 1;
        }
    }

    h.ziprint(
        "\n        Total samples: {d} CompositeMlDsaSignVerify, {d} CompositeMlDsaSignVerifyWithContext\n",
        .{ cCompositeMlDsaSignVerifySamples, cCompositeMlDsaSignVerifyWithContextSamples },
    );
}

fn testPqDsaCompositeMlDsa() void {
    var nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak {d} outstanding", nOutstandingAllocs);

    if (!h.isAlgorithmPresent("CompositeMlDsa", 1)) {
        h.ziprint("    Skipping Composite-ML-DSA tests\n", .{});
        return;
    }

    h.ziprint("    Composite-ML-DSA\n", .{});

    testPqDsaCompositeMlDsaFunctional();
    testPqDsaCompositeMlDsaKat();

    nOutstandingAllocs = @atomicLoad(i64, &cb.g_nOutstandingCheckedAllocs, .seq_cst);
    h.check3(nOutstandingAllocs == 0, "Memory leak, {d} outstanding", nOutstandingAllocs);
}

pub export fn testPqDsa() callconv(.c) void {
    testPqDsaMlDsa();
    testPqDsaCompositeMlDsa();
}
