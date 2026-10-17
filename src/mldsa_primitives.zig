//
// mldsa_primitives.zig   ML-DSA low-level primitive implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");
const data_accessors = @import("data_accessors.zig");
const sha3 = @import("sha3.zig");
const shake = @import("shake.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const INT8 = types.INT8;
const UINT8 = types.UINT8;
const UINT16 = types.UINT16;
const INT32 = types.INT32;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const SIZE_T = types.SIZE_T;
const BOOLEAN = types.BOOLEAN;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const SYMCRYPT_OID = types.SYMCRYPT_OID;
const PCSYMCRYPT_OID = types.PCSYMCRYPT_OID;
const SYMCRYPT_PQDSA_HASH_ID = types.SYMCRYPT_PQDSA_HASH_ID;
const SYMCRYPT_MLDSA_PARAMS = types.SYMCRYPT_MLDSA_PARAMS;
const SYMCRYPT_MLDSAKEY_FORMAT = types.SYMCRYPT_MLDSAKEY_FORMAT;

extern fn SymCryptCallbackAlloc(cb: SIZE_T) callconv(SYMCRYPT_CALL) ?*anyopaque;
extern fn SymCryptCallbackFree(p: *anyopaque) callconv(SYMCRYPT_CALL) void;

// ==============================================================================================
// Constants & Macros from inc/symcrypt.h, lib/sc_lib.h, and lib/sc_lib_mldsa.h
// ==============================================================================================

pub const SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS: UINT32 = 256;

pub const SYMCRYPT_MLDSA_CONTEXT_MAX_LENGTH: UINT8 = 255;
pub const SYMCRYPT_MLDSA_ROOT_SEED_SIZE: UINT32 = 32;
pub const SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE: UINT32 = SYMCRYPT_MLDSA_ROOT_SEED_SIZE;

pub const SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44: UINT32 = 1312;
pub const SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65: UINT32 = 1952;
pub const SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87: UINT32 = 2592;

pub const SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA44: UINT32 = 2560;
pub const SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA65: UINT32 = 4032;
pub const SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA87: UINT32 = 4896;

pub const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA44: UINT32 = 2420;
pub const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65: UINT32 = 3309;
pub const SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA87: UINT32 = 4627;

pub const SYMCRYPT_MLDSA_Q: UINT32 = 8380417;
pub const SYMCRYPT_MLDSA_R_LOG2: u6 = 32;

pub const SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE: usize = 32;
pub const SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE: usize = shake.SYMCRYPT_SHAKE256_RESULT_SIZE;
pub const SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE: usize = 32;
pub const SYMCRYPT_MLDSA_PRIVATE_VECTOR_SEED_SIZE: usize = 64;
pub const SYMCRYPT_MLDSA_SIGNING_RANDOM_SIZE: usize = 32;
pub const SYMCRYPT_MLDSA_SUPPORTED_HASH_OID_SIZE: UINT32 = 11;

pub const SYMCRYPT_FLAG_MLDSA_EXTERNALMU: UINT32 = 0x1;

pub const SYMCRYPT_MLDSA_VECTOR_MAX_LENGTH: UINT8 = 8;
pub const SYMCRYPT_MLDSA_MATRIX_MAX_NROWS: UINT8 = 8;
pub const SYMCRYPT_MLDSA_MATRIX_MAX_NCOLS: UINT8 = 7;

pub const SYMCRYPT_MLDSA_SIGN_INTERNAL_MAX_ITERATIONS: UINT32 = 814;
pub const SYMCRYPT_MLDSA_REJBOUNDEDPOLY_MAX_ITERATIONS: UINT32 = 481;
pub const SYMCRYPT_MLDSA_REJNTTPOLY_MAX_ITERATIONS: UINT32 = 298;
pub const SYMCRYPT_MLDSA_SAMPLEINBALL_MAX_ITERATIONS: UINT32 = 121;

const SYMCRYPT_MLDSA_Q_INV: UINT32 = 58728449;
const SYMCRYPT_MLDSA_INTT_FIXUP_TIMES_R: UINT32 = 16382;
const SYMCRYPT_MLDSA_RSQR: UINT32 = 2365951;
const SYMCRYPT_MLDSA_REJNTTPOLY_SEED_SIZE: usize = 34;
const SYMCRYPT_MLDSA_REJBOUNDEDPOLY_SEED_SIZE: usize = 66;
pub const SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS: UINT32 = 13;

// ==============================================================================================
// Struct Definitions matching lib/sc_lib_mldsa.h
// ==============================================================================================

pub const SYMCRYPT_MLDSA_POLYELEMENT = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]UINT32,
};
pub const PSYMCRYPT_MLDSA_POLYELEMENT = *SYMCRYPT_MLDSA_POLYELEMENT;
pub const PCSYMCRYPT_MLDSA_POLYELEMENT = *const SYMCRYPT_MLDSA_POLYELEMENT;

pub const SYMCRYPT_MLDSA_VECTOR = extern struct {
    nElems: UINT8,
    cbTotalSize: UINT32,
};
pub const PSYMCRYPT_MLDSA_VECTOR = *SYMCRYPT_MLDSA_VECTOR;
pub const PCSYMCRYPT_MLDSA_VECTOR = *const SYMCRYPT_MLDSA_VECTOR;

pub const SYMCRYPT_MLDSA_MATRIX = extern struct {
    nRows: UINT8,
    nCols: UINT8,
    cbTotalSize: UINT32,
};
pub const PSYMCRYPT_MLDSA_MATRIX = *SYMCRYPT_MLDSA_MATRIX;
pub const PCSYMCRYPT_MLDSA_MATRIX = *const SYMCRYPT_MLDSA_MATRIX;

pub const SYMCRYPT_MLDSA_INTERNAL_PARAMS = extern struct {
    params: UINT32,

    cbPolyElement: UINT32,
    cbRowVector: UINT32,
    cbColVector: UINT32,
    cbMatrix: UINT32,

    nRows: UINT8,
    nCols: UINT8,

    privateKeyRange: UINT8,
    encodedCoefficientBitLength: UINT8,

    nChallengeNonZeroCoeffs: UINT8,
    nHintNonZeroCoeffs: UINT8,
    maskCoefficientRangeLog2: UINT8,
    commitmentModulus: UINT8,
    decomposeR1Factor: UINT32,
    commitmentRoundingRange: UINT32,
    w1EncodeCoefficientBitLength: UINT32,

    cbCommitmentHash: UINT32,
    cbEncodedPrivateKey: UINT32,
    cbEncodedPublicKey: UINT32,
    cbEncodedSignature: UINT32,
};
pub const PSYMCRYPT_MLDSA_INTERNAL_PARAMS = *SYMCRYPT_MLDSA_INTERNAL_PARAMS;
pub const PCSYMCRYPT_MLDSA_INTERNAL_PARAMS = *const SYMCRYPT_MLDSA_INTERNAL_PARAMS;

pub const SYMCRYPT_MLDSAKEY = extern struct {
    fAlgorithmInfo: UINT32,
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    cbTotalSize: UINT32,
    hasRootSeed: BOOLEAN,
    hasPrivateKey: BOOLEAN,
    rootSeed: [SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE]BYTE,
    privateSigningSeed: [SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE]BYTE,
    publicSeed: [SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE]BYTE,
    publicKeyHash: [SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE]BYTE,
    pmA: PSYMCRYPT_MLDSA_MATRIX,
    pvt1: PSYMCRYPT_MLDSA_VECTOR,
    pvs1: PSYMCRYPT_MLDSA_VECTOR,
    pvs2: PSYMCRYPT_MLDSA_VECTOR,
    pvt0: PSYMCRYPT_MLDSA_VECTOR,
    magic: SIZE_T,
};
pub const PSYMCRYPT_MLDSAKEY = *SYMCRYPT_MLDSAKEY;
pub const PCSYMCRYPT_MLDSAKEY = *const SYMCRYPT_MLDSAKEY;

pub const SYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES = extern struct {
    cbTotalSize: UINT32,
    nRowVectors: UINT32,
    nColVectors: UINT32,
    nPolyElements: UINT32,
    cbScratch: UINT32,

    shake256State: shake.SYMCRYPT_SHAKE256_STATE,

    pvRowVectors: ?[*]PSYMCRYPT_MLDSA_VECTOR,
    pvColVectors: ?[*]PSYMCRYPT_MLDSA_VECTOR,
    pePolyElements: ?[*]PSYMCRYPT_MLDSA_POLYELEMENT,
    pbScratch: ?PBYTE,

    magic: SIZE_T,
};
pub const PSYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES = *SYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES;

pub const SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT: UINT32 = @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT);

pub inline fn SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(nElems: UINT32) UINT32 {
    return @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (nElems * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
}

pub inline fn SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(nRows: UINT32, nCols: UINT32) UINT32 {
    return @sizeOf(SYMCRYPT_MLDSA_MATRIX) + (nRows * nCols * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
}

pub inline fn SYMCRYPT_INTERNAL_MLDSA_SIZEOF_KEY(nRows: UINT32, nCols: UINT32) UINT32 {
    return @as(UINT32, @sizeOf(SYMCRYPT_MLDSAKEY)) +
        SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(nRows, nCols) +
        SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(nCols) +
        (SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(nRows) * 3);
}

pub inline fn vectorElement(row: usize, pVector: PSYMCRYPT_MLDSA_VECTOR) PSYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]u8 = @ptrCast(pVector);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (row * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

pub inline fn vectorElementConst(row: usize, pVector: PCSYMCRYPT_MLDSA_VECTOR) PCSYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]const u8 = @ptrCast(pVector);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_VECTOR) + (row * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

pub inline fn matrixElement(row: usize, col: usize, pMatrix: PSYMCRYPT_MLDSA_MATRIX) PSYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]u8 = @ptrCast(pMatrix);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_MATRIX) + ((row * @as(usize, pMatrix.nCols) + col) * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

pub inline fn matrixElementConst(row: usize, col: usize, pMatrix: PCSYMCRYPT_MLDSA_MATRIX) PCSYMCRYPT_MLDSA_POLYELEMENT {
    const base: [*]const u8 = @ptrCast(pMatrix);
    const offset: usize = @sizeOf(SYMCRYPT_MLDSA_MATRIX) + ((row * @as(usize, pMatrix.nCols) + col) * @sizeOf(SYMCRYPT_MLDSA_POLYELEMENT));
    return @ptrCast(@alignCast(base + offset));
}

pub inline fn sizeofEncodedVector(pVector: PCSYMCRYPT_MLDSA_VECTOR, nBitsPerCoeff: UINT32) usize {
    return (@as(usize, pVector.nElems) * SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS * @as(usize, nBitsPerCoeff)) / 8;
}

// ==============================================================================================
// Zeta Tables & Internal Parameter Sets
// ==============================================================================================

const MLDSA_ZETA_BITREV_TIMES_R = [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]UINT32{
    4193792, 25847,   5771523, 7861508, 237124,  7602457, 7504169, 466468,
    1826347, 2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103,
    2725464, 1024112, 7300517, 3585928, 7830929, 7260833, 2619752, 6271868,
    6262231, 4520680, 6980856, 5102745, 1757237, 8360995, 4010497, 280005,
    2706023, 95776,   3077325, 3530437, 6718724, 4788269, 5842901, 3915439,
    4519302, 5336701, 3574422, 5512770, 3539968, 8079950, 2348700, 7841118,
    6681150, 6736599, 3505694, 4558682, 3507263, 6239768, 6779997, 3699596,
    811944,  531354,  954230,  3881043, 3900724, 5823537, 2071892, 5582638,
    4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
    7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489, 126922,
    3412210, 7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370,
    7709315, 7151892, 8357436, 7072248, 7998430, 1349076, 1852771, 6949987,
    5037034, 264944,  508951,  3097992, 44288,   7280319, 904516,  3958618,
    4656075, 8371839, 1653064, 5130689, 2389356, 8169440, 759969,  7063561,
    189548,  4827145, 3159746, 6529015, 5971092, 8202977, 1315589, 1341330,
    1285669, 6795489, 7567685, 6940675, 5361315, 4499357, 4751448, 3839961,
    2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984, 4817955,
    266997,  2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
    900702,  1859098, 909542,  819034,  495491,  6767243, 8337157, 7857917,
    7725090, 5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,
    342297,  286988,  5942594, 4108315, 3437287, 5038140, 1735879, 203044,
    2842341, 2691481, 5790267, 1265009, 4055324, 1247620, 2486353, 1595974,
    4613401, 1250494, 2635921, 4832145, 5386378, 1869119, 1903435, 7329447,
    7047359, 1237275, 5062207, 6950192, 7929317, 1312455, 3306115, 6417775,
    7100756, 1917081, 5834105, 7005614, 1500165, 777191,  2235880, 3406031,
    7838005, 5548557, 6709241, 6533464, 5796124, 4656147, 594136,  4603424,
    6366809, 2432395, 2454455, 8215696, 1957272, 3369112, 185531,  7173032,
    5196991, 162844,  1616392, 3014001, 810149,  1652634, 4686184, 6581310,
    5341501, 3523897, 3866901, 269760,  2213111, 7404533, 1717735, 472078,
    7953734, 1723600, 6577327, 1910376, 6712985, 7276084, 8119771, 4546524,
    5441381, 6144432, 7959518, 6094090, 183443,  7403526, 1612842, 4834730,
    7826001, 3919660, 8332111, 7018208, 3937738, 1400424, 7534263, 1976782,
};

const MLDSA_NEGATIVE_ZETA_BITREV_TIMES_R = [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]UINT32{
    4186625, 8354570, 2608894, 518909,  8143293, 777960,  876248,  7913949,
    6554070, 6026966, 359251,  2091905, 5260684, 2884855, 5268920, 5700314,
    5654953, 7356305, 1079900, 4794489, 549488,  1119584, 5760665, 2108549,
    2118186, 3859737, 1399561, 3277672, 6623180, 19422,   4369920, 8100412,
    5674394, 8284641, 5303092, 4849980, 1661693, 3592148, 2537516, 4464978,
    3861115, 3043716, 4805995, 2867647, 4840449, 300467,  6031717, 539299,
    1699267, 1643818, 4874723, 3821735, 4873154, 2140649, 1600420, 4680821,
    7568473, 7849063, 7426187, 4499374, 4479693, 2556880, 6308525, 2797779,
    3930395, 1528703, 3677745, 3041255, 1452451, 4904467, 6203962, 1585221,
    1257611, 6441103, 4083598, 1000202, 3190144, 3157330, 3632928, 8253495,
    4968207, 983419,  6232521, 5665122, 2967645, 3693493, 411027,  2477047,
    671102,  1228525, 22981,   1308169, 381987,  7031341, 6527646, 1430430,
    3343383, 8115473, 7871466, 5282425, 8336129, 1100098, 7475901, 4421799,
    3724342, 8578,    6727353, 3249728, 5991061, 210977,  7620448, 1316856,
    8190869, 3553272, 5220671, 1851402, 2409325, 177440,  7064828, 7039087,
    7094748, 1584928, 812732,  1439742, 3019102, 3881060, 3628969, 4540456,
    6288750, 4972711, 6063917, 4562441, 3342478, 6136326, 2446433, 3562462,
    8113420, 5945978, 1235728, 4867236, 3520352, 3759364, 1197226, 3193378,
    7479715, 6521319, 7470875, 7561383, 7884926, 1613174, 43260,   522500,
    655327,  3122442, 6348669, 5173371, 3556995, 525098,  768622,  3595838,
    8038120, 8093429, 2437823, 4272102, 4943130, 3342277, 6644538, 8177373,
    5538076, 5688936, 2590150, 7115408, 4325093, 7132797, 5894064, 6784443,
    3767016, 7129923, 5744496, 3548272, 2994039, 6511298, 6476982, 1050970,
    1333058, 7143142, 3318210, 1430225, 451100,  7067962, 5074302, 1962642,
    1279661, 6463336, 2546312, 1374803, 6880252, 7603226, 6144537, 4974386,
    542412,  2831860, 1671176, 1846953, 2584293, 3724270, 7786281, 3776993,
    2013608, 5948022, 5925962, 164721,  6423145, 5011305, 8194886, 1207385,
    3183426, 8217573, 6764025, 5366416, 7570268, 6727783, 3694233, 1799107,
    3038916, 4856520, 4513516, 8110657, 6167306, 975884,  6662682, 7908339,
    426683,  6656817, 1803090, 6470041, 1667432, 1104333, 260646,  3833893,
    2939036, 2235985, 420899,  2286327, 8196974, 976891,  6767575, 3545687,
    554416,  4460757, 48306,   1362209, 4442679, 6979993, 846154,  6403635,
};

pub export const SymCryptMlDsaInternalParams44 = SYMCRYPT_MLDSA_INTERNAL_PARAMS{
    .params = @backingInt(SYMCRYPT_MLDSA_PARAMS.SYMCRYPT_MLDSA_PARAMS_MLDSA44),
    .cbPolyElement = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT,
    .cbRowVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(4),
    .cbColVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(4),
    .cbMatrix = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(4, 4),
    .nRows = 4,
    .nCols = 4,
    .privateKeyRange = 2,
    .encodedCoefficientBitLength = 3,
    .nChallengeNonZeroCoeffs = 39,
    .nHintNonZeroCoeffs = 80,
    .maskCoefficientRangeLog2 = 17,
    .commitmentModulus = 44,
    .decomposeR1Factor = 11275,
    .commitmentRoundingRange = 95232,
    .w1EncodeCoefficientBitLength = 6,
    .cbCommitmentHash = 32,
    .cbEncodedPrivateKey = SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA44,
    .cbEncodedPublicKey = SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA44,
    .cbEncodedSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA44,
};

pub export const SymCryptMlDsaInternalParams65 = SYMCRYPT_MLDSA_INTERNAL_PARAMS{
    .params = @backingInt(SYMCRYPT_MLDSA_PARAMS.SYMCRYPT_MLDSA_PARAMS_MLDSA65),
    .cbPolyElement = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT,
    .cbRowVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(6),
    .cbColVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(5),
    .cbMatrix = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(6, 5),
    .nRows = 6,
    .nCols = 5,
    .privateKeyRange = 4,
    .encodedCoefficientBitLength = 4,
    .nChallengeNonZeroCoeffs = 49,
    .nHintNonZeroCoeffs = 55,
    .maskCoefficientRangeLog2 = 19,
    .commitmentModulus = 16,
    .decomposeR1Factor = 4100,
    .commitmentRoundingRange = 261888,
    .w1EncodeCoefficientBitLength = 4,
    .cbCommitmentHash = 48,
    .cbEncodedPrivateKey = SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA65,
    .cbEncodedPublicKey = SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA65,
    .cbEncodedSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA65,
};

pub export const SymCryptMlDsaInternalParams87 = SYMCRYPT_MLDSA_INTERNAL_PARAMS{
    .params = @backingInt(SYMCRYPT_MLDSA_PARAMS.SYMCRYPT_MLDSA_PARAMS_MLDSA87),
    .cbPolyElement = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT,
    .cbRowVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(8),
    .cbColVector = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(7),
    .cbMatrix = SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(8, 7),
    .nRows = 8,
    .nCols = 7,
    .privateKeyRange = 2,
    .encodedCoefficientBitLength = 3,
    .nChallengeNonZeroCoeffs = 60,
    .nHintNonZeroCoeffs = 75,
    .maskCoefficientRangeLog2 = 19,
    .commitmentModulus = 16,
    .decomposeR1Factor = 4100,
    .commitmentRoundingRange = 261888,
    .w1EncodeCoefficientBitLength = 4,
    .cbCommitmentHash = 64,
    .cbEncodedPrivateKey = SYMCRYPT_MLDSA_PRIVATE_KEY_SIZE_MLDSA87,
    .cbEncodedPublicKey = SYMCRYPT_MLDSA_PUBLIC_KEY_SIZE_MLDSA87,
    .cbEncodedSignature = SYMCRYPT_MLDSA_SIGNATURE_SIZE_MLDSA87,
};

// ==============================================================================================
// Parameter & Size Helpers
// ==============================================================================================

pub export fn SymCryptMlDsaGetInternalParamsFromParams(
    params: SYMCRYPT_MLDSA_PARAMS,
    pInternalParams: *PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    switch (params) {
        .SYMCRYPT_MLDSA_PARAMS_MLDSA44 => {
            pInternalParams.* = &SymCryptMlDsaInternalParams44;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_MLDSA_PARAMS_MLDSA65 => {
            pInternalParams.* = &SymCryptMlDsaInternalParams65;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_MLDSA_PARAMS_MLDSA87 => {
            pInternalParams.* = &SymCryptMlDsaInternalParams87;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_MLDSA_PARAMS_NULL => return .SYMCRYPT_INCOMPATIBLE_FORMAT,
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

pub export fn SymCryptMlDsaSizeofKeyFormatFromParams(
    params: SYMCRYPT_MLDSA_PARAMS,
    mlDsakeyFormat: SYMCRYPT_MLDSAKEY_FORMAT,
    pcbKeyFormat: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pInternalParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS = undefined;
    const scError = SymCryptMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    switch (mlDsakeyFormat) {
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_SEED => {
            pcbKeyFormat.* = SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PRIVATE_KEY => {
            pcbKeyFormat.* = pInternalParams.cbEncodedPrivateKey;
            return .SYMCRYPT_NO_ERROR;
        },
        .SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY => {
            pcbKeyFormat.* = pInternalParams.cbEncodedPublicKey;
            return .SYMCRYPT_NO_ERROR;
        },
        else => return .SYMCRYPT_INVALID_ARGUMENT,
    }
}

pub export fn SymCryptMlDsaSizeofSignatureFromParams(
    params: SYMCRYPT_MLDSA_PARAMS,
    pcbSignature: *SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pInternalParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS = undefined;
    const scError = SymCryptMlDsaGetInternalParamsFromParams(params, &pInternalParams);
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    pcbSignature.* = pInternalParams.cbEncodedSignature;
    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsakeyInitialize(
    pInternalParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbKey: PBYTE,
    cbKey: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLDSAKEY {
    const nRows = pInternalParams.nRows;
    const nCols = pInternalParams.nCols;

    macros.ASSERT(cbKey == SYMCRYPT_INTERNAL_MLDSA_SIZEOF_KEY(nRows, nCols));

    const cbMatrix = pInternalParams.cbMatrix;
    const cbRowVector = pInternalParams.cbRowVector;
    const cbColVector = pInternalParams.cbColVector;

    libmain.SymCryptWipe(@ptrCast(pbKey), cbKey);

    const pkMlDsakey: PSYMCRYPT_MLDSAKEY = @ptrCast(@alignCast(pbKey));
    pkMlDsakey.pParams = pInternalParams;
    pkMlDsakey.cbTotalSize = cbKey;

    var pbCurrent: PBYTE = pbKey + @sizeOf(SYMCRYPT_MLDSAKEY);

    pkMlDsakey.pmA = SymCryptMlDsaMatrixCreate(pbCurrent, cbMatrix, nRows, nCols);
    pbCurrent += cbMatrix;

    pkMlDsakey.pvt1 = SymCryptMlDsaVectorCreate(pbCurrent, cbRowVector, nRows);
    pbCurrent += cbRowVector;

    pkMlDsakey.pvs1 = SymCryptMlDsaVectorCreate(pbCurrent, cbColVector, nCols);
    pbCurrent += cbColVector;

    pkMlDsakey.pvs2 = SymCryptMlDsaVectorCreate(pbCurrent, cbRowVector, nRows);
    pbCurrent += cbRowVector;

    pkMlDsakey.pvt0 = SymCryptMlDsaVectorCreate(pbCurrent, cbRowVector, nRows);
    pbCurrent += cbRowVector;

    macros.ASSERT(@intFromPtr(pbCurrent) == @intFromPtr(pbKey) + cbKey);

    macros.SET_MAGIC(pkMlDsakey);

    return pkMlDsakey;
}

pub export fn SymCryptMlDsakeyComputeT(
    pmA: PCSYMCRYPT_MLDSA_MATRIX,
    pvs1: PCSYMCRYPT_MLDSA_VECTOR,
    pvs2: PCSYMCRYPT_MLDSA_VECTOR,
    pvt0: PSYMCRYPT_MLDSA_VECTOR,
    pvt1: PSYMCRYPT_MLDSA_VECTOR,
    pvTmp: PSYMCRYPT_MLDSA_VECTOR,
    peTmp: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    SymCryptMlDsaMatrixVectorMontMul(pmA, pvs1, pvTmp, peTmp);

    for (0..pvTmp.nElems) |i| {
        SymCryptMlDsaPolyElementMulR(vectorElement(i, pvTmp));
    }

    SymCryptMlDsaVectorAdd(pvTmp, pvs2, pvTmp);
    SymCryptMlDsaVectorINTT(pvTmp);
    SymCryptMlDsaVectorPower2Round(pvTmp, pvt1, pvt0);
}

// ==============================================================================================
// Montgomery Reduction & 32-bit Modular Arithmetic
// ==============================================================================================

pub export fn SymCryptMlDsaMontReduce(a: UINT64) callconv(SYMCRYPT_CALL) UINT32 {
    const t: UINT32 = @as(UINT32, @truncate(a)) *% SYMCRYPT_MLDSA_Q_INV;
    const m: UINT32 = @truncate((@as(UINT64, t) * SYMCRYPT_MLDSA_Q) >> SYMCRYPT_MLDSA_R_LOG2);

    var res: UINT64 = (a >> SYMCRYPT_MLDSA_R_LOG2) -% @as(UINT64, m);
    const additionMask: UINT32 = @truncate(res >> 32);

    res = res +% @as(UINT64, SYMCRYPT_MLDSA_Q & additionMask);
    macros.ASSERT(res < SYMCRYPT_MLDSA_Q);

    return @truncate(res);
}

pub export fn SymCryptMlDsaMontMul(a: UINT32, b: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.ASSERT(a < SYMCRYPT_MLDSA_Q);
    macros.ASSERT(b < SYMCRYPT_MLDSA_Q);

    return SymCryptMlDsaMontReduce(@as(UINT64, a) * @as(UINT64, b));
}

pub export fn SymCryptMlDsaModAdd(a: UINT32, b: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.ASSERT(a < SYMCRYPT_MLDSA_Q);
    macros.ASSERT(b < SYMCRYPT_MLDSA_Q);

    var res: UINT32 = a + b;
    const subtractionMask: UINT32 = macros.MASK32_LT(SYMCRYPT_MLDSA_Q - 1, res);

    res = res -% (SYMCRYPT_MLDSA_Q & subtractionMask);
    return res;
}

pub export fn SymCryptMlDsaModSub(a: UINT32, b: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    macros.ASSERT(a < SYMCRYPT_MLDSA_Q);
    macros.ASSERT(b < SYMCRYPT_MLDSA_Q);

    const additionMask: UINT32 = macros.MASK32_LT(a, b);
    return (a -% b) +% (SYMCRYPT_MLDSA_Q & additionMask);
}

// ==============================================================================================
// Polynomial Operations
// ==============================================================================================

pub export fn SymCryptMlDsaPolyElementCreate(
    pbBuffer: PBYTE,
    cbBuffer: SIZE_T,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_MLDSA_POLYELEMENT {
    macros.ASSERT(cbBuffer == SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT);
    return @ptrCast(@alignCast(pbBuffer));
}

pub export fn SymCryptMlDsaPolyElementSetZero(
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    @memset(&peDst.coeffs, 0);
}

pub export fn SymCryptMlDsaPolyElementNTT(
    peSrc: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var k: UINT32 = 0;
    var len: UINT32 = SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 2;

    while (len >= 1) : (len /= 2) {
        var start: UINT32 = 0;
        while (start < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (start += 2 * len) {
            k += 1;
            const twiddleFactor: UINT32 = MLDSA_ZETA_BITREV_TIMES_R[k];

            var j: UINT32 = start;
            while (j < start + len) : (j += 1) {
                const t: UINT32 = SymCryptMlDsaMontMul(twiddleFactor, peSrc.coeffs[j + len]);
                peSrc.coeffs[j + len] = SymCryptMlDsaModSub(peSrc.coeffs[j], t);
                peSrc.coeffs[j] = SymCryptMlDsaModAdd(peSrc.coeffs[j], t);
            }
        }
    }
}

pub export fn SymCryptMlDsaPolyElementINTT(
    peSrc: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var k: UINT32 = SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS;
    var len: UINT32 = 1;

    while (len < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (len *= 2) {
        var start: UINT32 = 0;
        while (start < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (start += 2 * len) {
            k -= 1;
            const twiddleFactor: UINT32 = MLDSA_NEGATIVE_ZETA_BITREV_TIMES_R[k];

            var j: UINT32 = start;
            while (j < start + len) : (j += 1) {
                const t: UINT32 = peSrc.coeffs[j];
                peSrc.coeffs[j] = SymCryptMlDsaModAdd(t, peSrc.coeffs[j + len]);
                peSrc.coeffs[j + len] = SymCryptMlDsaModSub(t, peSrc.coeffs[j + len]);
                peSrc.coeffs[j + len] = SymCryptMlDsaMontMul(twiddleFactor, peSrc.coeffs[j + len]);
            }
        }
    }

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peSrc.coeffs[i] = SymCryptMlDsaMontMul(SYMCRYPT_MLDSA_INTT_FIXUP_TIMES_R, peSrc.coeffs[i]);
    }
}

pub export fn SymCryptMlDsaPolyElementMulR(
    peSrc: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peSrc.coeffs[i] = SymCryptMlDsaMontMul(SYMCRYPT_MLDSA_RSQR, peSrc.coeffs[i]);
    }
}

pub export fn SymCryptMlDsaPolyElementMontMul(
    peSrc1: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peDst.coeffs[i] = SymCryptMlDsaMontMul(peSrc1.coeffs[i], peSrc2.coeffs[i]);
    }
}

pub export fn SymCryptMlDsaPolyElementAdd(
    peSrc1: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peDst.coeffs[i] = SymCryptMlDsaModAdd(peSrc1.coeffs[i], peSrc2.coeffs[i]);
    }
}

pub export fn SymCryptMlDsaPolyElementSub(
    peSrc1: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peSrc2: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peDst.coeffs[i] = SymCryptMlDsaModSub(peSrc1.coeffs[i], peSrc2.coeffs[i]);
    }
}

// ==============================================================================================
// Vector & Matrix Operations
// ==============================================================================================

pub export fn SymCryptMlDsaVectorCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
    nElems: UINT8,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_MLDSA_VECTOR {
    macros.ASSERT(nElems > 0);
    macros.ASSERT(nElems <= SYMCRYPT_MLDSA_VECTOR_MAX_LENGTH);
    macros.ASSERT(cbBuffer == SYMCRYPT_INTERNAL_MLDSA_SIZEOF_VECTOR(nElems));

    const pvVector: PSYMCRYPT_MLDSA_VECTOR = @ptrCast(@alignCast(pbBuffer));
    pvVector.nElems = nElems;
    pvVector.cbTotalSize = cbBuffer;

    var pbCurrent: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_MLDSA_VECTOR);
    for (0..nElems) |_| {
        _ = SymCryptMlDsaPolyElementCreate(pbCurrent, SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT);
        pbCurrent += SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT;
    }

    return pvVector;
}

pub export fn SymCryptMlDsaVectorCopy(
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc.nElems == pvDst.nElems);

    const srcBytes: [*]const u8 = @ptrCast(pvSrc);
    const dstBytes: [*]u8 = @ptrCast(pvDst);
    @memcpy(dstBytes[0..pvSrc.cbTotalSize], srcBytes[0..pvSrc.cbTotalSize]);
}

pub export fn SymCryptMlDsaVectorSetZero(
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    for (0..pvDst.nElems) |i| {
        SymCryptMlDsaPolyElementSetZero(vectorElement(i, pvDst));
    }
}

pub export fn SymCryptMlDsaVectorAdd(
    pvSrc1: PCSYMCRYPT_MLDSA_VECTOR,
    pvSrc2: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc1.nElems == pvSrc2.nElems);
    macros.ASSERT(pvSrc1.nElems == pvDst.nElems);

    for (0..pvSrc1.nElems) |i| {
        SymCryptMlDsaPolyElementAdd(
            vectorElementConst(i, pvSrc1),
            vectorElementConst(i, pvSrc2),
            vectorElement(i, pvDst),
        );
    }
}

pub export fn SymCryptMlDsaVectorSub(
    pvSrc1: PCSYMCRYPT_MLDSA_VECTOR,
    pvSrc2: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc1.nElems == pvSrc2.nElems);
    macros.ASSERT(pvSrc1.nElems == pvDst.nElems);

    for (0..pvSrc1.nElems) |i| {
        SymCryptMlDsaPolyElementSub(
            vectorElementConst(i, pvSrc1),
            vectorElementConst(i, pvSrc2),
            vectorElement(i, pvDst),
        );
    }
}

pub export fn SymCryptMlDsaVectorPolyElementMontMul(
    pvSrc1: PCSYMCRYPT_MLDSA_VECTOR,
    peSrc2: PCSYMCRYPT_MLDSA_POLYELEMENT,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc1.nElems == pvDst.nElems);

    for (0..pvSrc1.nElems) |i| {
        SymCryptMlDsaPolyElementMontMul(
            vectorElementConst(i, pvSrc1),
            peSrc2,
            vectorElement(i, pvDst),
        );
    }
}

pub export fn SymCryptMlDsaVectorNTT(
    pvSrc: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    for (0..pvSrc.nElems) |i| {
        SymCryptMlDsaPolyElementNTT(vectorElement(i, pvSrc));
    }
}

pub export fn SymCryptMlDsaVectorINTT(
    pvSrc: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    for (0..pvSrc.nElems) |i| {
        SymCryptMlDsaPolyElementINTT(vectorElement(i, pvSrc));
    }
}

pub export fn SymCryptMlDsaMatrixCreate(
    pbBuffer: PBYTE,
    cbBuffer: UINT32,
    nRows: UINT8,
    nCols: UINT8,
) callconv(SYMCRYPT_CALL) PSYMCRYPT_MLDSA_MATRIX {
    macros.ASSERT(nRows > 0);
    macros.ASSERT(nCols > 0);
    macros.ASSERT(nRows <= SYMCRYPT_MLDSA_MATRIX_MAX_NROWS);
    macros.ASSERT(nCols <= SYMCRYPT_MLDSA_MATRIX_MAX_NCOLS);
    macros.ASSERT(cbBuffer == SYMCRYPT_INTERNAL_MLDSA_SIZEOF_MATRIX(nRows, nCols));

    const pMatrix: PSYMCRYPT_MLDSA_MATRIX = @ptrCast(@alignCast(pbBuffer));
    pMatrix.nRows = nRows;
    pMatrix.nCols = nCols;
    pMatrix.cbTotalSize = cbBuffer;

    var pbCurrent: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_MLDSA_MATRIX);
    const totalElems: usize = @as(usize, nRows) * @as(usize, nCols);
    for (0..totalElems) |_| {
        _ = SymCryptMlDsaPolyElementCreate(pbCurrent, SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT);
        pbCurrent += SYMCRYPT_INTERNAL_MLDSA_SIZEOF_POLYELEMENT;
    }

    return pMatrix;
}

pub export fn SymCryptMlDsaMatrixVectorMontMul(
    pmSrc1: PCSYMCRYPT_MLDSA_MATRIX,
    pvSrc2: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
    peTmp: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pmSrc1.nCols == pvSrc2.nElems);
    macros.ASSERT(pmSrc1.nRows == pvDst.nElems);

    SymCryptMlDsaVectorSetZero(pvDst);

    for (0..pmSrc1.nRows) |i| {
        const peDst = vectorElement(i, pvDst);
        for (0..pmSrc1.nCols) |j| {
            const peSrc1 = matrixElementConst(i, j, pmSrc1);
            const peSrc2 = vectorElementConst(j, pvSrc2);

            SymCryptMlDsaPolyElementMontMul(peSrc1, peSrc2, peTmp);
            SymCryptMlDsaPolyElementAdd(peDst, peTmp, peDst);
        }
    }
}

// ==============================================================================================
// Sampling & Rejection
// ==============================================================================================

pub export fn SymCryptMlDsaRejNttPoly(
    pbRejNttPolySeed: PCBYTE,
    cbRejNttPolySeed: SIZE_T,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(cbRejNttPolySeed == SYMCRYPT_MLDSA_REJNTTPOLY_SEED_SIZE);

    var shakeState: shake.SYMCRYPT_SHAKE128_STATE = undefined;
    shake.SymCryptShake128Init(&shakeState);
    shake.SymCryptShake128Append(&shakeState, pbRejNttPolySeed, cbRejNttPolySeed);

    var nIterations: UINT32 = 0;
    var shakeBytes: [4]BYTE = .{ 0, 0, 0, 0 };

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        var coeff: UINT32 = 0;
        while (true) {
            if (nIterations >= SYMCRYPT_MLDSA_REJNTTPOLY_MAX_ITERATIONS) {
                return .SYMCRYPT_EXTERNAL_FAILURE;
            }
            shake.SymCryptShake128Extract(&shakeState, &shakeBytes, 3, types.FALSE);
            shakeBytes[2] &= 0x7F;
            coeff = macros.LOAD_LSBFIRST32(&shakeBytes);
            nIterations += 1;
            if (coeff < SYMCRYPT_MLDSA_Q) {
                break;
            }
        }
        peDst.coeffs[i] = coeff;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaExpandA(
    pbPublicSeed: PCBYTE,
    cbPublicSeed: SIZE_T,
    pmA: PSYMCRYPT_MLDSA_MATRIX,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(cbPublicSeed == SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE);

    var rejNttSeed: [SYMCRYPT_MLDSA_REJNTTPOLY_SEED_SIZE]BYTE = undefined;
    @memcpy(rejNttSeed[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE], pbPublicSeed[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE]);

    for (0..pmA.nRows) |i| {
        for (0..pmA.nCols) |j| {
            rejNttSeed[SYMCRYPT_MLDSA_REJNTTPOLY_SEED_SIZE - 2] = @intCast(j);
            rejNttSeed[SYMCRYPT_MLDSA_REJNTTPOLY_SEED_SIZE - 1] = @intCast(i);

            const scError = SymCryptMlDsaRejNttPoly(
                &rejNttSeed,
                rejNttSeed.len,
                matrixElement(i, j, pmA),
            );
            if (scError != .SYMCRYPT_NO_ERROR) {
                return scError;
            }
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub inline fn SymCryptMlDsaCoeffFromHalfByte(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    halfByte: UINT8,
) INT8 {
    macros.ASSERT(halfByte <= 15);
    macros.ASSERT(pParams.privateKeyRange == 2 or pParams.privateKeyRange == 4);

    if (pParams.privateKeyRange == 2 and halfByte < 15) {
        const halfByteDiv5: UINT8 = @intCast((@as(u16, halfByte) * 13) >> 6);
        const halfByteMod5: UINT8 = halfByte - (5 * halfByteDiv5);
        return 2 - @as(INT8, @intCast(halfByteMod5));
    } else if (pParams.privateKeyRange == 4 and halfByte < 9) {
        return 4 - @as(INT8, @intCast(halfByte));
    }

    return std.math.minInt(INT8);
}

pub export fn SymCryptMlDsaRejBoundedPoly(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbRejBoundedPolySeed: PCBYTE,
    cbRejBoundedPolySeed: SIZE_T,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(cbRejBoundedPolySeed == SYMCRYPT_MLDSA_REJBOUNDEDPOLY_SEED_SIZE);

    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var shakeState: shake.SYMCRYPT_SHAKE256_STATE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&shakeState), @sizeOf(shake.SYMCRYPT_SHAKE256_STATE));

    shake.SymCryptShake256Init(&shakeState);
    shake.SymCryptShake256Append(&shakeState, pbRejBoundedPolySeed, cbRejBoundedPolySeed);

    var shakeByte: [1]BYTE = undefined;
    var i: UINT32 = 0;
    var nIterations: UINT32 = 0;

    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) {
        if (nIterations >= SYMCRYPT_MLDSA_REJBOUNDEDPOLY_MAX_ITERATIONS) {
            scError = .SYMCRYPT_EXTERNAL_FAILURE;
            break;
        }

        shake.SymCryptShake256Extract(&shakeState, &shakeByte, 1, types.FALSE);
        const z0: INT8 = SymCryptMlDsaCoeffFromHalfByte(pParams, shakeByte[0] & 0x0F);
        const z1: INT8 = SymCryptMlDsaCoeffFromHalfByte(pParams, shakeByte[0] >> 4);
        nIterations += 1;

        if (z0 != std.math.minInt(INT8)) {
            peDst.coeffs[i] = SymCryptMlDsaSignedCoefficientModQ(z0);
            i += 1;
        }

        if (z1 != std.math.minInt(INT8) and i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) {
            peDst.coeffs[i] = SymCryptMlDsaSignedCoefficientModQ(z1);
            i += 1;
        }
    }

    return scError;
}

pub export fn SymCryptMlDsaExpandS(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbPrivateVectorSeed: PCBYTE,
    cbPrivateVectorSeed: SIZE_T,
    pvs1: PSYMCRYPT_MLDSA_VECTOR,
    pvs2: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(cbPrivateVectorSeed == SYMCRYPT_MLDSA_PRIVATE_VECTOR_SEED_SIZE);

    const nRows: UINT16 = pParams.nRows;
    const nCols: UINT16 = pParams.nCols;

    var rejBoundedPolySeed: [SYMCRYPT_MLDSA_REJBOUNDEDPOLY_SEED_SIZE]BYTE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&rejBoundedPolySeed), rejBoundedPolySeed.len);

    @memcpy(
        rejBoundedPolySeed[0..SYMCRYPT_MLDSA_PRIVATE_VECTOR_SEED_SIZE],
        pbPrivateVectorSeed[0..SYMCRYPT_MLDSA_PRIVATE_VECTOR_SEED_SIZE],
    );

    var i: UINT16 = 0;
    while (i < nCols) : (i += 1) {
        macros.STORE_LSBFIRST16(rejBoundedPolySeed[SYMCRYPT_MLDSA_REJBOUNDEDPOLY_SEED_SIZE - 2 ..].ptr, i);
        const scError = SymCryptMlDsaRejBoundedPoly(
            pParams,
            &rejBoundedPolySeed,
            rejBoundedPolySeed.len,
            vectorElement(i, pvs1),
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    i = 0;
    while (i < nRows) : (i += 1) {
        macros.STORE_LSBFIRST16(rejBoundedPolySeed[SYMCRYPT_MLDSA_REJBOUNDEDPOLY_SEED_SIZE - 2 ..].ptr, nCols + i);
        const scError = SymCryptMlDsaRejBoundedPoly(
            pParams,
            &rejBoundedPolySeed,
            rejBoundedPolySeed.len,
            vectorElement(i, pvs2),
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaSampleInBall(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbCommitmentHash: PCBYTE,
    cbCommitmentHash: SIZE_T,
    peChallenge: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    SymCryptMlDsaPolyElementSetZero(peChallenge);

    var shakeState: shake.SYMCRYPT_SHAKE256_STATE = undefined;
    defer libmain.SymCryptWipe(@ptrCast(&shakeState), @sizeOf(shake.SYMCRYPT_SHAKE256_STATE));

    shake.SymCryptShake256Init(&shakeState);
    shake.SymCryptShake256Append(&shakeState, pbCommitmentHash, cbCommitmentHash);

    var temp: [8]BYTE = undefined;
    macros.ASSERT(pParams.nChallengeNonZeroCoeffs <= 8 * temp.len);
    shake.SymCryptShake256Extract(&shakeState, &temp, temp.len, types.FALSE);

    var powersOfNegativeOne: UINT64 = macros.LOAD_LSBFIRST64(&temp);

    var i: UINT32 = SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS - pParams.nChallengeNonZeroCoeffs;
    while (i < SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) : (i += 1) {
        var jByte: [1]BYTE = .{0};
        var nIterations: UINT32 = 0;
        while (true) {
            if (nIterations >= SYMCRYPT_MLDSA_SAMPLEINBALL_MAX_ITERATIONS) {
                return .SYMCRYPT_EXTERNAL_FAILURE;
            }
            shake.SymCryptShake256Extract(&shakeState, &jByte, 1, types.FALSE);
            nIterations += 1;
            if (jByte[0] <= i) {
                break;
            }
        }

        const j: usize = jByte[0];
        peChallenge.coeffs[i] = peChallenge.coeffs[j];

        const negativeMask: UINT32 = macros.MASK32_NONZERO(@intCast(powersOfNegativeOne & 1));
        powersOfNegativeOne >>= 1;

        peChallenge.coeffs[j] = ((SYMCRYPT_MLDSA_Q - 1) & negativeMask) | (1 & ~negativeMask);
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaExpandMask(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pShakeState: *shake.SYMCRYPT_SHAKE256_STATE,
    pbPrivateRandom: PCBYTE,
    cbPrivateRandom: SIZE_T,
    counter: UINT16,
    pvMask: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pParams.nCols == pvMask.nElems);
    macros.ASSERT(cbPrivateRandom == shake.SYMCRYPT_SHAKE256_RESULT_SIZE);

    var seedSuffix: [2]BYTE = undefined;
    const cbShakeOutput: UINT32 = (@as(UINT32, pParams.maskCoefficientRangeLog2) + 1) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);
    var shakeOutput: [20 * 32]BYTE = undefined;
    macros.ASSERT(cbShakeOutput <= shakeOutput.len);

    var i: UINT16 = 0;
    while (i < pvMask.nElems) : (i += 1) {
        macros.STORE_LSBFIRST16(&seedSuffix, counter + i);
        shake.SymCryptShake256Append(pShakeState, pbPrivateRandom, cbPrivateRandom);
        shake.SymCryptShake256Append(pShakeState, &seedSuffix, seedSuffix.len);
        shake.SymCryptShake256Extract(pShakeState, &shakeOutput, cbShakeOutput, types.TRUE);

        const shiftRange: u5 = @intCast(pParams.maskCoefficientRangeLog2);
        const scError = SymCryptMlDsaPolyElementDecode(
            &shakeOutput,
            @as(UINT32, pParams.maskCoefficientRangeLog2) + 1,
            @as(UINT32, 1) << shiftRange,
            vectorElement(i, pvMask),
        );
        macros.ASSERT(scError == .SYMCRYPT_NO_ERROR);
    }

    SymCryptMlDsaVectorNTT(pvMask);
}

// ==============================================================================================
// Hints, Rounding, Decompose & Norms
// ==============================================================================================

pub export fn SymCryptMlDsaMakeHint(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvWMinusCs2: PSYMCRYPT_MLDSA_VECTOR,
    pvWMinusCs2PlusCt0: PSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
    nBitsSet: *UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvWMinusCs2.nElems == pvWMinusCs2PlusCt0.nElems);
    macros.ASSERT(pvWMinusCs2.nElems == pvDst.nElems);

    nBitsSet.* = 0;

    SymCryptMlDsaVectorHighBits(pParams, pvWMinusCs2, pvWMinusCs2);
    SymCryptMlDsaVectorHighBits(pParams, pvWMinusCs2PlusCt0, pvWMinusCs2PlusCt0);

    for (0..pvDst.nElems) |i| {
        const peDst = vectorElement(i, pvDst);
        const peVec0 = vectorElement(i, pvWMinusCs2);
        const peVec1 = vectorElement(i, pvWMinusCs2PlusCt0);

        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            peDst.coeffs[j] = 1 & ~macros.MASK32_EQ(peVec0.coeffs[j], peVec1.coeffs[j]);
            nBitsSet.* += peDst.coeffs[j];
        }
    }
}

pub export fn SymCryptMlDsaUseHint(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvHint: PCSYMCRYPT_MLDSA_VECTOR,
    pvCommitment: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvHint.nElems == pvCommitment.nElems);

    var r1: UINT32 = 0;
    var r0: UINT32 = 0;

    for (0..pvHint.nElems) |i| {
        const peHint = vectorElementConst(i, pvHint);
        const peCommitment = vectorElement(i, pvCommitment);

        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            macros.ASSERT(peHint.coeffs[j] == 0 or peHint.coeffs[j] == 1);

            SymCryptMlDsaDecompose(pParams, peCommitment.coeffs[j], &r1, &r0);

            const hintIsZeroMask: UINT32 = peHint.coeffs[j] -% 1;
            const r0PrimeGtZeroMask: UINT32 = macros.MASK32_LT(r0 -% 1, pParams.commitmentRoundingRange);

            const commitmentModulusMinus1: UINT32 = @as(UINT32, pParams.commitmentModulus) - 1;
            var tmpMask: UINT32 = ~macros.MASK32_EQ(r1, commitmentModulusMinus1);
            var positiveOffsetCoeff: UINT32 = tmpMask & (r1 + 1);

            tmpMask = macros.MASK32_EQ(r1, 0);
            var negativeOffsetCoeff: UINT32 = (tmpMask & commitmentModulusMinus1) | (~tmpMask & (r1 -% 1));

            r1 &= hintIsZeroMask;
            positiveOffsetCoeff &= ~hintIsZeroMask & r0PrimeGtZeroMask;
            negativeOffsetCoeff &= ~hintIsZeroMask & ~r0PrimeGtZeroMask;

            macros.ASSERT((r1 & positiveOffsetCoeff) == 0);
            macros.ASSERT((r1 & negativeOffsetCoeff) == 0);
            macros.ASSERT((positiveOffsetCoeff & negativeOffsetCoeff) == 0);

            peCommitment.coeffs[j] = r1 | positiveOffsetCoeff | negativeOffsetCoeff;
        }
    }
}

pub inline fn SymCryptMlDsaModPlusMinus(r: UINT32, modulus: UINT32) INT32 {
    macros.ASSERT(r < modulus);

    const halfModulus: UINT32 = modulus >> 1;
    const subtractionMask: UINT32 = macros.MASK32_LT(halfModulus, r);

    const r0: INT32 = @bitCast(r -% (modulus & subtractionMask));
    macros.ASSERT(r0 > -@as(INT32, @bitCast(halfModulus)) and r0 <= @as(INT32, @bitCast(halfModulus)));

    return r0;
}

pub inline fn SymCryptMlDsaPolyElementInfinityNorm(peSrc: PCSYMCRYPT_MLDSA_POLYELEMENT) UINT32 {
    var norm: UINT32 = 0;
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        const currSigned: INT32 = SymCryptMlDsaModPlusMinus(peSrc.coeffs[i], SYMCRYPT_MLDSA_Q);
        const currBits: UINT32 = @bitCast(currSigned);
        const negBits: UINT32 = @bitCast(-%currSigned);

        const negMask: UINT32 = @bitCast(currSigned >> 31);
        const absCurr: UINT32 = (currBits & ~negMask) | (negBits & negMask);

        const ltMask: UINT32 = macros.MASK32_LT(norm, absCurr);
        norm = (norm & ~ltMask) | (absCurr & ltMask);
    }

    return norm;
}

pub export fn SymCryptMlDsaVectorInfinityNorm(
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) UINT32 {
    var norm: UINT32 = 0;
    for (0..pvSrc.nElems) |i| {
        const curr = SymCryptMlDsaPolyElementInfinityNorm(vectorElementConst(i, pvSrc));
        const mask = macros.MASK32_LT(norm, curr);
        norm = (norm & ~mask) | (curr & mask);
    }

    return norm;
}

pub inline fn SymCryptMlDsaDecompose(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    r: UINT32,
    puR1: ?*UINT32,
    puR0: ?*UINT32,
) void {
    macros.ASSERT(r < SYMCRYPT_MLDSA_Q);
    macros.ASSERT(puR1 != null or puR0 != null);

    const rdiv128: UINT32 = (r + 127) >> 7;
    var r1: UINT32 = (rdiv128 * pParams.decomposeR1Factor + (1 << 23)) >> 24;

    const mask: UINT32 = macros.MASK32_LT(r1, pParams.commitmentModulus);
    r1 &= mask;

    var r0: INT32 = @bitCast(r -% (r1 * 2 * pParams.commitmentRoundingRange));

    const qHalf: INT32 = (SYMCRYPT_MLDSA_Q - 1) >> 1;
    const subQMask: INT32 = (qHalf -% r0) >> 31;
    r0 -%= subQMask & @as(INT32, SYMCRYPT_MLDSA_Q);
    const r0ModQ: UINT32 = SymCryptMlDsaSignedCoefficientModQ(r0);

    if (puR1) |p1| {
        p1.* = r1;
    }
    if (puR0) |p0| {
        p0.* = r0ModQ;
    }
}

pub export fn SymCryptMlDsaVectorHighBits(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc.nElems == pvDst.nElems);

    for (0..pvSrc.nElems) |i| {
        const peSrc = vectorElementConst(i, pvSrc);
        const peDst = vectorElement(i, pvDst);
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            SymCryptMlDsaDecompose(pParams, peSrc.coeffs[j], &peDst.coeffs[j], null);
        }
    }
}

pub export fn SymCryptMlDsaVectorLowBits(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc.nElems == pvDst.nElems);

    for (0..pvSrc.nElems) |i| {
        const peSrc = vectorElementConst(i, pvSrc);
        const peDst = vectorElement(i, pvDst);
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            SymCryptMlDsaDecompose(pParams, peSrc.coeffs[j], null, &peDst.coeffs[j]);
        }
    }
}

pub export fn SymCryptMlDsaPower2Round(
    r: UINT32,
    puR1: *UINT32,
    puR0: *UINT32,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(r < SYMCRYPT_MLDSA_Q);

    const rPrime: UINT32 = r & ((1 << SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS) - 1);
    const r0: INT32 = SymCryptMlDsaModPlusMinus(rPrime, 1 << SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS);
    const r1: UINT32 = (r -% @as(UINT32, @bitCast(r0))) >> SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS;

    puR1.* = r1;
    puR0.* = SymCryptMlDsaSignedCoefficientModQ(r0);
}

pub export fn SymCryptMlDsaPolyElementPower2Round(
    peSrc: PCSYMCRYPT_MLDSA_POLYELEMENT,
    peDst1: PSYMCRYPT_MLDSA_POLYELEMENT,
    peDst0: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) void {
    var r1: UINT32 = 0;
    var r0: UINT32 = 0;

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        SymCryptMlDsaPower2Round(peSrc.coeffs[i], &r1, &r0);
        peDst1.coeffs[i] = r1;
        peDst0.coeffs[i] = r0;
    }
}

pub export fn SymCryptMlDsaVectorPower2Round(
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    pvDst1: PSYMCRYPT_MLDSA_VECTOR,
    pvDst0: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(pvSrc.nElems == pvDst1.nElems);
    macros.ASSERT(pvSrc.nElems == pvDst0.nElems);

    for (0..pvSrc.nElems) |i| {
        SymCryptMlDsaPolyElementPower2Round(
            vectorElementConst(i, pvSrc),
            vectorElement(i, pvDst1),
            vectorElement(i, pvDst0),
        );
    }
}

pub inline fn SymCryptMlDsaSignedCoefficientModQ(coefficient: INT32) UINT32 {
    macros.ASSERT(coefficient > -@as(INT32, SYMCRYPT_MLDSA_Q) and coefficient < @as(INT32, SYMCRYPT_MLDSA_Q));

    const negativeMask: UINT32 = @bitCast(coefficient >> 31);
    const result: UINT32 = @as(UINT32, @bitCast(coefficient)) +% (SYMCRYPT_MLDSA_Q & negativeMask);
    macros.ASSERT(result < SYMCRYPT_MLDSA_Q);

    return result;
}

// ==============================================================================================
// Encoding & Decoding
// ==============================================================================================

pub export fn SymCryptMlDsaPolyElementEncode(
    peSrc: PCSYMCRYPT_MLDSA_POLYELEMENT,
    nBitsPerCoefficient: UINT32,
    signedCoefficientBound: UINT32,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 20);

    var cbDstWritten: usize = 0;
    var accumulator: UINT32 = 0;
    var nBitsInAccumulator: UINT32 = 0;

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        var nBitsInCoefficient: UINT32 = nBitsPerCoefficient;
        var coefficient: UINT32 = peSrc.coeffs[i];

        macros.ASSERT(coefficient < SYMCRYPT_MLDSA_Q);

        coefficient -%= SYMCRYPT_MLDSA_Q & macros.MASK32_LT(signedCoefficientBound, coefficient);
        coefficient = signedCoefficientBound -% coefficient;
        coefficient = (peSrc.coeffs[i] & macros.MASK32_ZERO(signedCoefficientBound)) |
            (coefficient & macros.MASK32_NONZERO(signedCoefficientBound));

        macros.ASSERT(signedCoefficientBound == 0 or coefficient <= signedCoefficientBound * 2);
        macros.ASSERT(coefficient < (@as(UINT32, 1) << @intCast(nBitsPerCoefficient)));

        while (nBitsInCoefficient > 0) {
            const nBitsToEncode: UINT32 = @min(nBitsInCoefficient, 32 - nBitsInAccumulator);
            const shiftEncode: u5 = @intCast(nBitsToEncode);

            const bitsToEncode: UINT32 = coefficient & ((@as(UINT32, 1) << shiftEncode) - 1);
            coefficient >>= shiftEncode;
            nBitsInCoefficient -= nBitsToEncode;

            accumulator |= bitsToEncode << @intCast(nBitsInAccumulator);
            nBitsInAccumulator += nBitsToEncode;
            if (nBitsInAccumulator == 32) {
                macros.STORE_LSBFIRST32(pbDst + cbDstWritten, accumulator);
                cbDstWritten += 4;
                accumulator = 0;
                nBitsInAccumulator = 0;
            }
        }
    }

    macros.ASSERT(nBitsInAccumulator == 0);
    macros.ASSERT(cbDstWritten == (nBitsPerCoefficient * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8)));
}

pub export fn SymCryptMlDsaPolyElementDecode(
    pbSrc: PCBYTE,
    nBitsPerCoefficient: UINT32,
    signedCoefficientBound: UINT32,
    peDst: PSYMCRYPT_MLDSA_POLYELEMENT,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    macros.ASSERT(nBitsPerCoefficient > 0);
    macros.ASSERT(nBitsPerCoefficient <= 20);

    var cbSrcRead: usize = 0;
    var accumulator: UINT32 = 0;
    var nBitsInAccumulator: UINT32 = 0;

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        var coefficient: UINT32 = 0;
        var nBitsInCoefficient: UINT32 = 0;

        while (nBitsPerCoefficient > nBitsInCoefficient) {
            if (nBitsInAccumulator == 0) {
                accumulator = macros.LOAD_LSBFIRST32(pbSrc + cbSrcRead);
                cbSrcRead += 4;
                nBitsInAccumulator = 32;
            }

            const nBitsToDecode: UINT32 = @min(nBitsPerCoefficient - nBitsInCoefficient, nBitsInAccumulator);
            const shiftDecode: u5 = @intCast(nBitsToDecode);

            const bitsToDecode: UINT32 = accumulator & ((@as(UINT32, 1) << shiftDecode) - 1);
            accumulator >>= shiftDecode;
            nBitsInAccumulator -= nBitsToDecode;

            coefficient |= bitsToDecode << @intCast(nBitsInCoefficient);
            nBitsInCoefficient += nBitsToDecode;
        }
        macros.ASSERT(nBitsInCoefficient == nBitsPerCoefficient);

        if (signedCoefficientBound != 0 and coefficient > 2 * signedCoefficientBound) {
            return .SYMCRYPT_INVALID_BLOB;
        }

        if (signedCoefficientBound != 0) {
            const signedCoeff: INT32 = @as(INT32, @bitCast(signedCoefficientBound)) -% @as(INT32, @bitCast(coefficient));
            coefficient = SymCryptMlDsaSignedCoefficientModQ(signedCoeff);
        }

        peDst.coeffs[i] = coefficient;
    }

    macros.ASSERT(nBitsInAccumulator == 0);
    macros.ASSERT(cbSrcRead == (nBitsPerCoefficient * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8)));

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaVectorEncode(
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    nBitsPerCoefficient: UINT32,
    signedCoefficientBound: UINT32,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    var pbCurr: PBYTE = pbDst;
    const cbEncodedPoly: usize = @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    for (0..pvSrc.nElems) |i| {
        SymCryptMlDsaPolyElementEncode(
            vectorElementConst(i, pvSrc),
            nBitsPerCoefficient,
            signedCoefficientBound,
            pbCurr,
        );
        pbCurr += cbEncodedPoly;
    }
}

pub export fn SymCryptMlDsaVectorDecode(
    pbSrc: PCBYTE,
    nBitsPerCoefficient: UINT32,
    signedCoefficientBound: UINT32,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pbCurr: PCBYTE = pbSrc;
    const cbEncodedPoly: usize = @as(usize, nBitsPerCoefficient) * (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS / 8);

    for (0..pvDst.nElems) |i| {
        const scError = SymCryptMlDsaPolyElementDecode(
            pbCurr,
            nBitsPerCoefficient,
            signedCoefficientBound,
            vectorElement(i, pvDst),
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }
        pbCurr += cbEncodedPoly;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaPkEncode(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pParams = pkMlDsakey.pParams;
    const cbEncodedKey = pParams.cbEncodedPublicKey;

    if (cbDst != cbEncodedKey) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pTemps = SymCryptMlDsaTemporariesAllocateAndInitialize(pParams, 1, 0, 0, 0) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer SymCryptMlDsaTemporariesFree(pTemps);

    const pvT1InvNTT = pTemps.pvRowVectors.?[0];

    @memcpy(pbDst[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE], &pkMlDsakey.publicSeed);
    const pbCurr: PBYTE = pbDst + SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE;

    SymCryptMlDsaVectorCopy(pkMlDsakey.pvt1, pvT1InvNTT);
    SymCryptMlDsaVectorINTT(pvT1InvNTT);

    macros.ASSERT(cbDst - SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE == sizeofEncodedVector(pvT1InvNTT, 10));
    SymCryptMlDsaVectorEncode(pvT1InvNTT, 10, 0, pbCurr);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaPkDecode(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;

    const cbEncodedPoly: UINT32 = SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS * 10 / 8;

    if (cbSrc != pkMlDsakey.pParams.cbEncodedPublicKey) {
        return .SYMCRYPT_WRONG_KEY_SIZE;
    }

    const pTemps = SymCryptMlDsaTemporariesAllocateAndInitialize(pkMlDsakey.pParams, 0, 0, 0, cbEncodedPoly) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer SymCryptMlDsaTemporariesFree(pTemps);

    SymCryptMlDsakeyWipePrivateState(pkMlDsakey);

    var pbCurr: PCBYTE = pbSrc;
    @memcpy(&pkMlDsakey.publicSeed, pbCurr[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE]);
    pbCurr += SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE;

    const pShakeState = &pTemps.shake256State;
    shake.SymCryptShake256Init(pShakeState);
    shake.SymCryptShake256Append(pShakeState, &pkMlDsakey.publicSeed, SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE);

    const pbScratch = pTemps.pbScratch.?;
    for (0..pkMlDsakey.pvt1.nElems) |i| {
        @memcpy(pbScratch[0..cbEncodedPoly], pbCurr[0..cbEncodedPoly]);

        const scError = SymCryptMlDsaPolyElementDecode(
            pbScratch,
            10,
            0,
            vectorElement(i, pkMlDsakey.pvt1),
        );
        if (scError != .SYMCRYPT_NO_ERROR) {
            return scError;
        }

        shake.SymCryptShake256Append(pShakeState, pbScratch, cbEncodedPoly);
        pbCurr += cbEncodedPoly;
    }

    macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbSrc) + cbSrc);

    SymCryptMlDsaVectorNTT(pkMlDsakey.pvt1);

    const scError = SymCryptMlDsaExpandA(
        &pkMlDsakey.publicSeed,
        SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE,
        pkMlDsakey.pmA,
    );
    if (scError != .SYMCRYPT_NO_ERROR) {
        return scError;
    }

    shake.SymCryptShake256Result(pShakeState, &pkMlDsakey.publicKeyHash);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaSkEncode(
    pkMlDsakey: PCSYMCRYPT_MLDSAKEY,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const pParams = pkMlDsakey.pParams;
    const cbEncodedKey = pParams.cbEncodedPrivateKey;

    if (pkMlDsakey.hasPrivateKey == types.FALSE) {
        return .SYMCRYPT_INCOMPATIBLE_FORMAT;
    }

    if (cbDst != cbEncodedKey) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const pTemps = SymCryptMlDsaTemporariesAllocateAndInitialize(pParams, 1, 1, 0, 0) orelse {
        return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
    };
    defer SymCryptMlDsaTemporariesFree(pTemps);

    var pbCurr: PBYTE = pbDst;

    @memcpy(pbCurr[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE], &pkMlDsakey.publicSeed);
    pbCurr += SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE;

    @memcpy(pbCurr[0..SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE], &pkMlDsakey.privateSigningSeed);
    pbCurr += SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE;

    @memcpy(pbCurr[0..SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE], &pkMlDsakey.publicKeyHash);
    pbCurr += SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE;

    {
        const pvs1InvNTT = pTemps.pvColVectors.?[0];
        SymCryptMlDsaVectorCopy(pkMlDsakey.pvs1, pvs1InvNTT);
        SymCryptMlDsaVectorINTT(pvs1InvNTT);

        SymCryptMlDsaVectorEncode(
            pvs1InvNTT,
            pParams.encodedCoefficientBitLength,
            pParams.privateKeyRange,
            pbCurr,
        );
        pbCurr += sizeofEncodedVector(pvs1InvNTT, pParams.encodedCoefficientBitLength);
    }

    {
        const pvs2InvNTT = pTemps.pvRowVectors.?[0];
        SymCryptMlDsaVectorCopy(pkMlDsakey.pvs2, pvs2InvNTT);
        SymCryptMlDsaVectorINTT(pvs2InvNTT);

        SymCryptMlDsaVectorEncode(
            pvs2InvNTT,
            pParams.encodedCoefficientBitLength,
            pParams.privateKeyRange,
            pbCurr,
        );
        pbCurr += sizeofEncodedVector(pvs2InvNTT, pParams.encodedCoefficientBitLength);
    }

    {
        const pvt0InvNTT = pTemps.pvRowVectors.?[0];
        SymCryptMlDsaVectorCopy(pkMlDsakey.pvt0, pvt0InvNTT);
        SymCryptMlDsaVectorINTT(pvt0InvNTT);

        SymCryptMlDsaVectorEncode(
            pvt0InvNTT,
            SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS,
            1 << (SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS - 1),
            pbCurr,
        );
        pbCurr += sizeofEncodedVector(pvt0InvNTT, SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS);
    }

    macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbDst) + cbDst);

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptMlDsaSkDecode(
    pbSrc: PCBYTE,
    cbSrc: SIZE_T,
    flags: UINT32,
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    _ = flags;

    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    const pParams = pkMlDsakey.pParams;
    var pubKeyHashTmp: [SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE]BYTE = undefined;

    if (cbSrc != pParams.cbEncodedPrivateKey) {
        scError = .SYMCRYPT_WRONG_KEY_SIZE;
    } else {
        const pTemps = SymCryptMlDsaTemporariesAllocateAndInitialize(
            pParams,
            2,
            0,
            1,
            pParams.cbEncodedPublicKey,
        );
        if (pTemps == null) {
            scError = .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        } else {
            defer SymCryptMlDsaTemporariesFree(pTemps.?);

            const pvtTmp = pTemps.?.pvRowVectors.?[0];
            const pvt0Tmp = pTemps.?.pvRowVectors.?[1];
            const peTmp = pTemps.?.pePolyElements.?[0];
            const pbEncodedPubKeyTmp = pTemps.?.pbScratch.?;

            pkMlDsakey.hasRootSeed = types.FALSE;
            pkMlDsakey.hasPrivateKey = types.FALSE;
            libmain.SymCryptWipe(@ptrCast(&pkMlDsakey.rootSeed), SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE);

            var pbCurr: PCBYTE = pbSrc;
            @memcpy(&pkMlDsakey.publicSeed, pbCurr[0..SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE]);
            pbCurr += SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE;

            @memcpy(&pkMlDsakey.privateSigningSeed, pbCurr[0..SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE]);
            pbCurr += SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE;

            @memcpy(&pubKeyHashTmp, pbCurr[0..SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE]);
            pbCurr += SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE;

            blk: {
                scError = SymCryptMlDsaExpandA(&pkMlDsakey.publicSeed, SYMCRYPT_MLDSA_PUBLIC_SEED_SIZE, pkMlDsakey.pmA);
                if (scError != .SYMCRYPT_NO_ERROR) break :blk;

                scError = SymCryptMlDsaVectorDecode(
                    pbCurr,
                    pParams.encodedCoefficientBitLength,
                    pParams.privateKeyRange,
                    pkMlDsakey.pvs1,
                );
                if (scError != .SYMCRYPT_NO_ERROR) break :blk;
                pbCurr += sizeofEncodedVector(pkMlDsakey.pvs1, pParams.encodedCoefficientBitLength);

                scError = SymCryptMlDsaVectorDecode(
                    pbCurr,
                    pParams.encodedCoefficientBitLength,
                    pParams.privateKeyRange,
                    pkMlDsakey.pvs2,
                );
                if (scError != .SYMCRYPT_NO_ERROR) break :blk;
                pbCurr += sizeofEncodedVector(pkMlDsakey.pvs2, pParams.encodedCoefficientBitLength);

                scError = SymCryptMlDsaVectorDecode(
                    pbCurr,
                    SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS,
                    1 << (SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS - 1),
                    pvt0Tmp,
                );
                if (scError != .SYMCRYPT_NO_ERROR) break :blk;
                pbCurr += sizeofEncodedVector(pkMlDsakey.pvt0, SYMCRYPT_POWER2ROUND_LOW_ORDER_BITS);

                macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbSrc) + cbSrc);

                SymCryptMlDsaVectorNTT(pkMlDsakey.pvs1);
                SymCryptMlDsaVectorNTT(pkMlDsakey.pvs2);

                SymCryptMlDsakeyComputeT(
                    pkMlDsakey.pmA,
                    pkMlDsakey.pvs1,
                    pkMlDsakey.pvs2,
                    pkMlDsakey.pvt0,
                    pkMlDsakey.pvt1,
                    pvtTmp,
                    peTmp,
                );

                const t0Bytes: [*]const u8 = @ptrCast(pkMlDsakey.pvt0);
                const t0TmpBytes: [*]const u8 = @ptrCast(pvt0Tmp);
                if (!std.mem.eql(u8, t0Bytes[0..pvt0Tmp.cbTotalSize], t0TmpBytes[0..pvt0Tmp.cbTotalSize])) {
                    scError = .SYMCRYPT_INVALID_BLOB;
                    break :blk;
                }

                SymCryptMlDsaVectorNTT(pkMlDsakey.pvt0);
                SymCryptMlDsaVectorNTT(pkMlDsakey.pvt1);

                scError = SymCryptMlDsaPkEncode(pkMlDsakey, pbEncodedPubKeyTmp, pParams.cbEncodedPublicKey);
                if (scError != .SYMCRYPT_NO_ERROR) break :blk;

                shake.SymCryptShake256(
                    pbEncodedPubKeyTmp,
                    pParams.cbEncodedPublicKey,
                    &pkMlDsakey.publicKeyHash,
                    SYMCRYPT_MLDSA_PUBLIC_KEY_HASH_SIZE,
                );

                if (!std.mem.eql(u8, &pkMlDsakey.publicKeyHash, &pubKeyHashTmp)) {
                    scError = .SYMCRYPT_INVALID_BLOB;
                    break :blk;
                }

                pkMlDsakey.hasPrivateKey = types.TRUE;
            }
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        libmain.SymCryptWipe(@ptrCast(&pkMlDsakey.privateSigningSeed), SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvs1);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvs2);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvt0);
    }

    return scError;
}

pub export fn SymCryptMlDsaSigEncode(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbCommitmentHash: PBYTE,
    cbCommitmentHash: SIZE_T,
    pvResponse: PCSYMCRYPT_MLDSA_VECTOR,
    pvHint: PCSYMCRYPT_MLDSA_VECTOR,
    pbDst: PBYTE,
    cbDst: SIZE_T,
) callconv(SYMCRYPT_CALL) void {
    macros.ASSERT(cbDst == pParams.cbEncodedSignature);

    const cbEncodedHint: SIZE_T = @as(SIZE_T, pParams.nHintNonZeroCoeffs) + pvHint.nElems;
    var pbCurr: PBYTE = pbDst;

    @memcpy(pbCurr[0..cbCommitmentHash], pbCommitmentHash[0..cbCommitmentHash]);
    pbCurr += cbCommitmentHash;

    const shiftRange: u5 = @intCast(pParams.maskCoefficientRangeLog2);
    SymCryptMlDsaVectorEncode(
        pvResponse,
        @as(UINT32, pParams.maskCoefficientRangeLog2) + 1,
        @as(UINT32, 1) << shiftRange,
        pbCurr,
    );
    pbCurr += sizeofEncodedVector(pvResponse, @as(UINT32, pParams.maskCoefficientRangeLog2) + 1);

    SymCryptMlDsaHintBitPack(pParams, pvHint, pbCurr);
    pbCurr += cbEncodedHint;

    macros.ASSERT(@intFromPtr(pbCurr) == @intFromPtr(pbDst) + cbDst);
}

pub export fn SymCryptMlDsaSigDecode(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbSig: PCBYTE,
    cbSig: SIZE_T,
    pbCommitmentHash: PBYTE,
    cbCommitmentHash: SIZE_T,
    pvResponse: PSYMCRYPT_MLDSA_VECTOR,
    pvHint: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (cbSig != pParams.cbEncodedSignature) {
        return .SYMCRYPT_WRONG_DATA_SIZE;
    }

    macros.ASSERT(cbCommitmentHash == pParams.cbCommitmentHash);

    var pbCurr: PCBYTE = pbSig;

    @memcpy(pbCommitmentHash[0..cbCommitmentHash], pbSig[0..cbCommitmentHash]);
    pbCurr += cbCommitmentHash;

    const shiftRange: u5 = @intCast(pParams.maskCoefficientRangeLog2);
    _ = SymCryptMlDsaVectorDecode(
        pbCurr,
        @as(UINT32, pParams.maskCoefficientRangeLog2) + 1,
        @as(UINT32, 1) << shiftRange,
        pvResponse,
    );
    pbCurr += sizeofEncodedVector(pvResponse, @as(UINT32, pParams.maskCoefficientRangeLog2) + 1);

    return SymCryptMlDsaHintBitUnpack(pParams, pbCurr, pvHint);
}

pub export fn SymCryptMlDsaHintBitPack(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pvSrc: PCSYMCRYPT_MLDSA_VECTOR,
    pbDst: PBYTE,
) callconv(SYMCRYPT_CALL) void {
    libmain.SymCryptWipe(@ptrCast(pbDst), pParams.nHintNonZeroCoeffs);

    var index: usize = 0;
    for (0..pvSrc.nElems) |i| {
        const peElement = vectorElementConst(i, pvSrc);
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            if (peElement.coeffs[j] != 0) {
                pbDst[index] = @intCast(j);
                index += 1;
            }
        }

        macros.ASSERT(index <= pParams.nHintNonZeroCoeffs);
        pbDst[@as(usize, pParams.nHintNonZeroCoeffs) + i] = @intCast(index);
    }
}

pub export fn SymCryptMlDsaHintBitUnpack(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    pbSrc: PCBYTE,
    pvDst: PSYMCRYPT_MLDSA_VECTOR,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var index: UINT32 = 0;

    for (0..pvDst.nElems) |i| {
        const peElement = vectorElement(i, pvDst);
        SymCryptMlDsaPolyElementSetZero(peElement);

        const maxIndex: UINT32 = pbSrc[@as(usize, pParams.nHintNonZeroCoeffs) + i];
        if (maxIndex < index or maxIndex > pParams.nHintNonZeroCoeffs) {
            return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
        }

        const first: UINT32 = index;
        while (index < maxIndex) : (index += 1) {
            if (index > first and pbSrc[index - 1] >= pbSrc[index]) {
                return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
            }
            peElement.coeffs[pbSrc[index]] = 1;
        }
    }

    var leftover: UINT32 = index;
    while (leftover < pParams.nHintNonZeroCoeffs) : (leftover += 1) {
        if (pbSrc[leftover] != 0) {
            return .SYMCRYPT_SIGNATURE_VERIFICATION_FAILURE;
        }
    }

    return .SYMCRYPT_NO_ERROR;
}

// ==============================================================================================
// Hash OID Validation & Temporaries Allocation
// ==============================================================================================

const HashOidEntry = struct {
    hashId: SYMCRYPT_PQDSA_HASH_ID,
    pOid: PCSYMCRYPT_OID,
    cbHashExpected: SIZE_T,
    fIsXof: bool,
};

const g_hashOidMap = [_]HashOidEntry{
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA224, .pOid = &data_accessors.SymCryptSha224OidList[1], .cbHashExpected = 28, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA256, .pOid = &data_accessors.SymCryptSha256OidList[1], .cbHashExpected = 32, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA384, .pOid = &data_accessors.SymCryptSha384OidList[1], .cbHashExpected = 48, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA512, .pOid = &data_accessors.SymCryptSha512OidList[1], .cbHashExpected = 64, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA512_224, .pOid = &data_accessors.SymCryptSha512_224OidList[1], .cbHashExpected = 28, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA512_256, .pOid = &data_accessors.SymCryptSha512_256OidList[1], .cbHashExpected = 32, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA3_224, .pOid = &sha3.SymCryptSha3_224OidList[1], .cbHashExpected = 28, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA3_256, .pOid = &sha3.SymCryptSha3_256OidList[1], .cbHashExpected = 32, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA3_384, .pOid = &sha3.SymCryptSha3_384OidList[1], .cbHashExpected = 48, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHA3_512, .pOid = &sha3.SymCryptSha3_512OidList[1], .cbHashExpected = 64, .fIsXof = false },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHAKE128, .pOid = &shake.SymCryptShake128OidList[1], .cbHashExpected = 32, .fIsXof = true },
    .{ .hashId = .SYMCRYPT_PQDSA_HASH_ID_SHAKE256, .pOid = &shake.SymCryptShake256OidList[1], .cbHashExpected = 64, .fIsXof = true },
};

pub export fn SymCryptHashMlDsaValidateHashAlgAndGetOid(
    hashAlg: SYMCRYPT_PQDSA_HASH_ID,
    cbHash: SIZE_T,
    ppOid: *PCSYMCRYPT_OID,
) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    for (g_hashOidMap) |entry| {
        if (entry.hashId == hashAlg) {
            macros.ASSERT(entry.pOid.cbOID == SYMCRYPT_MLDSA_SUPPORTED_HASH_OID_SIZE);
            if (entry.fIsXof) {
                if (cbHash < entry.cbHashExpected) {
                    return .SYMCRYPT_INVALID_ARGUMENT;
                }
            } else if (cbHash != entry.cbHashExpected) {
                return .SYMCRYPT_INVALID_ARGUMENT;
            }
            ppOid.* = entry.pOid;
            return .SYMCRYPT_NO_ERROR;
        }
    }

    return .SYMCRYPT_INVALID_ARGUMENT;
}

pub export fn SymCryptMlDsaTemporariesAllocateAndInitialize(
    pParams: PCSYMCRYPT_MLDSA_INTERNAL_PARAMS,
    nRowVectors: UINT32,
    nColVectors: UINT32,
    nPolyElements: UINT32,
    cbScratchIn: UINT32,
) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES {
    const cbScratch: UINT32 = (cbScratchIn + 7) & ~@as(UINT32, 7);

    const ptrSize: UINT32 = @sizeOf(usize);
    const cbTotalSize: UINT32 = @as(UINT32, @sizeOf(SYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES)) +
        (nRowVectors * ptrSize) +
        (nColVectors * ptrSize) +
        (nPolyElements * ptrSize) +
        (nRowVectors * pParams.cbRowVector) +
        (nColVectors * pParams.cbColVector) +
        (nPolyElements * pParams.cbPolyElement) +
        cbScratch;

    const rawPtr = SymCryptCallbackAlloc(cbTotalSize) orelse return null;
    const pbBuffer: PBYTE = @ptrCast(rawPtr);

    libmain.SymCryptWipe(@ptrCast(pbBuffer), cbTotalSize);

    const pTemporaries: PSYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES = @ptrCast(@alignCast(pbBuffer));
    pTemporaries.cbTotalSize = cbTotalSize;
    pTemporaries.nRowVectors = nRowVectors;
    pTemporaries.nColVectors = nColVectors;
    pTemporaries.nPolyElements = nPolyElements;
    pTemporaries.cbScratch = cbScratch;

    var pbCurrent: PBYTE = pbBuffer + @sizeOf(SYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES);

    if (nRowVectors > 0) {
        pTemporaries.pvRowVectors = @ptrCast(@alignCast(pbCurrent));
        pbCurrent += nRowVectors * ptrSize;
    }

    if (nColVectors > 0) {
        pTemporaries.pvColVectors = @ptrCast(@alignCast(pbCurrent));
        pbCurrent += nColVectors * ptrSize;
    }

    if (nPolyElements > 0) {
        pTemporaries.pePolyElements = @ptrCast(@alignCast(pbCurrent));
        pbCurrent += nPolyElements * ptrSize;
    }

    for (0..nRowVectors) |i| {
        pTemporaries.pvRowVectors.?[i] = SymCryptMlDsaVectorCreate(pbCurrent, pParams.cbRowVector, pParams.nRows);
        pbCurrent += pParams.cbRowVector;
    }

    for (0..nColVectors) |i| {
        pTemporaries.pvColVectors.?[i] = SymCryptMlDsaVectorCreate(pbCurrent, pParams.cbColVector, pParams.nCols);
        pbCurrent += pParams.cbColVector;
    }

    for (0..nPolyElements) |i| {
        pTemporaries.pePolyElements.?[i] = SymCryptMlDsaPolyElementCreate(pbCurrent, pParams.cbPolyElement);
        pbCurrent += pParams.cbPolyElement;
    }

    if (cbScratch > 0) {
        pTemporaries.pbScratch = pbCurrent;
        pbCurrent += cbScratch;
    }

    macros.ASSERT(@intFromPtr(pbCurrent) == @intFromPtr(pbBuffer) + cbTotalSize);

    macros.SET_MAGIC(pTemporaries);

    return pTemporaries;
}

pub export fn SymCryptMlDsaTemporariesFree(
    pTemporaries: PSYMCRYPT_MLDSA_INTERNAL_COMPUTATION_TEMPORARIES,
) callconv(SYMCRYPT_CALL) void {
    macros.CHECK_MAGIC(pTemporaries);

    const cbTotalSize = pTemporaries.cbTotalSize;
    libmain.SymCryptWipe(@ptrCast(pTemporaries), cbTotalSize);
    SymCryptCallbackFree(@ptrCast(pTemporaries));
}

pub export fn SymCryptMlDsakeyWipePrivateState(
    pkMlDsakey: PSYMCRYPT_MLDSAKEY,
) callconv(SYMCRYPT_CALL) void {
    if (pkMlDsakey.hasRootSeed != types.FALSE) {
        libmain.SymCryptWipe(@ptrCast(&pkMlDsakey.rootSeed), SYMCRYPT_MLDSA_PRIVATE_SEED_SIZE);
        pkMlDsakey.hasRootSeed = types.FALSE;
    }

    if (pkMlDsakey.hasPrivateKey != types.FALSE) {
        libmain.SymCryptWipe(@ptrCast(&pkMlDsakey.privateSigningSeed), SYMCRYPT_MLDSA_PRIVATE_SIGNING_SEED_SIZE);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvs1);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvs2);
        SymCryptMlDsaVectorSetZero(pkMlDsakey.pvt0);
        pkMlDsakey.hasPrivateKey = types.FALSE;
    }
}
