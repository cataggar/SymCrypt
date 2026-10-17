// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");
const h = @import("main_harness.zig");
const cb = @import("callback.zig");
const kat = @import("kat.zig");
const rng = @import("rng.zig");
const rm = @import("result_merge.zig");

const STATUS_SUCCESS: i32 = 0;
const STATUS_NOT_SUPPORTED: i32 = @bitCast(@as(u32, 0xC00000BB));

const SYMCRYPT_NO_ERROR: u32 = 0;
const SYMCRYPT_INVALID_BLOB: u32 = 0x800C;

const SYMCRYPT_MLKEM_PARAMS_MLKEM512: u32 = 1;
const SYMCRYPT_MLKEM_PARAMS_MLKEM768: u32 = 2;
const SYMCRYPT_MLKEM_PARAMS_MLKEM1024: u32 = 3;

const SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED: u32 = 1;
const SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY: u32 = 2;
const SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY: u32 = 3;

const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256: u32 = 1;
const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519: u32 = 2;
const SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384: u32 = 3;

const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED: u32 = 1;
const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY: u32 = 2;
const SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY: u32 = 3;

const SYMCRYPT_CACHED_ECURVE_ID_NIST_P256: u32 = 0;
const SYMCRYPT_CACHED_ECURVE_ID_NIST_P384: u32 = 1;
const SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519: u32 = 2;

const SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS: usize = 256;
const SYMCRYPT_MLKEM_Q: u32 = 3329;

const SYMCRYPT_MLKEM_POLYELEMENT = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]u16 align(32),
};

const SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR = extern struct {
    coeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]u32 align(32),
};

const SYMCRYPT_MLKEMKEY = opaque {};
const SYMCRYPT_COMPOSITE_MLKEMKEY = opaque {};

pub const MLKEMKEY_TESTBLOB = extern struct {
    params: u32 = 0,
    format: u32 = 0,
    abKeyBlob: [3168]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

pub const COMPOSITE_MLKEMKEY_TESTBLOB = extern struct {
    params: u32 = 0,
    format: u32 = 0,
    abKeyBlob: [1665]u8 = @splat(0),
    cbKeyBlob: usize = 0,
};

extern fn SymCryptMlKemPolyElementCreate(
    pbBuffer: [*]u8,
    cbBuffer: u32,
) callconv(.c) ?*SYMCRYPT_MLKEM_POLYELEMENT;

extern fn SymCryptMlKemPolyElementAccumulatorCreate(
    pbBuffer: [*]u8,
    cbBuffer: u32,
) callconv(.c) ?*SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR;

extern fn SymCryptMlKemPolyElementNTT(
    peSrc: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementINTTAndMulR(
    peSrc: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementAdd(
    peSrc1: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementSub(
    peSrc1: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementMulAndAccumulate(
    peSrc1: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peSrc2: *const SYMCRYPT_MLKEM_POLYELEMENT,
    paDst: *SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
) callconv(.c) void;

extern fn SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(
    paSrc: *SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementCompressAndEncode(
    peSrc: *const SYMCRYPT_MLKEM_POLYELEMENT,
    nBitsPerCoefficient: u32,
    pbDst: [*]u8,
) callconv(.c) void;

extern fn SymCryptMlKemPolyElementDecodeAndDecompress(
    pbSrc: [*]const u8,
    nBitsPerCoefficient: u32,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) u32;

extern fn SymCryptMlKemPolyElementMulR(
    peSrc: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) callconv(.c) void;

extern fn SymCryptMlKemkeyAllocate(params: u32) callconv(.c) ?*SYMCRYPT_MLKEMKEY;
extern fn SymCryptMlKemkeyFree(pkMlKemkey: *SYMCRYPT_MLKEMKEY) callconv(.c) void;
extern fn SymCryptMlKemkeyGenerate(pkMlKemkey: *SYMCRYPT_MLKEMKEY, flags: u32) callconv(.c) u32;
extern fn SymCryptMlKemkeySetValue(
    pbSrc: [*]const u8,
    cbSrc: usize,
    mlKemkeyFormat: u32,
    flags: u32,
    pkMlKemkey: *SYMCRYPT_MLKEMKEY,
) callconv(.c) u32;
extern fn SymCryptMlKemkeyGetValue(
    pkMlKemkey: *const SYMCRYPT_MLKEMKEY,
    pbDst: [*]u8,
    cbDst: usize,
    mlKemkeyFormat: u32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptMlKemSizeofKeyFormatFromParams(
    params: u32,
    mlKemkeyFormat: u32,
    pcbKeyFormat: *usize,
) callconv(.c) u32;
extern fn SymCryptMlKemSizeofCiphertextFromParams(
    params: u32,
    pcbCiphertext: *usize,
) callconv(.c) u32;
extern fn SymCryptMlKemEncapsulate(
    pkMlKemkey: *const SYMCRYPT_MLKEMKEY,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) u32;
extern fn SymCryptMlKemDecapsulate(
    pkMlKemkey: *const SYMCRYPT_MLKEMKEY,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) u32;

extern fn SymCryptCompositeMlKemkeyAllocate(params: u32) callconv(.c) ?*SYMCRYPT_COMPOSITE_MLKEMKEY;
extern fn SymCryptCompositeMlKemkeyFree(pkCompositeMlKemkey: *SYMCRYPT_COMPOSITE_MLKEMKEY) callconv(.c) void;
extern fn SymCryptCompositeMlKemkeyGenerate(pkCompositeMlKemkey: *SYMCRYPT_COMPOSITE_MLKEMKEY, flags: u32) callconv(.c) u32;
extern fn SymCryptCompositeMlKemkeySetValue(
    pbSrc: [*]const u8,
    cbSrc: usize,
    compositeMlKemkeyFormat: u32,
    flags: u32,
    pkCompositeMlKemkey: *SYMCRYPT_COMPOSITE_MLKEMKEY,
) callconv(.c) u32;
extern fn SymCryptCompositeMlKemkeyGetValue(
    pkCompositeMlKemkey: *const SYMCRYPT_COMPOSITE_MLKEMKEY,
    pbDst: [*]u8,
    cbDst: usize,
    compositeMlKemkeyFormat: u32,
    flags: u32,
) callconv(.c) u32;
extern fn SymCryptCompositeMlKemSizeofKeyFormatFromParams(
    params: u32,
    compositeMlKemkeyFormat: u32,
    pcbKeyFormat: *usize,
) callconv(.c) u32;
extern fn SymCryptCompositeMlKemSizeofCiphertextFromParams(
    params: u32,
    pcbCiphertext: *usize,
) callconv(.c) u32;
extern fn SymCryptCompositeMlKemEncapsulate(
    pkCompositeMlKemkey: *const SYMCRYPT_COMPOSITE_MLKEMKEY,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) u32;
extern fn SymCryptCompositeMlKemDecapsulate(
    pkCompositeMlKemkey: *const SYMCRYPT_COMPOSITE_MLKEMKEY,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) u32;

extern fn SymCryptCompositeGetSizeOfEncodedEcSk(curveId: u32) callconv(.c) usize;

extern fn scTestKemMultiImpCreate(algName: [*:0]const u8) callconv(.c) ?*anyopaque;
extern fn scTestKemMultiImpDestroy(pMultiImp: *anyopaque) callconv(.c) void;
extern fn scTestKemMultiImpGetCount(pMultiImp: *anyopaque) callconv(.c) usize;
extern fn scTestKemMultiImpGetImp(pMultiImp: *anyopaque, idx: usize) callconv(.c) *anyopaque;
extern fn scTestKemMultiImpGetImpName(pMultiImp: *anyopaque, idx: usize) callconv(.c) [*:0]const u8;
extern fn scTestKemMultiImpAddKatError(pMultiImp: *anyopaque, nErrorKatFailure: i64) callconv(.c) void;

extern fn scTestKemImpSetKeyFromTestBlob(
    pImp: *anyopaque,
    pcbTestKeyBlob: ?[*]const u8,
    cbTestKeyBlob: usize,
    canDecapsulate: c_int,
) callconv(.c) i32;

extern fn scTestKemImpGetBlobFromKey(
    pImp: *anyopaque,
    blobType: u32,
    pbBlob: [*]u8,
    cbBlob: usize,
) callconv(.c) i32;

extern fn scTestKemImpEncapsulate(
    pImp: *anyopaque,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) i32;

extern fn scTestKemImpEncapsulateEx(
    pImp: *anyopaque,
    pbRandom: [*]const u8,
    cbRandom: usize,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
    pbCiphertext: [*]u8,
    cbCiphertext: usize,
) callconv(.c) i32;

extern fn scTestKemImpDecapsulate(
    pImp: *anyopaque,
    pbCiphertext: [*]const u8,
    cbCiphertext: usize,
    pbAgreedSecret: [*]u8,
    cbAgreedSecret: usize,
) callconv(.c) i32;

fn testSymCryptMlKemPolyEqual(
    peA: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peB: *const SYMCRYPT_MLKEM_POLYELEMENT,
) bool {
    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        if (peA.coeffs[i] != peB.coeffs[i]) {
            h.ziprint("\nCoefficient {d} mismatch: {d} != {d}\n", .{ @as(u32, @intCast(i)), peA.coeffs[i], peB.coeffs[i] });
            h.ziprint("A:\n", .{});
            for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
                h.ziprint("{d: >4} ", .{peA.coeffs[j]});
                if ((j & 15) == 15) {
                    h.ziprint("\n", .{});
                }
            }
            h.ziprint("B:\n", .{});
            for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
                h.ziprint("{d: >4} ", .{peB.coeffs[j]});
                if ((j & 15) == 15) {
                    h.ziprint("\n", .{});
                }
            }
            return false;
        }
    }
    return true;
}

fn testMlKemPolyNaiveSchoolbookMul(
    peA: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peB: *const SYMCRYPT_MLKEM_POLYELEMENT,
    peDst: *SYMCRYPT_MLKEM_POLYELEMENT,
) void {
    var acoeffs: [SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS]u32 = @splat(0);

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS - i) |j| {
            acoeffs[i + j] += @as(u32, peA.coeffs[i]) * @as(u32, peB.coeffs[j]);
        }
        for (SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS - i..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |j| {
            acoeffs[i + j - SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS] += @as(u32, peA.coeffs[i]) * (SYMCRYPT_MLKEM_Q - @as(u32, peB.coeffs[j]));
        }
    }

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peDst.coeffs[i] = @intCast(acoeffs[i] % SYMCRYPT_MLKEM_Q);
    }
}

fn testMlKemArithmetic() void {
    var abPolyElementBufferA: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferB: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferC: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferD: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferE: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferZero: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferOne: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementBufferOneNTT: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)]u8 align(32) = undefined;
    var abPolyElementAccumulatorBuffer: [@sizeOf(SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR)]u8 align(32) = undefined;
    var encodeBuffer: [384]u8 = undefined;

    const peA = SymCryptMlKemPolyElementCreate(&abPolyElementBufferA, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peB = SymCryptMlKemPolyElementCreate(&abPolyElementBufferB, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peC = SymCryptMlKemPolyElementCreate(&abPolyElementBufferC, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peD = SymCryptMlKemPolyElementCreate(&abPolyElementBufferD, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peE = SymCryptMlKemPolyElementCreate(&abPolyElementBufferE, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peZero = SymCryptMlKemPolyElementCreate(&abPolyElementBufferZero, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peOne = SymCryptMlKemPolyElementCreate(&abPolyElementBufferOne, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const peOneNTT = SymCryptMlKemPolyElementCreate(&abPolyElementBufferOneNTT, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT)).?;
    const paTmp = SymCryptMlKemPolyElementAccumulatorCreate(&abPolyElementAccumulatorBuffer, @sizeOf(SYMCRYPT_MLKEM_POLYELEMENT_ACCUMULATOR)).?;

    for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |i| {
        peZero.coeffs[i] = 0;
        peOne.coeffs[i] = 0;
        peOneNTT.coeffs[i] = 0;
        paTmp.coeffs[i] = 0;
    }

    peOne.coeffs[0] = 1;
    peOneNTT.coeffs[0] = 1;

    SymCryptMlKemPolyElementNTT(peOneNTT);

    SymCryptMlKemPolyElementAdd(peZero, peZero, peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peZero), "(0+0) != 0");

    SymCryptMlKemPolyElementNTT(peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peZero), "NTT(0) != 0");

    SymCryptMlKemPolyElementINTTAndMulR(peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peZero), "INTT(0) .* R != 0");

    SymCryptMlKemPolyElementAdd(peOne, peZero, peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peOne), "1 + 0 != 1");

    SymCryptMlKemPolyElementSub(peOne, peOne, peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peZero), "1 - 1 != 0");

    SymCryptMlKemPolyElementMulAndAccumulate(peOneNTT, peOneNTT, paTmp);
    SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peD);
    SymCryptMlKemPolyElementINTTAndMulR(peD);
    h.check(testSymCryptMlKemPolyEqual(peD, peOne), "INTT(((NTT(1) o NTT(1)) ./ R) + 0) .* R != 1");

    const testStepValue: u32 = 29;
    var i: u32 = 0;
    while (i < SYMCRYPT_MLKEM_Q) : (i += testStepValue) {
        for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |k| {
            peA.coeffs[k] = @intCast((i + @as(u32, @intCast(k))) % SYMCRYPT_MLKEM_Q);
        }

        for (1..13) |k| {
            const nBits: u32 = @intCast(k);
            SymCryptMlKemPolyElementCompressAndEncode(peA, nBits, &encodeBuffer);
            _ = SymCryptMlKemPolyElementDecodeAndDecompress(&encodeBuffer, nBits, peB);

            if (nBits == 12) {
                h.check3(testSymCryptMlKemPolyEqual(peA, peB), "({d}): decode_12(encode_12(A)) != A", i);
            }

            SymCryptMlKemPolyElementCompressAndEncode(peB, nBits, &encodeBuffer);
            _ = SymCryptMlKemPolyElementDecodeAndDecompress(&encodeBuffer, nBits, peA);

            h.check4(testSymCryptMlKemPolyEqual(peA, peB), "({d}, {d}): decode(encode(decode(encode(A)) != decode(encode(A))", i, nBits);
        }

        SymCryptMlKemPolyElementSub(peA, peA, peD);
        h.check3(testSymCryptMlKemPolyEqual(peD, peZero), "({d}): (A-A) != 0", i);

        SymCryptMlKemPolyElementAdd(peA, peZero, peC);
        h.check3(testSymCryptMlKemPolyEqual(peC, peA), "({d}): (A+0) != A", i);

        SymCryptMlKemPolyElementAdd(peZero, peA, peC);
        h.check3(testSymCryptMlKemPolyEqual(peC, peA), "({d}): (0+A) != A", i);

        SymCryptMlKemPolyElementMulAndAccumulate(peA, peZero, paTmp);
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peD);
        h.check3(testSymCryptMlKemPolyEqual(peD, peZero), "({d}): ((A o 0) ./ R) + 0 != 0", i);

        SymCryptMlKemPolyElementMulR(peC, peC);
        SymCryptMlKemPolyElementMulAndAccumulate(peC, peOneNTT, paTmp);
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peD);
        h.check3(testSymCryptMlKemPolyEqual(peD, peA), "({d}): (((A .* R) o NTT(1)) ./ R) + 0 != A", i);

        SymCryptMlKemPolyElementAdd(peA, peZero, peC);
        SymCryptMlKemPolyElementAdd(peZero, peZero, peD);

        SymCryptMlKemPolyElementNTT(peC);
        SymCryptMlKemPolyElementMulAndAccumulate(peC, peOneNTT, paTmp);
        SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peD);
        SymCryptMlKemPolyElementINTTAndMulR(peD);
        h.check3(testSymCryptMlKemPolyEqual(peD, peA), "({d}): INTT( ((NTT(A) o NTT(1)) ./ R) + 0 ) .* R != A", i);

        var j: u32 = 0;
        while (j < SYMCRYPT_MLKEM_Q) : (j += testStepValue) {
            for (0..SYMCRYPT_MLWE_POLYNOMIAL_COEFFICIENTS) |k| {
                peB.coeffs[k] = @intCast((j + 3 * @as(u32, @intCast(k))) % SYMCRYPT_MLKEM_Q);
            }

            SymCryptMlKemPolyElementAdd(peA, peB, peC);
            SymCryptMlKemPolyElementAdd(peB, peA, peD);
            h.check4(testSymCryptMlKemPolyEqual(peC, peD), "({d}, {d}): (A+B) != (B+A)", i, j);

            SymCryptMlKemPolyElementSub(peC, peB, peD);
            h.check4(testSymCryptMlKemPolyEqual(peD, peA), "({d}, {d}): (A+B)-B != A", i, j);

            SymCryptMlKemPolyElementNTT(peC);
            SymCryptMlKemPolyElementNTT(peD);
            SymCryptMlKemPolyElementAdd(peB, peZero, peE);
            SymCryptMlKemPolyElementNTT(peE);

            SymCryptMlKemPolyElementSub(peC, peD, peC);
            h.check4(testSymCryptMlKemPolyEqual(peC, peE), "({d}, {d}): NTT(A+B)-NTT(A) != NTT(B)", i, j);

            SymCryptMlKemPolyElementSub(peE, peE, peE);
            SymCryptMlKemPolyElementMulAndAccumulate(peC, peD, paTmp);
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peE);
            SymCryptMlKemPolyElementINTTAndMulR(peE);

            testMlKemPolyNaiveSchoolbookMul(peA, peB, peC);
            h.check4(testSymCryptMlKemPolyEqual(peC, peE), "({d}, {d}): INTT(((NTT(A) o NTT(B)) ./ R) + 0) .* R != (A o B)", i, j);

            SymCryptMlKemPolyElementAdd(peA, peB, peC);
            SymCryptMlKemPolyElementSub(peA, peB, peD);

            SymCryptMlKemPolyElementMulAndAccumulate(peC, peD, paTmp);
            SymCryptMlKemPolyElementSub(peC, peC, peC);
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peC);

            SymCryptMlKemPolyElementSub(peZero, peB, peD);
            SymCryptMlKemPolyElementMulAndAccumulate(peA, peA, paTmp);
            SymCryptMlKemPolyElementMulAndAccumulate(peB, peD, paTmp);
            SymCryptMlKemPolyElementSub(peD, peD, peD);
            SymCryptMlKemMontgomeryReduceAndAddPolyElementAccumulatorToPolyElement(paTmp, peD);

            h.check4(testSymCryptMlKemPolyEqual(peC, peD), "({d}, {d}): (A+B) o (A-B) != (A o A) + (B o -B)", i, j);
        }
    }
}

const KemMultiImp = struct {
    pHandle: *anyopaque,
    comps: [16]usize = @splat(0),
    nComps: usize = 0,
    canDecapsulate: bool = false,
    nErrorKatFailure: i64 = 0,

    fn init(algName: [*:0]const u8) ?KemMultiImp {
        const p = scTestKemMultiImpCreate(algName) orelse return null;
        if (scTestKemMultiImpGetCount(p) == 0) {
            scTestKemMultiImpDestroy(p);
            return null;
        }
        return KemMultiImp{ .pHandle = p };
    }

    fn deinit(self: *KemMultiImp) void {
        if (self.nErrorKatFailure != 0) {
            scTestKemMultiImpAddKatError(self.pHandle, self.nErrorKatFailure);
        }
        scTestKemMultiImpDestroy(self.pHandle);
    }

    fn setKeyFromTestBlob(self: *KemMultiImp, pcbTestKeyBlob: ?[*]const u8, cbKeyBlob: usize, canDecapsulate: bool) i32 {
        self.nComps = 0;
        self.canDecapsulate = canDecapsulate;

        const count = scTestKemMultiImpGetCount(self.pHandle);
        for (0..count) |i| {
            const pImp = scTestKemMultiImpGetImp(self.pHandle, i);
            if (scTestKemImpSetKeyFromTestBlob(pImp, pcbTestKeyBlob, cbKeyBlob, if (canDecapsulate) 1 else 0) == STATUS_SUCCESS) {
                self.comps[self.nComps] = i;
                self.nComps += 1;
            }
        }

        return if (self.nComps == 0) STATUS_NOT_SUPPORTED else STATUS_SUCCESS;
    }

    fn getBlobFromKey(self: *KemMultiImp, blobType: u32, pbBlob: []u8) i32 {
        var abBlob: [3169]u8 = undefined;
        var resAgreedSecret = rm.ResultMerge.init();
        defer resAgreedSecret.deinit();
        const cbBlob = pbBlob.len;

        h.check(cbBlob < abBlob.len, "Buffer too small");

        for (0..self.nComps) |compIdx| {
            const impIdx = self.comps[compIdx];
            const pImp = scTestKemMultiImpGetImp(self.pHandle, impIdx);

            @memset(abBlob[0 .. cbBlob + 1], 'b');
            const ntStatus = scTestKemImpGetBlobFromKey(pImp, blobType, &abBlob, cbBlob);
            h.check((ntStatus == STATUS_SUCCESS) or (ntStatus == STATUS_NOT_SUPPORTED), "Failure during KEM getBlobFromKey");
            h.check(abBlob[cbBlob] == 'b', "?");

            if (ntStatus == STATUS_SUCCESS) {
                resAgreedSecret.addResult(pImp, abBlob[0..cbBlob]);
            }
        }

        resAgreedSecret.getResult(pbBlob);
        return STATUS_SUCCESS;
    }

    fn encapsulate(self: *KemMultiImp, pbAgreedSecret: []u8, pbCiphertext: []u8) i32 {
        var abEncapsAgreedSecret: [33]u8 = undefined;
        var abEncapsCiphertext: [1666]u8 = undefined;
        var abDecapsAgreedSecret: [33]u8 = undefined;
        var nEncapsulations: u32 = 0;

        const cbAgreedSecret = pbAgreedSecret.len;
        const cbCiphertext = pbCiphertext.len;

        h.check(cbAgreedSecret < abEncapsAgreedSecret.len, "Buffer too small");
        h.check(cbCiphertext < abEncapsCiphertext.len, "Buffer too small");
        h.check(cbAgreedSecret < abDecapsAgreedSecret.len, "Buffer too small");

        for (0..self.nComps) |compIdx| {
            const i = self.comps[compIdx];
            const pImpI = scTestKemMultiImpGetImp(self.pHandle, i);
            const nameI = scTestKemMultiImpGetImpName(self.pHandle, i);

            @memset(abEncapsAgreedSecret[0 .. cbAgreedSecret + 1], 'd');
            @memset(abEncapsCiphertext[0 .. cbCiphertext + 1], 'c');
            var ntStatus = scTestKemImpEncapsulate(
                pImpI,
                &abEncapsAgreedSecret,
                cbAgreedSecret,
                &abEncapsCiphertext,
                cbCiphertext,
            );
            h.check(ntStatus == STATUS_SUCCESS, "Failure during KEM Encapsulate");
            h.check(abEncapsAgreedSecret[cbAgreedSecret] == 'd', "?");
            h.check(abEncapsCiphertext[cbCiphertext] == 'c', "?");

            if (self.canDecapsulate) {
                for (0..self.nComps) |compIdxJ| {
                    const j = self.comps[compIdxJ];
                    const pImpJ = scTestKemMultiImpGetImp(self.pHandle, j);
                    const nameJ = scTestKemMultiImpGetImpName(self.pHandle, j);

                    ntStatus = scTestKemImpDecapsulate(
                        pImpJ,
                        &abEncapsCiphertext,
                        cbCiphertext,
                        &abDecapsAgreedSecret,
                        cbAgreedSecret,
                    );
                    h.check4(ntStatus == STATUS_SUCCESS, "KEM encapsulate -> decapsulate failure {s}, {s}", std.mem.span(nameI), std.mem.span(nameJ));
                    h.check4(
                        std.mem.eql(u8, abEncapsAgreedSecret[0..cbAgreedSecret], abDecapsAgreedSecret[0..cbAgreedSecret]),
                        "KEM encapsulate -> decapsulate agreed secret mismatch {s}, {s}",
                        std.mem.span(nameI),
                        std.mem.span(nameJ),
                    );
                }
            }

            nEncapsulations += 1;
            if ((rng.g_rng.byte() % nEncapsulations) == 0) {
                @memcpy(pbAgreedSecret, abEncapsAgreedSecret[0..cbAgreedSecret]);
                @memcpy(pbCiphertext, abEncapsCiphertext[0..cbCiphertext]);
            }
        }

        return STATUS_SUCCESS;
    }

    fn encapsulateEx(
        self: *KemMultiImp,
        pbRandom: []const u8,
        pbAgreedSecret: []u8,
        pbCiphertext: []u8,
    ) i32 {
        var abEncapsAgreedSecret: [33]u8 = undefined;
        var abEncapsCiphertext: [1666]u8 = undefined;
        var resAgreedSecret = rm.ResultMerge.init();
        defer resAgreedSecret.deinit();
        var resCipherText = rm.ResultMerge.init();
        defer resCipherText.deinit();

        const cbAgreedSecret = pbAgreedSecret.len;
        const cbCiphertext = pbCiphertext.len;

        h.check(cbAgreedSecret < abEncapsAgreedSecret.len, "Buffer too small");
        h.check(cbCiphertext < abEncapsCiphertext.len, "Buffer too small");

        for (0..self.nComps) |compIdx| {
            const i = self.comps[compIdx];
            const pImp = scTestKemMultiImpGetImp(self.pHandle, i);

            @memset(abEncapsAgreedSecret[0 .. cbAgreedSecret + 1], 'd');
            @memset(abEncapsCiphertext[0 .. cbCiphertext + 1], 'c');
            const ntStatus = scTestKemImpEncapsulateEx(
                pImp,
                pbRandom.ptr,
                pbRandom.len,
                &abEncapsAgreedSecret,
                cbAgreedSecret,
                &abEncapsCiphertext,
                cbCiphertext,
            );
            h.check(abEncapsAgreedSecret[cbAgreedSecret] == 'd', "?");
            h.check(abEncapsCiphertext[cbCiphertext] == 'c', "?");

            if (ntStatus != STATUS_NOT_SUPPORTED) {
                h.check(ntStatus == STATUS_SUCCESS, "Failure during KEM EncapsulateEx");
                resAgreedSecret.addResult(pImp, abEncapsAgreedSecret[0..cbAgreedSecret]);
                resCipherText.addResult(pImp, abEncapsCiphertext[0..cbCiphertext]);
            }
        }

        resAgreedSecret.getResult(pbAgreedSecret);
        resCipherText.getResultEx(pbCiphertext, false);

        return STATUS_SUCCESS;
    }

    fn decapsulate(self: *KemMultiImp, pbCiphertext: []const u8, pbAgreedSecret: []u8) i32 {
        var abDecapsAgreedSecret: [33]u8 = undefined;
        var resAgreedSecret = rm.ResultMerge.init();
        defer resAgreedSecret.deinit();
        var resStatus = rm.ResultMerge.init();
        defer resStatus.deinit();
        var b: [4]u8 = undefined;

        const cbAgreedSecret = pbAgreedSecret.len;

        h.check(cbAgreedSecret < abDecapsAgreedSecret.len, "Buffer too small");
        h.check(self.canDecapsulate, "Attempt to decapsulate with a key that does not support it");

        for (0..self.nComps) |compIdx| {
            const i = self.comps[compIdx];
            const pImp = scTestKemMultiImpGetImp(self.pHandle, i);

            @memset(abDecapsAgreedSecret[0 .. cbAgreedSecret + 1], 'd');
            const ntStatus = scTestKemImpDecapsulate(
                pImp,
                pbCiphertext.ptr,
                pbCiphertext.len,
                &abDecapsAgreedSecret,
                cbAgreedSecret,
            );
            h.check(abDecapsAgreedSecret[cbAgreedSecret] == 'd', "?");

            std.mem.writeInt(u32, &b, @bitCast(ntStatus), .big);
            resStatus.addResult(pImp, &b);
            resAgreedSecret.addResult(pImp, abDecapsAgreedSecret[0..cbAgreedSecret]);
        }

        resAgreedSecret.getResult(pbAgreedSecret);
        resStatus.getResultEx(&b, false);
        return @bitCast(std.mem.readInt(u32, &b, .big));
    }
};

const SYMCRYPT_TEST_MLKEM_PARAMS = struct {
    pszParamsName: [:0]const u8,
    params: u32,
};

const rgTestMlKemParams = [_]SYMCRYPT_TEST_MLKEM_PARAMS{
    .{ .pszParamsName = "ML-KEM-512", .params = SYMCRYPT_MLKEM_PARAMS_MLKEM512 },
    .{ .pszParamsName = "ML-KEM-768", .params = SYMCRYPT_MLKEM_PARAMS_MLKEM768 },
    .{ .pszParamsName = "ML-KEM-1024", .params = SYMCRYPT_MLKEM_PARAMS_MLKEM1024 },
};

const MlKemDef = struct {
    const TestParamsType = SYMCRYPT_TEST_MLKEM_PARAMS;
    const TestBlobType = MLKEMKEY_TESTBLOB;
    const KeyType = SYMCRYPT_MLKEMKEY;

    const FormatFull: u32 = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED;
    const FormatDecaps: u32 = SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY;
    const FormatEncaps: u32 = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY;

    const MaxCiphertextSize: usize = 1568;
    const AgreedSecretSize: usize = 32;
    const MaxEncapsKeyBlobSize: usize = 1568;
    const MaxDecapsKeyBlobSize: usize = 3168;
    const PrivateSeedSize: usize = 64;

    const KeyAllocate = SymCryptMlKemkeyAllocate;
    const KeyFree = SymCryptMlKemkeyFree;
    const KeyGenerate = SymCryptMlKemkeyGenerate;
    const KeySetValue = SymCryptMlKemkeySetValue;
    const KeyGetValue = SymCryptMlKemkeyGetValue;
    const SizeofKeyFormatFromParams = SymCryptMlKemSizeofKeyFormatFromParams;
    const SizeofCiphertextFromParams = SymCryptMlKemSizeofCiphertextFromParams;
    const Encapsulate = SymCryptMlKemEncapsulate;
    const Decapsulate = SymCryptMlKemDecapsulate;
};

const SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS = struct {
    pszParamsName: [:0]const u8,
    params: u32,
    curveId: u32,
};

const rgTestCompositeMlKemParams = [_]SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS{
    .{
        .pszParamsName = "ML-KEM-768-P256",
        .params = SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_P256,
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P256,
    },
    .{
        .pszParamsName = "ML-KEM-768-X25519",
        .params = SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM768_X25519,
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519,
    },
    .{
        .pszParamsName = "ML-KEM-1024-P384",
        .params = SYMCRYPT_COMPOSITE_MLKEM_PARAMS_MLKEM1024_P384,
        .curveId = SYMCRYPT_CACHED_ECURVE_ID_NIST_P384,
    },
};

const CompositeMlKemDef = struct {
    const TestParamsType = SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS;
    const TestBlobType = COMPOSITE_MLKEMKEY_TESTBLOB;
    const KeyType = SYMCRYPT_COMPOSITE_MLKEMKEY;

    const FormatFull: u32 = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED;
    const FormatDecaps: u32 = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY;
    const FormatEncaps: u32 = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY;

    const MaxCiphertextSize: usize = 1665;
    const AgreedSecretSize: usize = 32;
    const MaxEncapsKeyBlobSize: usize = 1665;
    const MaxDecapsKeyBlobSize: usize = 128;
    const PrivateSeedSize: usize = 32;

    const KeyAllocate = SymCryptCompositeMlKemkeyAllocate;
    const KeyFree = SymCryptCompositeMlKemkeyFree;
    const KeyGenerate = SymCryptCompositeMlKemkeyGenerate;
    const KeySetValue = SymCryptCompositeMlKemkeySetValue;
    const KeyGetValue = SymCryptCompositeMlKemkeyGetValue;
    const SizeofKeyFormatFromParams = SymCryptCompositeMlKemSizeofKeyFormatFromParams;
    const SizeofCiphertextFromParams = SymCryptCompositeMlKemSizeofCiphertextFromParams;
    const Encapsulate = SymCryptCompositeMlKemEncapsulate;
    const Decapsulate = SymCryptCompositeMlKemDecapsulate;
};

fn testKemHighLevelAPIGeneric(
    comptime KemDef: type,
    algName: [*:0]const u8,
    testParamsSlice: []const KemDef.TestParamsType,
) void {
    var kemImpOpt = KemMultiImp.init(algName);
    if (kemImpOpt == null) return;
    var kemImp = &kemImpOpt.?;
    defer kemImp.deinit();

    var ntStatus: i32 = STATUS_SUCCESS;
    var scError: u32 = SYMCRYPT_NO_ERROR;

    var keyTestBlobFull = KemDef.TestBlobType{ .format = KemDef.FormatFull };
    var keyTestBlobDecaps = KemDef.TestBlobType{ .format = KemDef.FormatDecaps };
    var keyTestBlobEncaps = KemDef.TestBlobType{ .format = KemDef.FormatEncaps };

    var abCipherText: [KemDef.MaxCiphertextSize]u8 = undefined;
    var abAgreedSecretEncaps: [KemDef.AgreedSecretSize]u8 = undefined;
    var abAgreedSecretDecaps: [KemDef.AgreedSecretSize]u8 = undefined;
    var cbCipherText: usize = 0;

    for (testParamsSlice) |tp| {
        const params = tp.params;

        keyTestBlobFull.params = params;
        keyTestBlobDecaps.params = params;
        keyTestBlobEncaps.params = params;

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatFull, &keyTestBlobFull.cbKeyBlob);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for full key failed with 0x{x}", scError);
        h.check(keyTestBlobFull.cbKeyBlob <= keyTestBlobFull.abKeyBlob.len, "?");

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatDecaps, &keyTestBlobDecaps.cbKeyBlob);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for decapsulation key failed with 0x{x}", scError);
        h.check(keyTestBlobDecaps.cbKeyBlob <= keyTestBlobDecaps.abKeyBlob.len, "?");

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatEncaps, &keyTestBlobEncaps.cbKeyBlob);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SizeOfKeyFormatFromParams for encapsulation key failed with 0x{x}", scError);
        h.check(keyTestBlobEncaps.cbKeyBlob <= keyTestBlobEncaps.abKeyBlob.len, "?");

        scError = KemDef.SizeofCiphertextFromParams(params, &cbCipherText);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SizeOfCiphertextFromParams failed with 0x{x}", scError);
        h.check(cbCipherText <= abCipherText.len, "?");

        for (0..100) |_| {
            h.GENRANDOM(&keyTestBlobFull.abKeyBlob, @intCast(keyTestBlobFull.cbKeyBlob));

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobFull), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = kemImp.getBlobFromKey(KemDef.FormatDecaps, keyTestBlobDecaps.abKeyBlob[0..keyTestBlobDecaps.cbKeyBlob]);
            h.check(ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob from full key");

            ntStatus = kemImp.getBlobFromKey(KemDef.FormatEncaps, keyTestBlobEncaps.abKeyBlob[0..keyTestBlobEncaps.cbKeyBlob]);
            h.check(ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob from full key");

            ntStatus = kemImp.encapsulate(&abAgreedSecretEncaps, abCipherText[0..cbCipherText]);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in encapsulate with full key");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with full key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (full key) and decaps (full key)");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobDecaps), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with full key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (full key) and decaps (decaps key)");

            ntStatus = kemImp.encapsulate(&abAgreedSecretEncaps, abCipherText[0..cbCipherText]);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in encapsulate with decapsulation key");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with decapsulation key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (decaps key) and decaps (decaps key)");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobFull), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with decapsulation key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (decaps key) and decaps (full key)");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobEncaps), @sizeOf(KemDef.TestBlobType), false);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob");

            ntStatus = kemImp.encapsulate(&abAgreedSecretEncaps, abCipherText[0..cbCipherText]);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in encapsulate with encapsulation key");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobDecaps), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key (encapsulated with encapsulation key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (encaps key) and decaps (decaps key)");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobFull), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from private seed");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with full key (encapsulated with encapsulation key)");
            h.check(std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Agreed secret mismatch between encaps (encaps key) and decaps (full key)");

            const t = rng.g_rng.uint32();
            abCipherText[(t / 8) % cbCipherText] ^= @as(u8, 1) << @intCast(t % 8);

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check((ntStatus != STATUS_SUCCESS) or !std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Modified ciphertext does not cause failure");

            ntStatus = kemImp.setKeyFromTestBlob(@ptrCast(&keyTestBlobDecaps), @sizeOf(KemDef.TestBlobType), true);
            h.check(ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key blob");

            ntStatus = kemImp.decapsulate(abCipherText[0..cbCipherText], &abAgreedSecretDecaps);
            h.check((ntStatus != STATUS_SUCCESS) or !std.mem.eql(u8, &abAgreedSecretEncaps, &abAgreedSecretDecaps), "Modified ciphertext does not cause failure");
        }
    }

    h.check(kemImp.setKeyFromTestBlob(null, 0, false) == STATUS_SUCCESS, "Failed to clear key");
}

fn testMlKemHighLevelAPI() void {
    testKemHighLevelAPIGeneric(MlKemDef, "MlKem", &rgTestMlKemParams);
}

fn testCompositeMlKemHighLevelAPI() void {
    testKemHighLevelAPIGeneric(CompositeMlKemDef, "CompositeMlKem", &rgTestCompositeMlKemParams);
}

fn testSymCryptKemNegativeTests(
    comptime KemDef: type,
    testParamsSlice: []const KemDef.TestParamsType,
) void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abPublicKeyBlob: [KemDef.MaxEncapsKeyBlobSize]u8 = undefined;
    var abPrivateKeyBlob: [KemDef.MaxDecapsKeyBlobSize]u8 = undefined;
    var abPrivateSeedBlob: [KemDef.PrivateSeedSize]u8 = undefined;
    var abCiphertext: [KemDef.MaxCiphertextSize]u8 = undefined;
    var abSharedSecret: [KemDef.AgreedSecretSize]u8 = undefined;
    var cbPublicKey: usize = 0;
    var cbPrivateKey: usize = 0;
    var cbPrivateSeed: usize = 0;
    var cbCiphertext: usize = 0;

    for (testParamsSlice) |tp| {
        const params = tp.params;

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatEncaps, &cbPublicKey);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get public key size");

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatDecaps, &cbPrivateKey);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get private key size");

        scError = KemDef.SizeofKeyFormatFromParams(params, KemDef.FormatFull, &cbPrivateSeed);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get private seed size");

        scError = KemDef.SizeofCiphertextFromParams(params, &cbCiphertext);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to get ciphertext size");

        const pKey = KemDef.KeyAllocate(params);
        h.check(pKey != null, "Failed to allocate key");

        scError = KemDef.KeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate key");

        scError = KemDef.KeyGetValue(pKey.?, &abPublicKeyBlob, cbPublicKey, KemDef.FormatEncaps, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to export public key");

        scError = KemDef.KeySetValue(&abPublicKeyBlob, 0, KemDef.FormatEncaps, 0, pKey.?);
        h.check(scError != SYMCRYPT_NO_ERROR, "SetValue with size 0 should fail");

        scError = KemDef.KeySetValue(&abPublicKeyBlob, cbPublicKey - 1, KemDef.FormatEncaps, 0, pKey.?);
        h.check(scError != SYMCRYPT_NO_ERROR, "SetValue with size - 1 should fail");

        scError = KemDef.KeySetValue(&abPublicKeyBlob, cbPublicKey + 1, KemDef.FormatEncaps, 0, pKey.?);
        h.check(scError != SYMCRYPT_NO_ERROR, "SetValue with size + 1 should fail");

        scError = KemDef.KeySetValue(&abPublicKeyBlob, cbPublicKey, KemDef.FormatEncaps, 0, pKey.?);
        h.check(scError == SYMCRYPT_NO_ERROR, "SetValue with correct size should succeed");

        scError = KemDef.KeyGetValue(pKey.?, &abPrivateSeedBlob, cbPrivateSeed, KemDef.FormatFull, 0);
        h.check(scError != SYMCRYPT_NO_ERROR, "Exporting private seed from public-only key should fail");

        scError = KemDef.KeyGetValue(pKey.?, &abPrivateKeyBlob, cbPrivateKey, KemDef.FormatDecaps, 0);
        h.check(scError != SYMCRYPT_NO_ERROR, "Exporting private key from public-only key should fail");

        scError = KemDef.Encapsulate(pKey.?, &abSharedSecret, KemDef.AgreedSecretSize, &abCiphertext, cbCiphertext);
        h.check(scError == SYMCRYPT_NO_ERROR, "Encapsulate with public-only key should succeed");

        scError = KemDef.Decapsulate(pKey.?, &abCiphertext, cbCiphertext, &abSharedSecret, KemDef.AgreedSecretSize);
        h.check(scError != SYMCRYPT_NO_ERROR, "Decapsulate with public-only key should fail");

        scError = KemDef.KeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "Failed to generate key");

        scError = KemDef.Encapsulate(pKey.?, &abSharedSecret, KemDef.AgreedSecretSize, &abCiphertext, cbCiphertext - 1);
        h.check(scError != SYMCRYPT_NO_ERROR, "Encapsulate with wrong ciphertext size should fail");

        scError = KemDef.Encapsulate(pKey.?, &abSharedSecret, KemDef.AgreedSecretSize - 1, &abCiphertext, cbCiphertext);
        h.check(scError != SYMCRYPT_NO_ERROR, "Encapsulate with wrong shared secret size should fail");

        scError = KemDef.Encapsulate(pKey.?, &abSharedSecret, KemDef.AgreedSecretSize, &abCiphertext, cbCiphertext);
        h.check(scError == SYMCRYPT_NO_ERROR, "Encapsulate with correct sizes should succeed");

        scError = KemDef.Decapsulate(pKey.?, &abCiphertext, cbCiphertext - 1, &abSharedSecret, KemDef.AgreedSecretSize);
        h.check(scError != SYMCRYPT_NO_ERROR, "Decapsulate with wrong ciphertext size should fail");

        scError = KemDef.Decapsulate(pKey.?, &abCiphertext, cbCiphertext, &abSharedSecret, KemDef.AgreedSecretSize - 1);
        h.check(scError != SYMCRYPT_NO_ERROR, "Decapsulate with wrong shared secret size should fail");

        KemDef.KeyFree(pKey.?);
    }
}

const SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED: usize = 32;
const SYMCRYPT_TEST_MLKEM_SIZEOF_ENCAPS_HASH: usize = 32;
const SYMCRYPT_TEST_MLKEM_SIZEOF_Z: usize = 32;

fn testSymCryptMlKemSetInvalidDecapsKeyBlob() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var keyTestBlobFull = MLKEMKEY_TESTBLOB{};
    var keyTestBlobDecaps = MLKEMKEY_TESTBLOB{};

    for (rgTestMlKemParams) |testParams| {
        const params = testParams.params;
        const pKey = SymCryptMlKemkeyAllocate(params);
        h.check(pKey != null, "SymCryptMlKemkeyAllocate failed");

        keyTestBlobFull.params = params;
        scError = SymCryptMlKemSizeofKeyFormatFromParams(params, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, &keyTestBlobFull.cbKeyBlob);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED failed with 0x{x}", scError);

        h.GENRANDOM(&keyTestBlobFull.abKeyBlob, @intCast(keyTestBlobFull.cbKeyBlob));

        scError = SymCryptMlKemSizeofKeyFormatFromParams(params, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, &keyTestBlobDecaps.cbKeyBlob);
        h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemSizeofKeyFormatFromParams SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY failed with 0x{x}", scError);

        keyTestBlobDecaps.params = params;

        scError = SymCryptMlKemkeySetValue(
            &keyTestBlobFull.abKeyBlob,
            keyTestBlobFull.cbKeyBlob,
            SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
            0,
            pKey.?,
        );
        h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemkeySetValue SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED failed with 0x{x}", scError);

        scError = SymCryptMlKemkeyGetValue(
            pKey.?,
            &keyTestBlobDecaps.abKeyBlob,
            keyTestBlobDecaps.cbKeyBlob,
            SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
            0,
        );
        h.check3(scError == SYMCRYPT_NO_ERROR, "SymCryptMlKemkeyGetValue SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY failed with 0x{x}", scError);

        const decapsPublicSeedOffset = keyTestBlobDecaps.cbKeyBlob - SYMCRYPT_TEST_MLKEM_SIZEOF_Z - SYMCRYPT_TEST_MLKEM_SIZEOF_ENCAPS_HASH - SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED;
        const t = rng.g_rng.uint32();
        const byteIndex = t % SYMCRYPT_TEST_MLKEM_SIZEOF_PUBLIC_SEED;
        const bitIndex: u3 = @intCast(t % 8);

        keyTestBlobDecaps.abKeyBlob[decapsPublicSeedOffset + byteIndex] ^= @as(u8, 1) << bitIndex;
        scError = SymCryptMlKemkeySetValue(
            &keyTestBlobDecaps.abKeyBlob,
            keyTestBlobDecaps.cbKeyBlob,
            SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY,
            0,
            pKey.?,
        );
        h.check3(scError == SYMCRYPT_INVALID_BLOB, "SymCryptMlKemkeySetValue with corrupted public seed got something other than SYMCRYPT_INVALID_BLOB: 0x{x}", scError);

        SymCryptMlKemkeyFree(pKey.?);
    }
}

fn testSymCryptMlKemNegativeTests() void {
    testSymCryptKemNegativeTests(MlKemDef, &rgTestMlKemParams);
    testSymCryptMlKemSetInvalidDecapsKeyBlob();
}

fn testSymCryptCompositeMlKemCorruptEcPrivateKey() void {
    var scError: u32 = SYMCRYPT_NO_ERROR;
    var abPrivateKeyBlob: [CompositeMlKemDef.MaxDecapsKeyBlobSize]u8 = undefined;
    var abSharedSecret: [CompositeMlKemDef.AgreedSecretSize]u8 = undefined;
    var abDecapsSecret: [CompositeMlKemDef.AgreedSecretSize]u8 = undefined;
    var abCiphertext: [CompositeMlKemDef.MaxCiphertextSize]u8 = undefined;
    var cbPrivateKey: usize = 0;
    var cbCiphertext: usize = 0;

    for (rgTestCompositeMlKemParams) |testParams| {
        const params = testParams.params;

        if (testParams.curveId == SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519) {
            continue;
        }

        scError = SymCryptCompositeMlKemSizeofKeyFormatFromParams(params, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, &cbPrivateKey);
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        scError = SymCryptCompositeMlKemSizeofCiphertextFromParams(params, &cbCiphertext);
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        const pKey = SymCryptCompositeMlKemkeyAllocate(params);
        h.check(pKey != null, "?");

        scError = SymCryptCompositeMlKemkeyGenerate(pKey.?, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        scError = SymCryptCompositeMlKemkeyGetValue(pKey.?, &abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0);
        h.check(scError == SYMCRYPT_NO_ERROR, "?");

        const cbEcSkOffset = cbPrivateKey - SymCryptCompositeGetSizeOfEncodedEcSk(testParams.curveId);
        abPrivateKeyBlob[cbEcSkOffset] ^= 0xFF;

        scError = SymCryptCompositeMlKemkeySetValue(&abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0, pKey.?);
        h.check3(
            scError != SYMCRYPT_NO_ERROR,
            "SetValue with corrupted EC private key ASN.1 header should fail for param {s}",
            testParams.pszParamsName,
        );

        abPrivateKeyBlob[cbEcSkOffset] ^= 0xFF;
        scError = SymCryptCompositeMlKemkeySetValue(&abPrivateKeyBlob, cbPrivateKey, SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_LAMPS_PRIVATE_KEY, 0, pKey.?);
        h.check3(
            scError == SYMCRYPT_NO_ERROR,
            "SetValue should succeed after prior failure for param {s}",
            testParams.pszParamsName,
        );

        scError = SymCryptCompositeMlKemEncapsulate(pKey.?, &abSharedSecret, CompositeMlKemDef.AgreedSecretSize, &abCiphertext, cbCiphertext);
        h.check3(
            scError == SYMCRYPT_NO_ERROR,
            "Encapsulate should succeed after recovery for param {s}",
            testParams.pszParamsName,
        );

        scError = SymCryptCompositeMlKemDecapsulate(pKey.?, &abCiphertext, cbCiphertext, &abDecapsSecret, CompositeMlKemDef.AgreedSecretSize);
        h.check3(
            scError == SYMCRYPT_NO_ERROR,
            "Decapsulate should succeed after recovery for param {s}",
            testParams.pszParamsName,
        );

        h.check3(
            std.mem.eql(u8, &abSharedSecret, &abDecapsSecret),
            "Shared secrets should match after recovery for param {s}",
            testParams.pszParamsName,
        );

        SymCryptCompositeMlKemkeyFree(pKey.?);
    }
}

fn testSymCryptCompositeMlKemNegativeTests() void {
    testSymCryptKemNegativeTests(CompositeMlKemDef, &rgTestCompositeMlKemParams);
    testSymCryptCompositeMlKemCorruptEcPrivateKey();
}

fn testKemDecapsKat(
    comptime KemDef: type,
    pImpl: *KemMultiImp,
    testParams: KemDef.TestParamsType,
    katItem: *const kat.ZigKatItem,
    line: i64,
) void {
    var keyTestBlobDecaps = KemDef.TestBlobType{
        .params = testParams.params,
        .format = KemDef.FormatDecaps,
    };
    var abComputedAgreedSecret: [KemDef.AgreedSecretSize]u8 = undefined;

    h.check3(katItem.dataItems.items.len == 3, "Wrong number of items in Decaps record at line {d}", line);

    const bstrDecapsKey = katItem.parseData("dk");
    defer std.heap.c_allocator.free(bstrDecapsKey);
    const bstrCiphertext = katItem.parseData("c");
    defer std.heap.c_allocator.free(bstrCiphertext);
    const bstrAgreedSecret = katItem.parseData("k");
    defer std.heap.c_allocator.free(bstrAgreedSecret);

    h.check3(bstrDecapsKey.len <= keyTestBlobDecaps.abKeyBlob.len, "Decapsulation key too large at line {d}", line);
    h.check3(bstrAgreedSecret.len == abComputedAgreedSecret.len, "Agreed secret size incorrect at line {d}", line);

    @memcpy(keyTestBlobDecaps.abKeyBlob[0..bstrDecapsKey.len], bstrDecapsKey);
    keyTestBlobDecaps.cbKeyBlob = bstrDecapsKey.len;

    var ntStatus = pImpl.setKeyFromTestBlob(@ptrCast(&keyTestBlobDecaps), @sizeOf(KemDef.TestBlobType), true);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure setting key from decapsulation key at line {d}", line);

    ntStatus = pImpl.decapsulate(bstrCiphertext, &abComputedAgreedSecret);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure in decapsulate with decapsulation key at line {d}", line);
    if (!std.mem.eql(u8, &abComputedAgreedSecret, bstrAgreedSecret)) {
        h.zprint("Decapsulated secret mismatch at line {d}\n", .{line});
        pImpl.nErrorKatFailure += 1;
    }
}

fn testMlKemKeyGenKat(
    pImpl: *KemMultiImp,
    testParams: SYMCRYPT_TEST_MLKEM_PARAMS,
    katItem: *const kat.ZigKatItem,
    line: i64,
) void {
    var keyTestBlobFull = MLKEMKEY_TESTBLOB{
        .params = testParams.params,
        .format = SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED,
        .cbKeyBlob = MlKemDef.PrivateSeedSize,
    };
    var abComputedEncapsKey: [MlKemDef.MaxEncapsKeyBlobSize]u8 = undefined;
    var abComputedDecapsKey: [MlKemDef.MaxDecapsKeyBlobSize]u8 = undefined;

    h.check3(katItem.dataItems.items.len == 4, "Wrong number of items in KeyGen record at line {d}", line);

    const bstrZ = katItem.parseData("z");
    defer std.heap.c_allocator.free(bstrZ);
    const bstrD = katItem.parseData("d");
    defer std.heap.c_allocator.free(bstrD);
    const bstrEncapsKey = katItem.parseData("ek");
    defer std.heap.c_allocator.free(bstrEncapsKey);
    const bstrDecapsKey = katItem.parseData("dk");
    defer std.heap.c_allocator.free(bstrDecapsKey);

    h.check3((bstrD.len == 32) and (bstrZ.len == 32), "Seeds length should each be 32 bytes at line {d}", line);
    h.check3(bstrEncapsKey.len <= abComputedEncapsKey.len, "Encapsulation key too large at line {d}", line);
    h.check3(bstrDecapsKey.len <= abComputedDecapsKey.len, "Decapsulation key too large at line {d}", line);

    @memcpy(keyTestBlobFull.abKeyBlob[0..32], bstrD);
    @memcpy(keyTestBlobFull.abKeyBlob[32..64], bstrZ);

    var ntStatus = pImpl.setKeyFromTestBlob(@ptrCast(&keyTestBlobFull), @sizeOf(MLKEMKEY_TESTBLOB), false);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure setting key from private seed at line {d}", line);

    ntStatus = pImpl.getBlobFromKey(SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, abComputedEncapsKey[0..bstrEncapsKey.len]);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob from full key at line {d}", line);
    if (!std.mem.eql(u8, abComputedEncapsKey[0..bstrEncapsKey.len], bstrEncapsKey)) {
        h.zprint("Encapsulation key doesn't match at line {d}\n", .{line});
        pImpl.nErrorKatFailure += 1;
    }

    ntStatus = pImpl.getBlobFromKey(SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, abComputedDecapsKey[0..bstrDecapsKey.len]);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure getting decapsulation key blob from full key at line {d}", line);
    if (!std.mem.eql(u8, abComputedDecapsKey[0..bstrDecapsKey.len], bstrDecapsKey)) {
        h.zprint("Decapsulation key doesn't match at line {d}\n", .{line});
        pImpl.nErrorKatFailure += 1;
    }
}

fn testMlKemEncapsKat(
    pImpl: *KemMultiImp,
    testParams: SYMCRYPT_TEST_MLKEM_PARAMS,
    katItem: *const kat.ZigKatItem,
    line: i64,
) void {
    var keyTestBlobEncaps = MLKEMKEY_TESTBLOB{
        .params = testParams.params,
        .format = SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY,
    };
    var abComputedCiphertext: [MlKemDef.MaxCiphertextSize]u8 = undefined;
    var abComputedAgreedSecret: [MlKemDef.AgreedSecretSize]u8 = undefined;

    h.check3(katItem.dataItems.items.len == 4, "Wrong number of items in Encaps record at line {d}", line);

    const bstrEncapsKey = katItem.parseData("ek");
    defer std.heap.c_allocator.free(bstrEncapsKey);
    const bstrMsg = katItem.parseData("m");
    defer std.heap.c_allocator.free(bstrMsg);
    const bstrAgreedSecret = katItem.parseData("k");
    defer std.heap.c_allocator.free(bstrAgreedSecret);
    const bstrCiphertext = katItem.parseData("c");
    defer std.heap.c_allocator.free(bstrCiphertext);

    h.check3(bstrEncapsKey.len <= keyTestBlobEncaps.abKeyBlob.len, "Encapsulation key too large at line {d}", line);
    h.check3(bstrAgreedSecret.len == abComputedAgreedSecret.len, "Agreed secret size incorrect at line {d}", line);
    h.check3(bstrCiphertext.len <= abComputedCiphertext.len, "Ciphertext too large at line {d}", line);

    @memcpy(keyTestBlobEncaps.abKeyBlob[0..bstrEncapsKey.len], bstrEncapsKey);
    keyTestBlobEncaps.cbKeyBlob = bstrEncapsKey.len;

    var ntStatus = pImpl.setKeyFromTestBlob(@ptrCast(&keyTestBlobEncaps), @sizeOf(MLKEMKEY_TESTBLOB), false);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key at line {d}", line);

    ntStatus = pImpl.encapsulateEx(bstrMsg, &abComputedAgreedSecret, abComputedCiphertext[0..bstrCiphertext.len]);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure in encapsulateEx with encapsulation key at line {d}", line);
    if (!std.mem.eql(u8, &abComputedAgreedSecret, bstrAgreedSecret)) {
        h.zprint("Encapsulated secret mismatch at line {d}\n", .{line});
        pImpl.nErrorKatFailure += 1;
    }
    if (!std.mem.eql(u8, abComputedCiphertext[0..bstrCiphertext.len], bstrCiphertext)) {
        h.zprint("Encapsulated ciphertext mismatch at line {d}\n", .{line});
        pImpl.nErrorKatFailure += 1;
    }
}

const SYMCRYPT_ECURVE = opaque {};
extern fn SymCryptGetCachedEcurve(curveId: u32) callconv(.c) ?*const SYMCRYPT_ECURVE;
extern fn SymCryptEcurveSizeofScalarMultiplier(pCurve: *const SYMCRYPT_ECURVE) callconv(.c) u32;
extern fn SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
    curveId: u32,
    numFormat: u32,
    pbRandom: [*]const u8,
    cbRandom: usize,
    pbScalar: [*]u8,
    cbScalar: usize,
) callconv(.c) u32;
const SYMCRYPT_NUMBER_FORMAT_LSB_FIRST: u32 = 1;
const SYMCRYPT_NUMBER_FORMAT_MSB_FIRST: u32 = 2;

fn testCompositeMlKemKeyGenKat(
    pImpl: *KemMultiImp,
    testParams: SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS,
    katItem: *const kat.ZigKatItem,
    line: i64,
) void {
    h.check3(katItem.dataItems.items.len == 5, "Wrong number of items in Composite KEM KeyGen record at line {d}", line);

    const katPrivateRandom = katItem.parseData("z");
    defer std.heap.c_allocator.free(katPrivateRandom);
    const katPrivateSeed = katItem.parseData("d");
    defer std.heap.c_allocator.free(katPrivateSeed);
    const katEncapsKeyBlob = katItem.parseData("ek");
    defer std.heap.c_allocator.free(katEncapsKeyBlob);
    const katCipherText = katItem.parseData("c");
    defer std.heap.c_allocator.free(katCipherText);
    const katAgreedSecret = katItem.parseData("k");
    defer std.heap.c_allocator.free(katAgreedSecret);

    var abComputedEncapsKeyBlob: [CompositeMlKemDef.MaxEncapsKeyBlobSize]u8 = undefined;
    var abComputedCipherText: [CompositeMlKemDef.MaxCiphertextSize]u8 = undefined;
    var abComputedAgreedSecret: [CompositeMlKemDef.AgreedSecretSize]u8 = undefined;
    var abComputedIrtfSeed: [32]u8 = undefined;
    var keyTestBlob = COMPOSITE_MLKEMKEY_TESTBLOB{
        .params = testParams.params,
        .format = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED,
        .cbKeyBlob = katPrivateSeed.len,
    };

    const cbMlKemRandom: usize = 32;
    const pCurve = SymCryptGetCachedEcurve(testParams.curveId);
    h.check(pCurve != null, "Failed to get curve for Composite ML-KEM");

    const cbScalar: usize = SymCryptEcurveSizeofScalarMultiplier(pCurve.?);
    var abEncapsRandom: [32 + 48]u8 = undefined;

    h.check(katEncapsKeyBlob.len <= abComputedEncapsKeyBlob.len, "?");
    h.check(katCipherText.len <= abComputedCipherText.len, "?");
    h.check(katAgreedSecret.len <= abComputedAgreedSecret.len, "?");
    h.check3(katPrivateSeed.len == 32, "Unexpected private seed size for Composite ML-KEM record at line {d}", line);
    h.check3(katAgreedSecret.len == CompositeMlKemDef.AgreedSecretSize, "Unexpected agreed secret size for Composite ML-KEM record at line {d}", line);
    h.check(cbMlKemRandom + cbScalar <= abEncapsRandom.len, "?");

    @memcpy(keyTestBlob.abKeyBlob[0..katPrivateSeed.len], katPrivateSeed);

    var ntStatus = pImpl.setKeyFromTestBlob(@ptrCast(&keyTestBlob), @sizeOf(COMPOSITE_MLKEMKEY_TESTBLOB), true);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure setting key from IRTF private seed for Composite ML-KEM record at line {d}", line);

    ntStatus = pImpl.getBlobFromKey(SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_IRTF_PRIVATE_SEED, abComputedIrtfSeed[0..katPrivateSeed.len]);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure getting IRTF private seed for Composite ML-KEM record at line {d}", line);
    h.check3(std.mem.eql(u8, katPrivateSeed, abComputedIrtfSeed[0..katPrivateSeed.len]), "IRTF private seed doesn't match for Composite ML-KEM record at line {d}", line);

    ntStatus = pImpl.getBlobFromKey(SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY, abComputedEncapsKeyBlob[0..katEncapsKeyBlob.len]);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure getting encapsulation key blob for Composite ML-KEM record at line {d}", line);
    h.check3(std.mem.eql(u8, katEncapsKeyBlob, abComputedEncapsKeyBlob[0..katEncapsKeyBlob.len]), "Encapsulation key doesn't match for Composite ML-KEM record at line {d}", line);

    @memcpy(abEncapsRandom[0..cbMlKemRandom], katPrivateRandom[0..cbMlKemRandom]);

    const ecNumFormat: u32 = switch (testParams.curveId) {
        SYMCRYPT_CACHED_ECURVE_ID_NIST_P256, SYMCRYPT_CACHED_ECURVE_ID_NIST_P384 => SYMCRYPT_NUMBER_FORMAT_MSB_FIRST,
        SYMCRYPT_CACHED_ECURVE_ID_CURVE_25519 => SYMCRYPT_NUMBER_FORMAT_LSB_FIRST,
        else => unreachable,
    };

    const scError = SymCryptCompositeMlKemGetRandomScalarForEcKeyEx(
        testParams.curveId,
        ecNumFormat,
        katPrivateRandom.ptr + cbMlKemRandom,
        katPrivateRandom.len - cbMlKemRandom,
        abEncapsRandom[cbMlKemRandom..].ptr,
        cbScalar,
    );
    h.check3(scError == SYMCRYPT_NO_ERROR, "GetRandomScalarForEcKey failed for Composite ML-KEM record at line {d}", line);

    ntStatus = pImpl.encapsulateEx(
        abEncapsRandom[0 .. cbMlKemRandom + cbScalar],
        abComputedAgreedSecret[0..katAgreedSecret.len],
        abComputedCipherText[0..katCipherText.len],
    );
    h.check3(ntStatus == STATUS_SUCCESS, "Failure in encapsulateEx for Composite ML-KEM record at line {d}", line);
    h.check3(std.mem.eql(u8, katCipherText, abComputedCipherText[0..katCipherText.len]), "Ciphertext doesn't match for Composite ML-KEM record at line {d}", line);
    h.check3(std.mem.eql(u8, katAgreedSecret, abComputedAgreedSecret[0..katAgreedSecret.len]), "Agreed secret from encapsulateEx doesn't match for Composite ML-KEM record at line {d}", line);

    ntStatus = pImpl.decapsulate(
        katCipherText,
        abComputedAgreedSecret[0..katAgreedSecret.len],
    );
    h.check3(ntStatus == STATUS_SUCCESS, "Failure in decapsulate for Composite ML-KEM record at line {d}", line);
    h.check3(std.mem.eql(u8, katAgreedSecret, abComputedAgreedSecret[0..katAgreedSecret.len]), "Agreed secret from decapsulate doesn't match for Composite ML-KEM record at line {d}", line);

    h.check(pImpl.setKeyFromTestBlob(null, 0, false) == STATUS_SUCCESS, "Failed to clear key");
}

fn testCompositeMlKemEncapsKat(
    pImpl: *KemMultiImp,
    testParams: SYMCRYPT_TEST_COMPOSITE_MLKEM_PARAMS,
    katItem: *const kat.ZigKatItem,
    line: i64,
) void {
    h.check3(katItem.dataItems.items.len == 1, "Wrong number of items in Composite KEM Encapsulation record at line {d}", line);

    const katEncapsKeyBlob = katItem.parseData("ek");
    defer std.heap.c_allocator.free(katEncapsKeyBlob);

    var abComputedAgreedSecret: [CompositeMlKemDef.AgreedSecretSize]u8 = undefined;
    var abComputedCiphertext: [CompositeMlKemDef.MaxCiphertextSize]u8 = undefined;
    var keyTestBlob = COMPOSITE_MLKEMKEY_TESTBLOB{
        .params = testParams.params,
        .format = SYMCRYPT_COMPOSITE_MLKEMKEY_FORMAT_PUBLIC_KEY,
        .cbKeyBlob = katEncapsKeyBlob.len,
    };
    var cbCipherText: usize = 0;

    _ = SymCryptCompositeMlKemSizeofCiphertextFromParams(testParams.params, &cbCipherText);

    h.check(cbCipherText <= abComputedCiphertext.len, "?");
    h.check(katEncapsKeyBlob.len <= keyTestBlob.abKeyBlob.len, "?");

    @memcpy(keyTestBlob.abKeyBlob[0..katEncapsKeyBlob.len], katEncapsKeyBlob);

    var ntStatus = pImpl.setKeyFromTestBlob(@ptrCast(&keyTestBlob), @sizeOf(COMPOSITE_MLKEMKEY_TESTBLOB), false);
    h.check3(ntStatus == STATUS_SUCCESS, "Failure setting key from encapsulation key blob for Composite ML-KEM record at line {d}", line);

    ntStatus = pImpl.encapsulate(
        &abComputedAgreedSecret,
        abComputedCiphertext[0..cbCipherText],
    );
    h.check3(ntStatus == STATUS_SUCCESS, "Failure in encapsulate for Composite ML-KEM record at line {d}", line);

    h.check(pImpl.setKeyFromTestBlob(null, 0, false) == STATUS_SUCCESS, "Failed to clear key");
}

fn runKemKatTests(
    comptime KemDef: type,
    algName: [*:0]const u8,
    katResourceName: []const u8,
    katResourceType: []const u8,
    rgTestParams: []const KemDef.TestParamsType,
    comptime keyGenFn: fn (*KemMultiImp, KemDef.TestParamsType, *const kat.ZigKatItem, i64) void,
    comptime encapsFn: fn (*KemMultiImp, KemDef.TestParamsType, *const kat.ZigKatItem, i64) void,
) void {
    _ = katResourceType;
    var pKatKem = kat.ZigKatReader.init(katResourceName);
    var katItem: kat.ZigKatItem = .{};
    defer katItem.deinit();

    var sep: []const u8 = "    ";
    var doneAnything: bool = false;

    var kemImpOpt = KemMultiImp.init(algName);
    if (kemImpOpt == null) return;
    var kemImp = &kemImpOpt.?;
    defer kemImp.deinit();

    var currentParamsIdx: ?usize = null;

    while (true) {
        pKatKem.getKatItem(&katItem);
        const line = pKatKem.kat.m_line;

        if (katItem.type == kat.KAT_TYPE_END) {
            break;
        }

        if (katItem.type == kat.KAT_TYPE_CATEGORY) {
            var idx: usize = 0;
            while (idx < rgTestParams.len) : (idx += 1) {
                if (std.mem.eql(u8, katItem.categoryName, rgTestParams[idx].pszParamsName)) {
                    break;
                }
            }
            h.check3(idx < rgTestParams.len, "KemKat dataset at line {d} uses unknown category!", line);
            currentParamsIdx = idx;

            h.ziprint("{s}{s}", .{ sep, rgTestParams[idx].pszParamsName });
            sep = ", ";
            doneAnything = true;
        }

        if (katItem.type == kat.KAT_TYPE_DATASET) {
            const testParams = rgTestParams[currentParamsIdx.?];
            if (katItem.isFieldPresent("z")) {
                keyGenFn(kemImp, testParams, &katItem, line);
            } else if (katItem.isFieldPresent("ek")) {
                encapsFn(kemImp, testParams, &katItem, line);
            } else if (katItem.isFieldPresent("dk")) {
                testKemDecapsKat(KemDef, kemImp, testParams, &katItem, line);
            } else {
                h.fatal("Unknown data record at line {d}", .{line});
            }
        }
    }

    if (doneAnything) {
        h.ziprint("\n", .{});
    }

    h.check(kemImp.setKeyFromTestBlob(null, 0, false) == STATUS_SUCCESS, "Failed to clear key");
}

fn testMlKemKats() void {
    runKemKatTests(
        MlKemDef,
        "MlKem",
        "kat_kem.dat",
        "KAT_KEM",
        &rgTestMlKemParams,
        testMlKemKeyGenKat,
        testMlKemEncapsKat,
    );
}

fn testCompositeMlKemKats() void {
    runKemKatTests(
        CompositeMlKemDef,
        "CompositeMlKem",
        "kat_composite_kem.dat",
        "KAT_COMPOSITE_KEM",
        &rgTestCompositeMlKemParams,
        testCompositeMlKemKeyGenKat,
        testCompositeMlKemEncapsKat,
    );
}

pub export fn testKem() callconv(.c) void {
    const testMlKem = h.isAlgorithmPresent("MlKem", 0);
    const testCompositeMlKem = h.isAlgorithmPresent("CompositeMlKem", 0);

    if (!testMlKem and !testCompositeMlKem) {
        return;
    }

    if (testMlKem) {
        if (h.g_useDynamicFunctionsInTestCall == 0) {
            testMlKemArithmetic();
        }
        testMlKemHighLevelAPI();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

        testSymCryptMlKemNegativeTests();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

        testMlKemKats();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);
    }

    if (testCompositeMlKem) {
        testCompositeMlKemHighLevelAPI();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

        testSymCryptCompositeMlKemNegativeTests();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);

        testCompositeMlKemKats();
        h.check3(cb.g_nOutstandingCheckedAllocs == 0, "Memory leak {d} outstanding", cb.g_nOutstandingCheckedAllocs);
    }
}
