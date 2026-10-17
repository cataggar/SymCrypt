//
// a_dispatch.zig   Dispatch between different arithmetic format implementations.
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");
const fdef_general = @import("fdef_general.zig");
const fdef_int = @import("fdef_int.zig");

const SYMCRYPT_CALL = types.SYMCRYPT_CALL;
const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const PUINT32 = types.PUINT32;
const PCUINT32 = types.PCUINT32;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const SYMCRYPT_NUMBER_FORMAT = types.SYMCRYPT_NUMBER_FORMAT;
const SYMCRYPT_INT = types.SYMCRYPT_INT;
const PSYMCRYPT_INT = types.PSYMCRYPT_INT;
const PCSYMCRYPT_INT = types.PCSYMCRYPT_INT;
const SYMCRYPT_DIVISOR = types.SYMCRYPT_DIVISOR;
const PSYMCRYPT_DIVISOR = types.PSYMCRYPT_DIVISOR;
const PCSYMCRYPT_DIVISOR = types.PCSYMCRYPT_DIVISOR;
const SYMCRYPT_MODULUS = types.SYMCRYPT_MODULUS;
const PSYMCRYPT_MODULUS = types.PSYMCRYPT_MODULUS;
const PCSYMCRYPT_MODULUS = types.PCSYMCRYPT_MODULUS;
const SYMCRYPT_MODELEMENT = types.SYMCRYPT_MODELEMENT;
const PSYMCRYPT_MODELEMENT = types.PSYMCRYPT_MODELEMENT;
const PCSYMCRYPT_MODELEMENT = types.PCSYMCRYPT_MODELEMENT;
const SYMCRYPT_MODULAR_FUNCTIONS = types.SYMCRYPT_MODULAR_FUNCTIONS;
const SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY = types.SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY;
const SYMCRYPT_TRIALDIVISION_CONTEXT = types.SYMCRYPT_TRIALDIVISION_CONTEXT;
const PSYMCRYPT_TRIALDIVISION_CONTEXT = types.PSYMCRYPT_TRIALDIVISION_CONTEXT;
const PCSYMCRYPT_TRIALDIVISION_CONTEXT = types.PCSYMCRYPT_TRIALDIVISION_CONTEXT;

const SYMCRYPT_CPU_FEATURES_FOR_MULX: types.SYMCRYPT_CPU_FEATURES =
    types.SYMCRYPT_CPU_FEATURE_BMI2 | types.SYMCRYPT_CPU_FEATURE_ADX | types.SYMCRYPT_CPU_FEATURE_SSE2;

extern fn SymCryptCallbackFree(pMem: ?*anyopaque) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptWipe(pbData: *anyopaque, cbData: SIZE_T) callconv(SYMCRYPT_CALL) void;

// Extern FDEF modular functions (defined in fdef_mod.c, fdef369_mod.c, and ASM files)
extern fn SymCryptFdefModAddGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSubGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModNegGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModMulGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModInvGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModSetPostGeneric(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModPreGetGeneric(pmMod: PCSYMCRYPT_MODULUS, peObj: PCSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) PCUINT32;
extern fn SymCryptFdefModulusCopyFixupGeneric(pmSrc: PCSYMCRYPT_MODULUS, pmDst: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModulusInitGeneric(pmMod: PSYMCRYPT_MODULUS, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModInvMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModSetPostMontgomery(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModPreGetMontgomery(pmMod: PCSYMCRYPT_MODULUS, peObj: PCSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) PCUINT32;
extern fn SymCryptFdefModulusCopyFixupMontgomery(pmSrc: PCSYMCRYPT_MODULUS, pmDst: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModulusInitMontgomery(pmMod: PSYMCRYPT_MODULUS, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdef369ModAddGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdef369ModSubGeneric(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdef369ModMulMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdef369ModSquareMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdef369ModInvMontgomery(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdef369ModSetPostMontgomery(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdef369ModPreGetMontgomery(pmMod: PCSYMCRYPT_MODULUS, peObj: PCSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) PCUINT32;
extern fn SymCryptFdef369ModulusInitMontgomery(pmMod: PSYMCRYPT_MODULUS, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

// AMD64 specific functions
extern fn SymCryptFdefModAddMulx256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModAddMulx384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSub256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSub384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModMulMontgomeryMulx256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomeryMulx256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModInvMontgomery256(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModSetPostMontgomeryMulx256(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModPreGetMontgomery256(pmMod: PCSYMCRYPT_MODULUS, peObj: PCSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) PCUINT32;
extern fn SymCryptFdefModulusInitMontgomery256(pmMod: PSYMCRYPT_MODULUS, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomeryMulxP384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomeryMulxP384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSetPostMontgomeryMulxP384(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomeryMulx(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomeryMulx(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

extern fn SymCryptFdefModMulMontgomeryMulx1024(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomeryMulx1024(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

// ARM64 specific functions
extern fn SymCryptFdefModAdd256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModAdd384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModMulMontgomery256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomery256Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModMulMontgomeryP384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModSquareMontgomeryP384Asm(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;

// Other FDEF functions called by dispatchers (defined in fdef_mod.c, modexp.c)
extern fn SymCryptFdefModulusAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS;
extern fn SymCryptFdefModulusFree(pmObj: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefSizeofModulusFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptFdefModulusCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS;
extern fn SymCryptFdefModulusCopy(pmSrc: PCSYMCRYPT_MODULUS, pmDst: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementAllocate(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT;
extern fn SymCryptFdefModElementFree(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefSizeofModElementFromModulus(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptFdefModElementCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT;
extern fn SymCryptFdefModElementWipe(pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementCopy(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementMaskedCopy(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, mask: UINT32) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefDivisorFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_DIVISOR;
extern fn SymCryptFdefModElementConditionalSwap(pmMod: PCSYMCRYPT_MODULUS, peData1: PSYMCRYPT_MODELEMENT, peData2: PSYMCRYPT_MODELEMENT, cond: UINT32) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefIntFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_INT;
extern fn SymCryptFdefIntToModulus(piSrc: PCSYMCRYPT_INT, pmDst: PSYMCRYPT_MODULUS, averageOperations: UINT32, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefIntToModElement(piSrc: PCSYMCRYPT_INT, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementToIntGeneric(pmMod: PCSYMCRYPT_MODULUS, pSrc: PCUINT32, piDst: PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementSetValueGeneric(pbSrc: PCBYTE, cbSrc: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModElementGetValue(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, pbDst: PBYTE, cbDst: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModElementIsEqual(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptFdefModElementIsZero(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) UINT32;
extern fn SymCryptFdefModElementSetValueUint32Generic(value: UINT32, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModElementSetValueNegUint32(value: UINT32, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptFdefModDivPow2(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, exp: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptModExpGeneric(pmMod: PCSYMCRYPT_MODULUS, peBase: PCSYMCRYPT_MODELEMENT, piExp: PCSYMCRYPT_INT, nBitsExp: UINT32, flags: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;
extern fn SymCryptModMultiExpGeneric(pmMod: PCSYMCRYPT_MODULUS, peBaseArray: [*]const PCSYMCRYPT_MODELEMENT, piExpArray: [*]const PCSYMCRYPT_INT, nBases: UINT32, nBitsExp: UINT32, flags: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR;
extern fn SymCryptFdefModSetRandomGenericEx(pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pRngState: ?*anyopaque, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void;

const entry_fdef_generic = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = &SymCryptFdefModAddGeneric,
    .modSub = &SymCryptFdefModSubGeneric,
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = &SymCryptFdefModMulGeneric,
    .modSquare = &SymCryptFdefModSquareGeneric,
    .modInv = &SymCryptFdefModInvGeneric,
    .modSetPost = &SymCryptFdefModSetPostGeneric,
    .modPreGet = &SymCryptFdefModPreGetGeneric,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupGeneric,
    .modulusInit = &SymCryptFdefModulusInitGeneric,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = &SymCryptFdefModAddGeneric,
    .modSub = &SymCryptFdefModSubGeneric,
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = &SymCryptFdefModMulMontgomery,
    .modSquare = &SymCryptFdefModSquareMontgomery,
    .modInv = &SymCryptFdefModInvMontgomery,
    .modSetPost = &SymCryptFdefModSetPostMontgomery,
    .modPreGet = &SymCryptFdefModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdefModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef369_montgomery = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = &SymCryptFdef369ModAddGeneric,
    .modSub = &SymCryptFdef369ModSubGeneric,
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = &SymCryptFdef369ModMulMontgomery,
    .modSquare = &SymCryptFdef369ModSquareMontgomery,
    .modInv = &SymCryptFdef369ModInvMontgomery,
    .modSetPost = &SymCryptFdef369ModSetPostMontgomery,
    .modPreGet = &SymCryptFdef369ModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdef369ModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_mulx256 = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = @ptrCast(&SymCryptFdefModAddMulx256Asm),
    .modSub = @ptrCast(&SymCryptFdefModSub256Asm),
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = @ptrCast(&SymCryptFdefModMulMontgomeryMulx256Asm),
    .modSquare = @ptrCast(&SymCryptFdefModSquareMontgomeryMulx256Asm),
    .modInv = &SymCryptFdefModInvMontgomery256,
    .modSetPost = &SymCryptFdefModSetPostMontgomeryMulx256,
    .modPreGet = &SymCryptFdefModPreGetMontgomery256,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdefModulusInitMontgomery256,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_mulxp384 = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = @ptrCast(&SymCryptFdefModAddMulx384Asm),
    .modSub = @ptrCast(&SymCryptFdefModSub384Asm),
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = @ptrCast(&SymCryptFdefModMulMontgomeryMulxP384Asm),
    .modSquare = @ptrCast(&SymCryptFdefModSquareMontgomeryMulxP384Asm),
    .modInv = &SymCryptFdef369ModInvMontgomery,
    .modSetPost = &SymCryptFdefModSetPostMontgomeryMulxP384,
    .modPreGet = &SymCryptFdef369ModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdef369ModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_mulx = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = &SymCryptFdefModAddGeneric,
    .modSub = &SymCryptFdefModSubGeneric,
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = &SymCryptFdefModMulMontgomeryMulx,
    .modSquare = &SymCryptFdefModSquareMontgomeryMulx,
    .modInv = &SymCryptFdefModInvMontgomery,
    .modSetPost = &SymCryptFdefModSetPostMontgomery,
    .modPreGet = &SymCryptFdefModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdefModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_mulx1024 = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = &SymCryptFdefModAddGeneric,
    .modSub = &SymCryptFdefModSubGeneric,
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = &SymCryptFdefModMulMontgomeryMulx1024,
    .modSquare = &SymCryptFdefModSquareMontgomeryMulx1024,
    .modInv = &SymCryptFdefModInvMontgomery,
    .modSetPost = &SymCryptFdefModSetPostMontgomery,
    .modPreGet = &SymCryptFdefModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdefModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_arm64256 = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = @ptrCast(&SymCryptFdefModAdd256Asm),
    .modSub = @ptrCast(&SymCryptFdefModSub256Asm),
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = @ptrCast(&SymCryptFdefModMulMontgomery256Asm),
    .modSquare = @ptrCast(&SymCryptFdefModSquareMontgomery256Asm),
    .modInv = &SymCryptFdefModInvMontgomery,
    .modSetPost = &SymCryptFdefModSetPostMontgomery,
    .modPreGet = &SymCryptFdefModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdefModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const entry_fdef_montgomery_arm64p384 = SYMCRYPT_MODULAR_FUNCTIONS{
    .modAdd = @ptrCast(&SymCryptFdefModAdd384Asm),
    .modSub = @ptrCast(&SymCryptFdefModSub384Asm),
    .modNeg = &SymCryptFdefModNegGeneric,
    .modMul = @ptrCast(&SymCryptFdefModMulMontgomeryP384Asm),
    .modSquare = @ptrCast(&SymCryptFdefModSquareMontgomeryP384Asm),
    .modInv = &SymCryptFdef369ModInvMontgomery,
    .modSetPost = &SymCryptFdef369ModSetPostMontgomery,
    .modPreGet = &SymCryptFdef369ModPreGetMontgomery,
    .modulusCopyFixup = &SymCryptFdefModulusCopyFixupMontgomery,
    .modulusInit = &SymCryptFdef369ModulusInitMontgomery,
    .slack = .{ null, null, null, null, null, null },
};

const ModFnsArrayType = if (types.CPU_AMD64 or types.CPU_ARM64)
    [8]SYMCRYPT_MODULAR_FUNCTIONS
else
    [2]SYMCRYPT_MODULAR_FUNCTIONS;

pub export const g_SymCryptModFns: ModFnsArrayType = if (types.CPU_AMD64)
    .{
        entry_fdef_generic,
        entry_fdef_montgomery,
        entry_fdef369_montgomery,
        entry_fdef_montgomery_mulx256,
        entry_fdef_montgomery_mulxp384,
        entry_fdef_montgomery_mulx,
        entry_fdef_montgomery_mulx1024,
        std.mem.zeroes(SYMCRYPT_MODULAR_FUNCTIONS),
    }
else if (types.CPU_ARM64)
    .{
        entry_fdef_generic,
        entry_fdef_montgomery,
        entry_fdef369_montgomery,
        entry_fdef_montgomery_arm64256,
        entry_fdef_montgomery_arm64p384,
        std.mem.zeroes(SYMCRYPT_MODULAR_FUNCTIONS),
        std.mem.zeroes(SYMCRYPT_MODULAR_FUNCTIONS),
        std.mem.zeroes(SYMCRYPT_MODULAR_FUNCTIONS),
    }
else
    .{
        entry_fdef_generic,
        entry_fdef_montgomery,
    };

fn SymCryptModLabel(comptime label: []const u8) UINT32 {
    return macros.multiCharConstant(label) << 16;
}

const SYMCRYPT_MODULAR_FUNCTIONS_SIZE: UINT32 = @sizeOf(SYMCRYPT_MODULAR_FUNCTIONS);

const SymCryptModFntableGeneric: UINT32 = SymCryptModLabel("gM") + (0 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomery: UINT32 = SymCryptModLabel("mM") + (1 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntable369Montgomery: UINT32 = SymCryptModLabel("9m") + (2 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomeryMulx256: UINT32 = SymCryptModLabel("2x") + (3 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomeryMulxP384: UINT32 = SymCryptModLabel("3n") + (4 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomeryMulx: UINT32 = SymCryptModLabel("xM") + (5 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomeryMulx1024: UINT32 = SymCryptModLabel("1x") + (6 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);

const SymCryptModFntableMontgomeryArm64256: UINT32 = SymCryptModLabel("2m") + (3 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);
const SymCryptModFntableMontgomeryArm64P384: UINT32 = SymCryptModLabel("3n") + (4 * SYMCRYPT_MODULAR_FUNCTIONS_SIZE);

comptime {
    std.debug.assert((@sizeOf(ModFnsArrayType) & (@sizeOf(ModFnsArrayType) - 1)) == 0);
}

pub export const g_SymCryptModFnsMask: UINT32 = @sizeOf(ModFnsArrayType) - @sizeOf(SYMCRYPT_MODULAR_FUNCTIONS);

const SelectionTableType = if (types.CPU_AMD64)
    [10]SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY
else if (types.CPU_ARM64)
    [7]SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY
else
    [2]SYMCRYPT_MODULUS_TYPE_SELECTION_ENTRY;

pub export const SymCryptModulusTypeSelections: SelectionTableType = if (types.CPU_AMD64)
    .{
        .{ .type = SymCryptModFntableMontgomeryMulxP384, .cpuFeatures = SYMCRYPT_CPU_FEATURES_FOR_MULX, .maxBits = 384, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY | types.SYMCRYPT_MODULUS_FEATURE_NISTP384 },
        .{ .type = SymCryptModFntableMontgomeryMulx256, .cpuFeatures = SYMCRYPT_CPU_FEATURES_FOR_MULX, .maxBits = 256, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomeryMulx, .cpuFeatures = SYMCRYPT_CPU_FEATURES_FOR_MULX, .maxBits = 512, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntable369Montgomery, .cpuFeatures = 0, .maxBits = 384, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomery, .cpuFeatures = 0, .maxBits = 512, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntable369Montgomery, .cpuFeatures = 0, .maxBits = 576, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomeryMulx1024, .cpuFeatures = SYMCRYPT_CPU_FEATURES_FOR_MULX, .maxBits = 1024, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomeryMulx, .cpuFeatures = SYMCRYPT_CPU_FEATURES_FOR_MULX, .maxBits = 0, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomery, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableGeneric, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = 0 },
    }
else if (types.CPU_ARM64)
    .{
        .{ .type = SymCryptModFntableMontgomeryArm64P384, .cpuFeatures = 0, .maxBits = 384, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY | types.SYMCRYPT_MODULUS_FEATURE_NISTP384 },
        .{ .type = SymCryptModFntableMontgomeryArm64256, .cpuFeatures = 0, .maxBits = 256, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntable369Montgomery, .cpuFeatures = 0, .maxBits = 384, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomery, .cpuFeatures = 0, .maxBits = 512, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntable369Montgomery, .cpuFeatures = 0, .maxBits = 576, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableMontgomery, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableGeneric, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = 0 },
    }
else
    .{
        .{ .type = SymCryptModFntableMontgomery, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = types.SYMCRYPT_MODULUS_FEATURE_MONTGOMERY },
        .{ .type = SymCryptModFntableGeneric, .cpuFeatures = 0, .maxBits = 0, .modulusFeatures = 0 },
    };

pub inline fn SYMCRYPT_MOD_FUNCTIONS(pm: PCSYMCRYPT_MODULUS) *const SYMCRYPT_MODULAR_FUNCTIONS {
    const offset: usize = macros.SYMCRYPT_FORCE_READ32(&pm.type) & g_SymCryptModFnsMask;
    const base: [*]const u8 = @ptrCast(&g_SymCryptModFns);
    return @ptrCast(@alignCast(base + offset));
}

//==============================================================================================
//  Simple dispatchers
//==============================================================================================

pub export fn SymCryptDigitsFromBits(nBits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefDigitsFromBits(nBits);
}

pub export fn SymCryptIntAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT {
    return fdef_general.SymCryptFdefIntAllocate(nDigits);
}

pub export fn SymCryptIntFree(piObj: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    SymCryptIntWipe(piObj);
    SymCryptCallbackFree(piObj);
}

pub export fn SymCryptSizeofIntFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefSizeofIntFromDigits(nDigits);
}

pub export fn SymCryptIntCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_INT {
    return fdef_general.SymCryptFdefIntCreate(pbBuffer, cbBuffer, nDigits);
}

pub export fn SymCryptIntWipe(piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(piDst);
    SymCryptWipe(piDst, piDst.cbSize);
}

pub export fn SymCryptIntCopy(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntCopy(piSrc, piDst);
}

pub export fn SymCryptIntMaskedCopy(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, mask: UINT32) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntMaskedCopy(piSrc, piDst, mask);
}

pub export fn SymCryptIntConditionalCopy(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, cond: UINT32) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntConditionalCopy(piSrc, piDst, cond);
}

pub export fn SymCryptIntConditionalSwap(piSrc1: PSYMCRYPT_INT, piSrc2: PSYMCRYPT_INT, cond: UINT32) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntConditionalSwap(piSrc1, piSrc2, cond);
}

pub export fn SymCryptIntBitsizeOfObject(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntBitsizeOfObject(piSrc);
}

pub export fn SymCryptIntDigitsizeOfObject(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return piSrc.nDigits;
}

pub export fn SymCryptIntCopyMixedSize(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return fdef_general.SymCryptFdefIntCopyMixedSize(piSrc, piDst);
}

pub export fn SymCryptIntBitsizeOfValue(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntBitsizeOfValue(piSrc);
}

pub export fn SymCryptIntSetValueUint32(u32Src: UINT32, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntSetValueUint32(u32Src, piDst);
}

pub export fn SymCryptIntSetValueUint64(u64Src: UINT64, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefIntSetValueUint64(u64Src, piDst);
}

pub export fn SymCryptIntSetValue(pbSrc: PCBYTE, cbSrc: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return fdef_general.SymCryptFdefIntSetValue(pbSrc, cbSrc, format, piDst);
}

pub export fn SymCryptIntGetValue(piSrc: PCSYMCRYPT_INT, pbDst: PBYTE, cbDst: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return fdef_general.SymCryptFdefIntGetValue(piSrc, pbDst, cbDst, format);
}

pub export fn SymCryptIntGetValueLsbits32(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntGetValueLsbits32(piSrc);
}

pub export fn SymCryptIntGetValueLsbits64(piSrc: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT64 {
    return fdef_general.SymCryptFdefIntGetValueLsbits64(piSrc);
}

pub export fn SymCryptIntAddUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntAddUint32(piSrc1, u32Src2, piDst);
}

pub export fn SymCryptIntAddSameSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntAddSameSize(piSrc1, piSrc2, piDst);
}

pub export fn SymCryptIntAddMixedSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntAddMixedSize(piSrc1, piSrc2, piDst);
}

pub export fn SymCryptIntSubUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntSubUint32(piSrc1, u32Src2, piDst);
}

pub export fn SymCryptIntSubSameSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntSubSameSize(piSrc1, piSrc2, piDst);
}

pub export fn SymCryptIntSubMixedSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntSubMixedSize(piSrc1, piSrc2, piDst);
}

pub export fn SymCryptIntNeg(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntNeg(piSrc, piDst);
}

pub export fn SymCryptIntMulPow2(piSrc: PCSYMCRYPT_INT, exp: SIZE_T, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntMulPow2(piSrc, exp, piDst);
}

pub export fn SymCryptIntDivPow2(piSrc: PCSYMCRYPT_INT, exp: SIZE_T, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntDivPow2(piSrc, exp, piDst);
}

pub export fn SymCryptIntShr1(highestBit: UINT32, piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntShr1(highestBit, piSrc, piDst);
}

pub export fn SymCryptIntModPow2(piSrc: PCSYMCRYPT_INT, exp: SIZE_T, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntModPow2(piSrc, exp, piDst);
}

pub export fn SymCryptIntGetBit(piSrc: PCSYMCRYPT_INT, iBit: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntGetBit(piSrc, iBit);
}

pub export fn SymCryptIntGetBits(piSrc: PCSYMCRYPT_INT, iBit: UINT32, nBits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntGetBits(piSrc, iBit, nBits);
}

pub export fn SymCryptIntSetBits(piDst: PSYMCRYPT_INT, value: UINT32, iBit: UINT32, nBits: UINT32) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntSetBits(piDst, value, iBit, nBits);
}

pub export fn SymCryptIntIsEqualUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntIsEqualUint32(piSrc1, u32Src2);
}

pub export fn SymCryptIntIsEqual(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntIsEqual(piSrc1, piSrc2);
}

pub export fn SymCryptIntIsLessThan(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntIsLessThan(piSrc1, piSrc2);
}

pub export fn SymCryptIntMulUint32(piSrc1: PCSYMCRYPT_INT, u32Src2: UINT32, piDst: PSYMCRYPT_INT) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_int.SymCryptFdefIntMulUint32(piSrc1, u32Src2, piDst);
}

pub export fn SymCryptIntMulSameSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntMulSameSize(piSrc1, piSrc2, piDst, pbScratch, cbScratch);
}

pub export fn SymCryptIntSquare(piSrc: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntSquare(piSrc, piDst, pbScratch, cbScratch);
}

pub export fn SymCryptIntMulMixedSize(piSrc1: PCSYMCRYPT_INT, piSrc2: PCSYMCRYPT_INT, piDst: PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntMulMixedSize(piSrc1, piSrc2, piDst, pbScratch, cbScratch);
}

pub export fn SymCryptDivisorAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DIVISOR {
    return fdef_general.SymCryptFdefDivisorAllocate(nDigits);
}

pub export fn SymCryptDivisorFree(pdObj: PSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) void {
    SymCryptDivisorWipe(pdObj);
    SymCryptCallbackFree(pdObj);
}

pub export fn SymCryptSizeofDivisorFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefSizeofDivisorFromDigits(nDigits);
}

pub export fn SymCryptDivisorCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_DIVISOR {
    return fdef_general.SymCryptFdefDivisorCreate(pbBuffer, cbBuffer, nDigits);
}

pub export fn SymCryptDivisorWipe(pdObj: PSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pdObj);
    SymCryptWipe(pdObj, pdObj.cbSize);
}

pub export fn SymCryptDivisorCopy(pdSrc: PCSYMCRYPT_DIVISOR, pdDst: PSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefDivisorCopy(pdSrc, pdDst);
}

pub export fn SymCryptDivisorDigitsizeOfObject(pdSrc: PCSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) UINT32 {
    return pdSrc.nDigits;
}

pub export fn SymCryptIntFromDivisor(pdSrc: PSYMCRYPT_DIVISOR) callconv(SYMCRYPT_CALL) PSYMCRYPT_INT {
    return fdef_int.SymCryptFdefIntFromDivisor(pdSrc);
}

pub export fn SymCryptIntToDivisor(piSrc: PCSYMCRYPT_INT, pdDst: PSYMCRYPT_DIVISOR, totalOperations: UINT32, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntToDivisor(piSrc, pdDst, totalOperations, flags, pbScratch, cbScratch);
}

pub export fn SymCryptIntDivMod(piSrc: PCSYMCRYPT_INT, pdDivisor: PCSYMCRYPT_DIVISOR, piQuotient: ?PSYMCRYPT_INT, piRemainder: ?PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    fdef_int.SymCryptFdefIntDivMod(piSrc, pdDivisor, piQuotient, piRemainder, pbScratch, cbScratch);
}

pub export fn SymCryptModulusAllocate(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS {
    return SymCryptFdefModulusAllocate(nDigits);
}

pub export fn SymCryptModulusFree(pmObj: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModulusFree(pmObj);
}

pub export fn SymCryptSizeofModulusFromDigits(nDigits: UINT32) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefSizeofModulusFromDigits(nDigits);
}

pub export fn SymCryptModulusCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODULUS {
    return SymCryptFdefModulusCreate(pbBuffer, cbBuffer, nDigits);
}

pub export fn SymCryptModulusWipe(pmObj: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_CHECK_MAGIC(pmObj);
    SymCryptWipe(pmObj, pmObj.cbSize);
}

pub export fn SymCryptModulusCopy(pmSrc: PCSYMCRYPT_MODULUS, pmDst: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModulusCopy(pmSrc, pmDst);
}

pub export fn SymCryptModulusDigitsizeOfObject(pmSrc: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) UINT32 {
    return pmSrc.nDigits;
}

pub export fn SymCryptModElementAllocate(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT {
    return SymCryptFdefModElementAllocate(pmMod);
}

pub export fn SymCryptModElementFree(pmMod: PCSYMCRYPT_MODULUS, peObj: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementFree(pmMod, peObj);
}

pub export fn SymCryptSizeofModElementFromModulus(pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefSizeofModElementFromModulus(pmMod);
}

pub export fn SymCryptModElementCreate(pbBuffer: PBYTE, cbBuffer: SIZE_T, pmMod: PCSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) ?PSYMCRYPT_MODELEMENT {
    return SymCryptFdefModElementCreate(pbBuffer, cbBuffer, pmMod);
}

pub export fn SymCryptModElementWipe(pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementWipe(pmMod, peDst);
}

pub export fn SymCryptModElementCopy(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementCopy(pmMod, peSrc, peDst);
}

pub export fn SymCryptModElementMaskedCopy(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, mask: UINT32) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementMaskedCopy(pmMod, peSrc, peDst, mask);
}

pub export fn SymCryptDivisorFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_DIVISOR {
    return SymCryptFdefDivisorFromModulus(pmSrc);
}

pub export fn SymCryptModElementConditionalSwap(pmMod: PCSYMCRYPT_MODULUS, peData1: PSYMCRYPT_MODELEMENT, peData2: PSYMCRYPT_MODELEMENT, cond: UINT32) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementConditionalSwap(pmMod, peData1, peData2, cond);
}

pub export fn SymCryptIntFromModulus(pmSrc: PSYMCRYPT_MODULUS) callconv(SYMCRYPT_CALL) PSYMCRYPT_INT {
    return SymCryptFdefIntFromModulus(pmSrc);
}

pub export fn SymCryptIntToModulus(piSrc: PCSYMCRYPT_INT, pmDst: PSYMCRYPT_MODULUS, averageOperations: UINT32, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(((flags & types.SYMCRYPT_FLAG_MODULUS_PRIME) == 0) or
        (((SymCryptIntGetValueLsbits32(piSrc) & 1) | SymCryptIntIsEqualUint32(piSrc, 2)) != 0));

    SymCryptFdefIntToModulus(piSrc, pmDst, averageOperations, flags, pbScratch, cbScratch);
}

pub export fn SymCryptIntToModElement(piSrc: PCSYMCRYPT_INT, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefIntToModElement(piSrc, pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModElementToInt(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, piDst: PSYMCRYPT_INT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    macros.SYMCRYPT_ASSERT(piDst.nDigits >= pmMod.nDigits);

    const pData = SYMCRYPT_MOD_FUNCTIONS(pmMod).modPreGet.?(pmMod, peSrc, pbScratch, cbScratch);

    SymCryptFdefModElementToIntGeneric(pmMod, pData, piDst, pbScratch, cbScratch);
}

pub export fn SymCryptModElementSetValue(pbSrc: PCBYTE, cbSrc: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    const scError = SymCryptFdefModElementSetValueGeneric(pbSrc, cbSrc, format, pmMod, peDst, pbScratch, cbScratch);

    if (scError == .SYMCRYPT_NO_ERROR) {
        SYMCRYPT_MOD_FUNCTIONS(pmMod).modSetPost.?(pmMod, peDst, pbScratch, cbScratch);
    }

    return scError;
}

pub export fn SymCryptModElementGetValue(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, pbDst: PBYTE, cbDst: SIZE_T, format: SYMCRYPT_NUMBER_FORMAT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptFdefModElementGetValue(pmMod, peSrc, pbDst, cbDst, format, pbScratch, cbScratch);
}

pub export fn SymCryptModElementIsEqual(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefModElementIsEqual(pmMod, peSrc1, peSrc2);
}

pub export fn SymCryptModElementIsZero(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT) callconv(SYMCRYPT_CALL) UINT32 {
    return SymCryptFdefModElementIsZero(pmMod, peSrc);
}

pub export fn SymCryptModAdd(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modAdd.?(pmMod, peSrc1, peSrc2, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModSub(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modSub.?(pmMod, peSrc1, peSrc2, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModMul(pmMod: PCSYMCRYPT_MODULUS, peSrc1: PCSYMCRYPT_MODELEMENT, peSrc2: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modMul.?(pmMod, peSrc1, peSrc2, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModSquare(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modSquare.?(pmMod, peSrc, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModNeg(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modNeg.?(pmMod, peSrc, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModElementSetValueUint32(value: UINT32, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementSetValueUint32Generic(value, pmMod, peDst, pbScratch, cbScratch);
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modSetPost.?(pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModElementSetValueNegUint32(value: UINT32, pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModElementSetValueNegUint32(value, pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModDivPow2(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, exp: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModDivPow2(pmMod, peSrc, exp, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModInv(pmMod: PCSYMCRYPT_MODULUS, peSrc: PCSYMCRYPT_MODELEMENT, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SYMCRYPT_MOD_FUNCTIONS(pmMod).modInv.?(pmMod, peSrc, peDst, flags, pbScratch, cbScratch);
}

pub export fn SymCryptModExp(pmMod: PCSYMCRYPT_MODULUS, peBase: PCSYMCRYPT_MODELEMENT, piExp: PCSYMCRYPT_INT, nBitsExp: UINT32, flags: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptModExpGeneric(pmMod, peBase, piExp, nBitsExp, flags, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModMultiExp(pmMod: PCSYMCRYPT_MODULUS, peBaseArray: [*]const PCSYMCRYPT_MODELEMENT, piExpArray: [*]const PCSYMCRYPT_INT, nBases: UINT32, nBitsExp: UINT32, flags: UINT32, peDst: PSYMCRYPT_MODELEMENT, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) SYMCRYPT_ERROR {
    return SymCryptModMultiExpGeneric(pmMod, peBaseArray, piExpArray, nBases, nBitsExp, flags, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModSetRandomEx(pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pRngState: ?*anyopaque, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptFdefModSetRandomGenericEx(pmMod, peDst, flags, pRngState, pbScratch, cbScratch);
    SYMCRYPT_MOD_FUNCTIONS(pmMod).modSetPost.?(pmMod, peDst, pbScratch, cbScratch);
}

pub export fn SymCryptModSetRandom(pmMod: PCSYMCRYPT_MODULUS, peDst: PSYMCRYPT_MODELEMENT, flags: UINT32, pbScratch: PBYTE, cbScratch: SIZE_T) callconv(SYMCRYPT_CALL) void {
    SymCryptModSetRandomEx(pmMod, peDst, flags, null, pbScratch, cbScratch);
}

pub export fn SymCryptCreateTrialDivisionContext(nDigits: UINT32) callconv(SYMCRYPT_CALL) ?PCSYMCRYPT_TRIALDIVISION_CONTEXT {
    return fdef_general.SymCryptFdefCreateTrialDivisionContext(nDigits);
}

pub export fn SymCryptIntFindSmallDivisor(
    pContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT,
    piSrc: PCSYMCRYPT_INT,
    pbScratch: PBYTE,
    cbScratch: SIZE_T,
) callconv(SYMCRYPT_CALL) UINT32 {
    return fdef_general.SymCryptFdefIntFindSmallDivisor(pContext, piSrc, pbScratch, cbScratch);
}

pub export fn SymCryptFreeTrialDivisionContext(pContext: PCSYMCRYPT_TRIALDIVISION_CONTEXT) callconv(SYMCRYPT_CALL) void {
    fdef_general.SymCryptFdefFreeTrialDivisionContext(pContext);
}
