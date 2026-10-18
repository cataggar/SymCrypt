//
// cpuid.zig
// CPU feature detection based on CPUID / OS / status registers
// (ports lib/cpuid.c, lib/cpuid_um.c, lib/cpuid_notry.c)
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const builtin = @import("builtin");
const types = @import("types.zig");
const macros = @import("macros.zig");
const libmain = @import("libmain.zig");

pub const SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM: u32 = 1;

const CPUID_1_ECX_RDRAND_BIT: u5 = 30;
const CPUID_1_ECX_PCLMULQDQ_BIT: u5 = 1;
const CPUID_1_ECX_AESNI_BIT: u5 = 25;
const CPUID_1_ECX_SSSE3_BIT: u5 = 9;
const CPUID_1_ECX_SSE3_BIT: u5 = 0;
const CPUID_1_EDX_SSE2_BIT: u5 = 26;
const CPUID_1_EDX_SSE_BIT: u5 = 25;
const CPUID_1_ECX_AVX_BIT: u5 = 28;
const CPUID_1_ECX_CMPXCHG16B_BIT: u5 = 13;
const CPUID_70_EBX_AVX2_BIT: u5 = 5;
const CPUID_70_EBX_RDSEED_BIT: u5 = 18;
const CPUID_70_EBX_SHANI_BIT: u5 = 29;
const CPUID_70_EBX_ADX_BIT: u5 = 19;
const CPUID_70_EBX_BMI2_BIT: u5 = 8;
const CPUID_70_EBX_AVX512F_BIT: u5 = 16;
const CPUID_70_EBX_AVX512BW_BIT: u5 = 30;
const CPUID_70_EBX_AVX512DQ_BIT: u5 = 17;
const CPUID_70_EBX_AVX512VL_BIT: u5 = 31;
const CPUID_70_ECX_VAES_BIT: u5 = 9;
const CPUID_70_ECX_VPCLMULQDQ_BIT: u5 = 10;

const CPUID_1_ECX_OSXSAVE_BIT: u5 = 27;

const WORD_EAX: usize = 0;
const WORD_EBX: usize = 1;
const WORD_ECX: usize = 2;
const WORD_EDX: usize = 3;

const CpuidBitInfo = struct {
    leaf: u8,
    word: u8,
    bitno: u5,
    requiredBy: types.SYMCRYPT_CPU_FEATURES,
};

const cpuidBitInfo = [_]CpuidBitInfo{
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_RDRAND_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_RDRAND },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_PCLMULQDQ_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_PCLMULQDQ },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_AESNI_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AESNI },
    .{ .leaf = 1, .word = WORD_EDX, .bitno = CPUID_1_EDX_SSE_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_SSE2 | types.SYMCRYPT_CPU_FEATURE_SSSE3 },
    .{ .leaf = 1, .word = WORD_EDX, .bitno = CPUID_1_EDX_SSE2_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_SSE2 | types.SYMCRYPT_CPU_FEATURE_SSSE3 },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_SSE3_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_SSSE3 },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_SSSE3_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_SSSE3 },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_AVX_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX2 },
    .{ .leaf = 1, .word = WORD_ECX, .bitno = CPUID_1_ECX_CMPXCHG16B_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_CMPXCHG16B },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_AVX2_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX2 },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_RDSEED_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_RDSEED },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_SHANI_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_SHANI },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_ADX_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_ADX },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_BMI2_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_BMI2 },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_AVX512F_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX512 },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_AVX512VL_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX512 },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_AVX512BW_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX512 },
    .{ .leaf = 7, .word = WORD_EBX, .bitno = CPUID_70_EBX_AVX512DQ_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_AVX512 },
    .{ .leaf = 7, .word = WORD_ECX, .bitno = CPUID_70_ECX_VAES_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_VAES },
    .{ .leaf = 7, .word = WORD_ECX, .bitno = CPUID_70_ECX_VPCLMULQDQ_BIT, .requiredBy = types.SYMCRYPT_CPU_FEATURE_VAES },
};

pub var g_SymCryptCpuid1: [4]c_int = .{ 0, 0, 0, 0 };

pub extern fn SymCryptCpuidExFunc(
    cpuInfo: *[4]c_int,
    function_id: c_int,
    subfunction_id: c_int,
) callconv(types.SYMCRYPT_CALL) void;

inline fn xgetbv(xcr: u32) u64 {
    var eax: u32 = undefined;
    var edx: u32 = undefined;
    asm volatile ("xgetbv"
        : [eax] "={eax}" (eax),
          [edx] "={edx}" (edx),
        : [ecx] "{ecx}" (xcr),
    );
    return (@as(u64, edx) << 32) | @as(u64, eax);
}

pub fn SymCryptDetectCpuFeaturesByCpuid(flags: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    var CPUInfo: [4]c_int = .{ 0, 0, 0, 0 };

    var result: u32 = ~(types.SYMCRYPT_CPU_FEATURE_SSE2 |
        types.SYMCRYPT_CPU_FEATURE_SSSE3 |
        types.SYMCRYPT_CPU_FEATURE_AESNI |
        types.SYMCRYPT_CPU_FEATURE_PCLMULQDQ |
        types.SYMCRYPT_CPU_FEATURE_AVX2 |
        types.SYMCRYPT_CPU_FEATURE_SHANI |
        types.SYMCRYPT_CPU_FEATURE_BMI2 |
        types.SYMCRYPT_CPU_FEATURE_ADX |
        types.SYMCRYPT_CPU_FEATURE_RDRAND |
        types.SYMCRYPT_CPU_FEATURE_RDSEED |
        types.SYMCRYPT_CPU_FEATURE_AVX512 |
        types.SYMCRYPT_CPU_FEATURE_VAES |
        types.SYMCRYPT_CPU_FEATURE_CMPXCHG16B);

    var InfoType: c_int = 0;
    SymCryptCpuidExFunc(&CPUInfo, InfoType, 0);
    const maxInfoType: c_int = CPUInfo[WORD_EAX];

    for (cpuidBitInfo) |info| {
        if (@as(c_int, info.leaf) != InfoType) {
            InfoType = @as(c_int, info.leaf);
            SymCryptCpuidExFunc(&CPUInfo, InfoType, 0);
        }
        const word_val: u32 = @bitCast(CPUInfo[info.word]);
        if (@as(c_int, info.leaf) > maxInfoType or (word_val & (@as(u32, 1) << info.bitno)) == 0) {
            result |= info.requiredBy;
        }
    }

    if ((flags & SYMCRYPT_CPUID_DETECT_FLAG_CHECK_OS_SUPPORT_FOR_YMM) != 0) {
        var allowYmm = false;
        var allowZmm = false;
        SymCryptCpuidExFunc(&CPUInfo, 1, 0);

        const ecx_val: u32 = @bitCast(CPUInfo[WORD_ECX]);
        if ((ecx_val & (@as(u32, 1) << CPUID_1_ECX_OSXSAVE_BIT)) != 0) {
            const xGetBvResult = xgetbv(0);
            if ((xGetBvResult & 0x6) == 0x6) {
                allowYmm = true;
                if ((xGetBvResult & 0xe0) == 0xe0) {
                    allowZmm = true;
                }
            }
        }

        if (!allowYmm) {
            result |= types.SYMCRYPT_CPU_FEATURE_AVX2;
        }

        if (!allowZmm) {
            result |= types.SYMCRYPT_CPU_FEATURE_AVX512;
        }
    }

    if ((result & types.SYMCRYPT_CPU_FEATURE_AESNI) == 0) {
        SymCryptCpuidExFunc(&CPUInfo, 0, 0);
        if (@as(u32, @bitCast(CPUInfo[WORD_EBX])) == macros.multiCharConstant("htuA") and
            @as(u32, @bitCast(CPUInfo[WORD_ECX])) == macros.multiCharConstant("DMAc") and
            @as(u32, @bitCast(CPUInfo[WORD_EDX])) == macros.multiCharConstant("itne"))
        {
            SymCryptCpuidExFunc(&CPUInfo, 1, 0);
            const eax_val: u32 = @bitCast(CPUInfo[WORD_EAX]);
            const baseFamily: u32 = (eax_val >> 8) & 0xf;
            const extFamily: u32 = (eax_val >> 20) & 0xff;
            const family: u32 = if (baseFamily < 0xf) baseFamily else baseFamily + extFamily;

            if (family < 0x15) {
                result |= types.SYMCRYPT_CPU_FEATURE_AESNI;
            }
        }
    }

    SymCryptCpuidExFunc(&g_SymCryptCpuid1, 1, 0);

    libmain.g_SymCryptCpuFeaturesNotPresent = result;
}

pub fn SymCryptDetectCpuFeaturesFromRegisters() callconv(types.SYMCRYPT_CALL) void {
    if (types.CPU_ARM) {
        const result: u32 = ~types.SYMCRYPT_CPU_FEATURE_NEON;
        libmain.g_SymCryptCpuFeaturesNotPresent = result;
    } else if (types.CPU_ARM64) {
        const result: u32 = ~(types.SYMCRYPT_CPU_FEATURE_NEON |
            types.SYMCRYPT_CPU_FEATURE_NEON_AES |
            types.SYMCRYPT_CPU_FEATURE_NEON_PMULL |
            types.SYMCRYPT_CPU_FEATURE_NEON_SHA256);
        libmain.g_SymCryptCpuFeaturesNotPresent = result;
    }
}

pub fn SymCryptDetectCpuFeaturesFromRegistersNoTry() callconv(types.SYMCRYPT_CALL) void {
    if (types.CPU_ARM64) {
        var isar0: u64 = 0;
        asm volatile ("mrs %[val], id_aa64isar0_el1"
            : [val] "=r" (isar0),
        );

        var result: u32 = ~(types.SYMCRYPT_CPU_FEATURE_NEON |
            types.SYMCRYPT_CPU_FEATURE_NEON_AES |
            types.SYMCRYPT_CPU_FEATURE_NEON_PMULL |
            types.SYMCRYPT_CPU_FEATURE_NEON_SHA256);

        const aes_feat: u64 = (isar0 >> (1 * 4)) & 0xF;
        const sha2_feat: u64 = (isar0 >> (3 * 4)) & 0xF;

        if (aes_feat < 1) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_AES;
        }
        if (aes_feat < 2) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_PMULL;
        }
        if (sha2_feat < 1) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_SHA256;
        }

        libmain.g_SymCryptCpuFeaturesNotPresent = result;
    }
}

extern "c" fn sysctlbyname(
    name: [*:0]const u8,
    oldp: ?*anyopaque,
    oldlenp: ?*usize,
    newp: ?*const anyopaque,
    newlen: usize,
) c_int;

extern "c" fn getauxval(aux_type: c_ulong) c_ulong;

extern "kernel32" fn IsProcessorFeaturePresent(ProcessorFeature: u32) callconv(.winapi) c_int;

const PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE: u32 = 30;
const AT_HWCAP: c_ulong = 16;
const HWCAP_AES: c_ulong = 1 << 3;
const HWCAP_PMULL: c_ulong = 1 << 4;
const HWCAP_SHA2: c_ulong = 1 << 6;

pub fn SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent() callconv(types.SYMCRYPT_CALL) void {
    if (!types.CPU_ARM64) return;

    if (builtin.os.tag == .windows) {
        if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE) != 0) {
            libmain.g_SymCryptCpuFeaturesNotPresent = ~(types.SYMCRYPT_CPU_FEATURE_NEON |
                types.SYMCRYPT_CPU_FEATURE_NEON_AES |
                types.SYMCRYPT_CPU_FEATURE_NEON_PMULL |
                types.SYMCRYPT_CPU_FEATURE_NEON_SHA256);
        } else {
            libmain.g_SymCryptCpuFeaturesNotPresent = ~types.SYMCRYPT_CPU_FEATURE_NEON;
        }
    } else if (builtin.os.tag.isDarwin()) {
        var result: types.SYMCRYPT_CPU_FEATURES = ~types.SYMCRYPT_CPU_FEATURE_NEON;
        var has_feature: u32 = 0;
        var len: usize = @sizeOf(u32);

        if (sysctlbyname("hw.optional.arm.FEAT_AES", &has_feature, &len, null, 0) == 0 and has_feature != 0) {
            result &= ~types.SYMCRYPT_CPU_FEATURE_NEON_AES;
        }

        has_feature = 0;
        len = @sizeOf(u32);
        if (sysctlbyname("hw.optional.arm.FEAT_PMULL", &has_feature, &len, null, 0) == 0 and has_feature != 0) {
            result &= ~types.SYMCRYPT_CPU_FEATURE_NEON_PMULL;
        }

        has_feature = 0;
        len = @sizeOf(u32);
        if (sysctlbyname("hw.optional.arm.FEAT_SHA256", &has_feature, &len, null, 0) == 0 and has_feature != 0) {
            result &= ~types.SYMCRYPT_CPU_FEATURE_NEON_SHA256;
        }

        libmain.g_SymCryptCpuFeaturesNotPresent = result;
    } else {
        const hwcaps = getauxval(AT_HWCAP);
        var result: types.SYMCRYPT_CPU_FEATURES = ~(types.SYMCRYPT_CPU_FEATURE_NEON |
            types.SYMCRYPT_CPU_FEATURE_NEON_AES |
            types.SYMCRYPT_CPU_FEATURE_NEON_PMULL |
            types.SYMCRYPT_CPU_FEATURE_NEON_SHA256);

        if ((hwcaps & HWCAP_AES) == 0) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_AES;
        }
        if ((hwcaps & HWCAP_PMULL) == 0) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_PMULL;
        }
        if ((hwcaps & HWCAP_SHA2) == 0) {
            result |= types.SYMCRYPT_CPU_FEATURE_NEON_SHA256;
        }

        libmain.g_SymCryptCpuFeaturesNotPresent = result;
    }
}

comptime {
    if (types.CPU_X86 or types.CPU_AMD64) {
        @export(&g_SymCryptCpuid1, .{ .name = "g_SymCryptCpuid1" });
        @export(&SymCryptDetectCpuFeaturesByCpuid, .{ .name = "SymCryptDetectCpuFeaturesByCpuid" });
    } else if (types.CPU_ARM) {
        @export(&SymCryptDetectCpuFeaturesFromRegisters, .{ .name = "SymCryptDetectCpuFeaturesFromRegisters" });
    } else if (types.CPU_ARM64) {
        @export(&SymCryptDetectCpuFeaturesFromRegisters, .{ .name = "SymCryptDetectCpuFeaturesFromRegisters" });
        @export(&SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent, .{ .name = "SymCryptDetectCpuFeaturesFromIsProcessorFeaturePresent" });
        if (builtin.os.tag == .windows) {
            @export(&SymCryptDetectCpuFeaturesFromRegistersNoTry, .{ .name = "SymCryptDetectCpuFeaturesFromRegistersNoTry" });
        }
    }
}
