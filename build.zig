const std = @import("std");

const symcrypt_version = std.SemanticVersion{
    .major = 103,
    .minor = 13,
    .patch = 0,
};

const common_c_sources: []const []const u8 = &.{
    "a_dispatch.c",
    "aes-neon.c",
    "ccm.c",
    "crt.c",
    "dh.c",
    "dl_internal_groups.c",
    "dlgroup.c",
    "dlkey.c",
    "dsa.c",
    "ec_dh.c",
    "ec_dispatch.c",
    "ec_dsa.c",
    "ec_internal_curve_params.c",
    "ec_internal_curves.c",
    "ec_montgomery.c",
    "ec_mul.c",
    "ec_short_weierstrass.c",
    "ec_twisted_edwards.c",
    "eckey.c",
    "ecpoint.c",
    "ecurve.c",
    "fdef_general.c",
    "fdef_int.c",
    "fdef_mod.c",
    "fdef369_mod.c",
    "gcm.c",
    "gen_int.c",
    "ghash.c",
    "modexp.c",
    "parhash.c",
    "primes.c",
    "rsa_enc.c",
    "rsa_padding.c",
    "rsakey.c",
    "sha256Par.c",
    "sha512Par.c",
    "xtsaes.c",
};

const x86_specialized_c_sources: []const []const u8 = &.{
    "aes-xmm.c",
    "aes-ymm.c",
    "aes-zmm.c",
    "sha256Par-ymm.c",
    "sha512Par-ymm.c",
    "sha256-xmm.c",
    "sha256-ymm.c",
    "sha512-ymm.c",
};

const unittest_cpp_sources: []const []const u8 = &.{
    "callback.cpp",
    "kat.cpp",
    "main.cpp",
    "perf.cpp",
    "perfPrint.cpp",
    "printtable.cpp",
    "ref_implementations.cpp",
    "resultMerge.cpp",
    "rndDriver.cpp",
    "rng.cpp",
    "sc_implementations.cpp",
    "testAccessors.cpp",
    "testAesCtrDrbg.cpp",
    "testArithmetic.cpp",
    "testAuthEnc.cpp",
    "testBlockCiphers.cpp",
    "testCompositeHelpers.cpp",
    "testCustomizableXof.cpp",
    "testDh.cpp",
    "testDsa.cpp",
    "testEcc.cpp",
    "testEcEncoding.cpp",
    "testhash.cpp",
    "testHbs.cpp",
    "testKdf.cpp",
    "testKem.cpp",
    "testHpke.cpp",
    "testKeyWrap.cpp",
    "testKmac.cpp",
    "testMac.cpp",
    "testMontgomery.cpp",
    "testMultiThread.cpp",
    "testPaddingPkcs7.cpp",
    "testRsaEnc.cpp",
    "testRsaSign.cpp",
    "testPqDsa.cpp",
    "testScsTable.cpp",
    "testScsTools.cpp",
    "testSelftest.cpp",
    "testServiceIndicator.cpp",
    "testStatusIndicator.cpp",
    "testStreamCipher.cpp",
    "testTlsCbcHmac.cpp",
    "testutil.cpp",
    "testWipe.cpp",
    "testXof.cpp",
    "testXts.cpp",
};

const KatFile = struct {
    name: []const u8,
    cxx_name: []const u8,
    content: []const u8,
};

const kat_files: []const KatFile = &.{
    .{ .name = "kat_IEEE802_11SaeCustom.dat", .cxx_name = "kat_IEEE802_11SaeCustom_dat", .content = @embedFile("unittest/kat_IEEE802_11SaeCustom.dat") },
    .{ .name = "kat_authenc.dat", .cxx_name = "kat_authenc_dat", .content = @embedFile("unittest/kat_authenc.dat") },
    .{ .name = "kat_blockcipher.dat", .cxx_name = "kat_blockcipher_dat", .content = @embedFile("unittest/kat_blockcipher.dat") },
    .{ .name = "kat_composite_kem.dat", .cxx_name = "kat_composite_kem_dat", .content = @embedFile("unittest/kat_composite_kem.dat") },
    .{ .name = "kat_composite_mldsa.dat", .cxx_name = "kat_composite_mldsa_dat", .content = @embedFile("unittest/kat_composite_mldsa.dat") },
    .{ .name = "kat_cxof.dat", .cxx_name = "kat_cxof_dat", .content = @embedFile("unittest/kat_cxof.dat") },
    .{ .name = "kat_dh.dat", .cxx_name = "kat_dh_dat", .content = @embedFile("unittest/kat_dh.dat") },
    .{ .name = "kat_dsa.dat", .cxx_name = "kat_dsa_dat", .content = @embedFile("unittest/kat_dsa.dat") },
    .{ .name = "kat_ecdsa.dat", .cxx_name = "kat_ecdsa_dat", .content = @embedFile("unittest/kat_ecdsa.dat") },
    .{ .name = "kat_hash.dat", .cxx_name = "kat_hash_dat", .content = @embedFile("unittest/kat_hash.dat") },
    .{ .name = "kat_hash_long.dat", .cxx_name = "kat_hash_long_dat", .content = @embedFile("unittest/kat_hash_long.dat") },
    .{ .name = "kat_hbs.dat", .cxx_name = "kat_hbs_dat", .content = @embedFile("unittest/kat_hbs.dat") },
    .{ .name = "kat_hpke.dat", .cxx_name = "kat_hpke_dat", .content = @embedFile("unittest/kat_hpke.dat") },
    .{ .name = "kat_kdf.dat", .cxx_name = "kat_kdf_dat", .content = @embedFile("unittest/kat_kdf.dat") },
    .{ .name = "kat_kem.dat", .cxx_name = "kat_kem_dat", .content = @embedFile("unittest/kat_kem.dat") },
    .{ .name = "kat_keywrap.dat", .cxx_name = "kat_keywrap_dat", .content = @embedFile("unittest/kat_keywrap.dat") },
    .{ .name = "kat_kmac.dat", .cxx_name = "kat_kmac_dat", .content = @embedFile("unittest/kat_kmac.dat") },
    .{ .name = "kat_mac.dat", .cxx_name = "kat_mac_dat", .content = @embedFile("unittest/kat_mac.dat") },
    .{ .name = "kat_pqdsa.dat", .cxx_name = "kat_pqdsa_dat", .content = @embedFile("unittest/kat_pqdsa.dat") },
    .{ .name = "kat_rng.dat", .cxx_name = "kat_rng_dat", .content = @embedFile("unittest/kat_rng.dat") },
    .{ .name = "kat_rsaenc.dat", .cxx_name = "kat_rsaenc_dat", .content = @embedFile("unittest/kat_rsaenc.dat") },
    .{ .name = "kat_rsasign.dat", .cxx_name = "kat_rsasign_dat", .content = @embedFile("unittest/kat_rsasign.dat") },
    .{ .name = "kat_streamcipher.dat", .cxx_name = "kat_streamcipher_dat", .content = @embedFile("unittest/kat_streamcipher.dat") },
    .{ .name = "kat_xof.dat", .cxx_name = "kat_xof_dat", .content = @embedFile("unittest/kat_xof.dat") },
    .{ .name = "kat_xts.dat", .cxx_name = "kat_xts_dat", .content = @embedFile("unittest/kat_xts.dat") },
};

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const use_asm = b.option(
        bool,
        "asm",
        "Enable hand-written ASM optimizations where available (default: true)",
    ) orelse true;

    const fips_build = b.option(
        bool,
        "fips",
        "Enable FIPS self-tests and entropy definitions (default: true)",
    ) orelse true;

    const arch = target.result.cpu.arch;
    const os_tag = target.result.os.tag;
    const default_build_tests = os_tag == .linux or
        (os_tag == .macos and b.graph.host.result.os.tag == .macos);
    const build_tests = b.option(
        bool,
        "unit-tests",
        "Build SymCrypt unit test executable (default: true on Linux and native macOS)",
    ) orelse default_build_tests;

    const effective_use_asm = use_asm and switch (os_tag) {
        .linux => arch == .x86_64 or arch == .aarch64 or arch == .arm,
        .macos => arch == .aarch64,
        else => false,
    };

    const generated_headers = generateHeaders(b, os_tag == .windows, build_tests and os_tag != .windows);

    const build_options = b.addOptions();
    build_options.addOption(bool, "use_asm", effective_use_asm);
    build_options.addOption(bool, "fips_build", fips_build);
    build_options.addOption(std.SemanticVersion, "symcrypt_version", symcrypt_version);

    const common_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = if (os_tag == .windows) null else true,
    });
    common_mod.addOptions("build_options", build_options);
    configureModuleCommon(b, common_mod, generated_headers, target, optimize, effective_use_asm, fips_build);
    addSymCryptCommonSources(b, common_mod, target, optimize, effective_use_asm);

    const symcrypt_lib = b.addLibrary(.{
        .name = "symcrypt",
        .linkage = .static,
        .root_module = common_mod,
        .use_llvm = true,
    });
    b.installArtifact(symcrypt_lib);

    const plus_mod = b.createModule(.{
        .root_source_file = b.path("src_plus/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = if (os_tag == .windows) null else true,
    });
    plus_mod.linkLibrary(symcrypt_lib);

    const symcrypt_plus_lib = b.addLibrary(.{
        .name = "symcrypt_plus",
        .linkage = .static,
        .root_module = plus_mod,
    });
    b.installArtifact(symcrypt_plus_lib);

    if (build_tests and os_tag != .windows) {
        const unittest_mod = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .link_libcpp = true,
            .pic = true,
        });
        configureModuleCommon(b, unittest_mod, generated_headers, target, optimize, effective_use_asm, fips_build);
        unittest_mod.addIncludePath(b.path("inc/symcrypt_plus"));
        unittest_mod.addIncludePath(b.path("lib_plus"));
        unittest_mod.addIncludePath(b.path("unittest/inc"));
        unittest_mod.addIncludePath(b.path("unittest/lib"));
        unittest_mod.addCMacro("INCLUDE_IMPL_CAPI", "0");
        unittest_mod.addCMacro("INCLUDE_IMPL_CNG", "0");
        unittest_mod.addCMacro("INCLUDE_IMPL_MSBIGNUM", "0");
        unittest_mod.addCMacro("INCLUDE_IMPL_RSA32", "0");

        const cxx_flags = getCxxFlags(b, target, optimize, &.{}) catch @panic("OOM");
        unittest_mod.addCSourceFiles(.{
            .root = b.path("unittest/lib"),
            .files = unittest_cpp_sources,
            .flags = cxx_flags,
        });
        unittest_mod.addCSourceFile(.{
            .file = b.path("unittest/lib/env_linuxSymCryptUnittest.cpp"),
            .flags = cxx_flags,
        });

        const main_extra_flags: []const []const u8 = if (arch == .x86_64 or arch == .x86)
            targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2" })
        else
            &.{};
        unittest_mod.addCSourceFile(.{
            .file = b.path("unittest/exe_posix/main_exe.cpp"),
            .flags = getCxxFlags(b, target, optimize, main_extra_flags) catch @panic("OOM"),
        });

        if (effective_use_asm and arch == .x86_64) {
            const asm_flags = getAsmFlags(b, target, optimize) catch @panic("OOM");
            const saveymm_s = generated_headers.addCopyFile(b.path("unittest/lib/amd64/saveymm-gas.asm"), "saveymm-gas.S");
            const savezmm_s = generated_headers.addCopyFile(b.path("unittest/lib/amd64/savezmm-gas.asm"), "savezmm-gas.S");
            unittest_mod.addCSourceFile(.{ .file = saveymm_s, .flags = asm_flags });
            unittest_mod.addCSourceFile(.{ .file = savezmm_s, .flags = asm_flags });
        }

        unittest_mod.linkLibrary(symcrypt_lib);
        unittest_mod.linkLibrary(symcrypt_plus_lib);
        if (os_tag == .linux) {
            unittest_mod.linkSystemLibrary("dl", .{});
            unittest_mod.linkSystemLibrary("pthread", .{});
        } else if (os_tag == .macos) {
            unittest_mod.linkFramework("Security", .{});
        }

        const unittest_exe = b.addExecutable(.{
            .name = "symcryptunittest",
            .root_module = unittest_mod,
        });
        b.installArtifact(unittest_exe);

        const run_unittest = b.addRunArtifact(unittest_exe);
        const default_test_args: []const []const u8 = if (optimize == .debug)
            &.{
                "noperftests",
                "+Md5",
                "+Sha256",
                "+Sha3",
                "+HmacSha256",
                "+Aes",
                "+XtsAes",
                "+AesKw",
                "+AesCmac",
                "+AesCtrDrbg",
                "+ChaCha20",
                "+Poly1305",
                "+Pbkdf2",
                "+Hkdf",
                "+TlsPrf",
                "+Hpke",
            }
        else
            &.{
                "noperftests",
                "+Md5",
                "+Sha256",
                "+Sha3",
                "+HmacSha256",
                "+Aes",
                "+XtsAes",
                "+AesKw",
                "+AesCmac",
                "+AesCtrDrbg",
                "+ChaCha20",
                "+Poly1305",
                "+Pbkdf2",
                "+Hkdf",
                "+TlsPrf",
                "+Ecdsa",
                "+Ecdh",
                "+MlKem",
                "+MlDsa",
                "+Hpke",
            };
        if (b.option([]const []const u8, "test-args", "Arguments forwarded to symcryptunittest")) |args| {
            run_unittest.addArgs(args);
        } else {
            run_unittest.addArgs(default_test_args);
        }
        const test_step = b.step("test", "Run SymCrypt unit tests");
        test_step.dependOn(&run_unittest.step);
    }
}

fn generateHeaders(b: *std.Build, is_windows: bool, include_kat_headers: bool) *std.Build.Step.WriteFile {
    const wf = b.addWriteFiles();

    if (is_windows) {
        _ = wf.add("Windows.h",
            \\#pragma once
            \\#define __C_ASSERT__ __WINNT_C_ASSERT__
            \\#include <windows.h>
            \\#undef __C_ASSERT__
            \\#undef C_ASSERT
            \\#undef FORCEINLINE
            \\
        );
    }

    const shared_inc = std.fmt.allocPrint(
        b.allocator,
        \\#define SYMCRYPT_CODE_VERSION_API       {d}
        \\#define SYMCRYPT_CODE_VERSION_MINOR     {d}
        \\#define SYMCRYPT_CODE_VERSION_PATCH     {d}
        \\
        \\#if defined(DBG)
        \\#define SYMCRYPT_DEBUG 1
        \\#else
        \\#define SYMCRYPT_DEBUG 0
        \\#endif
        \\
    ,
        .{ symcrypt_version.major, symcrypt_version.minor, symcrypt_version.patch },
    ) catch @panic("OOM");
    _ = wf.add("symcrypt_internal_shared.inc", shared_inc);

    const build_info =
        \\#include "symcrypt_internal_shared.inc"
        \\
        \\#define _SYMCRYPT_STRING_INT(a) #a
        \\#define _SYMCRYPT_STRING(a) _SYMCRYPT_STRING_INT(a)
        \\#define SYMCRYPT_BUILD_INFO_BRANCH    "zig"
        \\#define SYMCRYPT_BUILD_INFO_COMMIT    "zig-build"
        \\#define SYMCRYPT_BUILD_INFO_VERSION   _SYMCRYPT_STRING(SYMCRYPT_CODE_VERSION_API) "." _SYMCRYPT_STRING(SYMCRYPT_CODE_VERSION_MINOR) "." _SYMCRYPT_STRING(SYMCRYPT_CODE_VERSION_PATCH)
        \\#define SYMCRYPT_BUILD_INFO_TIMESTAMP "1970-01-01T00:00:00"
        \\
    ;
    _ = wf.add("buildInfo.h", build_info);

    if (include_kat_headers) {
        var resource_buf: std.ArrayListUnmanaged(u8) = .empty;
        resource_buf.appendSlice(b.allocator, "#pragma once\n") catch @panic("OOM");

        for (kat_files) |kat| {
            const header_name = std.fmt.allocPrint(b.allocator, "{s}.h", .{kat.name}) catch @panic("OOM");
            const header_content = std.fmt.allocPrint(
                b.allocator,
                "#pragma once\nstatic const char {s}[] = R\"for_c++_include(\n{s})for_c++_include\";\n",
                .{ kat.cxx_name, kat.content },
            ) catch @panic("OOM");
            _ = wf.add(header_name, header_content);
            const include_line = std.fmt.allocPrint(b.allocator, "#include \"{s}\"\n", .{header_name}) catch @panic("OOM");
            resource_buf.appendSlice(b.allocator, include_line) catch @panic("OOM");
        }

        resource_buf.appendSlice(b.allocator,
            \\
            \\static inline
            \\size_t GetResourceBytes(const char *resourceName, const char **bytes)
            \\{
            \\
        ) catch @panic("OOM");

        for (kat_files) |kat| {
            const branch_code = std.fmt.allocPrint(
                b.allocator,
                \\    if (strcasecmp(resourceName, "{s}") == 0) {{
                \\        *bytes = {s};
                \\        return sizeof({s});
                \\    }}
                \\
            ,
                .{ kat.name, kat.cxx_name, kat.cxx_name },
            ) catch @panic("OOM");
            resource_buf.appendSlice(b.allocator, branch_code) catch @panic("OOM");
        }

        resource_buf.appendSlice(b.allocator, "    return 0;\n}\n") catch @panic("OOM");
        _ = wf.add("resource.h", resource_buf.items);
    }

    return wf;
}

fn configureModuleCommon(
    b: *std.Build,
    mod: *std.Build.Module,
    generated_headers: *std.Build.Step.WriteFile,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    use_asm: bool,
    fips_build: bool,
) void {
    mod.addIncludePath(b.path("inc"));
    mod.addIncludePath(b.path("lib"));
    mod.addIncludePath(generated_headers.getDirectory());

    if (!use_asm) {
        mod.addCMacro("SYMCRYPT_IGNORE_PLATFORM", "1");
    }
    if (fips_build) {
        mod.addCMacro("SYMCRYPT_MODULE_DO_FIPS_SELFTESTS", "1");
        mod.addCMacro("SYMCRYPT_MODULE_USE_FIPS_ENTROPY", "1");
    }
    if (optimize == .debug) {
        mod.addCMacro("DBG", "1");
    }
    _ = target;
}

fn addSymCryptCommonSources(
    b: *std.Build,
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    use_asm: bool,
) void {
    const base_c_flags = getCFlags(b, target, optimize, &.{}) catch @panic("OOM");
    mod.addCSourceFiles(.{
        .root = b.path("lib"),
        .files = common_c_sources,
        .flags = base_c_flags,
    });

    const arch = target.result.cpu.arch;
    const os_tag = target.result.os.tag;

    if (os_tag == .windows) {
        mod.addCSourceFile(.{
            .file = b.path("lib/IEEE802_11SaeCustom.c"),
            .flags = base_c_flags,
        });
    } else if (arch == .x86_64 or arch == .x86) {
        mod.addCSourceFile(.{
            .file = b.path("lib/linux/intrinsics.c"),
            .flags = base_c_flags,
        });
    }

    if (arch == .x86_64 or arch == .x86) {
        mod.addCSourceFile(.{
            .file = b.path("lib/aes-xmm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{"+ssse3"})) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/aes-ymm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2", "+vaes", "+vpclmulqdq" })) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/aes-zmm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2", "+f16c", "+avx512f", "+avx512bw", "+avx512dq", "+avx512vl", "+evex512", "+vaes", "+vpclmulqdq" })) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/sha256Par-ymm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2" })) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/sha512Par-ymm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2" })) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/sha256-xmm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{"+ssse3"})) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/sha256-ymm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2", "+bmi2" })) catch @panic("OOM"),
        });
        mod.addCSourceFile(.{
            .file = b.path("lib/sha512-ymm.c"),
            .flags = getCFlags(b, target, optimize, targetFeatureFlags(&.{ "+sse4.1", "+sse4.2", "+avx", "+avx2", "+bmi2" })) catch @panic("OOM"),
        });
    } else {
        mod.addCSourceFiles(.{
            .root = b.path("lib"),
            .files = x86_specialized_c_sources,
            .flags = base_c_flags,
        });
    }

    if (use_asm and os_tag != .windows) {
        const assembler = if (os_tag == .macos) "gas-macho" else "gas";
        const asm_flags = getAsmFlags(b, target, optimize) catch @panic("OOM");
        if (arch == .x86_64) {
            mod.addIncludePath(b.path("lib/amd64"));
            const amd64_asm = [_]struct { file: []const u8, out: []const u8, inc: ?[]const u8 }{
                .{ .file = "lib/amd64/aesasm.symcryptasm", .out = "aesasm-gas.S", .inc = null },
                .{ .file = "lib/amd64/fdef_asm.symcryptasm", .out = "fdef_asm-gas.S", .inc = null },
                .{ .file = "lib/amd64/fdef369_asm.symcryptasm", .out = "fdef369_asm-gas.S", .inc = null },
                .{ .file = "lib/amd64/fdef_mulx.symcryptasm", .out = "fdef_mulx-gas.S", .inc = null },
                .{ .file = "lib/amd64/wipe.symcryptasm", .out = "wipe-gas.S", .inc = null },
                .{ .file = "lib/amd64/sha256xmm_asm.symcryptasm", .out = "sha256xmm_asm-gas.S", .inc = "lib/amd64/sha2common_asm.symcryptasm" },
                .{ .file = "lib/amd64/sha256ymm_asm.symcryptasm", .out = "sha256ymm_asm-gas.S", .inc = "lib/amd64/sha2common_asm.symcryptasm" },
                .{ .file = "lib/amd64/sha512ymm_asm.symcryptasm", .out = "sha512ymm_asm-gas.S", .inc = "lib/amd64/sha2common_asm.symcryptasm" },
                .{ .file = "lib/amd64/sha512ymm_avx512vl_asm.symcryptasm", .out = "sha512ymm_avx512vl_asm-gas.S", .inc = "lib/amd64/sha2common_asm.symcryptasm" },
            };
            for (amd64_asm) |entry| {
                const processed = processSymCryptAsm(b, assembler, "amd64", "systemv", entry.file, entry.out, entry.inc);
                mod.addCSourceFile(.{
                    .file = processed,
                    .flags = asm_flags,
                });
            }
        } else if (arch == .aarch64) {
            mod.addIncludePath(b.path("lib/arm64"));
            const arm64_asm = [_]struct { file: []const u8, out: []const u8 }{
                .{ .file = "lib/arm64/fdef_asm.symcryptasm", .out = "fdef_asm-gas.S" },
                .{ .file = "lib/arm64/fdef369_asm.symcryptasm", .out = "fdef369_asm-gas.S" },
                .{ .file = "lib/arm64/wipe.symcryptasm", .out = "wipe-gas.S" },
            };
            for (arm64_asm) |entry| {
                const processed = processSymCryptAsm(b, assembler, "arm64", "aapcs64", entry.file, entry.out, null);
                mod.addCSourceFile(.{
                    .file = processed,
                    .flags = asm_flags,
                });
            }
        } else if (arch == .arm) {
            mod.addIncludePath(b.path("lib/arm"));
            const arm_asm = [_]struct { file: []const u8, out: []const u8 }{
                .{ .file = "lib/arm/aesasm.symcryptasm", .out = "aesasm-gas.S" },
                .{ .file = "lib/arm/fdef_asm.symcryptasm", .out = "fdef_asm-gas.S" },
                .{ .file = "lib/arm/wipe.symcryptasm", .out = "wipe-gas.S" },
            };
            for (arm_asm) |entry| {
                const processed = processSymCryptAsm(b, assembler, "arm", "aapcs32", entry.file, entry.out, null);
                mod.addCSourceFile(.{
                    .file = processed,
                    .flags = asm_flags,
                });
            }
        }
    }
}

fn processSymCryptAsm(
    b: *std.Build,
    assembler: []const u8,
    arch: []const u8,
    calling_conv: []const u8,
    input_rel_path: []const u8,
    output_name: []const u8,
    extra_dep: ?[]const u8,
) std.Build.LazyPath {
    const run = b.addSystemCommand(&.{"python3"});
    run.addFileArg(b.path("scripts/symcryptasm_processor.py"));
    run.addArgs(&.{ assembler, arch, calling_conv });
    run.addFileArg(b.path(input_rel_path));
    if (extra_dep) |dep| {
        run.addFileInput(b.path(dep));
    }
    return run.addOutputFileArg(output_name);
}

fn targetFeatureFlags(comptime features: []const []const u8) *const [features.len * 4][]const u8 {
    return comptime blk: {
        var result: [features.len * 4][]const u8 = undefined;
        for (features, 0..) |feat, i| {
            result[i * 4 + 0] = "-Xclang";
            result[i * 4 + 1] = "-target-feature";
            result[i * 4 + 2] = "-Xclang";
            result[i * 4 + 3] = feat;
        }
        const final = result;
        break :blk &final;
    };
}

fn appendCommonFlags(
    list: *std.ArrayListUnmanaged([]const u8),
    gpa: std.mem.Allocator,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) !void {
    try list.appendSlice(gpa, &.{
        "-Wno-unknown-pragmas",
        "-Werror",
        "-Wno-deprecated-declarations",
        "-Wno-deprecated",
        "-Wno-multichar",
        "-fno-builtin-bcmp",
        "-fms-extensions",
        "-fno-unroll-loops",
        "-fno-sanitize=alignment,null,object-size,function",
        "-fno-sanitize-trap=alignment,null,object-size,function",
    });

    const arch = target.result.cpu.arch;
    const os_tag = target.result.os.tag;
    if (os_tag != .macos and os_tag != .windows) {
        try list.append(gpa, "-fno-plt");
    }
    if (arch == .x86_64 or arch == .x86) {
        try list.appendSlice(gpa, targetFeatureFlags(&.{
            "+sse2",
            "+sse3",
            "+ssse3",
            "+xsave",
            "+aes",
            "+pclmul",
            "+sha",
            "+rdrnd",
            "+rdseed",
        }));
    } else if (arch == .aarch64) {
        if (os_tag != .macos) {
            try list.appendSlice(gpa, &.{
                "-flax-vector-conversions",
                "-mno-outline-atomics",
            });
        }
        try list.appendSlice(gpa, targetFeatureFlags(&.{
            "+neon",
            "+aes",
            "+sha2",
        }));
    } else if (arch == .arm) {
        try list.appendSlice(gpa, &.{
            "-march=armv7-a+neon-vfpv4",
            "-flax-vector-conversions",
            "-mfpu=neon",
            "-mno-unaligned-access",
        });
    }

    if (arch == .x86_64 and optimize != .debug) {
        try list.appendSlice(gpa, &.{
            "-mllvm",
            "-x86-speculative-load-hardening",
        });
    }
}

fn getCFlags(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    extra: []const []const u8,
) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    try list.appendSlice(b.allocator, &.{
        "-std=c11",
        "-Wno-incompatible-pointer-types",
    });
    try appendCommonFlags(&list, b.allocator, target, optimize);
    try list.appendSlice(b.allocator, extra);
    return list.toOwnedSlice(b.allocator);
}

fn getCxxFlags(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    extra: []const []const u8,
) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    try list.appendSlice(b.allocator, &.{
        "-std=c++17",
        "-Wno-write-strings",
    });
    try appendCommonFlags(&list, b.allocator, target, optimize);
    try list.appendSlice(b.allocator, extra);
    return list.toOwnedSlice(b.allocator);
}

fn getAsmFlags(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
) ![]const []const u8 {
    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    try list.appendSlice(b.allocator, &.{
        "-x",
        "assembler-with-cpp",
        "-Wno-unused-command-line-argument",
        "-Wno-unicode",
        "-DSYMCRYPT_GAS",
    });
    switch (target.result.cpu.arch) {
        .x86_64 => try list.append(b.allocator, "-DSYMCRYPT_CPU_AMD64"),
        .x86 => try list.append(b.allocator, "-DSYMCRYPT_CPU_X86"),
        .aarch64 => try list.append(b.allocator, "-DSYMCRYPT_CPU_ARM64"),
        .arm => try list.append(b.allocator, "-DSYMCRYPT_CPU_ARM"),
        else => {},
    }
    if (optimize == .debug) {
        try list.append(b.allocator, "-DDBG=1");
    }
    return list.toOwnedSlice(b.allocator);
}
