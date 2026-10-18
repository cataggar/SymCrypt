const std = @import("std");

const symcrypt_version = std.SemanticVersion{
    .major = 103,
    .minor = 13,
    .patch = 0,
};

const kat_file_names: []const []const u8 = &.{
    "kat_IEEE802_11SaeCustom.dat",
    "kat_authenc.dat",
    "kat_blockcipher.dat",
    "kat_composite_kem.dat",
    "kat_composite_mldsa.dat",
    "kat_cxof.dat",
    "kat_dh.dat",
    "kat_dsa.dat",
    "kat_ecdsa.dat",
    "kat_hash.dat",
    "kat_hash_long.dat",
    "kat_hbs.dat",
    "kat_hpke.dat",
    "kat_kdf.dat",
    "kat_kem.dat",
    "kat_keywrap.dat",
    "kat_kmac.dat",
    "kat_mac.dat",
    "kat_pqdsa.dat",
    "kat_rng.dat",
    "kat_rsaenc.dat",
    "kat_rsasign.dat",
    "kat_streamcipher.dat",
    "kat_xof.dat",
    "kat_xts.dat",
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

    const generated_headers = generateHeaders(b);

    const build_options = b.addOptions();
    build_options.addOption(bool, "use_asm", effective_use_asm);
    build_options.addOption(bool, "fips_build", fips_build);
    build_options.addOption(std.SemanticVersion, "symcrypt_version", symcrypt_version);
    const build_options_mod = build_options.createModule();

    const common_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = if (os_tag == .windows) null else true,
    });
    common_mod.addImport("build_options", build_options_mod);
    configureModuleCommon(b, common_mod, generated_headers);
    addSymCryptCommonSources(b, common_mod, target, optimize, effective_use_asm);

    const symcrypt_lib = b.addLibrary(.{
        .name = "symcrypt",
        .linkage = .static,
        .root_module = common_mod,
        .use_llvm = true,
    });
    b.installArtifact(symcrypt_lib);

    const jent_dep = b.dependency("jitterentropy", .{
        .target = target,
        .optimize = optimize,
        .linkage = .static,
        .tools = false,
    });

    const module_mod = b.createModule(.{
        .root_source_file = b.path("src/module_root.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .pic = if (os_tag == .windows) null else true,
    });
    module_mod.addImport("build_options", build_options_mod);
    configureModuleCommon(b, module_mod, generated_headers);
    addSymCryptCommonSources(b, module_mod, target, optimize, effective_use_asm);
    module_mod.linkLibrary(jent_dep.artifact("jitterentropy"));
    if (os_tag == .windows) {
        module_mod.linkSystemLibrary("bcrypt", .{});
    } else if (os_tag == .linux or os_tag == .macos) {
        module_mod.linkSystemLibrary("pthread", .{});
    }

    const symcrypt_shared_lib = b.addLibrary(.{
        .name = "symcrypt",
        .linkage = .dynamic,
        .version = symcrypt_version,
        .root_module = module_mod,
        .use_llvm = true,
    });
    b.installArtifact(symcrypt_shared_lib);

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
        const types_mod = b.createModule(.{
            .root_source_file = b.path("src/types.zig"),
            .target = target,
            .optimize = optimize,
        });
        types_mod.addImport("build_options", build_options_mod);

        const unittest_mod = b.createModule(.{
            .root_source_file = b.path("unittest_zig/root.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .pic = true,
        });
        unittest_mod.addImport("build_options", build_options_mod);
        unittest_mod.addImport("symcrypt_types", types_mod);
        for (kat_file_names) |kat_name| {
            const rel_path = std.fmt.allocPrint(b.allocator, "unittest/{s}", .{kat_name}) catch @panic("OOM");
            unittest_mod.addAnonymousImport(kat_name, .{
                .root_source_file = b.path(rel_path),
            });
        }
        configureModuleCommon(b, unittest_mod, generated_headers);

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
        run_unittest.step.dependOn(b.getInstallStep());
        const test_step = b.step("test", "Run SymCrypt unit tests");
        test_step.dependOn(&run_unittest.step);
    }
}

fn generateHeaders(b: *std.Build) *std.Build.Step.WriteFile {
    const wf = b.addWriteFiles();

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

    return wf;
}

fn configureModuleCommon(
    b: *std.Build,
    mod: *std.Build.Module,
    generated_headers: *std.Build.Step.WriteFile,
) void {
    mod.addIncludePath(b.path("inc"));
    mod.addIncludePath(b.path("lib"));
    mod.addIncludePath(generated_headers.getDirectory());
}

fn addSymCryptCommonSources(
    b: *std.Build,
    mod: *std.Build.Module,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.Optimize,
    use_asm: bool,
) void {
    const arch = target.result.cpu.arch;
    const os_tag = target.result.os.tag;

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
