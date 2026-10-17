// Copyright (c) Microsoft Corporation. Licensed under the MIT license.

const std = @import("std");

pub const rng = @import("rng.zig");
pub const rnd_driver = @import("rnd_driver.zig");
pub const callback = @import("callback.zig");
pub const testutil = @import("testutil.zig");
pub const printtable = @import("printtable.zig");
pub const result_merge = @import("result_merge.zig");
pub const kat = @import("kat.zig");
pub const main_harness = @import("main_harness.zig");
pub const ref_implementations = @import("ref_implementations.zig");
pub const sc_implementations = @import("sc_implementations.zig");
pub const test_hash = @import("test_hash.zig");
pub const test_xof = @import("test_xof.zig");
pub const test_customizable_xof = @import("test_customizable_xof.zig");
pub const test_kmac = @import("test_kmac.zig");
pub const test_mac = @import("test_mac.zig");
pub const test_kdf = @import("test_kdf.zig");
pub const test_block_ciphers = @import("test_block_ciphers.zig");
pub const test_auth_enc = @import("test_auth_enc.zig");
pub const test_stream_cipher = @import("test_stream_cipher.zig");
pub const test_xts = @import("test_xts.zig");
pub const test_key_wrap = @import("test_key_wrap.zig");
pub const test_padding_pkcs7 = @import("test_padding_pkcs7.zig");
pub const test_tls_cbc_hmac = @import("test_tls_cbc_hmac.zig");
pub const test_aes_ctr_drbg = @import("test_aes_ctr_drbg.zig");

extern fn scTestCppMain(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int;

pub export fn main(argc: c_int, argv: [*][*:0]u8) callconv(.c) c_int {
    std.debug.maybeEnableSegfaultHandler();
    return scTestCppMain(argc, argv);
}

comptime {
    _ = rng;
    _ = rnd_driver;
    _ = callback;
    _ = testutil;
    _ = printtable;
    _ = result_merge;
    _ = kat;
    _ = main_harness;
    _ = ref_implementations;
    _ = sc_implementations;
    _ = test_hash;
    _ = test_xof;
    _ = test_customizable_xof;
    _ = test_kmac;
    _ = test_mac;
    _ = test_kdf;
    _ = test_block_ciphers;
    _ = test_auth_enc;
    _ = test_stream_cipher;
    _ = test_xts;
    _ = test_key_wrap;
    _ = test_padding_pkcs7;
    _ = test_tls_cbc_hmac;
    _ = test_aes_ctr_drbg;
}
