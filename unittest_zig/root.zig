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
pub const test_arithmetic = @import("test_arithmetic.zig");
pub const test_montgomery = @import("test_montgomery.zig");
pub const test_dh = @import("test_dh.zig");
pub const test_dsa = @import("test_dsa.zig");
pub const test_ecc = @import("test_ecc.zig");
pub const test_ec_encoding = @import("test_ec_encoding.zig");
pub const test_rsa_enc = @import("test_rsa_enc.zig");
pub const test_rsa_sign = @import("test_rsa_sign.zig");
pub const test_accessors = @import("test_accessors.zig");
pub const test_wipe = @import("test_wipe.zig");
pub const test_scs_table = @import("test_scs_table.zig");
pub const test_scs_tools = @import("test_scs_tools.zig");
pub const test_selftest = @import("test_selftest.zig");
pub const test_service_indicator = @import("test_service_indicator.zig");
pub const test_status_indicator = @import("test_status_indicator.zig");
pub const test_multi_thread = @import("test_multi_thread.zig");
pub const test_composite_helpers = @import("test_composite_helpers.zig");
pub const test_hbs = @import("test_hbs.zig");
pub const test_kem = @import("test_kem.zig");
pub const test_pq_dsa = @import("test_pq_dsa.zig");
pub const test_hpke = @import("test_hpke.zig");
pub const perf = @import("perf.zig");

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
    _ = test_arithmetic;
    _ = test_montgomery;
    _ = test_dh;
    _ = test_dsa;
    _ = test_ecc;
    _ = test_ec_encoding;
    _ = test_rsa_enc;
    _ = test_rsa_sign;
    _ = test_accessors;
    _ = test_wipe;
    _ = test_scs_table;
    _ = test_scs_tools;
    _ = test_selftest;
    _ = test_service_indicator;
    _ = test_status_indicator;
    _ = test_multi_thread;
    _ = test_composite_helpers;
    _ = test_hbs;
    _ = test_kem;
    _ = test_pq_dsa;
    _ = test_hpke;
    _ = perf;
}
