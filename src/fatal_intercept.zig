//
// fatal_intercept.zig
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Empty function which our test code can replace to intercept any Fatal calls.
// Used in Kernel-mode tests so that an error doesn't bugcheck the machine.
// Rather, it can kill the current thread and not take down the machine.
//
// Exported with weak linkage so that callers (e.g. unittest) can override it
// even when other symbols from the Zig compilation unit are linked.
//

const types = @import("types.zig");

pub fn symCryptFatalInterceptImpl(fatalCode: types.UINT32) callconv(types.SYMCRYPT_CALL) void {
    _ = fatalCode;
}

comptime {
    @export(&symCryptFatalInterceptImpl, .{
        .name = "SymCryptFatalIntercept",
        .linkage = .weak,
    });
}
