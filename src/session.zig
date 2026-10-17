//
// session.zig   code for Session API implementation
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//

const std = @import("std");
const types = @import("types.zig");
const macros = @import("macros.zig");

const BYTE = types.BYTE;
const PBYTE = types.PBYTE;
const PCBYTE = types.PCBYTE;
const UINT32 = types.UINT32;
const UINT64 = types.UINT64;
const PUINT64 = types.PUINT64;
const PCUINT64 = types.PCUINT64;
const SIZE_T = types.SIZE_T;
const PVOID = types.PVOID;
const SYMCRYPT_ERROR = types.SYMCRYPT_ERROR;
const PCSYMCRYPT_GCM_EXPANDED_KEY = types.PCSYMCRYPT_GCM_EXPANDED_KEY;
const SYMCRYPT_SESSION_REPLAY_STATE = types.SYMCRYPT_SESSION_REPLAY_STATE;
const PSYMCRYPT_SESSION_REPLAY_STATE = types.PSYMCRYPT_SESSION_REPLAY_STATE;
const PCSYMCRYPT_SESSION_REPLAY_STATE = types.PCSYMCRYPT_SESSION_REPLAY_STATE;
const SYMCRYPT_SESSION = types.SYMCRYPT_SESSION;
const PSYMCRYPT_SESSION = types.PSYMCRYPT_SESSION;

const SYMCRYPT_FLAG_SESSION_ENCRYPT = types.SYMCRYPT_FLAG_SESSION_ENCRYPT;
const SYMCRYPT_SESSION_MAX_MESSAGE_NUMBER = types.SYMCRYPT_SESSION_MAX_MESSAGE_NUMBER;

extern fn SymCryptCallbackAllocateMutexFastInproc() callconv(types.SYMCRYPT_CALL) PVOID;
extern fn SymCryptCallbackFreeMutexFastInproc(pMutex: PVOID) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCallbackAcquireMutexFastInproc(pMutex: PVOID) callconv(types.SYMCRYPT_CALL) void;
extern fn SymCryptCallbackReleaseMutexFastInproc(pMutex: PVOID) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptGcmEncrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
) callconv(types.SYMCRYPT_CALL) void;

extern fn SymCryptGcmDecrypt(
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbNonce: PCBYTE,
    cbNonce: SIZE_T,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR;

inline fn atomicAdd64PostRelaxed(dest: *UINT64, val: UINT64) UINT64 {
    return @atomicRmw(UINT64, dest, .Add, val, .monotonic) +% val;
}

inline fn atomicLoad64Relaxed(dest: *const UINT64) UINT64 {
    return @atomicLoad(UINT64, dest, .monotonic);
}

inline fn SymCryptAtomicCas128Relaxed(
    destination: PUINT64,
    expectedValue: PUINT64,
    desiredValue: PCUINT64,
) bool {
    if (comptime types.CPU_AMD64) {
        var result: u8 = undefined;
        var exp_lo: u64 = expectedValue[0];
        var exp_hi: u64 = expectedValue[1];
        asm volatile (
            \\lock cmpxchg16b (%[dest])
            \\sete %[res]
            : [res] "=r" (result),
              [exp_hi] "+{rdx}" (exp_hi),
              [exp_lo] "+{rax}" (exp_lo),
            : [dest] "r" (destination),
              [des_hi] "{rcx}" (desiredValue[1]),
              [des_lo] "{rbx}" (desiredValue[0]),
            : .{ .cc = true, .memory = true });
        expectedValue[0] = exp_lo;
        expectedValue[1] = exp_hi;
        return result != 0;
    } else if (comptime types.CPU_ARM64) {
        const dest_ptr: *align(16) u128 = @ptrCast(@alignCast(destination));
        const exp_ptr: *align(8) u128 = @ptrCast(@alignCast(expectedValue));
        const des_ptr: *align(8) const u128 = @ptrCast(@alignCast(desiredValue));
        if (@cmpxchgStrong(u128, dest_ptr, exp_ptr.*, des_ptr.*, .monotonic, .monotonic)) |actual| {
            exp_ptr.* = actual;
            return false;
        }
        return true;
    } else {
        unreachable;
    }
}

pub export fn SymCryptSessionSenderInit(
    pSession: PSYMCRYPT_SESSION,
    senderId: UINT32,
    flags: UINT32,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    // Make sure we only specify the correct flags
    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    pSession.replayState.messageNumber = 0;
    pSession.senderId = senderId;
    pSession.flags = SYMCRYPT_FLAG_SESSION_ENCRYPT;
    pSession.pMutex = null;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSessionReceiverInit(
    pSession: PSYMCRYPT_SESSION,
    senderId: UINT32,
    flags: UINT32,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var pMutex: PVOID = null;

    // Make sure we only specify the correct flags
    if (flags != 0) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (comptime types.CPU_AMD64) {
        if (!macros.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_CMPXCHG16B)) {
            pMutex = SymCryptCallbackAllocateMutexFastInproc();
            if (pMutex == null) {
                return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
            }
        }
    } else if (comptime types.CPU_ARM64) {
        // Arm64 always has support for CAS128 - so never need a lock
    } else {
        // 32b and generic platforms will always need to use a lock
        pMutex = SymCryptCallbackAllocateMutexFastInproc();
        if (pMutex == null) {
            return .SYMCRYPT_MEMORY_ALLOCATION_FAILURE;
        }
    }
    pSession.pMutex = pMutex;

    // This represents that the message numbers 1-64 inclusive have not yet been successfully use in decryption
    pSession.replayState.replayMask = 0;
    pSession.replayState.messageNumber = 64;

    pSession.senderId = senderId;
    pSession.flags = 0;

    return .SYMCRYPT_NO_ERROR;
}

pub export fn SymCryptSessionDestroy(
    pSession: PSYMCRYPT_SESSION,
) callconv(types.SYMCRYPT_CALL) void {
    if (pSession.pMutex != null) {
        SymCryptCallbackFreeMutexFastInproc(pSession.pMutex);
    }
    macros.SymCryptWipeKnownSize(pSession, @sizeOf(SYMCRYPT_SESSION));
}

pub export fn SymCryptSessionGcmEncrypt(
    pSession: PSYMCRYPT_SESSION,
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PBYTE,
    cbTag: SIZE_T,
    pu64MessageNumber: ?*UINT64,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var nonce: [12]BYTE = undefined;

    if ((pSession.flags & SYMCRYPT_FLAG_SESSION_ENCRYPT) != SYMCRYPT_FLAG_SESSION_ENCRYPT) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    const messageNumber: UINT64 = atomicAdd64PostRelaxed(&pSession.replayState.messageNumber, 1);

    // We do not allow messageNumber to go above some maximum value (currently 2^64 - 2^32)
    if (messageNumber > SYMCRYPT_SESSION_MAX_MESSAGE_NUMBER) {
        // Decrement the session messageNumber on the error path so that this session will continue
        // to only generate errors
        _ = atomicAdd64PostRelaxed(&pSession.replayState.messageNumber, @bitCast(@as(i64, -1)));
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    macros.SYMCRYPT_STORE_MSBFIRST32(nonce[0..].ptr, pSession.senderId);
    macros.SYMCRYPT_STORE_MSBFIRST64(nonce[4..].ptr, messageNumber);

    SymCryptGcmEncrypt(
        pExpandedKey,
        &nonce,
        @sizeOf(@TypeOf(nonce)),
        pbAuthData,
        cbAuthData,
        pbSrc,
        pbDst,
        cbData,
        pbTag,
        cbTag,
    );

    if (pu64MessageNumber) |pMsgNum| {
        pMsgNum.* = messageNumber;
    }

    return .SYMCRYPT_NO_ERROR;
}

inline fn SymCryptSessionDecryptComputeDesiredReplayState(
    observedState: PCSYMCRYPT_SESSION_REPLAY_STATE,
    desiredState: PSYMCRYPT_SESSION_REPLAY_STATE,
    messageNumber: UINT64,
) SYMCRYPT_ERROR {
    if (messageNumber > observedState.messageNumber) {
        // The observed message number is behind messageNumber that we want to mark successful
        // Shift replayMask appropriately to preserve previously seen message numbers
        var shiftedMask: UINT64 = 0;
        const shiftAmount: UINT64 = messageNumber - observedState.messageNumber;
        if (shiftAmount < 64) {
            shiftedMask = observedState.replayMask << @intCast(shiftAmount);
        }
        // Mark messageNumber as seen in the replayMask
        desiredState.replayMask = shiftedMask | 1;
        desiredState.messageNumber = messageNumber;
    } else if (messageNumber <= observedState.messageNumber -% 64) {
        // The observed message number is too far ahead of messageNumber
        // We cannot hope to succeed
        return .SYMCRYPT_SESSION_REPLAY_FAILURE;
    } else {
        // The observed message number is ahead of or equal to messageNumber
        // Check if messageNumber has already been used
        const shift: u6 = @intCast(observedState.messageNumber - messageNumber); // shiftAmount is in [0, 63]
        const messageMask: UINT64 = @as(UINT64, 1) << shift;
        if ((messageMask & observedState.replayMask) == messageMask) {
            return .SYMCRYPT_SESSION_REPLAY_FAILURE;
        }
        // This is first time we have seen messageNumber - set the replayMask bit appropriately
        desiredState.replayMask = observedState.replayMask | messageMask;
        desiredState.messageNumber = observedState.messageNumber;
    }

    return .SYMCRYPT_NO_ERROR;
}

pub fn SymCryptSessionDecryptUpdateStateCAS128(
    pSession: PSYMCRYPT_SESSION,
    messageNumber: UINT64,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;
    var expectedState: SYMCRYPT_SESSION_REPLAY_STATE = pSession.replayState;
    var desiredState: SYMCRYPT_SESSION_REPLAY_STATE = undefined;

    if (SymCryptSessionDecryptComputeDesiredReplayState(&expectedState, &desiredState, messageNumber) != .SYMCRYPT_NO_ERROR) {
        expectedState.messageNumber = 0;
    }

    while (scError == .SYMCRYPT_NO_ERROR) {
        if (SymCryptAtomicCas128Relaxed(
            @ptrCast(&pSession.replayState),
            @ptrCast(&expectedState),
            @ptrCast(&desiredState),
        )) {
            break;
        }

        scError = SymCryptSessionDecryptComputeDesiredReplayState(&expectedState, &desiredState, messageNumber);
    }

    return scError;
}

comptime {
    if (types.SYMCRYPT_USE_CAS128) {
        @export(&SymCryptSessionDecryptUpdateStateCAS128, .{ .name = "SymCryptSessionDecryptUpdateStateCAS128" });
    }
}

pub export fn SymCryptSessionDecryptUpdateStateLock(
    pSession: PSYMCRYPT_SESSION,
    messageNumber: UINT64,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var desiredState: SYMCRYPT_SESSION_REPLAY_STATE = undefined;

    if (pSession.pMutex == null) {
        return .SYMCRYPT_INVALID_ARGUMENT;
    }

    if (messageNumber <= atomicLoad64Relaxed(&pSession.replayState.messageNumber) -% 64) {
        return .SYMCRYPT_SESSION_REPLAY_FAILURE;
    }

    SymCryptCallbackAcquireMutexFastInproc(pSession.pMutex);
    //////
    // !!! Do not return until we have called SymCryptCallbackReleaseMutexFastInproc !!!
    //////

    const scError = SymCryptSessionDecryptComputeDesiredReplayState(&pSession.replayState, &desiredState, messageNumber);
    if (scError == .SYMCRYPT_NO_ERROR) {
        pSession.replayState = desiredState;
    }

    SymCryptCallbackReleaseMutexFastInproc(pSession.pMutex);

    return scError;
}

pub export fn SymCryptSessionDecryptUpdateState(
    pSession: PSYMCRYPT_SESSION,
    messageNumber: UINT64,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    if (comptime types.CPU_AMD64) {
        if (macros.SYMCRYPT_CPU_FEATURES_PRESENT(types.SYMCRYPT_CPU_FEATURE_CMPXCHG16B)) {
            return SymCryptSessionDecryptUpdateStateCAS128(pSession, messageNumber);
        } else {
            return SymCryptSessionDecryptUpdateStateLock(pSession, messageNumber);
        }
    } else if (comptime types.CPU_ARM64) {
        return SymCryptSessionDecryptUpdateStateCAS128(pSession, messageNumber);
    } else {
        return SymCryptSessionDecryptUpdateStateLock(pSession, messageNumber);
    }
}

pub export fn SymCryptSessionGcmDecrypt(
    pSession: PSYMCRYPT_SESSION,
    messageNumber: UINT64,
    pExpandedKey: PCSYMCRYPT_GCM_EXPANDED_KEY,
    pbAuthData: ?PCBYTE,
    cbAuthData: SIZE_T,
    pbSrc: ?PCBYTE,
    pbDst: ?PBYTE,
    cbData: SIZE_T,
    pbTag: PCBYTE,
    cbTag: SIZE_T,
) callconv(types.SYMCRYPT_CALL) SYMCRYPT_ERROR {
    var nonce: [12]BYTE = undefined;
    var scError: SYMCRYPT_ERROR = .SYMCRYPT_NO_ERROR;

    if ((pSession.flags & SYMCRYPT_FLAG_SESSION_ENCRYPT) != 0) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else if ((messageNumber > SYMCRYPT_SESSION_MAX_MESSAGE_NUMBER) or (messageNumber == 0)) {
        scError = .SYMCRYPT_INVALID_ARGUMENT;
    } else if (messageNumber <= atomicLoad64Relaxed(&pSession.replayState.messageNumber) -% 64) {
        scError = .SYMCRYPT_SESSION_REPLAY_FAILURE;
    } else {
        macros.SYMCRYPT_STORE_MSBFIRST32(nonce[0..].ptr, pSession.senderId);
        macros.SYMCRYPT_STORE_MSBFIRST64(nonce[4..].ptr, messageNumber);

        scError = SymCryptGcmDecrypt(
            pExpandedKey,
            &nonce,
            @sizeOf(@TypeOf(nonce)),
            pbAuthData,
            cbAuthData,
            pbSrc,
            pbDst,
            cbData,
            pbTag,
            cbTag,
        );

        if (scError == .SYMCRYPT_NO_ERROR) {
            scError = SymCryptSessionDecryptUpdateState(pSession, messageNumber);
        }
    }

    if (scError != .SYMCRYPT_NO_ERROR) {
        macros.SymCryptWipe(@ptrCast(pbDst), cbData);
    }

    return scError;
}
