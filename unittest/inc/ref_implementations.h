//
// ref_implementations.h Header file for reference implementations
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

//
// Stub classes used as selector in templates. This class is never instantiated.
//
class ImpRef{
public:
    static char * name;
};

typedef struct _REF_POLY1305_STATE {
    PSYMCRYPT_MODULUS       pmMod;
    PSYMCRYPT_MODELEMENT    peAcc;
    PSYMCRYPT_MODELEMENT    peR;
    PSYMCRYPT_MODELEMENT    peData;
    PSYMCRYPT_INT           piS;
    PSYMCRYPT_INT           piAcc;      // Used for final addition

    BYTE                    block[17];
    SIZE_T                  bytesInBuffer;  
} REF_POLY1305_STATE, *PREF_POLY1305_STATE;



template<>
class MacImpState<ImpRef, AlgPoly1305> {
public:
    REF_POLY1305_STATE state;
};

extern "C" {

VOID
SYMCRYPT_CALL
RefPoly1305Init(
    _Out_                                       PREF_POLY1305_STATE pState,
    _In_reads_( SYMCRYPT_POLY1305_KEY_SIZE )    PCBYTE              pbKey );

VOID
SYMCRYPT_CALL
RefPoly1305ProcessBlock(
    _Inout_                 PREF_POLY1305_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbData,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
RefPoly1305Append(
    _Inout_                 PREF_POLY1305_STATE pState,
    _In_reads_( cbData )    PCBYTE              pbData,
                            SIZE_T              cbData );

VOID
SYMCRYPT_CALL
RefPoly1305Result(
    _Inout_                                         PREF_POLY1305_STATE pState,
    _Out_writes_( SYMCRYPT_POLY1305_RESULT_SIZE )   PBYTE               pbResult );

VOID
SYMCRYPT_CALL
RefPoly1305(
    _In_reads_( SYMCRYPT_POLY1305_KEY_SIZE )        PCBYTE  pbKey,
    _In_reads_( cbData )                            PCBYTE  pbData,
                                                    SIZE_T  cbData,
    _Out_writes_( SYMCRYPT_POLY1305_RESULT_SIZE )   PBYTE   pbResult );

BOOL
SYMCRYPT_CALL
RefIsPossiblePrime(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );

BOOL
SYMCRYPT_CALL
RefIsPrime(
    _In_                            PCSYMCRYPT_INT  piSrc,
    _Out_writes_bytes_( cbScratch ) PBYTE           pbScratch,
                                    SIZE_T          cbScratch );

}


