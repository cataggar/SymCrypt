//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// Thin C++ ABI bridge connecting remaining C++ test files and STL types
// (std::string, BString, KAT_ITEM, AlgorithmImplementationVector) to the
// Zig unittest infrastructure in unittest_zig/.
//

#include "precomp.h"

#include "C_asm_shared.inc"

//
// Static class member definitions for algorithm / mode descriptors
//
UINT32 ModeEcb::flags = 0;
UINT32 ModeCbc::flags = MODE_FLAG_CHAIN;
UINT32 ModeCfb::flags = MODE_FLAG_CHAIN | MODE_FLAG_CFB;
BOOL AlgRc4::isRandomAccess = FALSE;
BOOL AlgChaCha20::isRandomAccess = TRUE;

AlgorithmImplementation::AlgorithmImplementation()
{
    m_nResults = 0;
    m_nErrorKatFailure = 0;
    m_nErrorDisagreeWithMajority = 0;
    m_nErrorNoMajority = 0;
}

AlgorithmImplementationVector g_algorithmImplementation;

String g_measure_sizes_stringPrefix = "";
String g_dynamicModulePath = "";
StringSet g_algorithmsToTest;
StringSet g_implementationsToTest;

extern "C" {
extern UINT32 g_runRsaAverageKeyPerf;
UINT32 scTestSetContainsPrefixAlg(const char* ptr, size_t len);
UINT32 scTestSetContainsPrefixImp(const char* ptr, size_t len);

int scTestGenRandom(void* pbBuf, size_t cbBuf)
{
    return (int)GENRANDOM(pbBuf, cbBuf);
}

void* scTestAllocateFastInprocMutex()
{
    return ALLOCATE_FAST_INPROC_MUTEX();
}

void scTestFreeFastInprocMutex(void* pMutex)
{
    FREE_FAST_INPROC_MUTEX(pMutex);
}

void scTestAcquireFastInprocMutex(void* pMutex)
{
    ACQUIRE_FAST_INPROC_MUTEX(pMutex);
}

void scTestReleaseFastInprocMutex(void* pMutex)
{
    RELEASE_FAST_INPROC_MUTEX(pMutex);
}

void scTestSleepMs(UINT32 ms)
{
    SLEEP(ms * 1000);
}
}

BOOL
setContainsPrefix( const StringSet & set, const std::string & str )
{
    if( &set == &g_algorithmsToTest )
    {
        return scTestSetContainsPrefixAlg( str.data(), str.size() ) != 0;
    }
    if( &set == &g_implementationsToTest )
    {
        return scTestSetContainsPrefixImp( str.data(), str.size() ) != 0;
    }

    for( StringSet::const_iterator i = set.begin(); i != set.end(); ++i )
    {
        const std::string & prefix = *i;
        if( str.compare( 0, prefix.size(), prefix ) == 0 )
        {
            return TRUE;
        }
    }
    return FALSE;
}

BOOL
isAlgorithmPresent( String algName, BOOL isPrefix )
{
    for( std::vector<AlgorithmImplementation *>::iterator i = g_algorithmImplementation.begin();
            i != g_algorithmImplementation.end();
            i++ )
    {
        std::string str = (*i)->m_algorithmName;

        if( str == algName || (isPrefix && str.compare( 0, algName.size(), algName ) == 0) )
        {
            return TRUE;
        }
    }

    return FALSE;
}

//
// ResultMerge::addResult bridge to Zig scTestResultMergeAddResult
//
VOID
ResultMerge::addResult( AlgorithmImplementation * pAlgImp, PCBYTE pbData, SIZE_T cbData )
{
    scTestResultMergeAddResult(
        m_handle,
        pAlgImp,
        pAlgImp->m_implementationName.c_str(),
        pAlgImp->m_algorithmName.c_str(),
        &pAlgImp->m_nResults,
        &pAlgImp->m_nErrorDisagreeWithMajority,
        &pAlgImp->m_nErrorNoMajority,
        pbData,
        cbData );
}

//
// KAT C++ STL / KAT_ITEM bridge to Zig kat.zig
//
extern "C" {

KatData *
scTestNewKatData( PSTR name, PCBYTE pbData, SIZE_T cbData )
{
    return new KatData( name, (PCCHAR)pbData, cbData );
}

void
scTestKatItemSetType( void * p, int itemType, LONGLONG line )
{
    KAT_ITEM * pItem = (KAT_ITEM *)p;
    pItem->type = (KAT_ITEM_TYPE)itemType;
    pItem->line = line;
}

void
scTestKatItemSetCategory( void * p, const char * ptr, size_t len )
{
    KAT_ITEM * pItem = (KAT_ITEM *)p;
    pItem->categoryName.assign( ptr, len );
}

void
scTestKatItemClearData( void * p, LONGLONG line )
{
    KAT_ITEM * pItem = (KAT_ITEM *)p;
    pItem->line = line;
    pItem->type = KAT_TYPE_DATASET;
    pItem->dataItems.clear();
}

int
scTestKatItemHasField( const void * p, const char * name_ptr, size_t name_len )
{
    const KAT_ITEM * pItem = (const KAT_ITEM *)p;
    std::string fieldName( name_ptr, name_len );
    for( DataItems::const_iterator i = pItem->dataItems.begin(); i != pItem->dataItems.end(); ++i )
    {
        if( i->name == fieldName )
        {
            return 1;
        }
    }
    return 0;
}

void
scTestKatItemAddData(
    void * p,
    const char * name_ptr,
    size_t name_len,
    const char * val_ptr,
    size_t val_len,
    LONGLONG line )
{
    KAT_ITEM * pItem = (KAT_ITEM *)p;
    KAT_DATA_ITEM dataItem;
    dataItem.name.assign( name_ptr, name_len );
    dataItem.data.assign( val_ptr, val_len );
    dataItem.line = line;
    pItem->dataItems.push_back( dataItem );
}

} // extern "C"

// ============================================================================
// Reference Implementation C++ Template Registration Glue
// (C-callable implementations live in unittest_zig/ref_implementations.zig)
// ============================================================================

#if INCLUDE_IMPL_REF

char * ImpRef::name = "Ref";

template<>
VOID
algImpDataPerfFunction<ImpRef, AlgPoly1305>( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T dataSize )
{
    RefPoly1305( buf1, buf2, dataSize, buf3 );
}

template<>
MacImp<ImpRef, AlgPoly1305>::MacImp()
{
    m_perfKeyFunction     = NULL;
    m_perfCleanFunction   = NULL;
    m_perfDataFunction    = &algImpDataPerfFunction<ImpRef, AlgPoly1305>;
}

template<>
MacImp<ImpRef, AlgPoly1305>::~MacImp<ImpRef, AlgPoly1305>()
{
}

template<>
NTSTATUS MacImp<ImpRef, AlgPoly1305>::mac(
    _In_reads_( cbKey )      PCBYTE pbKey,   SIZE_T cbKey,
    _In_reads_( cbData )     PCBYTE pbData,  SIZE_T cbData,
    _Out_writes_( cbResult )  PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbKey == 32, "?" );
    CHECK( cbResult == 16, "?" );

    RefPoly1305( pbKey, pbData, cbData, pbResult );

    return STATUS_SUCCESS;
}

template<>
NTSTATUS
MacImp<ImpRef, AlgPoly1305>::init( _In_reads_( cbKey ) PCBYTE pbKey, SIZE_T cbKey )
{
    CHECK( cbKey == 32, "?" );
    RefPoly1305Init( &state.state, pbKey );

    return STATUS_SUCCESS;
}

template<>
VOID MacImp<ImpRef, AlgPoly1305>::append( _In_reads_( cbData ) PCBYTE pbData, SIZE_T cbData )
{
    RefPoly1305Append( &state.state, pbData, cbData );
}

template<>
VOID MacImp<ImpRef, AlgPoly1305>::result( _Out_writes_( cbResult ) PBYTE pbResult, SIZE_T cbResult )
{
    CHECK( cbResult == 16, "Result len error Ref/Poly1305" );
    RefPoly1305Result( &state.state, pbResult );
}

template<>
SIZE_T MacImp<ImpRef, AlgPoly1305>::inputBlockLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}

template<>
SIZE_T MacImp<ImpRef, AlgPoly1305>::resultLen()
{
    return SYMCRYPT_POLY1305_RESULT_SIZE;
}

VOID
addRefAlgs()
{
    SymCryptInit();
    addImplementationToGlobalList<MacImp<ImpRef, AlgPoly1305>>();
}

#endif // INCLUDE_IMPL_REF

// ============================================================================
// SymCrypt Implementation C++ Template Specializations & Registration Glue
// (C-callable shims and Zig implementation adapters live in unittest_zig/sc_implementations.zig)
// ============================================================================

extern "C" {
#include "hpke_internal.h"
VOID SYMCRYPT_CALL trialDivisionSetFakePrime( PSYMCRYPT_TRIALDIVISION_PRIME p );
VOID SYMCRYPT_CALL createFakeTrialDivisionContext( PBYTE pBuf, UINT32 primesPerGroup );
}

#define SYMCRYPT_2DES_EXPANDED_KEY  SYMCRYPT_3DES_EXPANDED_KEY

#define SCRATCH_BUF_OFFSET  (1 << 15)
#define SCRATCH_BUF_SIZE    (1 << 15)

template<class Implementation, class Algorithm, class Mode>
VOID
SYMCRYPT_CALL
SYMCRYPT_EncryptTest(
    _In_                    PVOID   pExpandedKey,
    _In_                    PBYTE   pbChainingValue,
    _In_reads_( cbData )    PCBYTE  pbSrc,
    _Out_writes_( cbData )  PBYTE   pbDst,
                            SIZE_T  cbData );

template<class Implementation, class Algorithm, class Mode>
VOID
SYMCRYPT_CALL
SYMCRYPT_DecryptTest(
    _In_                    PVOID   pExpandedKey,
    _In_                    PBYTE   pbChainingValue,
    _In_reads_( cbData )    PCBYTE  pbSrc,
    _Out_writes_( cbData )  PBYTE   pbDst,
                            SIZE_T  cbData );

template<class Implementation>
VOID
setupPerfInt( PBYTE pb, SIZE_T cb, UINT32 nDigits );

template<class Implementation>
VOID
setupIntsForPerfFunction( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T inSize, UINT32 outFactor );

template<class Implementation>
VOID
setupModulus( PBYTE buf1, PBYTE buf3, SIZE_T keySize );

template<class Implementation>
VOID
setupModOperations( PBYTE buf1, PBYTE buf2, PBYTE buf3, SIZE_T keySize );

template<class Implementation>
VOID
SetupSymCryptRsaKey( PBYTE buf1, SIZE_T keySize, UINT32 generateFlags );

template<class Implementation>
VOID
sc_RsaKeyPerf( PBYTE buf1, PBYTE buf2, SIZE_T keySize, UINT32 generateFlags );

template<class Implementation>
NTSTATUS
sc_RsaKeySetKeyFromBlob(
    _In_    PCRSAKEY_TESTBLOB   pcKeyBlob,
    _Inout_ PSYMCRYPT_RSAKEY*   ppKey,
            UINT32              flags );

template<class Implementation>
VOID
DlgroupSetup( PBYTE buf1, SIZE_T keySize, BOOLEAN forDiffieHellman );

template<class Implementation>
VOID
SetupDlGroup( PBYTE buf1, SIZE_T keySize );

template<class Implementation>
VOID
SetupSymCryptDsa( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

template<class Implementation>
PSYMCRYPT_DLKEY
dlkeyObjectFromTestBlob( PCSYMCRYPT_DLGROUP pGroup, PCDLKEY_TESTBLOB pBlob, UINT32 algFlags, BOOL setPrivate = TRUE );

template<class Implementation>
VOID
CleanupSymCryptCurves();

template<class Implementation>
VOID
SetupSymCryptCurves( PBYTE buf1, SIZE_T keySize );

template<class Implementation>
VOID
SetupSymCryptEcpoints( PBYTE buf1, PBYTE buf2, PBYTE buf3 );

template<class Implementation>
VOID
SetupSymCryptEckey( PBYTE buf1, PBYTE buf2, PBYTE buf3, UINT32 setRandomFlags );

template<class Implementation>
VOID
SetupSymCryptXmsskey( UINT32 algId );

template<class Implementation>
VOID
SetupSymCryptLmskey( UINT32 lmsAlgID, UINT32 lmsOtsAlgID );

template<class Implementation>
SYMCRYPT_MLKEM_PARAMS
SetupSymCryptMlKemKey( PBYTE buf1, SIZE_T keySize );

template<class Implementation>
SYMCRYPT_COMPOSITE_MLKEM_PARAMS
SetupSymCryptCompositeMlKemKey( PBYTE buf1, SIZE_T keySize );

template<class Implementation>
VOID
SetupSymCryptMlDsaKey( PBYTE pbKey, SIZE_T keySize );

template<class Implementation>
VOID
SetupSymCryptCompositeMlDsaKey( PBYTE pbKey, SIZE_T keySize );

template<class Implementation>
BOOL
SetSymCryptTlshandshakeParamsFromPerfKeySize( SIZE_T keySize, PVOID inout );

typedef struct _HASH_INFO {
    PCSTR   name;
    PCSYMCRYPT_HASH pcHash;
    PCSYMCRYPT_OID  pcOids;
    UINT32          nOids;
} HASH_INFO;
typedef const HASH_INFO * PCHASH_INFO;

typedef struct _DLGROUP_INFO {
    PCDLGROUP_TESTBLOB pBlob;
    PSYMCRYPT_DLGROUP pGroup;
} DLGROUP_INFO;
typedef DLGROUP_INFO * PDLGROUP_INFO;

template<class Implementation>
PCHASH_INFO getHashInfo(PCSTR pcstrName);

#include "sc_imp_shims.h"

char * ImpSc::name = "SymCrypt";

#define IMP_NAME    SYMCRYPT
#define IMP_Name    Sc

#include "sc_imp_pattern.cpp"

#undef IMP_NAME
#undef IMP_Name

char * ImpScStatic::name = "SymCryptStatic";

#define IMP_NAME    SYMCRYPT
#define IMP_Name    ScStatic

#include "sc_imp_pattern.cpp"

#undef IMP_NAME
#undef IMP_Name

char * ImpScDynamic::name = "SymCryptDynamic";

#define IMP_NAME    SYMCRYPTDYNAMIC
#define IMP_Name    ScDynamic
#define IMP_UseSymCryptRandom (1)

#include "sc_imp_pattern.cpp"

#undef IMP_UseSymCryptRandom
#undef IMP_NAME
#undef IMP_Name

template<class ImpScVariant>
VOID
addSymCryptImplementationToGlobalList()
{
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd2>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd4>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgMd5>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha1>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha224>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha256>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha384>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha512>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha512_224>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha512_256>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_224>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_256>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_384>>();
    addImplementationToGlobalList<HashImp<ImpScVariant, AlgSha3_512>>();

    addImplementationToGlobalList<XofImp<ImpScVariant, AlgShake128>>();
    addImplementationToGlobalList<XofImp<ImpScVariant, AlgShake256>>();
    addImplementationToGlobalList<CustomizableXofImp<ImpScVariant, AlgCShake128>>();
    addImplementationToGlobalList<CustomizableXofImp<ImpScVariant, AlgCShake256>>();
    addImplementationToGlobalList<KmacImp<ImpScVariant, AlgKmac128>>();
    addImplementationToGlobalList<KmacImp<ImpScVariant, AlgKmac256>>();

    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacMd5>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha1>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha224>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha256>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha384>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha512>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha512_224>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha512_256>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha3_224>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha3_256>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha3_384>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgHmacSha3_512>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgAesCmac>>();
    addImplementationToGlobalList<MacImp<ImpScVariant, AlgMarvin32>>();

    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgAes, ModeCfb>>();

    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDes, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg2Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, Alg3Des, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgDesx, ModeCfb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeEcb>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeCbc>>();
    addImplementationToGlobalList<BlockCipherImp<ImpScVariant, AlgRc2, ModeCfb>>();

    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgAes, ModeCcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgAes, ModeGcm>>();
    addImplementationToGlobalList<AuthEncImp<ImpScVariant, AlgChaCha20Poly1305, ModeNone>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgPbkdf2, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant , AlgSp800_108, AlgAesCmac>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_1, AlgHmacMd5>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgTlsPrf1_2, AlgHmacSha512>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgHkdf, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgHkdf, AlgHmacSha1>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha1>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSshKdf, AlgSha512>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSrtpKdf, AlgAes>>();

    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfHash, AlgSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfHash, AlgSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfHash, AlgSha3_384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfMac, AlgHmacSha256>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfMac, AlgHmacSha512>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfMac, AlgHmacSha3_384>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfMac, AlgKmac128>>();
    addImplementationToGlobalList<KdfImp<ImpScVariant, AlgSskdfMac, AlgKmac256>>();

    addImplementationToGlobalList<MacImp<ImpScVariant, AlgPoly1305>>();

    addImplementationToGlobalList<StreamCipherImp<ImpScVariant, AlgRc4>>();
    addImplementationToGlobalList<StreamCipherImp<ImpScVariant, AlgChaCha20>>();

    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha256>>();
    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha384>>();
    addImplementationToGlobalList<ParallelHashImp<ImpScVariant, AlgParallelSha512>>();

    addImplementationToGlobalList<XtsImp<ImpScVariant, AlgXtsAes>>();

    addImplementationToGlobalList<KeyWrapImp<ImpScVariant, AlgAesKw>>();
    addImplementationToGlobalList<KeyWrapImp<ImpScVariant, AlgAesKwp>>();

    addImplementationToGlobalList<RngSp800_90Imp<ImpScVariant, AlgAesCtrDrbg>>();
    addImplementationToGlobalList<RngSp800_90Imp<ImpScVariant, AlgAesCtrF142>>();

    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha1>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha256>>();
    addImplementationToGlobalList<TlsCbcHmacImp<ImpScVariant, AlgTlsCbcHmacSha384>>();

    addImplementationToGlobalList<RsaSignImp<ImpScVariant, AlgRsaSignPkcs1>>();
    addImplementationToGlobalList<RsaSignImp<ImpScVariant, AlgRsaSignPss>>();

    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncRaw>>();
    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncPkcs1>>();
    addImplementationToGlobalList<RsaEncImp<ImpScVariant, AlgRsaEncOaep>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgRsakeySetValue>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgRsakeySetValueFromPrivateExponent>>();

    addImplementationToGlobalList<DhImp<ImpScVariant, AlgDh>>();
    addImplementationToGlobalList<DsaImp<ImpScVariant, AlgDsa>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcurveAllocate>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEckeySetRandom>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdsaSign>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdsaVerify>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcdh>>();

    addImplementationToGlobalList<XmssImp<ImpScVariant, AlgXmss>>();
    addImplementationToGlobalList<LmsImp<ImpScVariant, AlgLms>>();

#if SYMCRYPT_MS_VC
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIEEE802_11SaeCustom>>();
#endif

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgDeveloperTest>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetZero>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetDistinguished>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointSetRandom>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointIsEqual>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointIsZero>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointOnCurve>>();

    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointAdd>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointAddDiffNz>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointDouble>>();
    addImplementationToGlobalList<EccImp<ImpScVariant, AlgEcpointScalarMul>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgEckeySetValue>>();

    addImplementationToGlobalList<KemImp<ImpScVariant, AlgMlKem>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgMlKemkeySetValue>>();

    addImplementationToGlobalList<KemImp<ImpScVariant, AlgCompositeMlKem>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgCompositeMlKemkeySetValue>>();

    addImplementationToGlobalList<PqDsaImp<ImpScVariant, AlgMlDsa>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgMlDsakeySetValue>>();
    addImplementationToGlobalList<PqDsaImp<ImpScVariant, AlgCompositeMlDsa>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntAdd>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntSub>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntMul>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntSquare>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgIntDivMod>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModAdd>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModSub>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModMul>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModSquare>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModExp>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgModInv>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgScsTable>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgTrialDivision>>();
    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgTrialDivisionContext>>();

    addImplementationToGlobalList<ArithImp<ImpScVariant, AlgTlsHandshake>>();
}

VOID
addSymCryptAlgs()
{
    SymCryptInit();

    addSymCryptImplementationToGlobalList<ImpSc>();
    addImplementationToGlobalList<HpkeImp<ImpSc, AlgHpke>>();

    if (g_dynamicSymCryptModuleHandle)
    {
        addSymCryptImplementationToGlobalList<ImpScDynamic>();
        addImplementationToGlobalList<RngSp800_90Imp<ImpScDynamic, AlgDynamicRandom>>();

        if (getDynamicSymbolPointerFromString(
                g_dynamicSymCryptModuleHandle,
                "SymCryptHpkekeyAllocate",
                SCTEST_DYNSYM_FUNCTION_PTR) != NULL)
        {
            addImplementationToGlobalList<HpkeImp<ImpScDynamic, AlgHpke>>();
        }
    }
}

VOID
updateSymCryptStaticAlgs()
{
    for (AlgorithmImplementationVector::iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); )
    {
        if ((*i)->m_implementationName == ImpSc::name)
        {
            delete *i;
            i = g_algorithmImplementation.erase(i);
        }
        else
        {
            i++;
        }
    }

    addSymCryptImplementationToGlobalList<ImpScStatic>();
    addImplementationToGlobalList<HpkeImp<ImpScStatic, AlgHpke>>();
}

const KAT_DATA_ITEM *
findDataItem( KAT_ITEM & item, LPCSTR name )
{
    for( DataItems::const_iterator i = item.dataItems.begin(); i != item.dataItems.end(); ++i )
    {
        if( strcmp( i->name.c_str(), name ) == 0 )
        {
            return &(*i);
        }
    }
    return NULL;
}

BOOL
katIsFieldPresent( KAT_ITEM & item, LPCSTR name )
{
    return findDataItem( item, name ) != NULL;
}

BString
katParseData( KAT_ITEM & item, LPCSTR name )
{
    const KAT_DATA_ITEM * pDataItem = findDataItem( item, name );
    CHECK4( pDataItem != NULL, "Could not find dataset field \"%s\" in dataset at line %lld", name, item.line );

    size_t outLen = 0;
    BYTE * outPtr = scTestKatParseDataRaw(
        pDataItem->data.data(),
        pDataItem->data.size(),
        pDataItem->line,
        &outLen );

    BString res( outPtr, outLen );
    scTestKatFreeParsedData( outPtr, outLen );
    return res;
}

LONGLONG
katParseInteger( KAT_ITEM & item, LPCSTR name )
{
    const KAT_DATA_ITEM * pDataItem = findDataItem( item, name );
    CHECK4( pDataItem != NULL, "Could not find dataset field \"%s\" in dataset at line %lld", name, item.line );

    return scTestKatParseIntegerRaw( pDataItem->data.c_str() );
}

//
// Main harness C++ helper callbacks
//
extern "C" {

void
scTestCheckAsmOffsets()
{
#define SYMCRYPT_CHECK_ASM_OFFSET( a, b ) CHECK4( (a) == (b), "ASM offset error %d != %d", a, b )
    SYMCRYPT_CHECK_ASM_OFFSETS;
}

void
scTestSetMeasureSizesPrefix( const char * ptr, size_t len )
{
    g_measure_sizes_stringPrefix.assign( ptr, len );
}

void
scTestSetDynamicModulePath( const char * ptr, size_t len )
{
    g_dynamicModulePath.assign( ptr, len );
}

const char *
scTestGetDynamicModulePath()
{
    return g_dynamicModulePath.c_str();
}

void
scTestRunSingleLayerCppTests()
{
    testWipe();
    testScsTable();
    testScsTools();
    testPaddingPkcs7();
}

void
scTestRunMultiImpCppTests()
{
    testDataAccessors();
    testHashAlgorithms();
    testBlockCipherAlgorithms();
    testKeyWrapAlgorithms();
    testMacAlgorithms();
    testXofAlgorithms();
    testCustomizableXofAlgorithms();
    testKmacAlgorithms();
    testStreamCipherAlgorithms();
    testKdfAlgorithms();
    testAuthEncAlgorithms();
    testAesCtrDrbg();
    testXtsAlgorithms();
    testTlsCbcHmacAlgorithms();
    testArithmetic();
    testRsaSignAlgorithms();
    testRsaEncAlgorithms();
    testDhAlgorithms();
    testDsaAlgorithms();
    testEcc();
    testHbs();
    testKem();
    testHpke();
    testPqDsa();
    testCompositeHelpers();
    testEcEncoding();
}

void
scTestRunStatusAndServiceIndicatorTests( UINT32 printIndicator )
{
    testStatusIndicator( (BOOL)printIndicator );
    testServiceIndicator();
}

void
scTestSummarizeFunctionalResults( ULONGLONG * pTotalErrors )
{
    PrintTable ptResults;
    PrintTable ptErrors;
    ULONGLONG totalErrors = 0;

    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin();
            i != g_algorithmImplementation.end();
            ++i )
    {
        String row = (*i)->m_algorithmName + (*i)->m_modeName;
        ptResults.addItemNonZero( row, (*i)->m_implementationName, (*i)->m_nResults );

        ULONGLONG nErrors = (*i)->m_nErrorDisagreeWithMajority + (*i)->m_nErrorNoMajority + (*i)->m_nErrorKatFailure;
        ptErrors.addItemNonZero( row, (*i)->m_implementationName, nErrors );

        totalErrors += nErrors;
    }

    ptResults.print( "Number of verified results" );
    print( "\n" );
    ptErrors.print( "NUMBER OF ERRORS" );
    print( "\n" );

    *pTotalErrors += totalErrors;
}

void
scTestRunPerfTestsCpp()
{
    for( UINT32 measurementRepetitions = 0; measurementRepetitions < g_measure_sizes_repetitions; measurementRepetitions++ )
    {
        measurePerf();
    }

    print( "Unit of performance measurement: %s\n    frequency = %4.0f MHz (using std::chrono)\n",
        g_perfUnits, g_tscFreq / 1e6);

    if( g_measure_specific_sizes )
    {
        print("AlgorithmName,KeySize,Operation,KeyParam,ImplementationName,DataSize,%s\n", g_perfUnits);
    }

    PrintTable ptPerf;
    PrintTable ptWipe;

    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin(); i != g_algorithmImplementation.end(); ++i )
    {
        for( std::vector<AlgorithmImplementation::ALG_PERF_INFO>::const_iterator j = (*i)->m_perfInfo.begin();
                j != (*i)->m_perfInfo.end();
                ++j )
        {
            if( !g_measure_specific_sizes )
            {
                String name = (*i)->m_algorithmName + (*i)->m_modeName;
                if( j->keySize > 0 )
                {
                    UINT32 keySize = (UINT32) (j->keySize);

                    if( (*i)->m_algorithmName.substr(0, 5) != "MlDsa" &&
                        (*i)->m_algorithmName.substr(0, 14) != "CompositeMlDsa" &&
                        (*i)->m_algorithmName.substr(0, 14) != "CompositeMlKem")
                    {
                        keySize &= 0xffff;
                        keySize *= 8;
                    }

                    char buf[100];
                    SNPRINTF_S( buf, sizeof( buf ), _TRUNCATE, "-%5u", keySize );

                    name = name + buf;
                }
                if (j->operationName != NULL && strlen(j->operationName) > 0)
                {
                    name += String(" ") + j->operationName;
                }

                if (j->strPostfix != NULL && strlen(j->strPostfix) > 0)
                {
                    name += String(" ") + j->strPostfix;
                }

                ptPerf.addItem( name, (*i)->m_implementationName,
                            j->cPerByte, j->cFixed, j->cRange );
            }
            else
            {
                print( "%s%s,%u,%s,%s,%s,%u,%u\n",
                    g_measure_sizes_stringPrefix.c_str(),
                    ((*i)->m_algorithmName + (*i)->m_modeName).c_str(),
                    (UINT32) (j->keySize & 0xffff) * 8,
                    j->operationName,
                    j->strPostfix,
                    ((*i)->m_implementationName).c_str(),
                    (UINT32) j->dataSize,
                    (UINT32) floor(j->cFixed) );
            }
        }
    }

    if( !g_measure_specific_sizes || isAlgorithmPresent( "Wipe", FALSE ) )
    {
        for( int offset = 0; offset < PERF_WIPE_N_OFFSETS; offset ++ )
        {
            for( int len = 0; len <= PERF_WIPE_MAX_SIZE; len ++ )
            {
                CHAR row[20];
                CHAR col[20];
                CHAR item[20];

                SNPRINTF_S( row, sizeof( row ), _TRUNCATE, "%2d", len );
                SNPRINTF_S( col, sizeof( col ), _TRUNCATE, "%2d", offset );
                SNPRINTF_S( item, sizeof( item ), _TRUNCATE, "%3.0f", g_wipePerf[len][offset] );

                ptWipe.addItem( String( row ), String( col ), String( item ) );
            }
        }

        ptWipe.print( "Wipe performance for each len & alignment" );
    }

    if( !g_measure_specific_sizes )
    {
        ptPerf.print( "Performance for n-byte message/key" );
        printOutput( 0 );

        if( g_runRsaAverageKeyPerf )
        {
            PrintTable ptRsaKeygen;
            addRsaKeyGenPerfSymCrypt<ImpScStatic>(ptRsaKeygen);
            if( g_dynamicSymCryptModuleHandle != NULL )
            {
                addRsaKeyGenPerfSymCrypt<ImpScDynamic>( ptRsaKeygen );
            }
#if INCLUDE_IMPL_MSBIGNUM
            addRsaKeyGenPerfMsBignum( ptRsaKeygen );
#endif
            ptRsaKeygen.print( "RSA key generation performance" );
            printOutput( 0 );
        }
    }
}

void
scTestClearAndFreeAlgImps()
{
    while( !g_algorithmImplementation.empty() )
    {
        delete g_algorithmImplementation.back();
        g_algorithmImplementation.pop_back();
    }
}

} // extern "C"

VOID
HashImplementation::hash(
    _In_reads_( cbData )        PCBYTE  pbData,
                                SIZE_T  cbData,
    _Out_writes_( cbResult )    PBYTE   pbResult,
                                SIZE_T  cbResult )
{
    init();
    append( pbData, cbData );
    result( pbResult, cbResult );
}

VOID
XofImplementation::xof(
        _In_reads_( cbData )        PCBYTE  pbData,
                                    SIZE_T  cbData,
        _Out_writes_( cbResult )    PBYTE   pbResult,
                                    SIZE_T  cbResult )
{
    init();
    append( pbData, cbData );
    result( pbResult, cbResult );
}

VOID
CustomizableXofImplementation::xof(
        _In_reads_( cbNstr )        PCBYTE  pbNstr,
                                    SIZE_T  cbNstr,
        _In_reads_( cbSstr )        PCBYTE  pbSstr,
                                    SIZE_T  cbSstr,
        _In_reads_( cbData )        PCBYTE  pbData,
                                    SIZE_T  cbData,
        _Out_writes_( cbResult )    PBYTE   pbResult,
                                    SIZE_T  cbResult )
{
    init( pbNstr, cbNstr, pbSstr, cbSstr );
    append( pbData, cbData );
    result( pbResult, cbResult );
}

VOID
KmacImplementation::mac(
        _In_reads_( cbCustomizationStr )    PCBYTE  pbCustomizationStr,
                                            SIZE_T  cbCustomizationStr,
        _In_reads_( cbKey )                 PCBYTE  pbKey,
                                            SIZE_T  cbKey,
        _In_reads_( cbData )                PCBYTE  pbData,
                                            SIZE_T  cbData,
        _Out_writes_( cbResult )            PBYTE   pbResult,
                                            SIZE_T  cbResult )
{
    init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey );
    append( pbData, cbData );
    result( pbResult, cbResult );
}

VOID
KmacImplementation::xof(
        _In_reads_( cbCustomizationStr )    PCBYTE  pbCustomizationStr,
                                            SIZE_T  cbCustomizationStr,
        _In_reads_( cbKey )                 PCBYTE  pbKey,
                                            SIZE_T  cbKey,
        _In_reads_( cbData )                PCBYTE  pbData,
                                            SIZE_T  cbData,
        _Out_writes_( cbResult )            PBYTE   pbResult,
                                            SIZE_T  cbResult )
{
    init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey );
    append( pbData, cbData );
    extract( pbResult, cbResult, true );
}

NTSTATUS
MacImplementation::mac(
    _In_reads_( cbKey )      PCBYTE pbKey,
                             SIZE_T cbKey,
    _In_reads_( cbData )     PCBYTE pbData,
                             SIZE_T cbData,
    _Out_writes_( cbResult ) PBYTE  pbResult,
                             SIZE_T cbResult )
{
    NTSTATUS status;

    status = init( pbKey, cbKey );
    if( !NT_SUCCESS( status ) )
    {
        return status;
    }

    append( pbData, cbData );
    result( pbResult, cbResult );

    return STATUS_SUCCESS;
}

template<typename ImpClass>
static size_t
getMatchingAlgImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    String target( algNamePtr, algNameLen );
    size_t count = 0;
    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin();
         i != g_algorithmImplementation.end();
         ++i )
    {
        if( (*i)->m_algorithmName + (*i)->m_modeName == target )
        {
            ImpClass * pImp = dynamic_cast<ImpClass *>( *i );
            if( pImp != NULL )
            {
                if( count < maxImps )
                {
                    outImps[count] = static_cast<void *>( pImp );
                }
                count++;
            }
        }
    }
    return count;
}

extern "C" {

size_t
scTestGetHashImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<HashImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetParallelHashImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<ParallelHashImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetXofImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<XofImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetCustomizableXofImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<CustomizableXofImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetKmacImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<KmacImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetMacImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<MacImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestGetKdfImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return getMatchingAlgImps<KdfImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

void
scTestAlgImpAddErrorKatFailure( void * pImp, ULONGLONG delta )
{
    static_cast<AlgorithmImplementation *>( pImp )->m_nErrorKatFailure += delta;
}

void
scTestResultMergeAddAlgImp( void * resMergeHandle, void * pImp, PCBYTE pbData, SIZE_T cbData )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    scTestResultMergeAddResult(
        resMergeHandle,
        pAlgImp,
        pAlgImp->m_implementationName.c_str(),
        pAlgImp->m_algorithmName.c_str(),
        &pAlgImp->m_nResults,
        &pAlgImp->m_nErrorDisagreeWithMajority,
        &pAlgImp->m_nErrorNoMajority,
        pbData,
        cbData );
}

// HashImplementation wrappers
SIZE_T scTestHashImpResultLen( void * pImp ) { return static_cast<HashImplementation *>( pImp )->resultLen(); }
SIZE_T scTestHashImpInputBlockLen( void * pImp ) { return static_cast<HashImplementation *>( pImp )->inputBlockLen(); }
void scTestHashImpInit( void * pImp ) { static_cast<HashImplementation *>( pImp )->init(); }
void scTestHashImpAppend( void * pImp, PCBYTE pbData, SIZE_T cbData ) { static_cast<HashImplementation *>( pImp )->append( pbData, cbData ); }
void scTestHashImpResult( void * pImp, PBYTE pbResult, SIZE_T cbResult ) { static_cast<HashImplementation *>( pImp )->result( pbResult, cbResult ); }
void scTestHashImpHash( void * pImp, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { static_cast<HashImplementation *>( pImp )->hash( pbData, cbData, pbResult, cbResult ); }
NTSTATUS scTestHashImpInitWithLongMessage( void * pImp, ULONGLONG nBytes ) { return static_cast<HashImplementation *>( pImp )->initWithLongMessage( nBytes ); }
NTSTATUS scTestHashImpExportSymCryptFormat( void * pImp, PBYTE pbResult, SIZE_T cbResultBufferSize, SIZE_T * pcbResult ) { return static_cast<HashImplementation *>( pImp )->exportSymCryptFormat( pbResult, cbResultBufferSize, pcbResult ); }

// ParallelHashImplementation wrappers
SIZE_T scTestParHashImpResultLen( void * pImp ) { return static_cast<ParallelHashImplementation *>( pImp )->resultLen(); }
SIZE_T scTestParHashImpInputBlockLen( void * pImp ) { return static_cast<ParallelHashImplementation *>( pImp )->inputBlockLen(); }
PCSYMCRYPT_HASH scTestParHashImpSymCryptHash( void * pImp ) { return static_cast<ParallelHashImplementation *>( pImp )->SymCryptHash(); }
void scTestParHashImpInit( void * pImp, SIZE_T nHashes ) { static_cast<ParallelHashImplementation *>( pImp )->init( nHashes ); }
void scTestParHashImpProcess( void * pImp, BCRYPT_MULTI_HASH_OPERATION * pOperations, SIZE_T nOperations ) { static_cast<ParallelHashImplementation *>( pImp )->process( pOperations, nOperations ); }
NTSTATUS scTestParHashImpInitWithLongMessage( void * pImp, ULONGLONG nBytes ) { return static_cast<ParallelHashImplementation *>( pImp )->initWithLongMessage( nBytes ); }

// XofImplementation wrappers
SIZE_T scTestXofImpInputBlockLen( void * pImp ) { return static_cast<XofImplementation *>( pImp )->inputBlockLen(); }
void scTestXofImpInit( void * pImp ) { static_cast<XofImplementation *>( pImp )->init(); }
void scTestXofImpAppend( void * pImp, PCBYTE pbData, SIZE_T cbData ) { static_cast<XofImplementation *>( pImp )->append( pbData, cbData ); }
void scTestXofImpResult( void * pImp, PBYTE pbResult, SIZE_T cbResult ) { static_cast<XofImplementation *>( pImp )->result( pbResult, cbResult ); }
void scTestXofImpExtract( void * pImp, PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe ) { static_cast<XofImplementation *>( pImp )->extract( pbResult, cbResult, bWipe ); }
void scTestXofImpXof( void * pImp, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { static_cast<XofImplementation *>( pImp )->xof( pbData, cbData, pbResult, cbResult ); }

// CustomizableXofImplementation wrappers
SIZE_T scTestCXofImpInputBlockLen( void * pImp ) { return static_cast<CustomizableXofImplementation *>( pImp )->inputBlockLen(); }
void scTestCXofImpInit( void * pImp, PCBYTE pbNstr, SIZE_T cbNstr, PCBYTE pbSstr, SIZE_T cbSstr ) { static_cast<CustomizableXofImplementation *>( pImp )->init( pbNstr, cbNstr, pbSstr, cbSstr ); }
void scTestCXofImpAppend( void * pImp, PCBYTE pbData, SIZE_T cbData ) { static_cast<CustomizableXofImplementation *>( pImp )->append( pbData, cbData ); }
void scTestCXofImpResult( void * pImp, PBYTE pbResult, SIZE_T cbResult ) { static_cast<CustomizableXofImplementation *>( pImp )->result( pbResult, cbResult ); }
void scTestCXofImpExtract( void * pImp, PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe ) { static_cast<CustomizableXofImplementation *>( pImp )->extract( pbResult, cbResult, bWipe ); }
void scTestCXofImpXof( void * pImp, PCBYTE pbNstr, SIZE_T cbNstr, PCBYTE pbSstr, SIZE_T cbSstr, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { static_cast<CustomizableXofImplementation *>( pImp )->xof( pbNstr, cbNstr, pbSstr, cbSstr, pbData, cbData, pbResult, cbResult ); }

// KmacImplementation wrappers
SIZE_T scTestKmacImpInputBlockLen( void * pImp ) { return static_cast<KmacImplementation *>( pImp )->inputBlockLen(); }
void scTestKmacImpInit( void * pImp, PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr, PCBYTE pbKey, SIZE_T cbKey ) { static_cast<KmacImplementation *>( pImp )->init( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey ); }
void scTestKmacImpAppend( void * pImp, PCBYTE pbData, SIZE_T cbData ) { static_cast<KmacImplementation *>( pImp )->append( pbData, cbData ); }
void scTestKmacImpResult( void * pImp, PBYTE pbResult, SIZE_T cbResult ) { static_cast<KmacImplementation *>( pImp )->result( pbResult, cbResult ); }
void scTestKmacImpExtract( void * pImp, PBYTE pbResult, SIZE_T cbResult, BOOLEAN bWipe ) { static_cast<KmacImplementation *>( pImp )->extract( pbResult, cbResult, bWipe ); }
void scTestKmacImpMac( void * pImp, PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr, PCBYTE pbKey, SIZE_T cbKey, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { static_cast<KmacImplementation *>( pImp )->mac( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, pbResult, cbResult ); }
void scTestKmacImpXof( void * pImp, PCBYTE pbCustomizationStr, SIZE_T cbCustomizationStr, PCBYTE pbKey, SIZE_T cbKey, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { static_cast<KmacImplementation *>( pImp )->xof( pbCustomizationStr, cbCustomizationStr, pbKey, cbKey, pbData, cbData, pbResult, cbResult ); }

// MacImplementation wrappers
SIZE_T scTestMacImpResultLen( void * pImp ) { return static_cast<MacImplementation *>( pImp )->resultLen(); }
SIZE_T scTestMacImpInputBlockLen( void * pImp ) { return static_cast<MacImplementation *>( pImp )->inputBlockLen(); }
NTSTATUS scTestMacImpInit( void * pImp, PCBYTE pbKey, SIZE_T cbKey ) { return static_cast<MacImplementation *>( pImp )->init( pbKey, cbKey ); }
void scTestMacImpAppend( void * pImp, PCBYTE pbData, SIZE_T cbData ) { static_cast<MacImplementation *>( pImp )->append( pbData, cbData ); }
void scTestMacImpResult( void * pImp, PBYTE pbResult, SIZE_T cbResult ) { static_cast<MacImplementation *>( pImp )->result( pbResult, cbResult ); }
NTSTATUS scTestMacImpMac( void * pImp, PCBYTE pbKey, SIZE_T cbKey, PCBYTE pbData, SIZE_T cbData, PBYTE pbResult, SIZE_T cbResult ) { return static_cast<MacImplementation *>( pImp )->mac( pbKey, cbKey, pbData, cbData, pbResult, cbResult ); }

// KdfImplementation wrappers
void scTestKdfImpDerive( void * pImp, PCBYTE pbKey, SIZE_T cbKey, PKDF_ARGUMENTS pArgs, PBYTE pbDst, SIZE_T cbDst ) { static_cast<KdfImplementation *>( pImp )->derive( pbKey, cbKey, pArgs, pbDst, cbDst ); }

} // extern "C"
