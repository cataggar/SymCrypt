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

//
// Asymmetric / ECC / DL / RSA C ABI helpers for unittest_zig/
//
void *
scTestEckeyGetPublicKey( void * pkEckey )
{
    return ((PSYMCRYPT_ECKEY)pkEckey)->poPublicKey;
}

void *
scTestEckeyGetPrivateKey( void * pkEckey )
{
    return ((PSYMCRYPT_ECKEY)pkEckey)->piPrivateKey;
}

UINT32
scTestEcurveScratchCommon( const void * pCurve )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_COMMON_ECURVE_OPERATIONS( (PCSYMCRYPT_ECURVE)pCurve );
}

UINT32
scTestEcurveScratchScalar( const void * pCurve )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_SCALAR_ECURVE_OPERATIONS( (PCSYMCRYPT_ECURVE)pCurve );
}

UINT32
scTestEcurveScratchMultiScalar( const void * pCurve, UINT32 nPoints )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_MULTI_SCALAR_ECURVE_OPERATIONS( (PCSYMCRYPT_ECURVE)pCurve, nPoints );
}

UINT32
scTestEcurveScratchGetSetValue( const void * pCurve )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_GETSET_VALUE_ECURVE_OPERATIONS( (PCSYMCRYPT_ECURVE)pCurve );
}

void *
scTestEcurveGOrd( const void * pCurve )
{
    return ((PCSYMCRYPT_ECURVE)pCurve)->GOrd;
}

UINT32
scTestEcurveGOrdDigits( const void * pCurve )
{
    return ((PCSYMCRYPT_ECURVE)pCurve)->GOrdDigits;
}

UINT32
scTestScratchBytesForIntDivMod( UINT32 nSrcDigits, UINT32 nDivisorDigits )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_INT_DIVMOD( nSrcDigits, nDivisorDigits );
}

void
scTestSha256Init( void * pState )
{
    SymCryptSha256Init( (PSYMCRYPT_SHA256_STATE)pState );
}

void
scTestSha256Append( void * pState, PCBYTE pbData, SIZE_T cbData )
{
    SymCryptSha256Append( (PSYMCRYPT_SHA256_STATE)pState, pbData, cbData );
}

void
scTestSha256Result( void * pState, PBYTE pbResult )
{
    SymCryptSha256Result( (PSYMCRYPT_SHA256_STATE)pState, pbResult );
}

BYTE
scTestDlgroupIsSafePrime( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->isSafePrimeGroup;
}

UINT32
scTestDlgroupNBitsOfQ( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->nBitsOfQ;
}

UINT32
scTestDlgroupNBitsOfP( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->nBitsOfP;
}

UINT32
scTestDlgroupNMinBitsPriv( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->nMinBitsPriv;
}

UINT32
scTestDlgroupNDefaultBitsPriv( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->nDefaultBitsPriv;
}

const void *
scTestDlgroupPmP( const void * pGroup )
{
    return ((PCSYMCRYPT_DLGROUP)pGroup)->pmP;
}

INT32
scTestDlkeyFPrivateModQ( const void * pkKey )
{
    return ((PCSYMCRYPT_DLKEY)pkKey)->fPrivateModQ;
}

UINT32
scTestDlkeyNBitsPriv( const void * pkKey )
{
    return ((PCSYMCRYPT_DLKEY)pkKey)->nBitsPriv;
}

const void *
scTestDlkeyPiPrivateKey( const void * pkKey )
{
    return ((PCSYMCRYPT_DLKEY)pkKey)->piPrivateKey;
}

const void *
scTestDlkeyPePublicKey( const void * pkKey )
{
    return ((PCSYMCRYPT_DLKEY)pkKey)->pePublicKey;
}

SIZE_T
scTestGetAllImplementations( const char * algNamePtr, SIZE_T algNameLen, void ** outImps, SIZE_T maxImps )
{
    std::string algName( algNamePtr, algNameLen );
    SIZE_T count = 0;
    for( AlgorithmImplementationVector::const_iterator i = g_algorithmImplementation.begin();
         i != g_algorithmImplementation.end();
         ++i )
    {
        if( (*i)->m_algorithmName == algName )
        {
            if( count < maxImps )
            {
                outImps[count] = *i;
                count++;
            }
        }
    }
    return count;
}

void
scTestImpIncResults( void * impPtr )
{
    AlgorithmImplementation * pImp = (AlgorithmImplementation *)impPtr;
    pImp->m_nResults++;
}

void
scTestResultMergeAddAlgImp( void * handle, void * impPtr, PCBYTE pbData, SIZE_T cbData )
{
    AlgorithmImplementation * pAlgImp = (AlgorithmImplementation *)impPtr;
    scTestResultMergeAddResult(
        handle,
        pAlgImp,
        pAlgImp->m_implementationName.c_str(),
        pAlgImp->m_algorithmName.c_str(),
        &pAlgImp->m_nResults,
        &pAlgImp->m_nErrorDisagreeWithMajority,
        &pAlgImp->m_nErrorNoMajority,
        pbData,
        cbData );
}

NTSTATUS
scTestDhImpSetKey( void * impPtr, PCDLKEY_TESTBLOB pcKeyBlob )
{
    return ((DhImplementation *)impPtr)->setKey( pcKeyBlob );
}

NTSTATUS
scTestDhImpSharedSecret( void * impPtr, PCDLKEY_TESTBLOB pcPubkey, PBYTE pbSecret, SIZE_T cbSecret )
{
    return ((DhImplementation *)impPtr)->sharedSecret( pcPubkey, pbSecret, cbSecret );
}

NTSTATUS
scTestDsaImpSetKey( void * impPtr, PCDLKEY_TESTBLOB pcKeyBlob )
{
    return ((DsaImplementation *)impPtr)->setKey( pcKeyBlob );
}

NTSTATUS
scTestDsaImpSign( void * impPtr, PCBYTE pbHash, SIZE_T cbHash, PBYTE pbSig, SIZE_T cbSig )
{
    return ((DsaImplementation *)impPtr)->sign( pbHash, cbHash, pbSig, cbSig );
}

NTSTATUS
scTestDsaImpVerify( void * impPtr, PCBYTE pbHash, SIZE_T cbHash, PCBYTE pbSig, SIZE_T cbSig )
{
    return ((DsaImplementation *)impPtr)->verify( pbHash, cbHash, pbSig, cbSig );
}

void
scTestRsakeySetAlgorithmInfo( void * pKey, UINT32 flags )
{
    ((PSYMCRYPT_RSAKEY)pKey)->fAlgorithmInfo = flags;
}

SIZE_T
scTestScratchBytesForRsaPkcs1( SIZE_T cbPKCS1Format )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_RSA_PKCS1( cbPKCS1Format );
}

SIZE_T
scTestScratchBytesForRsaPss( const void * pHashAlgorithm, SIZE_T cbHash, SIZE_T cbPSSFormat )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_RSA_PSS( (PCSYMCRYPT_HASH)pHashAlgorithm, cbHash, cbPSSFormat );
}

SIZE_T
scTestScratchBytesForRsaOaep( const void * pHashAlgorithm, SIZE_T cbOAEPFormat )
{
    return SYMCRYPT_SCRATCH_BYTES_FOR_RSA_OAEP( (PCSYMCRYPT_HASH)pHashAlgorithm, cbOAEPFormat );
}

NTSTATUS
scTestRsaSignImpSetKey( void * impPtr, PCRSAKEY_TESTBLOB pcKeyBlob )
{
    return ((RsaSignImplementation *)impPtr)->setKey( pcKeyBlob );
}

NTSTATUS
scTestRsaSignImpSign(
    void * impPtr,
    PCBYTE pbHash,
    SIZE_T cbHash,
    PCSTR pcstrHashAlgName,
    UINT32 u32Other,
    PBYTE pbSig,
    SIZE_T cbSig )
{
    return ((RsaSignImplementation *)impPtr)->sign( pbHash, cbHash, pcstrHashAlgName, u32Other, pbSig, cbSig );
}

NTSTATUS
scTestRsaSignImpVerify(
    void * impPtr,
    PCBYTE pbHash,
    SIZE_T cbHash,
    PCBYTE pbSig,
    SIZE_T cbSig,
    PCSTR pcstrHashAlgName,
    UINT32 u32Other )
{
    return ((RsaSignImplementation *)impPtr)->verify( pbHash, cbHash, pbSig, cbSig, pcstrHashAlgName, u32Other );
}

NTSTATUS
scTestRsaEncImpSetKey( void * impPtr, PCRSAKEY_TESTBLOB pcKeyBlob )
{
    return ((RsaEncImplementation *)impPtr)->setKey( pcKeyBlob );
}

NTSTATUS
scTestRsaEncImpEncrypt(
    void * impPtr,
    PCBYTE pbMsg,
    SIZE_T cbMsg,
    PCSTR pcstrHashAlgName,
    PCBYTE pbLabel,
    SIZE_T cbLabel,
    PBYTE pbCiphertext,
    SIZE_T cbCiphertext )
{
    return ((RsaEncImplementation *)impPtr)->encrypt( pbMsg, cbMsg, pcstrHashAlgName, pbLabel, cbLabel, pbCiphertext, cbCiphertext );
}

NTSTATUS
scTestRsaEncImpDecrypt(
    void * impPtr,
    PCBYTE pbCiphertext,
    SIZE_T cbCiphertext,
    PCSTR pcstrHashAlgName,
    PCBYTE pbLabel,
    SIZE_T cbLabel,
    PBYTE pbMsg,
    SIZE_T cbMsg,
    SIZE_T * pcbMsg )
{
    return ((RsaEncImplementation *)impPtr)->decrypt( pbCiphertext, cbCiphertext, pcstrHashAlgName, pbLabel, cbLabel, pbMsg, cbMsg, pcbMsg );
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
// perfPrint C++ variadic and String wrappers -> Zig perf.zig
//
extern "C" {
void scTestAddOutput( const char * str, size_t len );
void scTestAddDirectOutput( const char * str, size_t len );
size_t scTestFormatNumber( double v, char * outBuf, size_t outBufCap );
}

VOID
print( String s )
{
    scTestAddOutput( s.data(), s.size() );
}

String
formatNumber( double v )
{
    char buf[100];
    size_t len = scTestFormatNumber( v, buf, sizeof(buf) );
    return String( buf, len );
}

extern "C" {

VOID
print( const char * format, ... )
{
    char buf[8192];
    va_list vl;
    va_start( vl, format );
    int res = vsnprintf( buf, sizeof(buf), format, vl );
    va_end( vl );
    CHECK( res >= 0, "WHOA!!!" );
    size_t len = (size_t)res < sizeof(buf) ? (size_t)res : sizeof(buf) - 1;
    scTestAddOutput( buf, len );
}

VOID
iprint( const char * format, ... )
{
    char buf[8192];
    va_list vl;
    va_start( vl, format );
    int res = vsnprintf( buf, sizeof(buf), format, vl );
    va_end( vl );
    CHECK( res >= 0, "WHOA!!!" );
    size_t len = (size_t)res < sizeof(buf) ? (size_t)res : sizeof(buf) - 1;
    scTestAddDirectOutput( buf, len );
}

VOID
dprint( const char * format, ... )
{
    UNREFERENCED_PARAMETER( format );
}

VOID
vprint( BOOL bPrint, const char * format, ... )
{
    if( bPrint )
    {
        char buf[8192];
        va_list vl;
        va_start( vl, format );
        int res = vsnprintf( buf, sizeof(buf), format, vl );
        va_end( vl );
        CHECK( res >= 0, "WHOA!!!" );
        size_t len = (size_t)res < sizeof(buf) ? (size_t)res : sizeof(buf) - 1;
        scTestAddDirectOutput( buf, len );
    }
}

} // extern "C"

#include "sc_imp_shims.h"

#define IMP_Name ScStatic
#define IMP_PrettyNameStr "SymCryptStatic"
#include "perf_sc_imp_pattern.cpp"
#undef IMP_PrettyNameStr
#undef IMP_Name

#define IMP_Name ScDynamic
#define IMP_PrettyNameStr "SymCryptDynamic"
#include "perf_sc_imp_pattern.cpp"
#undef IMP_PrettyNameStr
#undef IMP_Name

//
// Main harness C++ helper callbacks
//
extern "C" {

void *
scTestDlgroupObjectFromTestBlob( PCDLGROUP_TESTBLOB pGroupBlob )
{
    return dlgroupObjectFromTestBlob<ImpSc>( pGroupBlob );
}

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

UINT32
scTestIsAlgorithmPresent( const char * name_ptr, size_t name_len, UINT32 isPrefix )
{
    return (UINT32)isAlgorithmPresent( String( name_ptr, name_len ), (BOOL)isPrefix );
}

void
scTestAlgImpIncKatFailure( void * pAlgImpVoid, ULONGLONG delta )
{
    ((AlgorithmImplementation *)pAlgImpVoid)->m_nErrorKatFailure += delta;
}

const char *
scTestAlgImpName( const void * pAlgImpVoid, size_t * pLen )
{
    const AlgorithmImplementation * pAlgImp = (const AlgorithmImplementation *)pAlgImpVoid;
    *pLen = pAlgImp->m_algorithmName.size();
    return pAlgImp->m_algorithmName.data();
}

const char *
scTestAlgImpModeName( const void * pAlgImpVoid, size_t * pLen )
{
    const AlgorithmImplementation * pAlgImp = (const AlgorithmImplementation *)pAlgImpVoid;
    *pLen = pAlgImp->m_modeName.size();
    return pAlgImp->m_modeName.data();
}

const char *
scTestAlgImpImpName( const void * pAlgImpVoid, size_t * pLen )
{
    const AlgorithmImplementation * pAlgImp = (const AlgorithmImplementation *)pAlgImpVoid;
    *pLen = pAlgImp->m_implementationName.size();
    return pAlgImp->m_implementationName.data();
}

//
// KAT item helpers for Zig test drivers
//
void
scTestKatDestroy( KatData * pKat )
{
    delete pKat;
}

void
scTestKatGetNextItem( KatData * pKat, void * pItem )
{
    pKat->getKatItem( (KAT_ITEM *)pItem );
}

void
scTestKatReportWrongData(
    const char * algName,
    const char * dataDesc,
    const BYTE * pbExpected,
    size_t cbExpected,
    const BYTE * pbActual,
    size_t cbActual,
    LONGLONG line )
{
    print( "\nWrong %s result (%s) in line %lld. \nExpected ", algName, dataDesc, line );
    printHex( pbExpected, cbExpected );
    print( "\nGot      " );
    printHex( pbActual, cbActual );
    iprint( "\n" );
}

void *
scTestKatItemCreate()
{
    return new KAT_ITEM();
}

void
scTestKatItemDestroy( void * pItem )
{
    delete (KAT_ITEM *)pItem;
}

int
scTestKatItemType( const void * pItem )
{
    return (int)((const KAT_ITEM *)pItem)->type;
}

LONGLONG
scTestKatItemLine( const void * pItem )
{
    return ((const KAT_ITEM *)pItem)->line;
}

const char *
scTestKatItemCategory( const void * pItem, size_t * pLen )
{
    const KAT_ITEM * p = (const KAT_ITEM *)pItem;
    *pLen = p->categoryName.size();
    return p->categoryName.data();
}

size_t
scTestKatItemDataCount( const void * pItem )
{
    return ((const KAT_ITEM *)pItem)->dataItems.size();
}

UINT32
scTestKatIsFieldPresent( void * pItem, const char * name )
{
    return (UINT32)katIsFieldPresent( *(KAT_ITEM *)pItem, name );
}

LONGLONG
scTestKatParseInteger( void * pItem, const char * name )
{
    return katParseInteger( *(KAT_ITEM *)pItem, name );
}

BYTE *
scTestKatParseDataAlloc( void * pItem, const char * name, size_t * pOutLen )
{
    KAT_ITEM * p = (KAT_ITEM *)pItem;
    const KAT_DATA_ITEM * pDataItem = findDataItem( *p, name );
    CHECK4( pDataItem != NULL, "Could not find dataset field \"%s\" in dataset at line %lld", name, p->line );

    return scTestKatParseDataRaw(
        pDataItem->data.data(),
        pDataItem->data.size(),
        pDataItem->line,
        pOutLen );
}

} // extern "C"

template<typename AlgorithmType>
static size_t
scTestGetImpsByNameInternal( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    String algName( algNamePtr, algNameLen );
    std::vector<AlgorithmType *> res;
    getAllImplementations<AlgorithmType>( algName, &res );
    CHECK( res.size() <= maxImps, "Too many implementations" );
    for( size_t i = 0; i < res.size(); ++i )
    {
        outImps[i] = (void *)res[i];
    }
    return res.size();
}

static size_t
scTestCopySizeSet( const std::set<SIZE_T> & s, size_t * outSizes, size_t maxSizes )
{
    CHECK( s.size() <= maxSizes, "Too many sizes in set" );
    size_t idx = 0;
    for( std::set<SIZE_T>::const_iterator i = s.begin(); i != s.end(); ++i )
    {
        outSizes[idx++] = *i;
    }
    return idx;
}

extern "C" {

//
// BlockCipherImplementation C bridge
//
size_t
scTestGetBlockCipherImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<BlockCipherImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestBlockCipherMsgBlockLen( void * pImp )
{
    return ((BlockCipherImplementation *)pImp)->msgBlockLen();
}

size_t
scTestBlockCipherChainBlockLen( void * pImp )
{
    return ((BlockCipherImplementation *)pImp)->chainBlockLen();
}

size_t
scTestBlockCipherCoreBlockLen( void * pImp )
{
    return ((BlockCipherImplementation *)pImp)->coreBlockLen();
}

NTSTATUS
scTestBlockCipherSetKey( void * pImp, const BYTE * pbKey, size_t cbKey )
{
    return ((BlockCipherImplementation *)pImp)->setKey( pbKey, cbKey );
}

void
scTestBlockCipherEncrypt( void * pImp, BYTE * pbChain, size_t cbChain, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    ((BlockCipherImplementation *)pImp)->encrypt( pbChain, cbChain, pbSrc, pbDst, cbData );
}

void
scTestBlockCipherDecrypt( void * pImp, BYTE * pbChain, size_t cbChain, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    ((BlockCipherImplementation *)pImp)->decrypt( pbChain, cbChain, pbSrc, pbDst, cbData );
}

//
// AuthEncImplementation C bridge
//
size_t
scTestGetAuthEncImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<AuthEncImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestAuthEncGetNonceSizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((AuthEncImplementation *)pImp)->getNonceSizes(), outSizes, maxSizes );
}

size_t
scTestAuthEncGetTagSizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((AuthEncImplementation *)pImp)->getTagSizes(), outSizes, maxSizes );
}

size_t
scTestAuthEncGetKeySizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((AuthEncImplementation *)pImp)->getKeySizes(), outSizes, maxSizes );
}

NTSTATUS
scTestAuthEncSetKey( void * pImp, const BYTE * pbKey, size_t cbKey )
{
    return ((AuthEncImplementation *)pImp)->setKey( pbKey, cbKey );
}

void
scTestAuthEncSetTotalCbData( void * pImp, size_t cbData )
{
    ((AuthEncImplementation *)pImp)->setTotalCbData( cbData );
}

NTSTATUS
scTestAuthEncEncrypt(
    void * pImp,
    const BYTE * pbNonce, size_t cbNonce,
    const BYTE * pbAuthData, size_t cbAuthData,
    const BYTE * pbSrc, BYTE * pbDst, size_t cbData,
    BYTE * pbTag, size_t cbTag,
    UINT32 flags )
{
    return ((AuthEncImplementation *)pImp)->encrypt(
        pbNonce, cbNonce, pbAuthData, cbAuthData, pbSrc, pbDst, cbData, pbTag, cbTag, flags );
}

NTSTATUS
scTestAuthEncDecrypt(
    void * pImp,
    const BYTE * pbNonce, size_t cbNonce,
    const BYTE * pbAuthData, size_t cbAuthData,
    const BYTE * pbSrc, BYTE * pbDst, size_t cbData,
    const BYTE * pbTag, size_t cbTag,
    UINT32 flags )
{
    return ((AuthEncImplementation *)pImp)->decrypt(
        pbNonce, cbNonce, pbAuthData, cbAuthData, pbSrc, pbDst, cbData, pbTag, cbTag, flags );
}

//
// StreamCipherImplementation C bridge
//
size_t
scTestGetStreamCipherImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<StreamCipherImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestStreamCipherGetNonceSizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((StreamCipherImplementation *)pImp)->getNonceSizes(), outSizes, maxSizes );
}

size_t
scTestStreamCipherGetKeySizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((StreamCipherImplementation *)pImp)->getKeySizes(), outSizes, maxSizes );
}

NTSTATUS
scTestStreamCipherSetKey( void * pImp, const BYTE * pbKey, size_t cbKey )
{
    return ((StreamCipherImplementation *)pImp)->setKey( pbKey, cbKey );
}

NTSTATUS
scTestStreamCipherSetNonce( void * pImp, const BYTE * pbNonce, size_t cbNonce )
{
    return ((StreamCipherImplementation *)pImp)->setNonce( pbNonce, cbNonce );
}

UINT32
scTestStreamCipherIsRandomAccess( void * pImp )
{
    return (UINT32)((StreamCipherImplementation *)pImp)->isRandomAccess();
}

void
scTestStreamCipherSetOffset( void * pImp, UINT64 offset )
{
    ((StreamCipherImplementation *)pImp)->setOffset( offset );
}

void
scTestStreamCipherEncrypt( void * pImp, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    ((StreamCipherImplementation *)pImp)->encrypt( pbSrc, pbDst, cbData );
}

//
// XtsImplementation C bridge
//
size_t
scTestGetXtsImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<XtsImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

NTSTATUS
scTestXtsSetKey( void * pImp, const BYTE * pbKey, size_t cbKey, UINT32 flags )
{
    return ((XtsImplementation *)pImp)->setKey( pbKey, cbKey, flags );
}

NTSTATUS
scTestXtsEncrypt( void * pImp, size_t cbDataUnit, ULONGLONG tweak, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    return ((XtsImplementation *)pImp)->encrypt( cbDataUnit, tweak, pbSrc, pbDst, cbData );
}

NTSTATUS
scTestXtsDecrypt( void * pImp, size_t cbDataUnit, ULONGLONG tweak, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    return ((XtsImplementation *)pImp)->decrypt( cbDataUnit, tweak, pbSrc, pbDst, cbData );
}

NTSTATUS
scTestXtsEncryptWith128bTweak( void * pImp, size_t cbDataUnit, const BYTE * pbTweak, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    return ((XtsImplementation *)pImp)->encryptWith128bTweak( cbDataUnit, pbTweak, pbSrc, pbDst, cbData );
}

NTSTATUS
scTestXtsDecryptWith128bTweak( void * pImp, size_t cbDataUnit, const BYTE * pbTweak, const BYTE * pbSrc, BYTE * pbDst, size_t cbData )
{
    return ((XtsImplementation *)pImp)->decryptWith128bTweak( cbDataUnit, pbTweak, pbSrc, pbDst, cbData );
}

//
// KeyWrapImplementation C bridge
//
size_t
scTestGetKeyWrapImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<KeyWrapImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

size_t
scTestKeyWrapGetMinPlaintextSize( void * pImp )
{
    return ((KeyWrapImplementation *)pImp)->getMinPlaintextSize();
}

size_t
scTestKeyWrapGetMaxPlaintextSize( void * pImp )
{
    return ((KeyWrapImplementation *)pImp)->getMaxPlaintextSize();
}

size_t
scTestKeyWrapGetPlaintextSizeIncrement( void * pImp )
{
    return ((KeyWrapImplementation *)pImp)->getPlaintextSizeIncrement();
}

size_t
scTestKeyWrapGetKeySizes( void * pImp, size_t * outSizes, size_t maxSizes )
{
    return scTestCopySizeSet( ((KeyWrapImplementation *)pImp)->getKeySizes(), outSizes, maxSizes );
}

NTSTATUS
scTestKeyWrapSetKey( void * pImp, const BYTE * pbKey, size_t cbKey )
{
    return ((KeyWrapImplementation *)pImp)->setKey( pbKey, cbKey );
}

NTSTATUS
scTestKeyWrapEncrypt( void * pImp, const BYTE * pbSrc, size_t cbSrc, BYTE * pbDst, size_t cbDst, size_t * pcbResult )
{
    return ((KeyWrapImplementation *)pImp)->encrypt( pbSrc, cbSrc, pbDst, cbDst, pcbResult );
}

NTSTATUS
scTestKeyWrapDecrypt( void * pImp, const BYTE * pbSrc, size_t cbSrc, BYTE * pbDst, size_t cbDst, size_t * pcbResult )
{
    return ((KeyWrapImplementation *)pImp)->decrypt( pbSrc, cbSrc, pbDst, cbDst, pcbResult );
}

//
// TlsCbcHmacImplementation C bridge
//
size_t
scTestGetTlsCbcHmacImps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<TlsCbcHmacImplementation>( algNamePtr, algNameLen, outImps, maxImps );
}

NTSTATUS
scTestTlsCbcHmacVerify(
    void * pImp,
    const BYTE * pbKey, size_t cbKey,
    const BYTE * pbHeader, size_t cbHeader,
    const BYTE * pbData, size_t cbData )
{
    return ((TlsCbcHmacImplementation *)pImp)->verify( pbKey, cbKey, pbHeader, cbHeader, pbData, cbData );
}

//
// RngSp800_90Implementation C bridge
//
size_t
scTestGetRngSp800_90Imps( const char * algNamePtr, size_t algNameLen, void ** outImps, size_t maxImps )
{
    return scTestGetImpsByNameInternal<RngSp800_90Implementation>( algNamePtr, algNameLen, outImps, maxImps );
}

NTSTATUS
scTestRngSp800_90Instantiate( void * pImp, const BYTE * pbEntropy, size_t cbEntropy )
{
    return ((RngSp800_90Implementation *)pImp)->instantiate( pbEntropy, cbEntropy );
}

NTSTATUS
scTestRngSp800_90Reseed( void * pImp, const BYTE * pbEntropy, size_t cbEntropy )
{
    return ((RngSp800_90Implementation *)pImp)->reseed( pbEntropy, cbEntropy );
}

void
scTestRngSp800_90Generate( void * pImp, BYTE * pbData, size_t cbData )
{
    ((RngSp800_90Implementation *)pImp)->generate( pbData, cbData );
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

// HbsMultiImp bridge
struct ScTestHbsMultiImp
{
    std::vector<HbsImplementation *> m_imps;
    std::vector<HbsImplementation *> m_comps;
    LONGLONG m_nErrorKatFailure = 0;

    explicit ScTestHbsMultiImp( const char * algName )
    {
        getAllImplementations<HbsImplementation>( algName, &m_imps );
    }

    ~ScTestHbsMultiImp()
    {
        for( std::vector<HbsImplementation *>::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
        {
            (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
        }
    }
};

void *
scTestHbsMultiImpCreate( const char * algName )
{
    return new ScTestHbsMultiImp( algName );
}

void
scTestHbsMultiImpDestroy( void * pMultiImp )
{
    delete static_cast<ScTestHbsMultiImp *>( pMultiImp );
}

size_t
scTestHbsMultiImpGetCount( void * pMultiImp )
{
    return static_cast<ScTestHbsMultiImp *>( pMultiImp )->m_imps.size();
}

int32_t
scTestHbsImpSetKey(
    void * pImp,
    uint32_t algId,
    uint32_t otsAlgId,
    int fMultitree,
    PCBYTE pbSrc,
    size_t cbSrc,
    int fVerifyRoot )
{
    ScTestHbsMultiImp * pMulti = static_cast<ScTestHbsMultiImp *>( pImp );
    pMulti->m_comps.clear();
    for( std::vector<HbsImplementation *>::const_iterator i = pMulti->m_imps.begin(); i != pMulti->m_imps.end(); ++i )
    {
        if( (*i)->setKey( algId, otsAlgId, (BOOL)fMultitree, pbSrc, cbSrc, (BOOL)fVerifyRoot ) == STATUS_SUCCESS )
        {
            pMulti->m_comps.push_back( *i );
        }
    }
    return pMulti->m_comps.empty() ? STATUS_NOT_SUPPORTED : STATUS_SUCCESS;
}

int32_t
scTestHbsImpVerify(
    void * pImp,
    PCBYTE pbMsg,
    size_t cbMsg,
    uint32_t flags,
    PCBYTE pbSig,
    size_t cbSig )
{
    UNREFERENCED_PARAMETER( flags );
    ScTestHbsMultiImp * pMulti = static_cast<ScTestHbsMultiImp *>( pImp );
    NTSTATUS status = STATUS_SUCCESS;
    ResultMerge res;
    BYTE b[4];

    for( std::vector<HbsImplementation *>::const_iterator i = pMulti->m_comps.begin(); i != pMulti->m_comps.end(); ++i )
    {
        status = (*i)->verify( pbMsg, cbMsg, pbSig, cbSig );
        SYMCRYPT_STORE_MSBFIRST32( b, status );
        res.addResult( (*i), b, 4 );
    }

    res.getResult( b, 4 );
    status = SYMCRYPT_LOAD_MSBFIRST32( b );
    return status;
}

int32_t
scTestHbsImpSign(
    void * pImp,
    PCBYTE pbMsg,
    size_t cbMsg,
    uint32_t flags,
    PBYTE pbSig,
    size_t cbSig )
{
    UNREFERENCED_PARAMETER( flags );
    ScTestHbsMultiImp * pMulti = static_cast<ScTestHbsMultiImp *>( pImp );
    NTSTATUS status = STATUS_SUCCESS;
    ResultMerge res;
    PBYTE pbBuffer = new BYTE[cbSig];
    CHECK( pbBuffer != nullptr, "Memory allocation error" );

    for( std::vector<HbsImplementation *>::const_iterator i = pMulti->m_comps.begin(); i != pMulti->m_comps.end(); ++i )
    {
        SymCryptWipe( pbBuffer, cbSig );
        if( (*i)->sign( pbMsg, cbMsg, pbBuffer, cbSig ) != STATUS_SUCCESS )
        {
            CHECK( FALSE, "Signature generation error" );
            continue;
        }
        res.addResult( (*i), pbBuffer, cbSig );
    }

    res.getResult( pbSig, cbSig );
    delete[] pbBuffer;
    return status;
}

// KemMultiImp bridge
struct ScTestKemMultiImp
{
    std::vector<KemImplementation *> m_imps;
    LONGLONG m_nErrorKatFailure = 0;

    explicit ScTestKemMultiImp( const char * algName )
    {
        getAllImplementations<KemImplementation>( algName, &m_imps );
    }

    ~ScTestKemMultiImp()
    {
        for( std::vector<KemImplementation *>::iterator i = m_imps.begin(); i != m_imps.end(); ++i )
        {
            (*i)->m_nErrorKatFailure += m_nErrorKatFailure;
        }
    }
};

void *
scTestKemMultiImpCreate( const char * algName )
{
    return new ScTestKemMultiImp( algName );
}

void
scTestKemMultiImpDestroy( void * pMultiImp )
{
    delete static_cast<ScTestKemMultiImp *>( pMultiImp );
}

size_t
scTestKemMultiImpGetCount( void * pMultiImp )
{
    return static_cast<ScTestKemMultiImp *>( pMultiImp )->m_imps.size();
}

void *
scTestKemMultiImpGetImp( void * pMultiImp, size_t idx )
{
    return static_cast<ScTestKemMultiImp *>( pMultiImp )->m_imps[idx];
}

const char *
scTestKemMultiImpGetImpName( void * pMultiImp, size_t idx )
{
    return static_cast<ScTestKemMultiImp *>( pMultiImp )->m_imps[idx]->m_implementationName.c_str();
}

void
scTestKemMultiImpAddKatError( void * pMultiImp, int64_t nErrorKatFailure )
{
    static_cast<ScTestKemMultiImp *>( pMultiImp )->m_nErrorKatFailure += nErrorKatFailure;
}

int32_t
scTestKemImpSetKeyFromTestBlob( void * pImp, PCBYTE pcbTestKeyBlob, size_t cbTestKeyBlob, int canDecapsulate )
{
    return static_cast<KemImplementation *>( pImp )->setKeyFromTestBlob( pcbTestKeyBlob, cbTestKeyBlob, (BOOL)canDecapsulate );
}

int32_t
scTestKemImpGetBlobFromKey( void * pImp, uint32_t blobType, PBYTE pbBlob, size_t cbBlob )
{
    return static_cast<KemImplementation *>( pImp )->getBlobFromKey( blobType, pbBlob, cbBlob );
}

int32_t
scTestKemImpEncapsulate( void * pImp, PBYTE pbAgreedSecret, size_t cbAgreedSecret, PBYTE pbCiphertext, size_t cbCiphertext )
{
    return static_cast<KemImplementation *>( pImp )->encapsulate( pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext );
}

int32_t
scTestKemImpEncapsulateEx( void * pImp, PCBYTE pbRandom, size_t cbRandom, PBYTE pbAgreedSecret, size_t cbAgreedSecret, PBYTE pbCiphertext, size_t cbCiphertext )
{
    return static_cast<KemImplementation *>( pImp )->encapsulateEx( pbRandom, cbRandom, pbAgreedSecret, cbAgreedSecret, pbCiphertext, cbCiphertext );
}

int32_t
scTestKemImpDecapsulate( void * pImp, PCBYTE pbCiphertext, size_t cbCiphertext, PBYTE pbAgreedSecret, size_t cbAgreedSecret )
{
    return static_cast<KemImplementation *>( pImp )->decapsulate( pbCiphertext, cbCiphertext, pbAgreedSecret, cbAgreedSecret );
}

// PqDsaImplementation wrappers
size_t
scTestPqDsaCount( const char * algName )
{
    std::vector<PqDsaImplementation *> imps;
    getAllImplementations<PqDsaImplementation>( algName, &imps );
    return imps.size();
}

void *
scTestPqDsaCreate( const char * algName, size_t index )
{
    std::vector<PqDsaImplementation *> imps;
    getAllImplementations<PqDsaImplementation>( algName, &imps );
    return index < imps.size() ? imps[index] : nullptr;
}

void
scTestPqDsaFree( void * handle )
{
    UNREFERENCED_PARAMETER( handle );
}

int32_t
scTestPqDsaSetKey( void * handle, PCPQDSAKEY_TESTBLOB pcKeyBlob )
{
    return static_cast<PqDsaImplementation *>( handle )->setKey( pcKeyBlob );
}

int32_t
scTestPqDsaGetBlobFromKey( void * handle, uint32_t keyFormat, PBYTE pbBlob, size_t cbBlob )
{
    return static_cast<PqDsaImplementation *>( handle )->getBlobFromKey( keyFormat, pbBlob, cbBlob );
}

int32_t
scTestPqDsaSign( void * handle, PCBYTE pbMessage, size_t cbMessage, PCBYTE pbContext, size_t cbContext, PBYTE pbSignature, size_t cbSignature, size_t * pcbResult )
{
    return static_cast<PqDsaImplementation *>( handle )->sign( pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature, pcbResult );
}

int32_t
scTestPqDsaSignExternalMu( void * handle, PCBYTE pbMu, size_t cbMu, PBYTE pbSignature, size_t cbSignature )
{
    return static_cast<PqDsaImplementation *>( handle )->signExternalMu( pbMu, cbMu, pbSignature, cbSignature );
}

int32_t
scTestPqDsaSignHash( void * handle, uint32_t hashId, PCBYTE pbHash, size_t cbHash, PCBYTE pbContext, size_t cbContext, PBYTE pbSignature, size_t cbSignature, size_t * pcbResult )
{
    return static_cast<PqDsaImplementation *>( handle )->signHash( (SYMCRYPT_PQDSA_HASH_ID)hashId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature, pcbResult );
}

int32_t
scTestPqDsaSignEx( void * handle, uint32_t hashId, PCBYTE pbInput, size_t cbInput, PCBYTE pbContext, size_t cbContext, PCBYTE pbRandom, size_t cbRandom, uint32_t flags, PBYTE pbSignature, size_t cbSignature )
{
    return static_cast<PqDsaImplementation *>( handle )->signEx( (SYMCRYPT_PQDSA_HASH_ID)hashId, pbInput, cbInput, pbContext, cbContext, pbRandom, cbRandom, flags, pbSignature, cbSignature );
}

int32_t
scTestPqDsaVerify( void * handle, PCBYTE pbMessage, size_t cbMessage, PCBYTE pbContext, size_t cbContext, PCBYTE pbSignature, size_t cbSignature )
{
    return static_cast<PqDsaImplementation *>( handle )->verify( pbMessage, cbMessage, pbContext, cbContext, pbSignature, cbSignature );
}

int32_t
scTestPqDsaVerifyExternalMu( void * handle, PCBYTE pbMu, size_t cbMu, PCBYTE pbSignature, size_t cbSignature )
{
    return static_cast<PqDsaImplementation *>( handle )->verifyExternalMu( pbMu, cbMu, pbSignature, cbSignature );
}

int32_t
scTestPqDsaVerifyHash( void * handle, uint32_t hashId, PCBYTE pbHash, size_t cbHash, PCBYTE pbContext, size_t cbContext, PCBYTE pbSignature, size_t cbSignature )
{
    return static_cast<PqDsaImplementation *>( handle )->verifyHash( (SYMCRYPT_PQDSA_HASH_ID)hashId, pbHash, cbHash, pbContext, cbContext, pbSignature, cbSignature );
}

// HpkeImplementation wrappers
size_t
scTestHpkeCount( const char * algName )
{
    std::vector<HpkeImplementation *> imps;
    getAllImplementations<HpkeImplementation>( algName, &imps );
    return imps.size();
}

void *
scTestHpkeCreate( const char * algName, size_t index )
{
    std::vector<HpkeImplementation *> imps;
    getAllImplementations<HpkeImplementation>( algName, &imps );
    return index < imps.size() ? imps[index] : nullptr;
}

void
scTestHpkeFree( void * handle )
{
    UNREFERENCED_PARAMETER( handle );
}

const char *
scTestHpkeGetLastError( void * handle )
{
    return static_cast<HpkeImplementation *>( handle )->getLastError().c_str();
}

int32_t
scTestHpkeSetKey( void * handle, SYMCRYPT_HPKE_CIPHERSUITE ciphersuite, uint32_t format, PCBYTE pbKey, size_t cbKey )
{
    return static_cast<HpkeImplementation *>( handle )->setKey( ciphersuite, format, pbKey, cbKey );
}

int32_t
scTestHpkeGetKey( void * handle, uint32_t format, PBYTE pbKey, size_t cbKey )
{
    return static_cast<HpkeImplementation *>( handle )->getKey( format, pbKey, cbKey );
}

int32_t
scTestHpkeDeriveKeyPair( void * handle, SYMCRYPT_HPKE_CIPHERSUITE ciphersuite, PCBYTE pbIkm, size_t cbIkm )
{
    return static_cast<HpkeImplementation *>( handle )->deriveKeyPair( ciphersuite, pbIkm, cbIkm );
}

int32_t
scTestHpkeSealSingleShot(
    void * handle,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId,
    PCBYTE pbAad, size_t cbAad,
    PCBYTE pbPlaintext, size_t cbPlaintext,
    PBYTE pbEnc, size_t cbEnc,
    PBYTE pbCiphertext, size_t cbCiphertext )
{
    return static_cast<HpkeImplementation *>( handle )->sealSingleShot(
        pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbAad, cbAad,
        pbPlaintext, cbPlaintext, pbEnc, cbEnc, pbCiphertext, cbCiphertext );
}

int32_t
scTestHpkeOpenSingleShot(
    void * handle,
    PCBYTE pbEnc, size_t cbEnc,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId,
    PCBYTE pbAad, size_t cbAad,
    PCBYTE pbCiphertext, size_t cbCiphertext,
    PBYTE pbPlaintext, size_t cbPlaintext )
{
    return static_cast<HpkeImplementation *>( handle )->openSingleShot(
        pbEnc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
        pbAad, cbAad, pbCiphertext, cbCiphertext, pbPlaintext, cbPlaintext );
}

int32_t
scTestHpkeSecretExportSingleShot(
    void * handle,
    PCBYTE pbEnc, size_t cbEnc,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId,
    PCBYTE pbExporterContext, size_t cbExporterContext,
    PBYTE pbExportedValue, uint16_t cbExportedValue )
{
    return static_cast<HpkeImplementation *>( handle )->secretExportSingleShot(
        pbEnc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId,
        pbExporterContext, cbExporterContext, pbExportedValue, cbExportedValue );
}

int32_t
scTestHpkeSetupSender(
    void * handle,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId,
    PBYTE pbEnc, size_t cbEnc )
{
    return static_cast<HpkeImplementation *>( handle )->setupSender(
        pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbEnc, cbEnc );
}

int32_t
scTestHpkeSetupSenderDeterministic(
    void * handle,
    PCBYTE pbRandom, size_t cbRandom,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId,
    PBYTE pbEnc, size_t cbEnc )
{
    return static_cast<HpkeImplementation *>( handle )->setupSenderDeterministic(
        pbRandom, cbRandom, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId, pbEnc, cbEnc );
}

int32_t
scTestHpkeSetupRecipient(
    void * handle,
    PCBYTE pbEnc, size_t cbEnc,
    PCBYTE pbInfo, size_t cbInfo,
    PCBYTE pbPsk, size_t cbPsk,
    PCBYTE pbPskId, size_t cbPskId )
{
    return static_cast<HpkeImplementation *>( handle )->setupRecipient(
        pbEnc, cbEnc, pbInfo, cbInfo, pbPsk, cbPsk, pbPskId, cbPskId );
}

int32_t
scTestHpkeSeal(
    void * handle,
    PCBYTE pbAuthData, size_t cbAuthData,
    PCBYTE pbSrc, size_t cbSrc,
    PBYTE pbDst, size_t cbDst,
    uint64_t * pu64SeqNumber )
{
    return static_cast<HpkeImplementation *>( handle )->seal(
        pbAuthData, cbAuthData, pbSrc, cbSrc, pbDst, cbDst, pu64SeqNumber );
}

int32_t
scTestHpkeOpen(
    void * handle,
    PCBYTE pbAuthData, size_t cbAuthData,
    PCBYTE pbSrc, size_t cbSrc,
    PBYTE pbDst, size_t cbDst )
{
    return static_cast<HpkeImplementation *>( handle )->open(
        pbAuthData, cbAuthData, pbSrc, cbSrc, pbDst, cbDst );
}

int32_t
scTestHpkeOpenUnordered(
    void * handle,
    uint64_t u64SeqNumber,
    PCBYTE pbAuthData, size_t cbAuthData,
    PCBYTE pbSrc, size_t cbSrc,
    PBYTE pbDst, size_t cbDst )
{
    return static_cast<HpkeImplementation *>( handle )->openUnordered(
        u64SeqNumber, pbAuthData, cbAuthData, pbSrc, cbSrc, pbDst, cbDst );
}

int32_t
scTestHpkeSecretExportSender(
    void * handle,
    PCBYTE pbExporterContext, size_t cbExporterContext,
    PBYTE pbResult, uint16_t cbResult )
{
    return static_cast<HpkeImplementation *>( handle )->secretExportSender(
        pbExporterContext, cbExporterContext, pbResult, cbResult );
}

int32_t
scTestHpkeSecretExportRecipient(
    void * handle,
    PCBYTE pbExporterContext, size_t cbExporterContext,
    PBYTE pbResult, uint16_t cbResult )
{
    return static_cast<HpkeImplementation *>( handle )->secretExportRecipient(
        pbExporterContext, cbExporterContext, pbResult, cbResult );
}

size_t
scTestHpkeEncSize( void * handle )
{
    return static_cast<HpkeImplementation *>( handle )->encSize();
}

// Perf infrastructure C++ bridge helpers
uint64_t
scTestGetPerfClock()
{
    return GET_PERF_CLOCK();
}

int
scTestIsImpToTest( const char * impNamePtr, size_t impNameLen )
{
    return scTestSetContainsPrefixImp( impNamePtr, impNameLen ) != 0 ? 1 : 0;
}

size_t
scTestGetAlgImpCount()
{
    return g_algorithmImplementation.size();
}

void *
scTestGetAlgImpAt( size_t idx )
{
    return g_algorithmImplementation[idx];
}

size_t
scTestAlgImpGetAlgName( void * pImp, const char ** outPtr )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    *outPtr = pAlgImp->m_algorithmName.data();
    return pAlgImp->m_algorithmName.size();
}

size_t
scTestAlgImpGetModeName( void * pImp, const char ** outPtr )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    *outPtr = pAlgImp->m_modeName.data();
    return pAlgImp->m_modeName.size();
}

size_t
scTestAlgImpGetImpName( void * pImp, const char ** outPtr )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    *outPtr = pAlgImp->m_implementationName.data();
    return pAlgImp->m_implementationName.size();
}

void
scTestAlgImpGetPerfFunctions(
    void * pImp,
    PerfKeySizeSupportedFn * pKeySizeSupported,
    PerfKeyFn * pKeyFn,
    PerfDataFn * pDataFn,
    PerfDataFn * pDecryptFn,
    PerfCleanFn * pCleanFn )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    *pKeySizeSupported = pAlgImp->m_perfKeySizeSupported;
    *pKeyFn = pAlgImp->m_perfKeyFunction;
    *pDataFn = pAlgImp->m_perfDataFunction;
    *pDecryptFn = pAlgImp->m_perfDecryptFunction;
    *pCleanFn = pAlgImp->m_perfCleanFunction;
}

void
scTestAlgImpAddPerfInfo(
    void * pImp,
    size_t keySize,
    size_t dataSize,
    const char * strPostfixPtr,
    size_t strPostfixLen,
    double cPerByte,
    double cOverhead,
    double cRange )
{
    static std::vector<std::unique_ptr<std::string>> s_postfixes;
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    AlgorithmImplementation::ALG_PERF_INFO info = {};
    info.keySize = keySize;
    info.dataSize = dataSize;
    info.cPerByte = cPerByte;
    info.cFixed = cOverhead;
    info.cRange = cRange;
    info.operationName = "";
    s_postfixes.push_back( std::make_unique<std::string>( strPostfixPtr, strPostfixLen ) );
    info.strPostfix = const_cast<char *>( s_postfixes.back()->c_str() );
    pAlgImp->m_perfInfo.push_back( info );
}

size_t
scTestAlgImpGetPerfInfoCount( void * pImp )
{
    return static_cast<AlgorithmImplementation *>( pImp )->m_perfInfo.size();
}

void
scTestAlgImpGetPerfInfoAt(
    void * pImp,
    size_t idx,
    size_t * pKeySize,
    size_t * pDataSize,
    const char ** outPostfixPtr,
    size_t * outPostfixLen,
    double * pCpb,
    double * pOverhead,
    double * pRange )
{
    AlgorithmImplementation * pAlgImp = static_cast<AlgorithmImplementation *>( pImp );
    const AlgorithmImplementation::ALG_PERF_INFO & info = pAlgImp->m_perfInfo[idx];
    *pKeySize = info.keySize;
    *pDataSize = info.dataSize;
    *outPostfixPtr = info.strPostfix != nullptr ? info.strPostfix : "";
    *outPostfixLen = info.strPostfix != nullptr ? strlen( info.strPostfix ) : 0;
    *pCpb = info.cPerByte;
    *pOverhead = info.cFixed;
    *pRange = info.cRange;
}

size_t
scTestGetMeasureSizesStringPrefix( const char ** outPtr )
{
    *outPtr = g_measure_sizes_stringPrefix.data();
    return g_measure_sizes_stringPrefix.size();
}

} // extern "C"
