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
