//
// Result merge infrastructure
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

extern "C" {
    void* scTestResultMergeCreate();
    void scTestResultMergeDestroy(void* handle);
    void scTestResultMergeAddResult(
        void* handle,
        void* pAlgImp,
        const char* impName,
        const char* algName,
        ULONGLONG* pNumResults,
        ULONGLONG* pNumErrorDisagree,
        ULONGLONG* pNumErrorNoMajority,
        PCBYTE pbData,
        SIZE_T cbData);
    void scTestResultMergeGetResult(void* handle, PBYTE pbResult, SIZE_T cbResult, BOOL countInvocation);
}

class ResultMerge {
public:
    ResultMerge() : m_handle(scTestResultMergeCreate()) {}
    ~ResultMerge() { scTestResultMergeDestroy(m_handle); }

private:
    ResultMerge( const ResultMerge & );
    VOID operator=( const ResultMerge & );

public:
    VOID addResult( 
        _In_                        AlgorithmImplementation * pAlgImp, 
        _In_reads_( cbData )        PCBYTE pbData, 
                                    SIZE_T cbData );

    VOID getResult( 
        _Out_writes_( cbResult )    PBYTE   pbResult, 
                                    SIZE_T  cbResult, 
                                    BOOL    countInvocation = TRUE ) {
        scTestResultMergeGetResult(m_handle, pbResult, cbResult, countInvocation);
    }

private:
    void* m_handle;

};
