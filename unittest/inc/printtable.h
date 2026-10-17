//
// PrintTable.h
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//

extern "C" {
    void* scTestPrintTableCreate();
    void scTestPrintTableDestroy(void* handle);
    void scTestPrintTableClear(void* handle);
    void scTestPrintTableAddItemStr(void* handle, const char* row_ptr, size_t row_len, const char* col_ptr, size_t col_len, const char* item_ptr, size_t item_len);
    void scTestPrintTableAddItemU64(void* handle, const char* row_ptr, size_t row_len, const char* col_ptr, size_t col_len, ULONGLONG value);
    void scTestPrintTableAddItemNonZero(void* handle, const char* row_ptr, size_t row_len, const char* col_ptr, size_t col_len, ULONGLONG value);
    void scTestPrintTableAddItemPerf(void* handle, const char* row_ptr, size_t row_len, const char* col_ptr, size_t col_len, double perByte, double overhead, double range);
    void scTestPrintTablePrint(void* handle, const char* heading_ptr, size_t heading_len);
}

class PrintTable
{
public:
    PrintTable() : m_handle(scTestPrintTableCreate()) {}
    ~PrintTable() { scTestPrintTableDestroy(m_handle); }

private:
    PrintTable( const PrintTable & );
    void operator=( const PrintTable & );

public:
    VOID addItem( String row, String col, String item ) {
        scTestPrintTableAddItemStr(m_handle, row.data(), row.size(), col.data(), col.size(), item.data(), item.size());
    }
    VOID addItem( String row, String col, ULONGLONG value ) {
        scTestPrintTableAddItemU64(m_handle, row.data(), row.size(), col.data(), col.size(), value);
    }
    VOID addItemNonZero( String row, String col, ULONGLONG value ) {
        scTestPrintTableAddItemNonZero(m_handle, row.data(), row.size(), col.data(), col.size(), value);
    }
    VOID addItem( String row, String col, double perByte, double overhead, double range ) {
        scTestPrintTableAddItemPerf(m_handle, row.data(), row.size(), col.data(), col.size(), perByte, overhead, range);
    }

    VOID clear() {
        scTestPrintTableClear(m_handle);
    }

    VOID print( String heading ) {
        scTestPrintTablePrint(m_handle, heading.data(), heading.size());
    }

private:
    void* m_handle;
};
