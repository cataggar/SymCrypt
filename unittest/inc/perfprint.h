//
// PerfPrint.h
// Printing output without affecting performance measurements
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license. 
//


extern "C" {

VOID
print( const char *format, ...);

VOID
printHex( PCBYTE pbData, SIZE_T cbData );

VOID
iprint( const char *format, ...);

VOID
dprint( const char *format, ...);   // Only prints if #if is modified in source code, used for debugging.

VOID printOutput( int delayMilliSeconds );

VOID
vprint( BOOL bPrint, const char *format, ...);   // Only prints if bPrint == TRUE

}

VOID
print( String s );

String
formatNumber( double v );