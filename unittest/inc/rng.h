//
// rng.h Header file for test RNG
//
// Copyright (c) Microsoft Corporation. Licensed under the MIT license.
//
// We use our own predictable RNG so that we can be repeatable.
//


extern "C" {
    class Rng;
    void scTestRngInit(Rng* rng);
    void scTestRngDeinit(Rng* rng);
    void scTestRngReset(Rng* rng, PCBYTE pbSeed, SIZE_T cbSeed);
    BYTE scTestRngByte(Rng* rng);
    UINT32 scTestRngUint32(Rng* rng);
    SIZE_T scTestRngSizet(Rng* rng, SIZE_T upb);
    SIZE_T scTestRngSizetRange(Rng* rng, SIZE_T min, SIZE_T upb);
    SIZE_T scTestRngSizetNonUniform(Rng* rng, SIZE_T upb, SIZE_T uniformLimit, UINT32 logIncrease);
    void scTestRngRandomSubRange(Rng* rng, SIZE_T bufSize, SIZE_T * pStart, SIZE_T * pLen);
}

class Rng
{
public:
    Rng() { scTestRngInit(this); }
    ~Rng() { scTestRngDeinit(this); }

private:
    Rng( const Rng &);
    void operator=( const Rng & );

public:
    VOID reset( PCBYTE pbData, SIZE_T cbData ) { scTestRngReset(this, pbData, cbData); }

    _Ret_range_( min, upb-1 )
    SIZE_T sizet( SIZE_T min, SIZE_T upb ) { return scTestRngSizetRange(this, min, upb); }

    _Ret_range_( 0, upb-1 )
    SIZE_T sizet( SIZE_T upb ) { return scTestRngSizet(this, upb); }

    _Ret_range_( 0, upb-1 )
    SIZE_T sizetNonUniform( SIZE_T upb, SIZE_T UniformProbLimit, UINT32 logIncrease ) {
        return scTestRngSizetNonUniform(this, upb, UniformProbLimit, logIncrease);
    }

    VOID randomSubRange( SIZE_T bufSize, SIZE_T * pStart, SIZE_T * pLen ) {
        scTestRngRandomSubRange(this, bufSize, pStart, pLen);
    }

    BYTE byte() { return scTestRngByte(this); }

    UINT32 uint32() { return scTestRngUint32(this); }

private:

    BYTE        m_seed[SYMCRYPT_SHA1_RESULT_SIZE];
    ULONGLONG   m_blockCtr;
    SIZE_T      m_bytesInBuf;
    BYTE        m_buf[SYMCRYPT_SHA1_RESULT_SIZE];

};

