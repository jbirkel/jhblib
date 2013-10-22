// ======================================================================================
// 
// jhbKrypto.h
//
//   Cryptographic functions, utilities and wrappers that help with programming 
//   encryption operations.
//
// --------------------------------------------------------------------------------------
// This software is open source under the MIT License:
//
// Copyright (C) 2012 Jeffrey H. Birkel
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of this 
// software and associated documentation files (the "Software"), to deal in the Software 
// without restriction, including without limitation the rights to use, copy, modify, 
// merge, publish, distribute, sublicense, and/or sell copies of the Software, and to 
// permit persons to whom the Software is furnished to do so, subject to the following 
// conditions:
//
// The above copyright notice and this permission notice shall be included in all copies 
// or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A 
// PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT 
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
// CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
// --------------------------------------------------------------------------------------
//
// History:
//
//   Created 2012-10-12
//
// ======================================================================================

#ifndef _JHB_KRYPTO_H_
#define _JHB_KRYPTO_H_

#include "jhbCommon.h"

// ======================================================================================
//
// Functions
//
// ======================================================================================

// Pad byte utilities.
int  PadLen     ( int ptLen, int blocksize           ) ;
void PadWrite   ( int ptLen, int blocksize, BYTE *pt ) ;
int  PadCheckGet( BYTE *ct, int ctLen, bool bClear = false ) ;

// SHA-1
#define SHA1_LEN 20
BYTE *sha1( const BYTE *p, int cb, BYTE *pOut );

// AES-CBC-128
BYTE *aes( const BYTE *in, BYTE *out, int cb, const BYTE *key, const BYTE *iv, bool bEncrypt );


// Psuedo-random byte stream generators
BYTE *GenKeyBytes( BYTE *p, int cb, const BYTE *seed, int cbSeed );
BYTE *GenKeyBytes( BYTE *p, int cb );

BYTE *GenKeyBytes( KeyBuf &kb, const BYTE *seed, int cbSeed );
BYTE *GenKeyBytes( KeyBuf &kb ); 


// -------------
// From HMAC.cpp
// -------------
 
typedef BYTE* (* pfnHash)( const BYTE *p, int cb, BYTE *pOut );

BYTE* hmac     ( PCBYTE in, int inlen, PCBYTE key, int keylen, BYTE* out, pfnHash hash, int hashlen );
BYTE* hmac     ( LPCSTR in           , PCBYTE key, int keylen, BYTE* out, pfnHash hash, int hashlen );
BYTE* hmac     ( PCBYTE in, int inlen, LPCSTR key,             BYTE* out, pfnHash hash, int hashlen );
BYTE* hmac     ( LPCSTR in           , LPCSTR key,             BYTE* out, pfnHash hash, int hashlen );

BYTE* hmac_sha1( PCBYTE in, int inlen, PCBYTE key, int keylen, BYTE* out );
BYTE* hmac_sha1( LPCSTR in           , PCBYTE key, int keylen, BYTE* out );
BYTE* hmac_sha1( PCBYTE in, int inlen, LPCSTR key,             BYTE* out );
BYTE* hmac_sha1( LPCSTR in           , LPCSTR key,             BYTE* out );

bool hmac_TEST();

// -------------
// From CMAC.cpp
// -------------

BYTE* cmac_aes128( PCBYTE in, int inlen, PCBYTE key, int keylen, BYTE* out );

bool cmac_TEST();

// ----------------
// From PBKDFF2.cpp
// ----------------

BYTE *PBKDF2( const MemBuf &text, const MemBuf &salt, int count, int length, MemBuf &out);
BYTE *PBKDF2( const char   *text, const char   *salt, int count, int length, MemBuf &out); 

bool PBKDF2_TEST();


// WPA passphrase to PSK conversion
#define WPAPSK_LEN 32
#define WPA_PASSPHRASE_LEN_MIN  8
#define WPA_PASSPHRASE_LEN_MAX 63

BYTE *WPAPSK(PCBYTE text, int len, PCBYTE ssid, int ssidlen, BYTE   *out); 
BYTE *WPAPSK(LPCSTR text,          PCBYTE ssid, int ssidlen, MemBuf &out);
BYTE *WPAPSK(LPCSTR text,          LPCSTR ssid             , MemBuf &out);

bool WPAPSK_TEST();


// ======================================================================================
//
// Classes
//
// ======================================================================================

// --------------------------------------------------------------------------------------
// Ciphertext "package" that includes an IV with the ciphertext.
// --------------------------------------------------------------------------------------
template <int BlockSize> struct _block_cipher_package_t {

   typedef BYTE Block[BlockSize];
   
   Block iv   ;   // initialization vector
   Block ct[1];   // array size as needed to fit the ciphertext
   
   // For calculating the size of the full structure from a plain text length.
   static int CalcSize( UINT ptLen ) { return sizeof(Block) + PadLen( ptLen, BlockSize ); }
   
   // For calculating the size of the ct member from a full structure size.
   static int ctSize( int size  ) { 
      return max( size - (int)sizeof(Block), (int)sizeof(Block)); 
   } 
   
   int blkSize() { return BlockSize; }
} ;

#define AesCbc128_BlkLen 16
typedef _block_cipher_package_t<AesCbc128_BlkLen> AesCbc128Pkg_t; 


// --------------------------------------------------------------------------------------
// Mechanism for defining hard-coded keys that are not embedded in the binary 
// image nor held for long periods in memory.
// --------------------------------------------------------------------------------------
template <int keylen> class HiddenHardKey {
public:
   BYTE *GetKey( KeyBuf &kb ) {
      kb.alloc( keylen );
      return GenKeyBytes( kb, _seed, _seed.size() );
   }
   int GetKeyLen() { return keylen; }
   
protected:
   virtual char *seed() = 0;  // must return a seed in hex ASCII
      
   void init() {
      UINT len = (UINT)strlen( seed() ) / 2;
      _seed.alloc( len );
      CvtHex( seed(), _seed );      
   }      
private:
   MemBuf _seed;
};


#endif // _JHB_KRYPTO_H_
