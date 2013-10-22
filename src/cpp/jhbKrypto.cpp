// ======================================================================================
// 
// jhbKrypto.cpp
//
//   Cryptographic functions, utilities and wrappers that help with programming 
//   encryption operations.
//
//   NOTE: Requires some OpenSSL files, which have different copyright requirement than
//         this file.  See those files for their copyright requirements. 
//
// --------------------------------------------------------------------------------------
// This software is open source under the MIT License:

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

//#include <time.h>
#include "jhbKrypto.h"

extern "C" {
   #include <openssl/aes.h>
   #include <openssl/modes/modes_lcl.h>

   #define SHA_1
   #include <openssl/sha_locl.h>   
}   
   
// --------------------------------------------------------------------------------------
// Rounds up the given length to a multiple of the block size, including 
// adding an extra block when necessary.
// --------------------------------------------------------------------------------------
int PadLen( int len, int blocksize ) {
   if (0 == blocksize) return 0;
   if (0 == (len % blocksize)) len++;
   return RoundUp( len, blocksize );
}

// --------------------------------------------------------------------------------------
// Assumes the buffer is sized correctly for the given plaintext length.
// NOTE: Use PadLen to allocate the memory.
// --------------------------------------------------------------------------------------
void PadWrite( int ptLen, int blocksize, BYTE *pt ) {
   int padLen = PadLen( ptLen, blocksize ); 
   BYTE pad = padLen - ptLen;
   for(int i=ptLen; i<padLen; i++) {
      pt[i] = pad;
   }
}

// ----------------------------------------------------------------------------
// Inspects the ciphertext for correct padding, returns pad byte value.
// ----------------------------------------------------------------------------
int PadCheckGet( BYTE *ct, int ctLen, bool bClear ) {
   int i   = ctLen - 1;
   const int pad = ct[i];
   while ((0 < i) && (pad == ct[i])) { 
      if (bClear) { ct[i] = 0; }
      i--; 
   }
   return (pad == (ctLen - 1 - i)) ? pad : -1;
}

// ----------------------------------------------------------------------------
// SHA-1 hash function based on OpenSSL library.
// ----------------------------------------------------------------------------
BYTE* sha1( const BYTE *p, int cb, BYTE *pOut ) {

   SHA_CTX ctx;
   
   SHA1_Init  ( &ctx        );
   SHA1_Update( &ctx, p, cb );
   SHA1_Final ( pOut, &ctx  );

   SecureZero ( &ctx, sizeof ctx );
   
   return pOut;
}

// ----------------------------------------------------------------------------
// AES-CBC-128 based on OpenSSL library.
// ----------------------------------------------------------------------------
BYTE *aes( const BYTE *in, BYTE *out, int cb, const BYTE *key, const BYTE *iv, bool bEncrypt ) {

   AES_KEY aks; 
   bEncrypt ? private_AES_set_encrypt_key( key, AesCbc128_BlkLen * 8, &aks )   
            : private_AES_set_decrypt_key( key, AesCbc128_BlkLen * 8, &aks ) ;
   
   AES_cbc_encrypt( in, out, cb, &aks, (BYTE *)iv, bEncrypt?1:0 );
   
   return out;
}

// ----------------------------------------------------------------------------
// Creates an arbitrarily long hash stream from the given seed.
// ----------------------------------------------------------------------------
BYTE *GenKeyBytes( BYTE *pOut, int cbOut, const BYTE *seed, int cbSeed ) {
   
   KeyBuf prev(SHA_DIGEST_LENGTH);
   
   // First round we use caller's seed.
   const BYTE *p =   seed;
         int  cb = cbSeed;
   
   for (int ofs=0; ofs<cbOut; ) {
   
      // Compute this round's hash.
      KeyBuf hash(SHA_DIGEST_LENGTH);      
      sha1( p, cb, hash );

      // Copy as much of the hash as we need, and bump the offset.   
      int count = min( cbOut - ofs, sizeof hash ) ;
      memcpy( pOut+ofs, hash, count );
      ofs += count; 
      
      // Save the hash for next round 
      memcpy( prev, hash, sizeof prev );

      // After the first round we use the previous round's hash as the seed.
      p  =        prev;
      cb = sizeof prev;
   }  
   
   return pOut; 
}

// ----------------------------------------------------------------------------
// These allow the use of a KeyBuf buffer with the GenKeyBytes functions.
// NOTE: Preallocate the KeyBuf buffer to the desired number of bytes.
// ----------------------------------------------------------------------------
BYTE *GenKeyBytes( KeyBuf &kb, const BYTE *seed, int cbSeed ) {
   return GenKeyBytes( kb, kb.size(), seed, cbSeed );
} 

BYTE *GenKeyBytes( BYTE *p, int cb );
BYTE *GenKeyBytes( KeyBuf &kb ) { return GenKeyBytes( kb, kb.size()); }


// ----------------------------------------------------------------------------
// Constructs an internal, unique seed and generates and feeds that
// to the PRF.
//
// NOTE: The hash function provides randomness.  All we need to do is feed it
//       a nonce seed.
// ----------------------------------------------------------------------------
#ifdef _WIN32
   #include <windows.h>
#endif

BYTE *GenKeyBytes( BYTE *p, int cb ) {

#ifdef _WIN32
   // Windows-only: use a GUID as the unique part of the seed.
   static struct { GUID guid; __int64 ctr; } _seed = { {0},0 };      
   if (0 == _seed.ctr++) { CoCreateGuid( &_seed.guid ); }
   
#else   
   // Possible non-Windows seed generator?
   //static struct { time_t t; clock_t c; __int64 ctr; } _seed = { 0,0,0 };   
   //if (0 == _seed.ctr++) { time( &_seed.t ), _seed.c = clock(); }     
#endif

   return GenKeyBytes( p, cb, (BYTE*)&_seed, sizeof _seed );
}

