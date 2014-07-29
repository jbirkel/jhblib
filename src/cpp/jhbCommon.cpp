// ======================================================================================
// 
// jhbCommon.cpp
//
//   Definitions of commonly used C++ functions and class members.
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
// ======================================================================================

#include <stdio.h>
#include <tchar.h>
#include "jhbCommon.h"

#include <sstream>

#pragma warning(disable:4996)


// ----------------------------------------------------------------------------
// MemBuf
// ----------------------------------------------------------------------------

PBYTE MemBuf::xor( PBYTE dst, PBYTE src, int count ) {
   int i; for (i=0; i<count; i++) { dst[i] ^= src[i]; }
   return dst;
}
PBYTE MemBuf::xor( PBYTE dst, PBYTE src1, PBYTE src2, int count ) {
   int i; for (i=0; i<count; i++) { dst[i] = src1[i] ^ src2[i]; }
   return dst;
}
//MemBuf MemBuf::XOR( MemBuf m1, MemBuf m2 ) {
//   UINT count = min( m1.size(), m2.size() );   
//   return *(MemBuf*) new MemBuf( (PCBYTE)XOR( m1, m2, count ), count );
//}
void MemBuf::xor( PBYTE in, int count ) {
   xor( ptr(), in, min( (int)size(), count ));
}


// This is a buffer-wide left shift of 1 bit.  
// NOTES:
// -- the MSB of the whole buffer is bit 7 of byte 0.
// -- in and out may point to the same buffer
PBYTE MemBuf::lsh1( PBYTE dst, PCBYTE src, int count ) {
   BYTE overflow = 0;
   for (int i=(count-1); i>=0; i--) {
      BYTE tmp = src[i];
      dst[i]   = src[i] << 1;
      dst[i]  |= overflow;
      overflow = (tmp & 0x80) ? 0x01 : 0x00;
   }
   return dst;
}   
PBYTE MemBuf::lsh1() {
   lsh1( ptr(), ptr(), size() );
   return ptr();
}



bool MemBuf::realloc( UINT size ) {
   MemBuf tmp( *this );
   return _alloc( size ) ? (memcpy( _p, tmp, min( _z, tmp.size() )), true)  
                         : false ;
}

// ----------------------------------------------------------------------------
// jhbCommon logging
// ----------------------------------------------------------------------------   

PrintProxy<char> jhbCommon::_pp;  

void _logf ( char * format, ... ) {
   va_list ap;
   va_start( ap, format );
    jhbCommon::_pp.printfv( format, ap );
   va_end( ap );    
}

// ----------------------------------------------------------------------------
// Rounds value up to next multiple of modulus.
// ----------------------------------------------------------------------------
UINT RoundUp( UINT value, UINT modulus ) {
   if (0 == modulus) return 0;
   if (0 == (value % modulus)) return value;   
   return modulus * (1 + (value / modulus));
}

// ----------------------------------------------------------------------------
// Compilers may optimize away memsets that appear to be inconsequential. Here
// we use the "volatile" keyword to try to force the compiler to do it anyway.
// ----------------------------------------------------------------------------
volatile void SecureZero( volatile void * p, int cb ) { memset( (void*)p, 0, cb ); }

// ----------------------------------------------------------------------------
// Read an entire text file into a string variable.
// ----------------------------------------------------------------------------
std::string ReadTextFile( const char *filePath ) {

   FILE *f = fopen( filePath, "rt" );
   if (NULL == f) { 
      return ""; 
   }
   
   // First get the length of the file.
   fseek( f, 0, SEEK_END );
   size_t size = ftell( f );
   fseek( f, 0, SEEK_SET );      
   
   // Pre-size a string buffer to receive the text. 
   std::string s; s.resize( size );
   
   // Read all of the file.
   fread( (char *)s.c_str(), 1, size, f );
   fclose( f );
   
   return s;
}

int ReadBinaryFile( const char *filePath, BYTE *p, size_t cb ) {
   return ReadBinaryFile( CvtStrW( filePath ), p, cb );
}

int ReadBinaryFile( const wchar_t *filePath, BYTE *p, size_t cb ) {
   
   // Open the file using the appropriate string type.   
   FILE *f = _wfopen( (WCHAR *)filePath, L"rb" );
   if (NULL == f) { return -1; }
   
   // Get the length of the file.
   fseek( f, 0, SEEK_END );
   size_t size = ftell( f );
   fseek( f, 0, SEEK_SET );   
   
   // Read as much of it as the caller can handle.
   int nRead = (int)fread( p, 1, min( size, cb ), f );
   fclose( f );
   
   return nRead;
}

const char    *FmtIP( std:: string &s, UINT ip ) { BYTE *p = (BYTE*)&ip; char    sIP[16];  sprintf ( sIP,  "%d.%d.%d.%d", p[0], p[1], p[2], p[3] ); s = sIP; return s.c_str(); }
const wchar_t *FmtIP( std::wstring &s, UINT ip ) { BYTE *p = (BYTE*)&ip; wchar_t sIP[16]; wsprintfW( sIP, L"%d.%d.%d.%d", p[0], p[1], p[2], p[3] ); s = sIP; return s.c_str(); }

// ----------------------------------------------------------------------------
// Performs log file cycling.
//
// -- This prevents log files from getting too big, by renaming them through a 
//    series of filenames suffixed with an index variable running from 1 to count-1.
//    The length determines when the log file gets renamed. The last file in the 
//    series gets deleted when incrementing it's index would equal the count.
//
//    Example: (filename.ext, 3, N) would (over time) result in these files:
//       filename.exe, filename1.ext, filename2.ext (all about N bytes in length)
//
// -- if maxCount is less than or equal to 1, no cycling is performed.
//
// NOTE: This implementation is Windows-specific
// ----------------------------------------------------------------------------
void CycleLogFiles( const char *filename, int maxCount, int maxLength ) {

   FILE *f = fopen( filename, "r" );
   if (NULL == f) return;
   
   fseek( f, 0, SEEK_END );
   bool bNeedCycle = (maxLength < ftell( f )) && (1 < maxCount);
   fclose( f );
   
   // Nothing to do here...
   if (!bNeedCycle) { return; }
   
   char drv[MAX_PATH+1], dir[MAX_PATH+1], name[MAX_PATH+1], ext[MAX_PATH+1];
   _splitpath( filename, drv, dir, name, ext );
   
   std::string next;
   const int last = maxCount-1;
   for (int i=last; i>=1; i--) {

      // Format filename for this index.
      std::stringstream ss; ss << name << i; 
      char tgt[MAX_PATH+1];
      _makepath( tgt, drv, dir, ss.str().c_str(), ext );
      
      // Does this file exist?
      FILE *f = fopen( tgt, "r" );
      if (NULL != f) {
         fclose( f );
         // If last file in sequence, delete it, otherwise rename it to the next index.
         if (last == i) { remove( tgt ); } 
         else           { rename( tgt, next.c_str() ); }
      }
      next = tgt;
   }
   
   // Finally, rename the base log file.
   rename( filename, next.c_str() ); 
}

// --- RegKey -----------------------------------------------------------------

/*
void RegKey::_open( HKEY root, RegKey::_PCH keyPath, bool bWrite ) { 
   _close();
//   _lasterr = bWrite ? RegCreateKeyEx( root, keyPath, 0, 0, 0, KEY_ALL_ACCESS, 0, &_hkey, 0 )
   _lasterr = bWrite ? RegCreateKeyEx( root, keyPath, 0, 0, 0, KEY_READ | KEY_WRITE, 0, &_hkey, 0 )   
                     : RegOpenKeyEx  ( root, keyPath, 0      , KEY_READ            ,    &_hkey    );

   if (ERROR_SUCCESS != _lasterr) {
      _logf( "jhblib: ***ERROR: %s returned %d\n", bWrite ? "RegCreateKeyEx" : "RegOpenKeyEx", _lasterr );
   }
}
*/


// --- PrintProxy -------------------------------------------------------------

timefmt_e operator &(timefmt_e e1, timefmt_e e2) { return (timefmt_e)((UINT)e1 & (UINT)e2); }
timefmt_e operator |(timefmt_e e1, timefmt_e e2) { return (timefmt_e)((UINT)e1 | (UINT)e2); }

// --- GDI --------------------------------------------------------------------

//bool IsFixedFont( LOGFONTA lf ) { return BITTST( lf.lfPitchAndFamily, FIXED_PITCH ); }
//bool IsFixedFont( LOGFONTW lf ) { return BITTST( lf.lfPitchAndFamily, FIXED_PITCH ); }
bool _stdcall IsFixedFont( HFONT hf ) {
   LOGFONT lf;
   return GetObject( hf, sizeof lf, &lf )
       && BITTST( lf.lfPitchAndFamily, FIXED_PITCH );
}
   

// --- CvtHex -----------------------------------------------------------------

int CvtHexA( const char    *pHex, BYTE *pBy ) { return CvtHex<char>   (pHex, pBy); }
int CvtHexW( const wchar_t *pHex, BYTE *pBy ) { return CvtHex<wchar_t>(pHex, pBy); }

#ifdef _TCHAR_DEFINED
int CvtHexT( const TCHAR *pHex, BYTE *pBy ) { return CvtHex<TCHAR>(pHex, pBy); }
#endif

