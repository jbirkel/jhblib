// ======================================================================================
// 
// jhbCommon.h
//
//   Repository of commonly-used macros, types, functions and classes.
//
// --------------------------------------------------------------------------------------
// This software is open source under the MIT License:
//
// Copyright (C) 2013 Jeffrey H. Birkel
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
//   2012-09    Added KeyBuf, RoundUp, SecureZero
//   2012-??    Added PrintProxy, RegKey 
//   2012-03-11 Added FmtHex, CvtHex, HexDigit, FmtAlpha, IsAlpha
//   2012-03-10 Added MemBuf
//
// ======================================================================================

#ifndef __JHB_COMMON_H__
#define __JHB_COMMON_H__

#include <string>
#include <vector>

#include <stdarg.h>
#include <stdio.h>
#include <assert.h>

#ifdef _WIN32
#include <windows.h>
#include <tchar.h>
#endif

#include "jhb_types.h"


// ----------------------------------------------------------------------------
//
// Macros
//
// ----------------------------------------------------------------------------

// Number of elements in a static array.
#define NELEM(a) (sizeof(a)/sizeof((a)[0]))

#define IsOdd(a)  (1==(a%2))
#define IsEven(a) !IsOdd(a)

#define TF(b) ((b)?"T":"F")

#define BITSET(v,bit) (v=(v)|(bit))
#define BITCLR(v,bit) (v=(v)&~(bit))
#define BITTST(v,bit) ((bit)==((v)&(bit)))
#define BITCHG(v,bit,bSetClr) ((bSetClr)?BITSET(v,bit):BITCLR(v,bit))

#ifndef min 
#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))
#endif

template <typename T> bool BitTst( T  v, const T bits ) { return bits == (v | bits) ; }

template <typename T> void BitSet( T &v, const T bits ) { v = (T)(v |  bits) ; }
template <typename T> void BitClr( T &v, const T bits ) { v = (T)(v & ~bits) ; }

template <typename T> void BitChg( T &v, const T bits, bool bSetClr ) { 
   bSetClr ? BitSet(v,bits) 
           : BitClr(v,bits); 
}

template <typename T> void Swap( T &a, T &b ) { T c = a; a = b; b = c; }

// ----------------------------------------------------------------------------
//
// Misc. non-template function prototypes
//
// ----------------------------------------------------------------------------

UINT RoundUp( UINT value, UINT modulus );

volatile void SecureZero( volatile void * p, int cb );

std::string ReadTextFile( const char *filePath );

int ReadBinaryFile( const char    *filePath, BYTE *p, size_t cb );
int ReadBinaryFile( const wchar_t *filePath, BYTE *p, size_t cb );

void CycleLogFiles( const char *filename, int maxCount, int maxLength );

// ----------------------------------------------------------------------------
//
// Template Functions
//
// ----------------------------------------------------------------------------

// --- String Formatting and Conversion Functions -----------------------------

const char    *FmtIP( std::string  &s, UINT ip );
const wchar_t *FmtIP( std::wstring &s, UINT ip );

// NOTE: In these templates, T may only be char or wchar_t.

// Convert an array of bytes to a Hexadecimal string.
template <typename T> const T *FmtHex( STD_STRING(T) &s, PBYTE p, UINT cnt, T chDelim = 0 ) {
   T Hex[] = { '0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f', } ;

   s.clear(); 
   UINT i; for(i=0; i<cnt; i++, p++) {
      T dig[3] = { Hex[*p >> 4], Hex[*p & 0x0f], '\0' } ; 
      if (chDelim && (0 != i)) { s += chDelim; }
      s += dig;
   } 
   return s.c_str();  
}

// True if character is any upper or lowercase letter or a space.
// False otherwise.
template <typename T> bool  IsAlpha( T c ) {
   return ('a' <= c) && (c <= 'z')  
       || ('A' <= c) && (c <= 'Z') 
       || (' ' == c)
       ;
}

// Convert an array of bytes to a string where:
// -- ASCII values for a-z, A-Z and space are printed as is
// -- the value 0 (0x00, not 0x30) is printed as an asterisk
// -- all other values are printed as a period.
template <typename T> const T *FmtAlpha( STD_STRING(T) &s, PBYTE p, UINT cnt ) {
   s.clear(); 
   UINT i; for(i=0; i<cnt; i++,p++) {
      s += IsAlpha(*p) ? (T)*p : 
           (0   == *p) ? '*'   : '.' ;
   } 
   s += '\0';
   
   return s.c_str();  
}

// Convert an array of bytes to a string where:
// -- all printable byte values are printed
// -- all other values are printed as a period.
template <typename T> const T *FmtAsc( STD_STRING(T) &s, PBYTE p, UINT cnt ) {
   s.clear(); 
   UINT i; for(i=0; i<cnt; i++,p++) {
      s += isprint(*p) ? (T)*p : '.' ;
   } 
   s += (TCHAR)'\0';
   
   return s.c_str();  
}

// Returns the numeric value of a Hexadecimal digit.
// NOTE: Hex chars may be upper or lower case.
template <typename T> BYTE HexDigit( T c ) {
   return (BYTE)(
      ('0' <= c) && (c <= '9') ? (c - '0') :
      ('A' <= c) && (c <= 'F') ? (c - 'A' + 10) :   
      ('a' <= c) && (c <= 'f') ? (c - 'a' + 10) : -1
   )  ;   
}

// Converts a hexadecimal string into an array of bytes.
// NOTE: Call with pBy==NULL to get the needed buffer length.
template <typename T> int CvtHex( const T *pHex, BYTE *pBy ) {

   if (NULL == pHex) return -1;
   
   // char or wchar_t only.
   int len = (int) (
                (1 == sizeof(T)) ? strlen( (char    *)pHex ) :   
                (2 == sizeof(T)) ? wcslen( (wchar_t *)pHex ) : -1
             )  ;   
   
   MemBuf m( len );
   BYTE accum = 0;
   const T *pc = pHex;
   int count = 0;
   int i; for(i=0; i<len; i++) {
      BYTE nib = HexDigit( *pc++ );
      if (0 == i%2) nib <<= 4;
      accum += nib;
      if (1 == i%2) { m[i/2] = accum; accum = 0; count++; }
   }
   
   if (NULL != pBy) { memcpy( pBy, m, count ); }
   
   return count;
}

int CvtHexA( const char    *pHex, BYTE *pBy );
int CvtHexW( const wchar_t *pHex, BYTE *pBy );

#ifdef _TCHAR_DEFINED
int CvtHexT( const TCHAR *pHex, BYTE *pBy );
#endif


// Find an element in a std::vector
template <typename T> int VecFind( std::vector<T> v, const T tgt ) {
   UINT i; for (i=0; i<v.size(); i++) {
      if (tgt == v[i]) { return i; }
   }
   return -1;
}

// ----------------------------------------------------------------------------
//
// Classes
//
// ----------------------------------------------------------------------------


// Simple memory buffer class.  Encapsulates an array of bytes.
class MemBuf {
public:
   MemBuf()                      { _init();                  }
   MemBuf( UINT size )           { _init(); alloc( size );   }
   MemBuf( PCBYTE p, UINT size ) { _init(); copy( p, size ); }   
   MemBuf( MemBuf &m )           { _init(); copy( m );       }
   
   ~MemBuf() { free(); }
   
   operator PBYTE () const { return _p; }
   
   UINT  size() const { return _z; }   
   PBYTE ptr () const { return _p; }
   PBYTE ptr (UINT ofs) const { return _p + ofs; }   
   
   BYTE &operator[] (int n) const { return *ptr(n); }
   
   //bool alloc( int    size ) { return _alloc( (UINT)size ); }      
   //bool alloc( UINT   size ) { return _alloc(       size ); }
   bool alloc( size_t size ) { return _alloc( (UINT)size ); }   
   void free () { _free(); }
   
   bool realloc( UINT size );   
   
   void fill ( BYTE by ) { memset( _p, by, _z );  }
   void zero ()          { fill(0);               }      
   void szero()          { SecureZero( _p, _z );  }         
   
   bool copy( MemBuf &m          ) { return alloc( m.size()) ? (memcpy( _p, m, _z ), true) : false; }
   bool copy( PBYTE p, UINT size ) { return alloc(   size  ) ? (memcpy( _p, p, _z ), true) : false; }   
   
   // Static MemBuf operations
   //static MemBuf XOR( MemBuf m1, MemBuf m2 ) ;
   static PBYTE  xor( PBYTE dst, PBYTE src             , int count );
   static PBYTE  xor( PBYTE dst, PBYTE src1, PBYTE src2, int count );
          void   xor( PBYTE src,                         int count = INT_MAX );
          
   static PBYTE lsh1( PBYTE dst, PCBYTE src, int count );
          PBYTE lsh1();
   
private:
   BYTE * _p;      
   UINT   _z;
   
   void _init() { _p = 0; _z = 0; }   
   
   bool _alloc( UINT size ) { _free(); _p = new BYTE [_z = size] (); return (0 != _p ); }
   void _free ()            { if (_p) delete [] _p; _p = NULL; _z = 0; }   
   
template<typename T> friend class PtrBuf;
};


// The only purpose of this class is to guarantee that the buffer is zeroed
// before it is freed.  Intended for use with encryption keys.
class KeyBuf : public MemBuf {
public:
   KeyBuf( UINT size          ) : MemBuf( size    ) {}
   KeyBuf( PBYTE p, UINT size ) : MemBuf( p, size ) {}    
   KeyBuf( KeyBuf &pb         ) : MemBuf( pb      ) {}
   
  ~KeyBuf() { szero(); }
};

// Like a fixed-size KeyBuf. Buffer operations are restricted to fixed-buffer
// size operations common to encryption algorithms.
template <int N> class BlockBuf : private MemBuf {
public:
   BlockBuf() : MemBuf(N) {}
  ~BlockBuf() { szero(); }   
   
   void lsh1( PCBYTE in ) { MemBuf::lsh1( ptr(), in, N ); }
   
   void xor ( PCBYTE in              ) { MemBuf::xor( ptr(), in      , N ); }
   void xor ( PCBYTE in1, PCBYTE in2 ) { MemBuf::xor( ptr(), in1, in2, N ); }   
   
   void zero() { MemBuf::zero(); }

         operator PBYTE ()      const { return MemBuf::operator PBYTE(); }   
   BYTE &operator []    (int n) const { return MemBuf::operator []  (n); }   
};


//
// Derivation of MemBuf that mimics a pointer to a given type. 
// NOTE: MemBuf is inherited private to make sure there are no
//       bad side effects when using a PtrBuf object like a T*
//     
template<typename T> class PtrBuf : private MemBuf {
public:
   PtrBuf()                     : MemBuf( sizeof(T) ) { zero(); }
   PtrBuf( UINT size )          : MemBuf( size )      { zero(); }
   PtrBuf( PBYTE p, UINT size ) : MemBuf( p, size )   { zero(); }    
   PtrBuf( PtrBuf &pb )         : MemBuf( pb )        { zero(); }
   
   // These operators provides the implicit type wrapping.
   typedef T* P;
     operator P     () const { return (P)    _p; }
   P operator ->    () const { return (P)    _p; }
   T operator *     () const { return (T)   *_p; }
     operator PVOID () const { return (PVOID)_p; }
     operator PBYTE () const { return        _p; }  // overrides inherited member
     operator bool  () const { return 0 !=   _p; }
      
   // Allow explicit access to the members of the inherited class;
   MemBuf &MB() const { return (MemBuf &)(*this); }
};

// ----------------------------------------------------------------------------
// Smart Pointer
// ----------------------------------------------------------------------------

// This the basis of an smart (auto) pointer class.  Generally, smart pointer 
// differ only in the function used to free memory
#define SMART_POINTER_CORE                         \
      operator T    (        ) { return      _p; } \
   T  operator ->   (        ) { return      _p; } \
   T* operator &    (        ) { return     &_p; } \
   T& operator =    (T p     ) { return  _p = p; } \
   T  operator +    (size_t i) { return  _p + i; } \
      operator bool (        ) { return 0 != _p; } \
private:                                           \
   T _p; 
   
// Auto-ptr for Service Control Manager (SCM) handles.
class ScHandle {
public:
  typedef SC_HANDLE T;

   ScHandle( SC_HANDLE h ) {                      _h = h; }   
   ScHandle() {                                   _h = 0; }
  ~ScHandle() { if (_h) CloseServiceHandle( _h ); _h = 0; }   
  
      operator T    (   ) { return  _h     ; }  
   T* operator &    (   ) { return &_h     ; }
   T& operator =    (T h) { return  _h  = h; }
      operator bool (   ) { return  _h != 0; } 
   
private:
   T _h;  
};

//
// Anti-memory leak class for working with WTSAPI32 pointers.
//
#if defined(WTS_CURRENT_SERVER) && !defined(__CWtsPtr)
#define __CWtsPtr
template<class T> class CWtsPtr {
public:
   CWtsPtr() {                      _p = 0; }
  ~CWtsPtr() { WTSFreeMemory( _p ); _p = 0; }     
   SMART_POINTER_CORE 
};
#endif



// ----------------------------------------------------------------------------
//
// Provides arbitrary timing numbers in user-specified units.
//
// -- if a high-resolution performance counter exists, we use it.  Otherwise
//    falls back to GetTickCount
//
// -- INT_T specifies an integer type for the time value (e.g., int, __int64)
// -- FREQ specifies the units, as in 1000 for ms, 1000000 for micro-s
//
// -- msTicker provides a millisecond time value in 32-bit integer type
// -- usTicker provides a microsecond time value with a 64-bit time type
//
// NOTE: Current implementation is Windows-specific (QueryPerformanceTimer)
//-----------------------------------------------------------------------------

template <typename INT_T,int FREQ> class __Ticker {

public:
   __Ticker() { _init(); }

   typedef INT_T _tick_t ;
   static int Freq() { return FREQ; }

   operator _tick_t() { return Now(); }
   
   _tick_t Now () { return _cvtToExt( _ticks() ); }

private:
   
   bool    _hires   ; // true if high-resolution performance counter exists
   __int64 _fInt    ; // units of the ticker values in 1/s
                
   void _init() {
      _hires = !!QueryPerformanceFrequency( (LARGE_INTEGER *)&_fInt );
      if (!_hires) { _fInt = 1000; }
   }                

   // Returns the internal count corresponding to the current time.
   __int64 _ticks() {
      __int64 ticks;
      return _hires ? (QueryPerformanceCounter( (LARGE_INTEGER *)&ticks ), ticks)
                    : GetTickCount();
   }        

   // Convert between internal and external time formats.
   _tick_t _cvtToExt  ( __int64 intTime ) { return (_tick_t)(intTime * FREQ / _fInt) ;}
   __int64 _cvtFromExt( _tick_t extTime ) { return           extTime * _fInt / FREQ; }           
};

typedef __Ticker<UINT   ,1000   > msTicker;  // millisecond timer
typedef __Ticker<__int64,1000000> usTicker;  // microsecond timer

//-----------------------------------------------------------------------------
// Companion to __Ticker that provides a way to measure elapse times in seconds.
//
// -- T must be a class compatible with _Ticker (msTicker and usTicker)
// -- Seconds() returns the difference between the current and start times
// -- start time is automatically set at class instantiation
// -- start time is manually set via Reset()
//
// -- msTimer provides millisecond resolution elapse time
// -- usTimer provides microsecond resolution elapse time
//-----------------------------------------------------------------------------
template <class Ticker_t> class __Timer {
public:
   __Timer() { _reset(); }
   double Seconds() { return ((double)_tkr.Now() - _start) / Ticker_t::Freq(); }
   void   Reset  () { _reset(); }
private:
   Ticker_t _tkr;
   typename Ticker_t::_tick_t _start;
   void _reset() { _start = _tkr.Now(); }
};

typedef __Timer<msTicker> msTimer;  // millisecond timer
typedef __Timer<usTicker> usTimer;  // microsecond timer


// ----------------------------------------------------------------------------
//
// PrintProxy - Allows text output to a print sink provided by someone else.
// -- the template type, CH, is expected to be either char or wchar_t
// -- this class does not do conversions. 
// ----------------------------------------------------------------------------

#define DEF_BUF_SIZE 0x1000

enum timefmt_e
{ TFMT_NONE     = 0         // do not prepend a timestamp to log lines
, TFMT_TIMEONLY = 1         // time-only: 123456.789
, TFMT_DATETIME = 2         // date and time: 20140308-123456.789
, TFMT_TYPEMASK = 0x0FF     // mask off flags
, TFMT_NOMS     = 0x100     // if set, don't include milliseconds 
};

//timefmt_e operator & (timefmt_e e1, timefmt_e e2);
//timefmt_e operator | (timefmt_e e1, timefmt_e e2);

template <typename CH> class PrintProxy {
public:
   typedef void (* PrintFunc_t) ( const CH *psz );      
   
   PrintProxy( PrintFunc_t pfn, size_t nChars = DEF_BUF_SIZE ) : _pfn(pfn ), _bufSize(nChars) {}
   PrintProxy(                  size_t nChars = DEF_BUF_SIZE ) : _pfn(NULL), _bufSize(nChars) {}

   typedef STD_STRING(CH) chstring;
  
   void SetPrintFunction( PrintFunc_t pfn ) { _pfn = pfn; }   
   //void SetCycleLengths ( int count = 1, int len = 0 } { _cycleCnt = count; _cycleLen = len; }

   timefmt_e SetTimestamp(bool      b) { return SetTimestamp( b ? TFMT_TIMEONLY : TFMT_NONE ); }
   timefmt_e SetTimestamp(timefmt_e e) { timefmt_e old = _tfmt; _tfmt = e; return old;}

   static void CycleLogFiles( char *filename, int maxCount, int maxLength );
   
   size_t SetPrintBufSize( size_t nChars ) { _bufSize = nChars; }
   
   void EnableConsole(bool b) { _bConOut = b; }

   void printf ( const CH * format, ... ) {
      va_list ap;
      va_start( ap, format );
      _print( _fmtVToStr( format, ap ).c_str() );
      va_end( ap );    
   }
   
   void printfv ( const CH * format, va_list ap ) {
      _print( _fmtVToStr( format, ap ).c_str() );
   }
   
private:
   size_t      _bufSize; 
   timefmt_e   _tfmt;
   PrintFunc_t _pfn;  
   bool        _bConOut;
   
   void _init() {
      _bufSize = DEF_BUF_SIZE;
      _tfmt = TFMT_DATETIME;
      _pfn = NULL;
      _bConOut = false;
   }
   
   void _print(const CH *psz) {
      
      //CycleLogFiles(  );
   
      CH ts[80]; int tsLen = _timestamp(ts);
      if (_pfn) {
         chstring s;
         if (0 < tsLen) { s = chstring(ts); }
         s += chstring(psz);
         _pfn(s.c_str()); 
      }
      if (_bConOut) { _conOut(psz); }
   }
   void _conOut(LPCSTR  psz) {  printf( "%s", psz); }
   void _conOut(LPCWSTR psz) { wprintf(L"%s", psz); }

   std::string _fmtVToStr( const char *format, va_list ap ) {
      std::string s( _bufSize, 0 );
      //int len  = _timestamp( &s[0] );
      //s[len++] = ' ';
      
#ifdef UNDER_CE
      //len += _vsnprintf( &s[len], s.size()-len, format, ap );  
      _vsnprintf( &s[0], s.size(), format, ap );  
#else
      //len +=  vsnprintf( &s[len], s.size()-len, format, ap );  
      vsnprintf(&s[0], s.size(), format, ap);
#endif
      //if (-1 < len) s.resize( (size_t)len );
      return s;
   } 
   
#ifdef _WIN32
   std::wstring _fmtVToStr( const wchar_t *format, va_list ap ) {
      std::wstring s( _bufSize, 0 );
      _vsnwprintf( &s[0], s.size(), format, ap );   // WIN-specific  
      return s;
   }
   
   // Buffer must be large enough for the time/date string.  
   // E.g., "225256.812" or "20140102-225256.812"
   int _timestamp( LPSTR buf ) {
      
      timefmt_e ttype = (timefmt_e)(_tfmt & TFMT_TYPEMASK);
      bool fNoMS = (0 != (_tfmt & TFMT_NOMS));

      if (TFMT_NONE == ttype) { 
         return 0; 
      }

      SYSTEMTIME st; GetLocalTime(&st);
      LPSTR p = buf;
      if (TFMT_DATETIME == ttype) {
         p += sprintf(p, "%4d%02d%02d-", st.wYear, st.wMonth, st.wDay);
      }
      p += sprintf(p, "%02d%02d%02d", st.wHour, st.wMinute, st.wSecond);
      if (!fNoMS) {
         p += sprintf(p, ".%03d", st.wMilliseconds);
      }
      p += sprintf(p, " ");  // add a space at the end
      return (int)strlen(buf);
   }
      
   int _timestamp( LPWSTR wbuf ) {
      char buf[40]; _timestamp(buf);  wcscpy( wbuf, CvtStrW(buf));
      return (int)wcslen( wbuf );
   }
#else
   int _timestamp( std:: string &s ) { return s = "<tstamp-notimpl>" ; }
   //int _timestamp( std::wstring &s ) { return _snwprintf( &s[0], s.capacity(), "<tstamp>" ); }
#endif

};


// ----------------------------------------------------------------------------
// Quicksort - sorts n items in-place in O(n log n) time
//
// Usage: 
//
//   std::vector<elem-type> A;
//   QSort( A );
//
//   elem-type A[size];
//   QSort( A, size );
//
// In both of the above cases, elem-type must define the '<' operator, which 
// is used to establish sort order.
// 
//   std::vector<elem-type> A;
//   QSort<elem-type, Pred>( A );
//
//   elem-type A[size];
//   QSort<elem-type, Pred>( A, size );
//
// In both of the above cases Pred is a function that is used to determine
// sort order (predecessor relationship).  When Pred is provided, the '<'
// operator need not be defined for elem-type.
//
// In all usages, elem-type must define operator '=', which is used to reorder
// the array elements.
//
// ----------------------------------------------------------------------------

template <typename T, bool Pred( T &a, T &b )> class __qsort {

public:
   static void sort( T A[], int size )  {
      srand( GetTickCount() );
      _sort( A, 0, size - 1 );      
   }
   
private:

   // Selects the pivot point (randomized)
   static int  _pivot( const T A[], int l, int r ) {
      return l + (int)(((__int64)rand()) * (r-l) / RAND_MAX);
   }
   
   // Partitioning routine.
   static int  _part ( T A[], int l, int r, int pivot  ) {
      Swap( A[l], A[pivot] );
      T p = A[l];
      int i = l+1;
      for (int j=l+1; j<=r; j++) {
         //if (A[j] < p) {
         if (Pred(A[j], p)) {         
            Swap( A[i], A[j] );
            i++;
         }
      }
      Swap( A[l], A[i-1] );
      return (i-1) ;
   }
   
   // Recursive sort.
   static void _sort ( T A[], int l, int r )  {
      if ((r - l) <= 0) { return; } 
      int pivot = _pivot( A, l, r );
          pivot = _part ( A, l, r, pivot );
      if (l<pivot) _sort( A, l, pivot-1 );
      if (pivot<r) _sort( A, pivot+1, r );         
   }
};


// Default predecessor (numeric less-than)
template <typename T> bool __LT_Pred( T &a, T &b ) { return a < b; }

// No explicit template arguments needed.  T must have "<" defined.
template <typename T> void QSort( std::vector<T> &A ) { __qsort<T,__LT_Pred<T>>::sort( &A[0], A.size() ); }
template <typename T> void QSort( T A[], UINT size  ) { __qsort<T,__LT_Pred<T>>::sort(  A   ,   size   ); }

// Explicit T and Pred template arguments required.
template <typename T, bool Pred( T &a, T &b )> void QSort( std::vector<T> &A ) { __qsort<T,Pred>::sort( &A[0], A.size() ); }
template <typename T, bool Pred( T &a, T &b )> void QSort( T A[], UINT size  ) { __qsort<T,Pred>::sort(  A   ,   size   ); }


// ----------------------------------------------------------------------------
// Heap                                      
//
// -- T defines heap element (may be a structure type)
// -- Pred must return true when a precedes b in the sorting order
// -- Add adds a new element to the heap (increases size by 1)
// -- Pop removes the first element in the sorting order (reduces size by 1)
// -- [i] returns the i'th element in the array (not i'th in sort order)
// -- size returns the current number of elements in the heap
//
// -- all heap operations take O(log n) time
// ----------------------------------------------------------------------------

template <typename T, bool Pred( T &a, T &b )> class Heap {
public:
  Heap() : _A( _aa ) { }
  Heap( std::vector<T> &A ) : _A( A ) { _heapify(); }  

  void Add( T &t ) { _A.push_back( t ); _heapify( _A.size()-1 );  }
  void Pop( T &t ) { _copy( t,_A[0] ); _swap( 0, _A.size()-1 ); _A.pop_back(); _heapify( 0 ); }
//  void Del( UINT i ) { _swap( i, _A.size()-1 );  _A.pop_back(); _heapify( i ); }      
  
  T &operator []( UINT i ){ return _A[i]; }
  UINT size() { return _A.size(); }
  
private:
   std::vector<T> &_A;
   std::vector<T> _aa;   
   
   void _copy( T &dst, T &src ) { memcpy( &dst, &src, sizeof(T) ); }
   void _swap( UINT a, UINT b ) { T t; _copy(t,_A[a]); _copy(_A[a],_A[b]); _copy(_A[b],t); }
   
   UINT _lChild( UINT i ) { return i*2 + 1; }
   UINT _rChild( UINT i ) { return i*2 + 2; }   
   UINT _parent( UINT i ) { return (i-1) / 2; }
   
   UINT _bubbleUp( UINT i ) {
      while ((0 != i) && Pred( _A[i], _A[_parent(i)] )) { 
         _swap( i, _parent(i) );
         i = _parent(i);
      }
      return i;
   } 
     
   UINT _bubbleDn( UINT i ) {
      bool done = false;
      while (!done) {
         UINT l = _lChild( i );
         UINT r = _rChild( i );
         if (  ((l < _A.size()) && Pred( _A[l], _A[i] )) 
            || ((r < _A.size()) && Pred( _A[r], _A[i] )) 
         )  {         
            UINT c = ((r < _A.size()) && Pred( _A[r], _A[l] )) ? r : l ;
            _swap( i, c); 
            i = c;           
         }
         else { done = true; }
      }   
      return i;
   }

   // Assuming the array is a heap, except for the element in the i-th position, 
   // move the element and any other necessary to regain the heap property.
   UINT _heapify( int i ) { return _bubbleDn( _bubbleUp(i) ); }   
   
   // Re-organize all the elements of the array into a heap. 
   // NOTE: Since heapify and qsort both run in n log n time, and a sorted
   //       array is also a heap, why not just use qsort?
   void _heapify() { QSort<T,Pred>( _A ); }      
};


#ifdef _WIN32

// ----------------------------------------------------------------------------
//
// Misc. non-template function prototypes
//
// ----------------------------------------------------------------------------
bool _stdcall IsFixedFont( HFONT hf );

// ----------------------------------------------------------------------------
// Class for converting between char and wchar_t, as in between UTF8 and 
// Unicode. (Uses Windows API conversion routines.)
//
// NOTE: Template argument CH must be either char or wchar_t
// ----------------------------------------------------------------------------
template <typename CH, int CP = CP_UTF8, size_t BUFSZ = 0x1000>  
class CvtStr {
public:
   CvtStr( const  char   *sz              ) { CvtCopy( _s, sz      ); }   
   CvtStr( const  char   *sz , size_t len ) { CvtCopy( _s, sz, len ); }   
   CvtStr( const wchar_t *sz              ) { CvtCopy( _s, sz      ); }
   CvtStr( const wchar_t *sz , size_t len ) { CvtCopy( _s, sz, len ); }
   
   CvtStr( const  char   *fmt, va_list ap ) { FmtCopy( _s, fmt, ap ); }
   CvtStr( const wchar_t *fmt, va_list ap ) { FmtCopy( _s, fmt, ap ); }   

   const CH *     Psz() { return _s.c_str (); }
   size_t         Len() { return _s.length(); }   
   STD_STRING(CH) Str() { return _s         ; }   

   operator const CH *     () { return Psz(); }
   operator STD_STRING(CH) () { return Str(); }   
   
   static const char *CvtCopy( std::string &dst, const wchar_t *src, size_t len = (size_t)-1 ) {
      len = (len != (size_t)-1 ) ? len : wcslen( src );
      dst.resize( len );   
      dst.resize( WideCharToMultiByte( CP, 0, src, (int)len, &dst[0], (int)dst.capacity(), NULL, NULL ));         
      return dst.c_str();   
   } 
   
   static const char *CvtCopy( std::string &dst, const char *src, size_t len = (size_t)-1 ) {
      len = (len != (size_t)-1 ) ? len : strlen( src );
      dst = std::string( src ).substr( 0, len );  // no conversion needed
      return dst.c_str();
   } 
   
   static const wchar_t *CvtCopy( std::wstring &dst, const wchar_t *src, size_t len = (size_t)-1 ) {
      len = (len != (size_t)-1 ) ? len : wcslen( src );
      dst = std::wstring( src ).substr( 0, len );  // no conversion needed
      return dst.c_str();
   } 
   
   static const wchar_t *CvtCopy( std::wstring &dst, const char *src, size_t len = (size_t)-1 ) {
      len = (len != (size_t)-1 ) ? len : strlen( src );
      dst.resize( len );
      dst.resize( MultiByteToWideChar( CP, 0, src, (int)len, &dst[0], (int)dst.capacity()));
      return dst.c_str();   
   }   
   
   static const CH *FmtCopy( STD_STRING(CH) &dst, const char *format, va_list ap ) {
      std::string s( BUFSZ, 0 );
      return CvtCopy( dst, s.c_str(), _vsnprintf( &s[0], s.capacity(), format, ap ));            
   } 
   
   static const CH *FmtCopy( STD_STRING(CH) &dst, const wchar_t *format, va_list ap ) {
      std::wstring s( BUFSZ, 0 );
      return CvtCopy( dst, s.c_str(), _vsnwprintf( &s[0], s.capacity(), format, ap ));      
   }   
   
private: 
   STD_STRING(CH) _s;   
};

typedef CvtStr<char   ,CP_ACP> CvtStrA;     
typedef CvtStr<wchar_t,CP_UTF8> CvtStrW;

#ifdef _TCHAR_DEFINED
typedef CvtStr<TCHAR>   CvtStrT;
#endif

#endif // _WIN32

// Interface required by class CritSection
class _critsect_usable {
public:
   virtual bool Acquire() = 0;
   virtual void Release() = 0;
};

// ----------------------------------------------------------------------------
class Mux : public _critsect_usable {
public:
   Mux()             { _h = CreateMutex (NULL, FALSE, NULL); }
   Mux(LPCSTR  Name) { _h = CreateMutexA(NULL, FALSE, Name); }
   Mux(LPCWSTR Name) { _h = CreateMutexW(NULL, FALSE, Name); }

   ~Mux() { Release(); CloseHandle(_h); }

   bool Acquire(DWORD msTimeout) {
      return WAIT_OBJECT_0 == WaitForSingleObject(_h, msTimeout);
   }

   // _critsect_usable
   virtual bool Acquire() { return WAIT_OBJECT_0 == WaitForSingleObject(_h, INFINITE); }
   virtual void Release() { ReleaseMutex(_h); }

private:
   HANDLE _h;
};

// Like Mux but uses a Windows critical section object, a light-weight mutex
// that cannot be named or used cross-process but which is more efficient than
// a Mutex.
class MuxLite : public _critsect_usable  {
public:
       MuxLite() { InitializeCriticalSection(&_cs); }
      ~MuxLite() {     DeleteCriticalSection(&_cs); }

      bool TryEnter() { return !!TryEnterCriticalSection(&_cs); }

  // _critsect_usable     
  void Release() {      LeaveCriticalSection(&_cs); }
  bool Acquire() {      EnterCriticalSection(&_cs); return true; }


private:
   CRITICAL_SECTION _cs;
};

// Acquires a Mux or MuxLite for the entire scope of the object.
// NOTE: MUX is intended for use with only Mux and MuxLite classes.
//template <typename MUX> class CritSection {
class CriticalSection {
public:
   typedef _critsect_usable mux_t;

   CriticalSection(mux_t &mux) : _mux(mux) { _mux.Acquire(); _bAcquired = true; }
   void Release()                          { _mux.Release(); _bAcquired = false; }

   ~CriticalSection() { Release(); }

   // Don't allow default construction.
   CriticalSection() : _mux(*(mux_t*)0) { assert(false); }

private:
   mux_t &_mux;
   bool   _bAcquired;
};


// ----------------------------------------------------------------------------
// Library-specific control class
// ----------------------------------------------------------------------------

class jhbCommon {
public:
   static PrintProxy<char> _pp;      
};

#endif // __COMMON_H__
