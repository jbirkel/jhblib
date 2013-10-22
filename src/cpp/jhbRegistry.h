// ======================================================================================
// 
// jhbRegistry.h
//
//   -- RegKey: a class wrapper around the Windows Registry API
//   -- ValKey: a RegKey-compatible implementatino that uses a file for storage 
//              instead of the Windows registry.  
//
// The two classes are intended to provide cross-platform registry-like functionality.
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
//   2013-04 Refactored RegKey into KeyStore and _regKey.
//           Created _valKey from KeyStore, KeyTree and ValStore
//   2013-01 Broke RegKey out of jhbCommon.h
//
// ======================================================================================

#ifndef JHB_REGISTRY_H
#define JHB_REGISTRY_H

#include "jhb_keystore.h"

// external logging function
extern void _logf ( char * format, ... );

//#ifdef _TCHAR_DEFINED
//typedef CvtStr<TCHAR>   CvtStrT;
//#endif

#ifdef _WIN32

// ----------------------------------------------------------------------------
//
//  RRRRRR                 KK  KK              
//  RR   RR                KK KK               
//  RR   RR                KKKK                
//  RR   RR   eeee   ggggg KKK      eeee  yy yy
//  RRRRRR   ee  ee gg  gg KKK     ee  ee yy yy
//  RR   RR  eeeeee gg  gg KKKK    eeeeee yy yy
//  RR   RR  ee     gg  gg KK KK   ee     yy yy
//  RR   RR  ee  ee gg  gg KK  KK  ee  ee  yyy 
//  RR   RR   eeee   ggggg KK   KK  eeee   yy  
//                      gg                 yy  
//                  ggggg                yyy   
//
// ----------------------------------------------------------------------------
//
// RegKey - Encapsulates a Windows registry key.
//
// ----------------------------------------------------------------------------
// NOTE: Since this is a Windows-only class there's no reason not to implement
//       it in Unicode only.  (Windows registry strings are always stored as
//       Unicode and Windows has full support for Unicode strings.)
//

//class _regKey: public KeyStore<wchar_t,HKEY> {
class _regKey: public KeyStore<TCHAR,HKEY> {
public:

   _regKey( HKEY root, _pch_t keyPath, bool bWrite = false ) { _init(); _open( root, keyPath, bWrite );                   }
   _regKey(                                                ) { _init();                                                   }        
  ~_regKey() { _close(); }
       
   operator HKEY() { return _hkey    ; }
       
   virtual bool Open  ( HKEY root, _pch_t keyPath, bool bWrite = false ) { _open( root, keyPath, bWrite ); return !IsNull(); }   
   virtual bool Close () { return _close(); }

   virtual bool IsNull() { return (NULL == _hkey); }
  
   // ----------------   
   // STATIC FUNCTIONS
   // ----------------   
   
   static bool IsKey( PCWSTR keyPath, HKEY root = HKEY_LOCAL_MACHINE ) { 
      HKEY h = 0; 
      RegOpenKeyExW( root, keyPath, 0, KEY_READ, &h );
      return (ERROR_SUCCESS == _close( h ));       
   }
  
private:
    
   HKEY _hkey;
   
   void _init() { _hkey = 0; }

   static  LONG _close( HKEY h ) { return RegCloseKey( h ); }   

   virtual bool _close( void   ) { 
      if (_hkey) { 
         _lasterr = _close( _hkey );  
         _hkey = 0; 
         return (ERROR_SUCCESS == _lasterr);
      }
      return true;
   } 
   
   virtual void _open( HKEY root, _pch_t keyPath, bool bWrite ) { 
      _close();
      _lasterr = bWrite ? RegCreateKeyEx( root, keyPath, 0, 0, 0, KEY_READ | KEY_WRITE, 0, &_hkey, 0 )   
                        : RegOpenKeyEx  ( root, keyPath, 0      , KEY_READ            ,    &_hkey    );
      if (ERROR_SUCCESS != _lasterr) {
         _logf( "jhblib: ***ERROR: %s returned %d\n", bWrite ? "RegCreateKeyEx" : "RegOpenKeyEx", _lasterr );
      }
   }   
   
   virtual bool _setVal( _pch_t name, DWORD regType, BYTE *data, size_t size ) {
      return ERROR_SUCCESS == (_lasterr = RegSetValueEx( _hkey, name, 0, regType, data, (DWORD)size ));       
   }
   
   virtual bool _setVal( _pch_t name, LPCSTR p, size_t maxlen ) {
      DWORD cbData = (DWORD)(min((strlen(p)+1), maxlen) * sizeof(wchar_t));
      return _setVal( name, REG_SZ, (LPBYTE)CvtStrW(p).Psz(), cbData );   
   }
   
   virtual bool _setVal( _pch_t name, LPCWSTR p, size_t maxlen ) {
      DWORD cbData = (DWORD)(min( (wcslen(p)+1), maxlen) * sizeof(wchar_t));
      return _setVal( name, REG_SZ, (LPBYTE)p, cbData );
   }
      
   virtual bool _getVal( _pch_t name, BYTE *data, size_t &size ) {
      DWORD dw = (DWORD)size;     
      bool bRet = (ERROR_SUCCESS == (_lasterr = RegQueryValueEx( _hkey, name, 0, 0, data, &dw )));   
      size = dw;
      return bRet;
   }   
   
   virtual bool _getVal( _pch_t name, wchar_t *p, size_t maxlen ) { 
      size_t cbData = maxlen * sizeof(*p) ;
      return _getVal( name, (LPBYTE)p, cbData );  
   }          
   
   virtual bool _getVal( _pch_t name, char    *p, size_t maxlen ) {
      std::wstring buf( maxlen+1, 0 ) ;
      DWORD cbData = (DWORD)(2 * maxlen);  // WCHAR strings takes twice as many bytes as chars
      _lasterr = RegQueryValueEx( _hkey, name, 0, 0, (LPBYTE)&buf[0], &cbData );
      if (ERROR_SUCCESS == _lasterr) {
         strncpy_s( p, maxlen,  CvtStrA( buf.c_str() ), maxlen ); 
         return true;
     }
     return false;   
   }
   
   virtual int _valLength( _pch_t valName ) {
      DWORD cb = 0;
      _lasterr = RegQueryValueEx( _hkey, valName, 0, 0, 0, &cb );
      return (ERROR_SUCCESS == _lasterr) ? cb : -1;
   }
   
   virtual bool _getSubKeys( std::vector<_str_t> &sk ) {   
      _ch_t buf[256];  // Max key name length is 255.
      DWORD i=0, dw, lret;
      while (ERROR_SUCCESS == (lret = RegEnumKeyEx( _hkey, i++, buf, &(dw=NELEM(buf)), 0, 0, 0, 0 ))) {
         sk.push_back( buf );
      }
      return (ERROR_NO_MORE_ITEMS == lret);
   }
   
   virtual bool _delSubKey( _pch_t name ) {    
      _lasterr = RegDeleteKey( _hkey, name );
      return (ERROR_SUCCESS == _lasterr);
   }
};

#define HKLM HKEY_LOCAL_MACHINE
#define HKCR HKEY_CURRENT_USER

typedef _regKey RegKey;

class RegKeyHKLM : public _regKey { RegKeyHKLM( _pch_t keyPath, bool bWrite = false ) : _regKey( HKLM, keyPath, bWrite ) {} };
class RegKeyHKCR : public _regKey { RegKeyHKCR( _pch_t keyPath, bool bWrite = false ) : _regKey( HKCR, keyPath, bWrite ) {} };

#endif // _WIN32


#ifndef UNDER_CE

// ----------------------------------------------------------------------------
//
// VV    VV        ll KK  KK              
// VV    VV        ll KK KK               
//  VV  VV         ll KKKK                
//  VV  VV   aaaa  ll KKK      eeee  yy yy
//  VV  VV      aa ll KKK     ee  ee yy yy
//   VVVV    aaaaa ll KKKK    eeeeee yy yy
//   VVVV   aa  aa ll KK KK   ee     yy yy
//    VV    aa  aa ll KK  KK  ee  ee  yyy 
//    VV     aaaaa ll KK   KK  eeee   yy  
//                                    yy  
//                                  yyy   
//
// ----------------------------------------------------------------------------

template <typename CHAR> class _valKey: public KeyStore<CHAR,STD_STRING(CHAR)> {
friend _valKey;
public:

   typedef STD_STRING(_ch_t) file_t;  // must match KeyStore template param #2
   
   typedef CvtStr<CHAR,CP_UTF8> _CvtCh;   
   
   class __vkdata {
   public:
      ValStore<_ch_t> VS;
      KeyTree <_ch_t> KT;
      file_t  hive;   // _valKey "hives" are files
      int refCount;  
      __vkdata() : refCount(1) {}
   };

   _valKey( _valKey &vkey, _pch_t keyPath, bool bWrite = false ) { _init(); _open( vkey, keyPath, bWrite ); }
   _valKey( file_t  hive, _pch_t keyPath, bool bWrite = false ) { _init(); _open( hive, keyPath, bWrite ); }
   _valKey(                                                   ) { _init();                                 }
   
  ~_valKey() { _close(); }
       
   operator file_t() { return _d->hive ; }
       
   virtual bool Open  ( _valKey &vkey, _pch_t keyPath, bool bWrite = false ) { _open( vkey, keyPath, bWrite ); return !IsNull(); }          
   virtual bool Open  ( file_t  hive, _pch_t keyPath, bool bWrite = false ) { _open( hive, keyPath, bWrite ); return !IsNull(); }   
   
   virtual bool Close () { return _close(); }

   virtual bool IsNull() { return NULL == _d; }
   
   _str_t Name() { return _key; }   

   bool GetValues( std::vector<_str_t> &sk ) { return _d->KT.EnumValues( _key, sk ); }        
  
   // ----------------   
   // STATIC FUNCTIONS
   // ----------------   
   
   static bool IsKey( LPCSTR keyPath, file_t root ) {
      _valKey vk( root, keyPath, false );
      return vk._d->KT.IsKey( keyPath );
   }
  
private:
    
   __vkdata *_d;  
   
   _str_t _key;   
   bool   _write;
   
   void _init() { 
      _d = NULL;
      _key.clear(); 
      _write = false;
   }
   
   bool _flush( void ) {    
      return !_write || _d->VS.Serialize( _d->hive );      
   }   
   
   bool _close( void ) { 
      if (_d) { 
         if (!_flush()) {      
            // return false;
         }
         _d->refCount--;         
         if (_d->refCount < 1) {
            delete _d;
         }
         _init();
      }
      return true;
   } 
   
   void _open( _valKey &vkey, _pch_t keyPath, bool bWrite ) {    
      _close();   
   
      _d = vkey._d;
      _d->refCount++;
      
      _key   = vkey._rel( keyPath );      
      _write = bWrite;                     
   }
   
   void _open( file_t hive, _pch_t keyPath, bool bWrite ) { 
      _close();
      
      _d = new __vkdata();
      if ((_d->VS.Deserialize( hive ) && _d->VS.BuildKeyTree( _d->KT )) || bWrite) {
         _d->hive  = hive;
         _key   = keyPath;      
         _write = bWrite;
      }   
   }   
   
   _str_t _rel( _str_t name ) { return _d->KT.BuildPath( _key, name ); }
   
   virtual bool _setVal( _pch_t name, DWORD type, BYTE *data, size_t size ) {
      _d->KT.AddValue( _key, name ); 
      _d->VS.SetVal( _rel(name), (ValStore<_ch_t>::type_t)type, data, size );      
      _lasterr = 0;
      return true;
   }

   virtual bool _setVal( _pch_t name, LPCSTR p, size_t maxlen ) {
      std::string s( p, maxlen );
      return _setVal( name, REG_SZ, (PBYTE)_CvtCh(s.c_str()).Psz(), s.size() * _ch_size() );
   }
   
   virtual bool _setVal( _pch_t name, LPCWSTR p, size_t maxlen ) {
      std::wstring s( p, maxlen );   
      return _setVal( name, REG_SZ, (PBYTE)_CvtCh(s.c_str()).Psz(), s.size() * _ch_size() );
   }
   // NOTE:
   // -- How does CvtStrA handle expansion in string size due to UTF-8 requiring
   //    multiple bytes to represent non-ANSI characters?
   //    (I'm thinking it doesn't.)
   //

   virtual bool _getVal( _pch_t name, PBYTE data, size_t &size ) {
      MemBuf mb;
      if (!_d->VS.GetVal( _rel( name ), mb )) {
         return false;
      }   
      size = mb.size();
      if (data) {
         memcpy( data, mb, mb.size() );            
      }
      return true;
   }   
   
   virtual bool _getVal( _pch_t name, char *p, size_t maxlen ) {
      int len = _valLength( name ); 
      if (-1 == len) { 
         return false; 
      }
      _str_t s; s.resize( len ); size_t size = len; 
      if (!_getVal( name, (PBYTE)&s[0], size )) { 
         return false; 
      }   
      strncpy( p, CvtStrA(s.c_str()), maxlen );          
      return true;      
   }
   
#ifdef _WIN32   
   virtual bool _getVal( _pch_t name, wchar_t *p, size_t maxlen ) { 
      std::string s; s.resize( maxlen ); if (!_getVal( name, &s[0], maxlen )) { return false; }     
      wcsncpy( p, CvtStrW( s.c_str() ), maxlen );    
      return true;
   }         
#else
   virtual bool _getVal( _pch_t name, wchar_t *p, size_t maxlen ) { 
      return false;
   }
#endif
   
   virtual int _valLength( _pch_t name ) {
      size_t size = 0; return _getVal( name, (PBYTE)0, size ) ? (int)size : -1 ; 
   }
   
   virtual bool _getSubKeys( std::vector<_str_t> &sk ) {  
      return _d->KT.EnumSubkeys( _key.c_str(), sk );
   }
   
   virtual bool _delSubKey( _pch_t name ) {
      _str_t subkey = _rel( name );
      std::vector<_str_t> values; 
      if (!_d->KT.EnumValues( subkey, values )) { return false; } // key not found
      if (!_d->KT.DeleteKey ( subkey         )) { return false; } // key has subkeys
      
      // Delete all values of the given subkey
      for (size_t i=0; i<values.size(); i++) {
         _str_t valpath = _d->KT.BuildPath( subkey, values[i] );      
         _d->VS.DeleteVal( valpath );         
      }
      return true;      
   }
};

typedef _valKey<char>    ValKeyA;
typedef _valKey<wchar_t> ValKeyW;

#ifndef _WIN32
#define REGKEY_FILEA
typedef _valKey<char>    RegKey;
#endif

#endif UNDER_CE

#endif // _JHB_REGISTRY_
