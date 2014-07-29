// ----------------------------------------------------------------------------
//
//  jhb_keystore.h
//
//    Declares an abstract base class for an object that stores values under a
//    hierarchy of keys based on the semantics of the Windows registry.
//
//    This is used by the library provide cross-platform support for a 
//    registry-like facility.
//
// ----------------------------------------------------------------------------

#ifndef _JHB_KEYSTORE_
#define _JHB_KEYSTORE_

#ifndef UNDER_CE
#include <unordered_set>
#include <unordered_map>
#endif  UNDER_CE

#include <sstream>

#include "jhbCommon.h"

// ----------------------------------------------------------------------------
//
//  KK  KK                SSSS                        
//  KK KK                SS  SS  tt                   
//  KKKK                 SS      tt                   
//  KKK      eeee  yy yy SS      ttt  oooo  rrr  eeee 
//  KKK     ee  ee yy yy  SSSS   tt  oo  oo rr  ee  ee
//  KKKK    eeeeee yy yy     SS  tt  oo  oo rr  eeeeee
//  KK KK   ee     yy yy     SS  tt  oo  oo rr  ee    
//  KK  KK  ee  ee  yyy  SS  SS  tt  oo  oo rr  ee  ee
//  KK   KK  eeee   yy    SSSS    tt  oooo  rr   eeee 
//                  yy                                
//                yyy                                 
//
// ----------------------------------------------------------------------------
// Abstract base class for RegKey and ValKey classes.
//
// ----------------------------------------------------------------------------
// Types:
//   CH - the string chracter type for the key and value names, and the string 
//        data type.  (Only 'char' and 'wchar_t' should be used.)
// ----------------------------------------------------------------------------

template <typename CHAR, typename HROOT> class KeyStore {
public:
   typedef CHAR  _ch_t;
   typedef const _ch_t *_pch_t;
   typedef STD_STRING(_ch_t) _str_t;

   KeyStore() { _init(); } 
   
   // -----------------------------------------------------------------
   // Pure virtuals       
   // -----------------------------------------------------------------
   
public:   
   virtual bool Open( HROOT root, _pch_t keyPath, bool bWrite = false ) = 0;
   virtual bool Close () = 0;
   virtual bool IsNull() = 0;
   
protected:   
   virtual bool _setVal( _pch_t name, DWORD regType, BYTE *data, size_t  size ) = 0;
   virtual bool _setVal( _pch_t name, LPCSTR  p, size_t maxlen ) = 0;
   virtual bool _setVal( _pch_t name, LPCWSTR p, size_t maxlen ) = 0;          
   
   template <typename T> bool _setVal( _pch_t name, const T &v, DWORD regType ) {
      return _setVal( name, regType, (LPBYTE)&v, sizeof v );       
   } 
   template <typename T> bool _setVal( _pch_t name, const T &v ) {
      return _setVal( name, v, (sizeof(T) == sizeof(DWORD)) ? REG_DWORD : REG_BINARY );
   }       
   
   virtual bool _getVal( _pch_t name, BYTE *data, size_t &size  ) = 0;   
   virtual bool _getVal( _pch_t name, char    *p, size_t maxlen ) = 0;
   virtual bool _getVal( _pch_t name, wchar_t *p, size_t maxlen ) = 0;       
   
   virtual int _valLength( _pch_t valName ) = 0;
   
   virtual bool _getSubKeys( std::vector<_str_t> &sk ) = 0;
   
   virtual bool _delSubKey( _pch_t name ) = 0;
      
   // -----------------------------------------------------------------   
   // Fully-defined methods 
   // -----------------------------------------------------------------   
   
public:

   operator bool() { return !IsNull(); }   
   LONG LastErr()  { return _lasterr; }

   // ----------------
   // Set
   // ----------------   
   
   // -- scalars
   bool SetVal( _pch_t name, int   v ) { return _setVal( name, v, REG_DWORD  ); }   
   bool SetVal( _pch_t name, UINT  v ) { return _setVal( name, v, REG_DWORD  ); }                         
   bool SetVal( _pch_t name, DWORD v ) { return _setVal( name, v, REG_DWORD  ); }
   
   template <typename T> bool SetVal( _pch_t name, T &v ) { return _setVal( name, v ); }
   
   // -- arrays
   template <typename T> bool SetVal( _pch_t name, const T *v, size_t count ) { 
      DWORD cbData = (DWORD)(count * sizeof *v) ;       
      return _setVal( name, REG_BINARY, (LPBYTE)&v[0], cbData );
   }

   // Calculates the size of the buffer (in chars) needed to hold the given 
   // zero-termianted string, including the zero terminator.  If the needed
   // buffer size (in chars) is greater than maxlen, returns maxlen.
   template <typename CHAR> size_t _szLenMax( const CHAR *v, size_t maxlen ) {
      const CHAR *c = v;
      for (size_t i=0; i<maxlen; i++) {
         if (0 == *c++) return i+1;
      } 
      return maxlen;
   }
   
   // -- strings
   bool SetVal( _pch_t name, LPCSTR  v                ) { return _setVal( name, v, strlen(v) + 1 ); }  
   bool SetVal( _pch_t name, LPCSTR  v, size_t maxlen ) { return _setVal( name, v, _szLenMax(v,maxlen)); }     
   
   bool SetVal( _pch_t name, LPCWSTR v                ) { return _setVal( name, v, wcslen(v) + 1 ); } 
   bool SetVal( _pch_t name, LPCWSTR v, size_t maxlen ) { return _setVal( name, v, _szLenMax(v,maxlen)); }   

   template <typename T> 
   bool SetVal(_pch_t name, STD_STRING(T) s) { return _setVal(name, s.c_str(), s.size() + 1); }
      
   // ----------------      
   // Get   
   // ----------------   
   
   // -- scalars
   template <typename T> bool GetVal( _pch_t name, T &v) { 
      size_t size = sizeof v;
      return _getVal( name, (LPBYTE)&v, size );      
   }    

   // -- strings (auto-sized)
   template <typename T> bool GetVal(_pch_t name, STD_STRING(T) &s) {

      // Get the length of the value's data.
      size_t size = 0;
      if (_getVal(name, (BYTE*)0, size)) {
         s.resize(size / sizeof(s[0]));
         return _getVal(name, &s[0], size);
      }
      return false;
   }

   // -- arrays (read into an auto-sizing vector)
   template <typename T> bool GetVal( _pch_t name, std::vector<T> &v ) { 
      
      // Get the length of the value's data.
      size_t size = 0;
      if (_getVal( name, 0, size )) {      
         v.resize( size / sizeof(T) ); 
         return _getVal( name, &v[0], size );
      }
      return false;
   }   
   
   // -- arrays (read into a fixed length array)
   template <typename T> bool GetVal( _pch_t name, T *p, size_t count ) { 
      count *= sizeof *p;
      return _getVal( name, (BYTE*)p, count );
   }
  
   
   // ----------------
   // Get-Set Wrappers
   // ----------------   
   //   Allow the use of a single series of statements for both reading and writing
   //   a series of registry values under one key.  (Avoids troublesome duplication.) 
   
   // scalars (w and w/o default value)
   template <typename T> bool gsVal( bool b, _pch_t name, T &v ) { return b ? SetVal( name, v ) : GetVal( name, v ); }      
   
   // arrays
   template <typename T> bool gsVal( bool b, _pch_t name, T *v, size_t maxlen ) {
      return b ? SetVal( name, v, maxlen )
               : GetVal( name, v, maxlen );
   }
   
   // Strings (zero-terminated) 
   bool gsVal( bool b, _pch_t name, char  *psz, size_t maxlen ) { return b ? SetVal( name, psz, maxlen ) : _getVal( name, psz, maxlen ); }         
   bool gsVal( bool b, _pch_t name, WCHAR *psz, size_t maxlen ) { return b ? SetVal( name, psz, maxlen ) : _getVal( name, psz, maxlen ); }            
   
   
   // ----------------      
   // Other
   // ----------------      
   
   // Returns the length in bytes of a value.
   virtual int  Length( _pch_t valName ) { return _valLength( valName ); }
   
   // Returns all names of all sub keys of the given key.
   virtual bool GetSubKeys( std::vector<_str_t> &sk ) { return _getSubKeys( sk ); }
   
   // Returns all names of all values under the given key.
   //virtual bool GetValues( std::vector<_str_t>  &sk ) { return _getValues ( sk ); }   
   
   // DelSubKey : deletes the named subkey and its values (fails if that key has subkeys)
   virtual bool DelSubKey( _pch_t keyname ) { return _delSubKey( keyname ); } 

   
protected:
   LONG _lasterr;
   void _init() { _lasterr = 0; }
   
   size_t _ch_size() { return sizeof(_ch_t); }   
};

#ifndef UNDER_CE

// ----------------------------------------------------------------------------
//
//  KK  KK               TTTTTT                   
//  KK KK                  TT                     
//  KKKK                   TT                     
//  KKK      eeee  yy yy   TT    rrr  eeee   eeee 
//  KKK     ee  ee yy yy   TT    rr  ee  ee ee  ee
//  KKKK    eeeeee yy yy   TT    rr  eeeeee eeeeee
//  KK KK   ee     yy yy   TT    rr  ee     ee    
//  KK  KK  ee  ee  yyy    TT    rr  ee  ee ee  ee
//  KK   KK  eeee   yy     TT    rr   eeee   eeee 
//                  yy                            
//                yyy                             
//
// ----------------------------------------------------------------------------
//
// Stores meta-information about values stored under a hierarchy of keys:
// -- what keys are sub-keys of other keys
// -- what values belong to what keys.
//
// ----------------------------------------------------------------------------

// Helper class for KeyTree: 
// --  a simple wrapper around the standard C library file handle.
class File {
public:
   File() { _f = 0; }
  ~File() { if (_f) { fclose( _f ); _f = 0; }}

   operator FILE* () { return _f; }
   operator bool  () { return _f != 0; }
   
   File & operator =(FILE *f) { _f = f; return *this; }

   FILE *_f;
};

// Strings may be based on either char or wchar_t.  
// -- all strings follow this choice.  There is no built-in conversion.

template <typename CHAR = char> class KeyTree {
public: 

   typedef CHAR _ch_t;
   typedef const _ch_t *_pch_t;   
   typedef STD_STRING(_ch_t) _str_t;

   // Caller can add multiple levels of keys in one call by specifying a path string
   // that separates key names with backslashes.
   int AddKey( _str_t keyPath ) {

      int nAdded = 0;   
      
      _str_t s = keyPath;
      while ((0 < s.size()) && (0 == _MAP.count( s ))) { 
      
         _val_t v; 
         _MAP[s] = v;
         nAdded++;
         
         size_t pos = s.rfind( _del );
         if (_str_t::npos == pos) { pos = 0; }
         s.erase( pos, s.size() );
      }
      
      // Every added key also must get added as a child of its parent key.
      s = keyPath;
      for (int i=0; i<nAdded; i++) {
         _str_t branch, leaf;
         if (!_splitpath( s, branch, leaf )) break;
         _MAP.find( branch )->second.children.insert( leaf );
         s = branch;
      }
      
      return nAdded;
   }      
   
   bool AddValue( _str_t keyPath, _str_t valName ) {
     AddKey( keyPath );
      _MAP[ keyPath ].values.insert( valName );
      return true;
   }   
   
   bool EnumSubkeys( _str_t keyPath, std::vector<_str_t> &subkeys ) {
      _map_t::const_iterator itKey = _MAP.find(_str_t(keyPath));
      if (itKey == _MAP.end()) {
         return false;
      }
      subkeys.clear();      
      const _strset_t &set = itKey->second.children;
      for (_strset_t::const_iterator it=set.begin(); it!=set.end(); it++) {
         subkeys.push_back( *it );
      }
      return true;
   }
   
   bool EnumValues( _str_t keyPath, std::vector<_str_t> &subkeys ) {
      typename _map_t::const_iterator itKey = _MAP.find(_str_t(keyPath));
      if (itKey == _MAP.end()) {
         return false;
      }
      subkeys.clear();
      const _strset_t &set = itKey->second.values;
      for (_strset_t::const_iterator it=set.begin(); it!=set.end(); it++) {
         subkeys.push_back( *it );
      }
      return true;   
   } 

   bool DeleteKey( _str_t keyPath ) {
      _map_t::const_iterator itKey = _MAP.find(_str_t(keyPath));
      if (itKey == _MAP.end()) {  // key not found
         return false;
      }
      if (0 < itKey->second.children.size()) {  // key has subkeys
         return false;   
      }
      _MAP.erase( itKey );
      return true;
   }
   
   static bool    SplitPath( _str_t path, _str_t &branch, _str_t &leaf ) { return _splitpath( path, branch, leaf ); }               
   static _str_t BuildPath(               _str_t  branch, _str_t  leaf ) { return _buildpath(       branch, leaf ); }               
   
   bool IsKey( LPCSTR keyPath ) { return _is( keyPath ); }
   
   void clear() { _MAP.clear(); }

private:

   static const _ch_t _del = '\\'; 
   
   typedef std::tr1::unordered_set<_str_t> _strset_t;
   struct _val_t {
      _strset_t children;      
      _strset_t values;
   };   
   
   typedef _str_t _name_t;   
   
   typedef std::tr1::unordered_map<_name_t,_val_t> _map_t;   
   _map_t _MAP;
   
   bool _is( _pch_t keyPath ) {
      _str_t s = keyPath;
      return 0 < _MAP.count( s );
   } 

   // Plucks the last backslash-delimited field off of path and puts it in leaf.
   // Puts the prefix string (sans the backslash) into branch.
   //
   // Returns: true if the path could be split (a delimiter was found)
   //          false indicates that leaf = path.
   //
   static bool _splitpath( const _str_t path, _str_t &branch, _str_t &leaf ) {
      size_t pos = path.rfind( _del ); 
      if (_str_t::npos == pos) { // top-level key
         branch.clear();
         leaf   = path;
      } else {
         branch = path.substr(0,pos);
         leaf   = path.substr(pos+1,_str_t::npos);
      } 
      return 0 < branch.size();
   }

   // Concatenates a root path and a leaf into a single path (reverse of _splitpath)
   static _str_t _buildpath( const _str_t branch, const _str_t leaf ) {
      return branch + _del + leaf;
   }
};

// ----------------------------------------------------------------------------
//
// VV    VV        ll  SSSS                        
// VV    VV        ll SS  SS  tt                   
//  VV  VV         ll SS      tt                   
//  VV  VV   aaaa  ll SS      ttt  oooo  rrr  eeee 
//  VV  VV      aa ll  SSSS   tt  oo  oo rr  ee  ee
//   VVVV    aaaaa ll     SS  tt  oo  oo rr  eeeeee
//   VVVV   aa  aa ll     SS  tt  oo  oo rr  ee    
//    VV    aa  aa ll SS  SS  tt  oo  oo rr  ee  ee
//    VV     aaaaa ll  SSSS    tt  oooo  rr   eeee 
//
// ----------------------------------------------------------------------------
//
// Provides storage of the typed data of named values in a hash table. 
//
// NOTES:
// -- the template CHAR type determine the string type of value names and of 
//    the REG_SZ data type.  Caller must observe this string type in all calls. 
//    There is no provision for automatic conversion between UTF-8 and Unicode.
//
template <typename CHAR> class ValStore {
public:
   typedef CHAR       _ch_t;
   typedef _ch_t    *_pch_t;   
   typedef STD_STRING(_ch_t)        _str_t;
   typedef STD_STRINGSTREAM(_ch_t) _sstr_t;  
   
   typedef _str_t name_t;
   
   // NOTE: These must match the values used by the Windows registry API
   typedef enum { 
      RT_NUL =  0, // REG_NONE
      RT_BIN =  3, // REG_BINARY 
      RT_U4  =  4, // REG_DWORD
      RT_U8  = 11, // REG_QWORD
      RT_SZ  =  1, // REG_SZ (UTF-8)
                   // REG_MULTI_SZ=7)
   } type_t;   
   
   void SetVal( name_t name, type_t type, PCBYTE pby, size_t size ) { 
       _setVal( name, type, pby, size ); 
   }         
   void SetVal( name_t name, PCBYTE  pby, size_t size ) { _setVal( name, RT_BIN, pby, size ); }   
   void SetVal( name_t name, UINT    val )              { _setVal( name, RT_U4 , (PBYTE)&val, sizeof val ); }   
   void SetVal( name_t name, __int64 val )              { _setVal( name, RT_U8 , (PBYTE)&val, sizeof val ); }    
   void SetVal( name_t name, _pch_t  psz ) { 
      _str_t s( psz );
      _setVal( name, RT_SZ , (PBYTE)psz , (s.size()+1) * _ch_size()); 
   }
   
   bool GetVal( name_t name, MemBuf &val ) { 
      size_t size = 0; return _getVal( name, 0, 0, &size )
      ? (val.alloc( size ), _getVal( name, 0, val, 0 ))
      : false;
   }
   bool GetVal( name_t name, UINT    &val ) { return _getVal( name, 0, (PBYTE)&val, 0 ); }
   bool GetVal( name_t name, __int64 &val ) { return _getVal( name, 0, (PBYTE)&val, 0 ); }  
   bool GetVal( name_t name, _str_t  &val ) { 
      size_t size = 0; 
      if (_getVal( name, 0, 0, &size )) {
         if (0 < size) {
            val.resize( size / _ch_size() );
            return _getVal( name, 0, (PBYTE)&val[0], 0 );
         }
         else {
            val.clear();
            return true;
         }   
      }   
      return false;      
   }
   
   bool DeleteVal( name_t name ) { 
      return IsValue( name )
             ? (_MAP.erase( name ), true)
             : false ;
   }

   bool     IsValue( name_t name ) { return _getVal( name, 0, 0, 0 ); }   
   type_t   GetType( name_t name ) { type_t type; return _getVal( name, &type, 0, 0 ) ? type : RT_NUL ; }
   int      GetSize( name_t name ) { size_t size; return _getVal( name, 0, 0, &size ) ? (int)size : -1; }   

   bool Serialize  ( name_t file ) { return _serialize  ( file ); }
   bool Deserialize( name_t file ) { return _deserialize( file ); }

   bool BuildKeyTree( KeyTree<_ch_t> &KT ) {
      KT.clear();
      for (_map_t::const_iterator it = _MAP.begin(); it != _MAP.end(); it++ ) {
         KeyTree<_ch_t>::_str_t keyPath, valName;
         KT.SplitPath( it->first, keyPath, valName );
         KT.AddValue( keyPath, valName );      
      }  
      return true; 
   }
   
   static char *typeLabel( type_t t ) {
      return (RT_NUL == t) ? "RT_NUL" :             
             (RT_BIN == t) ? "RT_BIN" :                
             (RT_U4  == t) ? "RT_U4"  :                
             (RT_U8  == t) ? "RT_U8"  :                
             (RT_SZ  == t) ? "RT_SZ"  : "RT_???" ;
   }   
   
   typedef void (*_dbgOut)(const _ch_t *sz);
   void Dump( _dbgOut pfn ) {
   
      for (_map_t::const_iterator it = _MAP.begin(); it != _MAP.end(); it++ ) {   
         const _val_t &v = it->second;
         _sstr_t ss;
         ss << it->first << " (type=" << typeLabel(v.type) << ", size=" << v.data.size() << "): ";
         
         switch (it->second.type) {
            case RT_NUL: 
            case RT_BIN:
            {  std::string buf;
               ss << FmtHex( buf, (PBYTE)&v.data[0], (UINT)v.data.size(), ' ' );
            }  break;
            
            case RT_U4 : ss << *(DWORD  *)&v.data[0]; break;
            case RT_U8 : ss << *(__int64*)&v.data[0]; break;
            case RT_SZ : ss << std::string((char *)&v.data[0],v.data.size()).c_str(); break;
         }         
         ss << "\n";
         pfn( ss.str().c_str() );
      }
   }
   
   void clear() { _MAP.clear(); }
   
private:
   
   size_t _ch_size() { return sizeof(_ch_t); }
   
   typedef struct { 
      type_t            type; 
      std::vector<BYTE> data; 
   }  _val_t;   
   
   typedef std::tr1::unordered_map<name_t,_val_t> _map_t;
   _map_t _MAP;
   
   void _setVal( name_t name, type_t type, PCBYTE pdata, size_t size ) {
      _val_t v; 
      v.type = type; 
      if (0 < size) { v.data.resize(size); memcpy( &v.data[0], pdata, size ); }
         else       { v.data.clear();                                         }
      _MAP[name] = v;      
   }

   bool _getVal( name_t name, type_t *ptype, BYTE *pdata, size_t *psize ) {

      _map_t::const_iterator it = _MAP.find(name);
      if (it == _MAP.end()) {
         return false;
      }
      _val_t v = it->second;
      
      if (ptype) { *ptype = v.type       ; }
      if (psize) { *psize = v.data.size(); } 
      if (pdata && (0 < v.data.size())) { 
         memcpy( pdata, &v.data[0], v.data.size()); 
      }
      
      return true;
   }   
   
   // -------------------------------------------------------------------------
   //
   // A serialized ValStore stream consists of one header structure followed
   // by N value record strucuture. (There's no need for a TLV structure because
   // after the header all structures are of the same type.) 
   // 
   // Notes:
   // -- The variable-length fields can be padded to a given packing size, up 
   //    to 4. (Packing 0 and 1 are effectively no packing.)
   //
   
   #define _PACK 0
   #define _VER  0   
   
   // Header 
   struct _hdr_t {
      UINT magic[2];
      BYTE version;
      BYTE packing;
      WORD reserved;
      UINT flags;
      
      _hdr_t() {
         static const char szMagic[] = "WDQAPI00";   
         memcpy( (void *)magic, (void*)szMagic, sizeof magic );
         version  = _VER ;
         packing  = _PACK;
         reserved = 0;
         flags    = 0;
      } 
   };

   // Record structure:
   //
   //    UINT      - name length
   //    variable  - name as a string of name-length UTF-8 characters
   //    filler    - 0 to 3 bytes of filler
   //    type_t    - value type
   //    UINT      - value size in bytes 
   //    variable  - value as an array of bytes
   //    filler    - 0 to 3 bytes of filler   
   //
   // -------------------------------------------------------------------------

   //void _wpack( UINT len, UINT pack, File & f ) { 
   //   if (pack < 2 ) return; 
   //   BYTE filler[4]={0}; 
   //   fwrite( filler, 1, (pack - len%pack) % pack, f ); 
   //}   
   //void _rpack( UINT len, UINT pack, File & f ) { 
   //   if (pack < 2 ) return; 
   //   BYTE filler[4];     
   //   fread ( filler, 1, (pack - len% pack) %  pack, f ); 
   //}
 
   // These handle reading or writing bytes to meet the packing spec.
   void _pack( bool Write, size_t len, size_t pack, File & f ) { 
      if (pack < 2 ) return; 
      BYTE filler[4]={0}; 
      Write ? fwrite( filler, 1, (pack - len % pack) % pack, f )
            : fread ( filler, 1, (pack - len % pack) % pack, f ); 
   }      
   void _wpack( size_t len, size_t pack, File & f ) { _pack( true , len, pack, f ); }
   void _rpack( size_t len, size_t pack, File & f ) { _pack( false, len, pack, f ); }
   
   // Writes a formatted file based on the content of the ValStore.
   bool _serialize( name_t file ) { 

      File f; f = (1 == _ch_size()) 
                  ?   fopen( (const  char   *)file.c_str(),  "wb" ) 
                  : _wfopen( (const wchar_t *)file.c_str(), L"wb" ) ;
                                           
      if (!f) return false;
      
      _hdr_t hdr;
      fwrite( &hdr, 1, sizeof hdr, f );
      
      for (_map_t::const_iterator it = _MAP.begin(); it != _MAP.end(); it++ ) {
      
         name_t name = it->first;
         _val_t val  = it->second;
         
         UINT len = (UINT)name.size();
         fwrite( &len        , 1, sizeof len      , f );      
         fwrite( name.c_str(), 1, len * _ch_size(), f );
         _wpack( len * _ch_size(), _PACK          , f );
         
         len = (UINT)val.data.size();
         fwrite( &val.type   , 1, sizeof val.type, f );
         fwrite( &len        , 1, sizeof len     , f ); 
         if (0 < len) {              
            fwrite( &val.data[0], 1, len         , f );                        
         }   
         _wpack( len, _PACK                      , f );         
      }
      
      return true;
   }

   // Populates an object from a serialized ValStore file.
   bool _deserialize( name_t file ) { 

      File f; f = (1 == _ch_size()) 
                  ? fopen  ( (const  char   *)file.c_str(),  "rb" ) 
                  : _wfopen( (const wchar_t *)file.c_str(), L"rb" ) ;
                                                 
      if (!f) return false;
      
      _MAP.clear();
      
      _hdr_t hdr;
      fread( &hdr, 1, sizeof hdr, f );
      
      _hdr_t hRef;
      if (0 != memcmp( _hdr_t().magic, hdr.magic, sizeof hdr.magic )) {
         return false; // invalid file format
      }
      
      while (!feof(f)) {  // NOTE: false at end if no read past the end has been attempted
      
         _str_t name;
         UINT len = 0;
         
         fread( &len        , 1, sizeof len      , f ); 
         if (feof(f)) break;
         
         name.resize( len );    
         fread( &name[0]    , 1, len * _ch_size(), f );
         _rpack( len * _ch_size(), hdr.packing   , f );  
                                  
         _val_t  val;
         fread( &val.type   , 1, sizeof val.type , f );
         fread( &len        , 1, sizeof len      , f ); 
         if (0 < len) {
            val.data.resize( len ); 
            fread( &val.data[0], 1, len          , f );                        
         }   
         _rpack( len, hdr.packing                , f );                  
         
         _MAP[name] = val;         
      }
      
      return true; 
   }      
};

#endif  UNDER_CE



#endif // _JHB_KEYSTORE_
