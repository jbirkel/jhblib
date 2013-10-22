// jhc.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#include "jhbCommon.h"
#include "jhbKrypto.h"
#include "jhbConsole.h"
#include "jhbRegistry.h"

cli::Error_e cmdTest( CLIARGS args, cli::Param_t prm) {

   printf( "cmac_TEST returned  : %s\n", (cmac_TEST()   ? "PASS" : "FAIL" ));
   printf( "hmac_TEST returned  : %s\n", (hmac_TEST()   ? "PASS" : "FAIL" ));
//   printf( "PBKDF2_TEST returned: %s\n", (PBKDF2_TEST() ? "PASS" : "FAIL" ));
//   printf( "WPAPSK_TEST returned: %s\n", (WPAPSK_TEST() ? "PASS" : "FAIL" ));   

   return cli::ERR_NOERROR;         
}

cli::Error_e cmdSha1( CLIARGS args, cli::Param_t prm) {

   tstring tsText = args[1];
   if (0 == tsText.length()) { 
      printf( "***ERROR: You must enter a text string." );
      return cli::ERR_MISSINGARG;
   }
      
   CvtStrA sText( tsText.c_str() );   
   MemBuf sOut( SHA1_LEN );
   sha1( (BYTE*)sText.Psz(), (int)sText.Len(), sOut );
   
   std::string s;
   printf( "%s\n", FmtHex( s, sOut, sOut.size() ));
   
   return cli::ERR_NOERROR;         
}

cli::Error_e cmdHmac( CLIARGS args, cli::Param_t prm) {

   tstring tsText = args[1];
   tstring tsKey  = args[2];   
   if ((0 == tsText.length()) || (0 == tsKey.length())) { 
      printf( "***ERROR: You must enter text and key strings." );
      return cli::ERR_MISSINGARG;
   }
      
   CvtStrA sText( tsText.c_str() );   
   CvtStrA sKey ( tsKey .c_str() );      
   MemBuf sOut( SHA1_LEN );
   hmac_sha1( sText, sKey, sOut );
   
   std::string s;
   printf( "%s\n", FmtHex( s, sOut, sOut.size() ));
   
   return cli::ERR_NOERROR;         
}

cli::Error_e cmdRHash( CLIARGS args, cli::Param_t prm) {
 
   ValStore<char> VS;

   MemBuf mb; 
   std::string s;
   UINT uint4 = 0; 
   __int64 uint8 = 0; 
   
   char bindata[] = "ABCDEFGHIJKLM" ;
   VS.SetVal( "binary", (PBYTE)bindata, strlen(bindata) );
   VS.SetVal( "uint4" , (UINT)12345678    );   
   VS.SetVal( "uint8" , (__int64)12345678901234L );
   VS.SetVal( "string", "Hello World!" );
   
   VS.GetVal( "binary", mb    ); printf( "binary = %s\n", FmtHex( s, mb, mb.size() ));
   VS.GetVal( "uint4" , uint4 ); printf( "uint4  = %u\n", uint4 );
   VS.GetVal( "uint8" , uint8 ); printf( "uint8  = %I64u\n", uint8 );   
   VS.GetVal( "string", s     ); printf( "string = %s\n", s.c_str() );      
   
   VS.Serialize  ( "valStore000" );
   VS.Deserialize( "valStore000" );   
   
   VS.GetVal( "binary", mb    ); printf( "binary = %s\n", FmtHex( s, mb, mb.size() ));
   VS.GetVal( "uint4" , uint4 ); printf( "uint4  = %u\n", uint4 );
   VS.GetVal( "uint8" , uint8 ); printf( "uint8  = %I64u\n", uint8 );   
   VS.GetVal( "string", s     ); printf( "string = %s\n", s.c_str() );   

   return cli::ERR_NOERROR;         
}

#include <iostream>

template <typename CHAR> void DumpKey( KeyTree<CHAR> &KT, LPCSTR keyPath ) {

   std::vector<STD_STRING(CHAR)> ss;
   char *label = NULL;
   
   KT.EnumSubkeys( keyPath, ss ); label = "subkeys" ; 
   std::cout << keyPath << " " << label << ": ";
   for (size_t i=0; i<ss.size(); i++) { std::cout << ss[i] << " "; } 
   std::cout << "\n";   
   
   KT.EnumValues ( keyPath, ss ); label = "values"  ;  
   std::cout << keyPath << " " << label << ": ";
   for (size_t i=0; i<ss.size(); i++) { std::cout << ss[i] << " "; }
   std::cout << "\n";      
}

cli::Error_e cmdKTree( CLIARGS args, cli::Param_t prm) {
 
   KeyTree<char> KT;

   KT.AddKey( "root\\middle\\leaf" );
   KT.AddValue( "root", "rval" );
   
   KT.AddValue( "root\\middle", "mval" );   
   KT.AddValue( "root\\middle\\leaf", "lval" );      
   KT.AddValue( "root\\middle\\leaf", "lval2" );  

   DumpKey( KT, "root" );
   DumpKey( KT, "root\\middle" );
   DumpKey( KT, "root\\middle\\leaf" );
   
   return cli::ERR_NOERROR;         
}

cli::Error_e cmdPanReg( CLIARGS args, cli::Param_t prm) {
 
   ValStore<char> VS;
   VS.SetVal( "root\\mid1\\mid2\\mid3\\leaf" , 12345678u );         
   VS.SetVal( "root\\mid1\\mid2\\mid3\\leaf1", 22345678u );      
   VS.SetVal( "root\\mid1\\mid2\\mid3\\leaf2", 32345678u );         
   
   VS.SetVal( "root\\mid1\\mid2\\mid3a\\leaf" , 12345678u );         
   VS.SetVal( "root\\mid1\\mid2\\mid3a\\leaf1", 22345678u );      
   VS.SetVal( "root\\mid1\\mid2\\mid3a\\leaf2", 32345678u );            
   
   VS.SetVal( "root\\mid1\\mid2a\\leaf" , 12345678u );         
   VS.SetVal( "root\\mid1\\mid2a\\leaf1", 22345678u );      
   VS.SetVal( "root\\mid1\\mid2a\\leaf2", 32345678u );            
   
   VS.SetVal( "root\\mid1\\leaf" , 12345678u );                  
   VS.SetVal( "root\\mid1\\leaf1", 22345678u );                  
   VS.SetVal( "root\\mid1\\leaf2", 32345678u );               
   
   VS.SetVal( "root\\leaf" , 12345678u );                  
   VS.SetVal( "root\\leaf1", 22345678u );                  
   VS.SetVal( "root\\leaf2", 32345678u );                  

   VS.Serialize  ( "valStoreReg" );
   VS.Deserialize( "valStoreReg" );      
      
   KeyTree<char> KT;
   VS.BuildKeyTree( KT );

   DumpKey( KT, "root" );
   DumpKey( KT, "root\\mid1" );   
   DumpKey( KT, "root\\mid1\\mid2a" );   
   DumpKey( KT, "root\\mid1\\mid2" );   
   DumpKey( KT, "root\\mid1\\mid2\\mid3" );
  
   
   return cli::ERR_NOERROR;         
}


// ----------------------------------------------------------------------------
// REGSVR32 functionality:
// ----------------------------------------------------------------------------

cli::Error_e cmdRegDll( CLIARGS args, cli::Param_t prm) {

   LPCTSTR pszDll = (1 < args.size()) ? args[1].c_str() : NULL    ;
   LPCTSTR pszOp  = (2 < args.size()) ? args[2].c_str() : _T("r") ;
   
   if (!pszDll) { 
      printf( "***ERROR: You must enter the name (full path) of a DLL.\n" );
      return cli::ERR_MISSINGARG;
   } 
   
   bool bReg = (pszOp[0] == 'r') || (pszOp[0] == 'R');
   
   SetLastError(0);
   
   HMODULE hmod = LoadLibrary( pszDll );
   if (0 == hmod) {
      DWORD gle = GetLastError();
      printf( "LoadLibrary( %S ) failed, gle = 0x%X (%d)\n", pszDll, gle, gle );
      return cli::ERR_GENERAL;
   }
   
   typedef HRESULT ( __stdcall * DllRegisterServer_t )(void);   
   LPCTSTR szFn = bReg ? _T("DllRegisterServer") :  _T("DllUnregisterServer") ;
   DllRegisterServer_t pfn = (DllRegisterServer_t)GetProcAddress( hmod, CvtStrA(szFn) );
   if (0 == pfn) {
      DWORD gle = GetLastError();
      printf( "GetProcAddress( %S ) failed, gle = 0x%X (%d)\n", szFn, gle, gle );
      return cli::ERR_GENERAL;
   }   
   //ERROR_SUCCESS
   HRESULT hres = pfn();
   DWORD gle = GetLastError();
   printf( "%S returned %d (gle = 0x%X (%d))\n", szFn, hres, gle, gle );
   return cli::ERR_GENERAL;
}


class abby {
public:
   virtual void b(int) { return; }
   virtual void b(int,int) { return; }   
   virtual void b(int,int,int) { return; }      
};

class road : public abby {
public:
   virtual void b() { return; }   
} ;

void abbyRoadTest () {
   road a;
   a.b();
   //a.b(1);      // error
   //a.b(1,2);    // error
   //a.b(1,2,3);  // error
}   

cli::Error_e cmdRegKey( CLIARGS args, cli::Param_t prm) {

   #ifdef REGKEY_FILEA
   RegKey r( L"HKEY_CURRENT_USER", L"Software\\wi-daq\\jhb", true );   
   #else
   RegKey r( HKEY_CURRENT_USER, _T("Software\\wi-daq\\jhb"), true );
   #endif
   
   r.SetVal( _T("String1"),  _T("Helloo"), 100 );
   
   DWORD dw = 0;
   r.GetVal( _T("Dword1"), dw );
   
   return cli::ERR_GENERAL;
}


void DumpKey( ValKeyA &vk ) {

   std::vector<std::string> sk;
   std::string name = vk.Name();
   
   printf( "%s: ", name.c_str() );
   printf( "|Subkeys: " );   
   sk.clear();
   if (vk.GetSubKeys( sk )) {
      for (size_t i=0; i<sk.size(); i++) {
         printf( "%s ", sk[i].c_str() );   
      }   
   }
   printf( "|Values: " );
   sk.clear();   
   if (vk.GetValues( sk )) {
      for (size_t i=0; i<sk.size(); i++) {
         printf( "%s ", sk[i].c_str() );   
      }   
   }
   printf("\n");
}

void ConOut ( const char    *sz ) { printf( "%s", sz ); }
void ConOutW( const wchar_t *sz ) { printf( "%S", sz ); }

cli::Error_e cmdValKey( CLIARGS args, cli::Param_t prm) {

   typedef ValKeyA ValKey;

   {  ValKey r( "jhcValKeyRoot", "k1", true );
      r.SetVal( "String1", "Helloo"   );
      r.SetVal( "Dword1" , 1111  );  

      {  ValKey r2( r, "k2", true );
         r2.SetVal( "String2", "Helloo22" );   
         r2.SetVal( "Dword2" , 2222 );      
         r2.SetVal( "Dword3" , 3333 );      
   
         {  ValKey r3( r2, "k3", true );   
            r3.SetVal( "Dword4" , 4444 );         
            DumpKey( r3 );   
         }   
   
         ValKey r4( r, "k4" );
         r4.SetVal( "Dword5", 5555 );         
         
         DumpKey( r2 );   
         DumpKey( r4 );
      }
      r.SetVal( "Dword6" , 6666 );        
      DumpKey( r );
   }   
         
   
//   char sz[100]; memset( sz, 0, sizeof sz );
//   r.GetVal( "String1"    , sz, 100 ); printf( "String1: %s\n", sz );   
//   r.GetVal( "k2\\String2", sz, 100 ); printf( "String2: %s\n", sz );
//   
//   DWORD dw = 0;
//   r.GetVal( "k3\\Dword1"    , dw ); printf( "Dword1: %u\n", dw );   
//   r.GetVal( "k4\\Dword2"    , dw ); printf( "Dword2: %u\n", dw );   
//   r.GetVal( "k4\\k5\\Dword3", dw ); printf( "Dword3: %u\n", dw );
   
   printf("\n");   
   
   printf("\n");   
   ValStore<char> VS;
   VS.Deserialize( "jhcValKeyRoot" );
   VS.Dump( ConOut );
   
   return cli::ERR_GENERAL;
}


cli::Error_e cmdVKDump( CLIARGS args, cli::Param_t prm) {

   if (args.size() < 2) {
      printf( "***ERROR: You must enter a file name.\n" );
      return cli::ERR_MISSINGARG; 
   }
   
   STD_STRING(TCHAR) filename = args[1];

   ValStore<TCHAR> vs;
   vs.Deserialize( filename );
   vs.Dump( ConOut );   
   
   return cli::ERR_NOERROR; 
}


cli::Error_e cmdZTest( CLIARGS args, cli::Param_t prm) {
//   std::vector<BYTE> d;  d.resize(0); memcpy( &d[0],(void*)0, 0 );   // <------- error

   char *sz = "12345678";  
   std::string s(sz,20);
   printf( "s.size() = %u\n", s.size() );
   return cli::ERR_GENERAL;
}


// ============================================================================ 
// Command table.
// ============================================================================ 

cli::CmdSpec_t cliCommands[] = 
{{ _T("test"), cmdTest , _T("Test jhbKrypto algorithms")
                       }                        
,{ _T("sha1"), cmdSha1 , _T("Hashes the given string using SHA-1")
                       , _T("<1> - string\n")
                       }  
,{ _T("hmac"), cmdHmac , _T("Calculate the SHA-1 HMAC of the given text and key")
                       , _T("<1> - text\n")
                         _T("<2> - key\n")                      
                       }
,{ _T("rht"), cmdRHash , _T("Runs tests on the registry hash object.") }
,{ _T("ktt"), cmdKTree , _T("Runs tests on the key tree object.") }
,{ _T("prt"), cmdPanReg, _T("Runs tests on the PanReg object.") }

,{ _T("rkt"), cmdRegKey, _T("Runs tests on a Windows registry object (RegKey).") }
,{ _T("vkt"), cmdValKey, _T("Runs tests on a generic registry object (ValKey).") }
,{ _T("vkd"), cmdVKDump, _T("Dump a ValKey file.")
                       , _T("<1> - file name and path\n")
                       }


,{ _T("rgs"), cmdRegDll, _T("Registers or Unregisters a DLL. (Respect bitness.)") 
                       , _T("<1> - name (full path) of DLL\n")
                       , _T("<2> - *r (register) or u (unregister)\n")
                       }
,{ _T("z")  , cmdZTest, _T("Arbitrary test code.") }                       
};

// ============================================================================ 
// Main
// ============================================================================ 

void _log( const char *sz ) { printf( "%s", sz ); }

int _tmain(int argc, _TCHAR* argv[])
{
   // Print a banner.
   printf( "JHC -- jhbCommon console utility\n" );
   
   // Init jhbCommon logging.
   PrintProxy<char> pp( _log );
   jhbCommon::_pp = pp;
   
   // Create the CLI command object and pass it control.
   int ret = cli( cliCommands, NELEM(cliCommands)).Main( argc, argv );
   
   return ret;
}