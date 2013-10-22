// ======================================================================================
// 
// jbh-console.cpp
//
//   Command Line Interface Application Framework 
//   Class member definitions 
//
//   This is implemented for Windows.
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

#include <windows.h>

#include "jhbConsole.h"

#include <list>
#include <string>
//#include <tchar.h>
#include <time.h>

#pragma warning(disable:4996)

// Set up a PrintProxy to the console output (stdout.)
static void Print( const char *psz ) { printf( "%s", psz ); }
static PrintProxy<char> _PP( Print );

// ============================================================================ 
// Built-in command handlers
// ============================================================================ 

cli::Error_e CLI_Exit ( std::vector<tstring> args, cli::Param_t param ) {
   cli &Cli = *(cli *)param;
   Cli.Exit( true );
   return cli::ERR_NOERROR;
}

cli::Error_e CLI_Echo ( std::vector<tstring> args, cli::Param_t param ) {
   tstring sEcho = (1 < args.size()) ? args[1] : _T("0") ;
   bool    bEcho = 0 != _tcstoul( sEcho.c_str(), 0, 0 );
   
   cli &Cli = *(cli *)param;
   Cli.Echo( bEcho );
   
   _PP.printf( "Command echoing is now %sabled.\n", bEcho ? "en" : "dis" );
   
   return cli::ERR_NOERROR;
}

cli::Error_e CLI_Load ( std::vector<tstring> args, cli::Param_t param ) {

   tstring sFile = (1 <= args.size()) ? args[1] : NULL ;
   if (sFile.empty()) {
      _PP.printf( "***ERROR: You must provide a command file name.\n" );
      return cli::ERR_MISSINGARG;      
   }
   
   FILE *f = _tfopen( sFile.c_str(), _T("rt") );
   if (NULL == f) {
      _PP.printf( "***ERROR: Failed trying to open file.\n" );
      return cli::ERR_INVALIDARG;         
   }
   
   cli &Cli = *(cli *)param;
   
   static char szLine[0x400];
   *szLine = '\0';
   while (fgets( szLine, NELEM(szLine)-1, f )) {
      if (Cli.IsEcho()) { _PP.printf( ">%s", szLine ); }
      Cli.Exec( CvtStrT ( szLine ));
   } 
   
   return cli::ERR_NOERROR;
}

cli::Error_e CLI_Comment ( std::vector<tstring> args, cli::Param_t param ) {
   return cli::ERR_COMMENT;
}

// Prints some generally useful information about the system:
cli::Error_e CLI_Info ( std::vector<tstring> args, cli::Param_t param ) {

   time_t tt; time( &tt );
   printf( "Time: %s", asctime( localtime( &tt )));   // includes \n
   
   TCHAR dir[MAX_PATH];
   GetCurrentDirectory( NELEM(dir), dir );
   printf( "Current directory: %S\n", dir );
   
   // -- operating system and version

   return cli::ERR_NOERROR;
}



// Prototype only: can't define it here because it references the 
// built-in command table, which is defined below.
cli::Error_e CLI_Help ( std::vector<tstring> args, cli::Param_t param ) ;

// ============================================================================ 
// Built-in command table.
// ============================================================================ 

static cli::CmdSpec_t cliBuiltIns[] = 
//  Name   | Func      | Desc1, Args, Desc2, Param 
{{ _T("x" ), CLI_Exit   , _T("Exits the program.") }
,{ _T("//"), CLI_Comment, _T("Starts a non-echoing comment line. (For command files.)" ) 
                        }
,{ _T("?" ), CLI_Help   , _T("Lists all commands or provides help for a given command.")
                        , _T("<1> - A command name. (Optional.)") 
                        }
,{ _T("$l"), CLI_Load   , _T("Load commands from a text file.")
                        , _T("<1> - File name.")                                        
                        }                 
,{ _T("$e"), CLI_Echo   , _T("Enables or disables command echoing.  (For command files.)")
                        , _T("<1> - 0*(disable) or 1(enable).  [DEF:0]")                                        
                        }                                        
,{ _T("$i"), CLI_Info   , _T("Information.)")
                        }  
};

// ----------------------------------------------------------------------------
// Lists all commands or prints help for a given command.
// ----------------------------------------------------------------------------
cli::Error_e CLI_Help ( std::vector<tstring> args, cli::Param_t param ) {
   cli &Cli = *(cli *)param;
   
   if (args.size() < 2) {
      
      // List application commands followed by built-in commands.
      Cli.PrintCommandList( "Commands:" );
      Cli.PrintCommandList( "---", cliBuiltIns, NELEM( cliBuiltIns ) ); 
   }
   
   else {
      if (!Cli.PrintCommandHelp( args[1].c_str() ))  {
         return cli::ERR_CMDUNKNOWN ;
      }   
   }
   return cli::ERR_NOERROR;
}

// ============================================================================ 
// Other cli class member definitions
// ============================================================================ 

// ----------------------------------------------------------------------------
void cli::SetPrintRoutine( PrintFunc_t lpfn ) {
   _PP.SetPrintFunction( lpfn );
}


// Macro for STL string type based on a given char type (A).  
#define STRING_T(A) std::basic_string<A, std::char_traits<A>, std::allocator<A> >  


// ----------------------------------------------------------------------------
// Helps in the task of parsing fields by whitespace while respecting quoted
// string containing whitespace.  Upon return there will be no quotes and all
// quoted fields will have no spaces.  After parsing by whitespace use Respace
// to restore the spaces in the parsed fields.
// 
// Replaces:
// - spaces within quotes with a special character.
// - quotes with spaces
//
// NOTE: These functions do not change the length of the passed-in string.
// ----------------------------------------------------------------------------
const char _cUnquoteChar = '\x7f';

template <typename CH> STRING_T(CH) Unquote( STRING_T(CH) &s ) {
   bool bInQuotes = false;
   for (UINT i=0; i<s.size(); i++) {   
      CH &c = s[i];
      if ('"' == c) { 
         bInQuotes = !bInQuotes; 
         c = ' ';  
      } 
      else if (bInQuotes && (' ' == c)) { 
         c = _cUnquoteChar; 
      }
   }
   return s;   
}

template <typename CH> STRING_T(CH) Respace( STRING_T(CH) &s ) {
   for (UINT i=0; i<s.size(); i++) {   
      if (_cUnquoteChar == s[i]) { s[i] = ' '; }
   }
   return s;
}

template <typename CH>
size_t ParseArgs( const CH *szLine, std::vector<STRING_T(CH)> &args ) {

   args.clear();
   
   STRING_T(CH) line( szLine );   
   Unquote( line );   
   
   size_t pos = 0;
   while (pos < line.size()-1) {

      static CH whsp[] = { ' ', '\t', '\n', '\r' } ;      
   
      size_t sub = line.find_first_not_of( whsp, pos );  
      if (-1 == sub) break;
      
      pos = line.find_first_of( whsp, sub );
      if (-1 == pos) pos = line.size()-1;

      args.push_back( Respace( line.substr( sub, pos - sub ) ));      
   }
   return (size_t)args.size();
}

cli::Error_e cli::Exec( const TCHAR *szLine ) {
  
   // Parse the string as whitespace delimited fields respecting double quotes.
   // NOTE: If no arguments, nothing to execute. (Arg[0] is command name) 
   std::vector<tstring> args;
   if (0 == ParseArgs( szLine, args )) {
      return ERR_NOCMDLINE;
   }
   
   // Save the value of these before executing the command. (They could change.)
   return exec( args );   
}   

cli::Error_e cli::Exec( int argc, TCHAR *argv[] ) {
   std::vector<tstring> args;
   for(int i=0; i<argc; i++) { 
      args.push_back( argv[i] ); 
   }
   return exec( args );      
}

cli::Error_e cli::exec( const std::vector<tstring> &args ) {   
       
   // First look in application-defined command table.
   size_t i; for (i=0; i<_cmdTableSize; i++) {
      if (0 == args[0].compare( _cmdTable[i].Name )) {
         CmdSpec_t &cmd = _cmdTable[i];
         return cmd.Func( args, cmd.Param );
      }
   }
   
   // If we didn't find a match, look in the built-in table.
   for (i=0; i<NELEM(cliBuiltIns); i++) {   
      if (0 == args[0].compare( cliBuiltIns[i].Name )) {
         CmdSpec_t &cmd = cliBuiltIns[i];
         return cmd.Func( args, (Param_t)this );
      }
   }   
   
   // If we are still here, we couldn't match the command name.
   return ERR_CMDUNKNOWN;
}

int cli::Main( int argc, TCHAR* argv[] )  { 

   // If there is an initial command, execute it and exit.
   if (1 < argc) {  
      Exec( argc - 1, &argv[1] );  
      return 0;       
   }
   
   // Start the internal command line.
   static TCHAR szLine[ 0x1000 ];
   while (!_bExit) {
   
      printf( ">" );
   
      *szLine = 0;
      _fgetts( szLine, NELEM( szLine ), stdin );
   
      Error_e err = Exec( szLine );
      switch (err) {
         case ERR_CMDUNKNOWN: printf( "***ERROR: Unknown command.\n" ); break;
         default: break;
      }
   }  

   return 0; 
}   

// ----------------------------------------------------------------------------
// Sort the table by command name, then print each entry on a separate line 
// containing command name and description.
// ----------------------------------------------------------------------------
void cli::PrintCommandList( char *pszHeadLine, cli::CmdSpec_t *cmdTable, size_t len ) {

   // Default is to print the internal command table
   if (!cmdTable) {
      cmdTable = _cmdTable     ;
      len      = _cmdTableSize ;
   }
   
   // Start with the headline:
   printf ("%s\n", pszHeadLine );
   
   // Create an STL list object from the cmdTable and sort it.
   std::list<CmdSpec_t *> sorted;
   size_t i; for(i=0; i<len; i++) {
      sorted.push_back( &cmdTable[i] );
   }
   sorted.sort( compareCmdSpec );
  
   std::list<CmdSpec_t *>::iterator it;
   for(it=sorted.begin(); it!=sorted.end(); it++) { 
      _tprintf( _T("%s\t%s\n"), (*it)->Name.c_str(), (*it)->Desc1.c_str() );
   }
}

bool cli::PrintCommandHelp( const TCHAR *Name ) {

   CmdSpec_t *pCS = NULL;
   
   // Look for the command in the application table.
   size_t i; for (i=0; i<_cmdTableSize; i++) {
      if (0 ==  _cmdTable[i].Name.compare( Name )) {
         pCS = &_cmdTable[i];
         break; 
      }
   }
   
   // If not found, look for it in the built-ins table. 
   if (!pCS) {
      for (i=0; i<NELEM(cliBuiltIns); i++) {
         if (0 ==  cliBuiltIns[i].Name.compare( Name )) {
            pCS = &cliBuiltIns[i];
            break; 
         }
      }   
   }
   
   // If still not found return false.
   if (!pCS) return false;
   
   // Print the command help.
//   _tprintf( _T("COMMAND: %s\n"), pCS->Name.c_str() ); 
   if (!pCS->Desc1.empty()) _tprintf( _T("%s\n"), pCS->Desc1.c_str() );
   if (!pCS->Args .empty()) _tprintf( _T("ARGS:\n%s\n"), pCS->Args .c_str() );      
   if (!pCS->Desc2.empty()) _tprintf( _T("NOTES:\n%s\n"), pCS->Desc2.c_str() );      
//   printf( "\n" );    
   
   return true;
}