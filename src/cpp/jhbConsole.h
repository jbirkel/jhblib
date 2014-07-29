// ======================================================================================
// 
// jhbConsole.h
//
//   Application Framework for console mode programs that want an internal 
//   command line and allow only one command per line.
//
//   Command table strings are TCHARs.
//   -- For non-Windows builds, provide a TCHAR typedef to either char or wchar_t
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

#ifndef __JHB_CONSOLE_H__
#define __JHB_CONSOLE_H__

#include <assert.h>
#include <vector>
#include <string>
#include "jhbCommon.h"

// char/wchar_t template functions
template <typename CHARTYPE> 
bool IsWhitespace( const CHARTYPE c ) {
   const CHARTYPE Whitespace[] = { ' ', '\n', '\r', '\t' };   
   int i; for(i=0; i<NELEM(Whitespace); i++) {      
      if (c == Whitespace[i]) return true;
   }
   return false;
}

// Shortcut for command handler 'args' argument data type.
#define CLIARGS std::vector<tstring> 

// Command Line Interface (CLI) Application Framework.
// -- Based on TCHAR macro.  TCHAR must be defined as char or wchar_t.  

class cli {
public:

   enum Error_e
   { ERR_STAYRESIDENT =  2  // Not an error. Special value used by $r command.
   , ERR_COMMENT      =  1   // Comment line encountered.  Ignored, but not an error.   
   , ERR_NOERROR      =  0   // Success
   , ERR_NOCMDLINE    = -1   // Inputted command line was blank.
   , ERR_CMDUNKNOWN   = -2   // Arg 0 of command line did not match any known command name.
   , ERR_MISSINGARG   = -3   // Required argument not present.
   , ERR_INVALIDARG   = -4   // Provided argument led to an error.
   , ERR_GENERAL      = -5   // Unspecified error.
   , ERR_MEMORY       = -6   // Memory allocation error.      
   , ERR_INTERNAL     = -7   // Internal error.      
   , ERR_LIBRARY      = -8   // A call to an external library failed.
   , ERR_READFAIL     = -9   // Read operation failed.   
   , ERR_WRITEFAIL    = -10  // Write operation failed.
   , ERR_OPENFAIL     = -11  // Open operation failed.   
   , ERR_LOCKFAIL     = -12  // Attempt to acquire or lock a resource failed.
   } ;

   typedef void *Param_t;

   // All command handlers must use this prototype.
   typedef Error_e (*Func_t) ( std::vector<tstring> args, Param_t param );
    
   // CMDSPEC 
   typedef struct cmdspec {
      tstring Name  ;  // Command name as the user types it
      Func_t  Func  ;  // The function that executes this command
      tstring Desc1 ;  // A short (one-line) description of the command. 
      tstring Args  ;  // An optional string describing the command arguments. 
      tstring Desc2 ;  // An optional string providing more description.       
      Param_t Param ;  // Optional extra value to be passed to the function.
      
      // Inits and returns a reference to a CMDSPEC structure.            
      cmdspec &init( TCHAR *name, Func_t func, TCHAR *args = NULL, TCHAR  *desc1 = NULL, Param_t param = 0, TCHAR  *desc2 = NULL ) {
                     Name = name; Func = func; Args = args       ; Desc1 = desc1       ; Param = param    ; Desc2 = desc2        ; 
         return *this;               
      }
   }  
   CmdSpec_t;
   
   // Construction requires a command table.
   cli( CmdSpec_t *CmdTable, size_t Size ) 
      : _cmdTable( CmdTable )
      , _cmdTableSize( Size )
      , _bExit(false)      
      , _bEcho(false)
      , _pfnPrint(NULL)
   {  }
  
   Error_e Exec( const TCHAR *szLine );
   Error_e Exec( int argc, TCHAR *argv[] );
   int     Main( int argc, TCHAR* argv[] );
   
   void PrintCommandList( char *pszTitle, cli::CmdSpec_t *cmdTable = NULL, size_t len = 0 );
   bool PrintCommandHelp( const TCHAR *Name );   
   
   void Exit( bool b ) { _bExit = b; }    bool IsExit() { return _bExit; }    
   void Echo( bool b ) { _bEcho = b; }    bool IsEcho() { return _bEcho; }    
   
   typedef void (* PrintFunc_t) ( const char *psz );
   void SetPrintRoutine( PrintFunc_t lpfn );
   
private:
   CmdSpec_t *_cmdTable     ;
   size_t     _cmdTableSize ;

   bool _bExit, _bEcho;   
   
   PrintFunc_t _pfnPrint;

   // STL list::sort compare function for CmdSpec_t sorting. 
   static bool compareCmdSpec( cli::CmdSpec_t *p1, cli::CmdSpec_t *p2 ) {
     return (p1->Name.compare( p2->Name ) < 0) ; 
   }
   
   // Internal command exec.  Takes a tstring vector. 
   Error_e exec( const std::vector<tstring> &args );
   
      
   // No default construction
   cli() { assert(0); }
   
};


#endif // __JHB_CONSOLE_H__