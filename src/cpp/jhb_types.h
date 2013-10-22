// ======================================================================================
// 
// types.h
//
//   Fundamental types.  (Intended for cross-platform compatibility.)
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
//   2013-01    Created
//
// ======================================================================================


#ifndef __JHB_TYPES_H__
#define __JHB_TYPES_H__

// Basic Windows types that may not be defined on other platforms ---
#ifndef _WINDOWS_ 
typedef void *       PVOID;
typedef unsigned char BYTE;
typedef BYTE *       PBYTE;
typedef unsigned int  UINT;
typedef const char * LPCSTR;
#endif _WINDOWS_


typedef const PBYTE PCBYTE;

// STL strings library
#ifdef _STRING_

   // Convenience macro for a roll-your-own STL string type. 
   #define STD_STRING(CH)       std::basic_string      <CH, std::char_traits<CH>,std::allocator<CH> >
   #define STD_STRINGSTREAM(CH) std::basic_stringstream<CH, std::char_traits<CH>,std::allocator<CH> > 

   // STL types compatible with TCHAR
   #ifdef _TCHAR_DEFINED
      typedef STD_STRING(TCHAR)       tstring;   
      typedef STD_STRINGSTREAM(TCHAR) tstringstream;   
   #else   
      typedef std::string             tstring;   
      typedef std::stringstream       tstringstream;   
   
      //#define _tcstoul    strtoul   
      //typedef char TCHAR;
   #endif   
  
#else  
#error "types.h - _STRING_ not defined"
#endif _STRING_


#endif __JHB_TYPES_H__

