// ======================================================================================
// 
// jhbNetwork.h
//
//   Network programming functions.  (Header is C-compatible.)
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
//   Created 2012-11-12
//   -- ping-related functions, implemented using WinSock
//
// ======================================================================================

 
#ifndef _JHB_NETWORK_H_
#define _JHB_NETWORK_H_

#include <winsock.h>

#define ICMP_ECHOREPLY	0
#define ICMP_ECHOREQ	   8

#pragma pack(push)
#pragma pack(1)

// ICMP header (RFC 792)
typedef struct icmp_hdr {
	u_char	type;	  // type of message
	u_char	code;	  // type sub code
	u_short  cksum;  // ones complement cksum
	u_short	id;     // identifier
	u_short	seq;    // sequence number
} ICMP_HDR;

// IP version 4 header (RFC 791)
typedef struct ip_hdr {	
   union { 	// header length, version
      struct { u_char len:4, ver :4; } _h;
      u_char _hdr;                     
   };          
   u_char	tos;	   // type of service
   short	   len;	   // total length
   u_short	id;	   // identification
   short	   off;	   // fragment offset field
   u_char	ttl;	   // time to live
   u_char	p;		   // protocol
   u_short	cksum;	// checksum
   struct in_addr  src;	   // source address
   struct in_addr  dst;	   // destination address
} IP_HDR;

#pragma pack(pop)

// ----------------------------------------------------------------------------
// ICMP PING Functions
// ----------------------------------------------------------------------------
SOCKET icmp_open (void);

int icmp_recvfrom( SOCKET s, int *pId, int *pSeq, LPSOCKADDR_IN pAddrFrom );
int icmp_sendto  ( SOCKET s, LPSOCKADDR_IN pAddrFrom, u_short id, u_short seq, int echoDataLen );

u_short ip_checksum( void *p, int len );

// Results structure: sent with callback
typedef enum {
   PING_STATUS_FINISHED  =  1,      
   PING_STATUS_REPLYRECV =  0,
   PING_STATUS_TIMEOUT   = -1,   
   PING_STATUS_ERROR     = -2,      
} pingStatus_e;

typedef struct {
   int status;
   int error;
   int lost;
   int recv;   
   int timeLast;
   int timeTotal;   
   int timeMin;      
   int timeMax;      
} pingTestResults_t;

typedef void (*pingTestCallback_t)( pingTestResults_t *pData );

DWORD StartPingTest( const char *pszAddr, int count, int len, pingTestCallback_t pfn, UINT *handle );
void  CancelPingTest( UINT handle );

typedef void (*net_LogFunc_t)( const char *sz );
void net_SetLogFunc( net_LogFunc_t pfn );

#endif _JHB_NETWORK_H_
