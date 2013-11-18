// ======================================================================================
// 
// jhbNetwork.cpp
//
//   Functions to support a basic ping capability.
//
// --------------------------------------------------------------------------------------
//
//   Some of this code is based on the ICMPPING.C sample from "Windows Sockets Network
//   Programming" by Bob Quinn & Dave Shute.  See www.sockets.com for sample source.
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
//   Created 2012-11-27
//
//  TODO:
//  -- add a Ctrl-C handler to jhblib
//     -- call CancelPingTest 
//  -- make this a conventional command-line only console ap
//
// ======================================================================================

#include "jhbCommon.h"
#include "jhbNetwork.h"

// Arbitrary limit on echo request payload.
#define MAX_PING_PAYLOAD 0x10000

msTicker _TIME;

// ----------------------------------------------------------------------------
// Logging
// ----------------------------------------------------------------------------
static PrintProxy<char> _PP;

void  net_SetLogFunc( net_LogFunc_t pfn ) {
   _PP.SetPrintFunction( pfn );
}

class AutoWinsock {
private: int _err;
public:
   AutoWinsock() { WSADATA wsa; _err = WSAStartup( 9, &wsa ); }
  ~AutoWinsock() { WSACleanup(); }   
};
AutoWinsock _AWS;

// ----------------------------------------------------------------------------
// Opens an ICMP "raw" socket,
// Returns: socket handle or INVALID_SOCKET
// ----------------------------------------------------------------------------
SOCKET icmp_open(void) {
   SOCKET s = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
   return (s != SOCKET_ERROR) ? s : INVALID_SOCKET ;
}


// ----------------------------------------------------------------------------
// Sends ICMP echo request message.
// ----------------------------------------------------------------------------
int icmp_sendto( SOCKET s, LPSOCKADDR_IN pAddr, u_short id, u_short seq, int len ) {

   DWORD time = _TIME.Now();			

   // Adjust the echo data len if necessary
   if (len < sizeof time) len = sizeof time;   
   if (MAX_PING_PAYLOAD < len) len = MAX_PING_PAYLOAD;

   // Fill-in ICMP header
   PtrBuf<ICMP_HDR> p( sizeof(ICMP_HDR) + len );
   p->type  = ICMP_ECHOREQ;
   p->code  = 0   ;
   p->cksum = 0   ; 
   p->id    = id  ;
   p->seq   = seq ;

   int ofs = sizeof *p;

   // Put current time before data. We will use it on receive to calculate 
   // round-trip time.
   memcpy ( &p.MB()[ofs], &time, sizeof time );
   ofs += sizeof time; 
   len -= sizeof time;     

   // Fill the data buffer with a sequence of ascending printable ASCII chars. (0x20-0x7E)
   char c = 0x20;
   for (int i=ofs;i<(ofs + len);i++) {
      p.MB()[i] = c++;
      if (0x7E < c) { c=0x20; }
   }   
   
   p->cksum = ip_checksum( p, ofs + len );
    
   int nRet = sendto (s, (char*)(PVOID)p, ofs+len, 0, (SOCKADDR*)pAddr, sizeof *pAddr );       
   if (nRet == SOCKET_ERROR) {
      _PP.printf( "sendto() err %d\n", WSAGetLastError() );
   }
   
   return nRet;
}


// ----------------------------------------------------------------------------
// Receive ICMP echo echo reply and return ping data.
// ----------------------------------------------------------------------------
int icmp_recvfrom(SOCKET s, int *pId, int *pSeq, LPSOCKADDR_IN pAddr ) {
   
   MemBuf mb( sizeof(ICMP_HDR) + MAX_PING_PAYLOAD );
   
   int nAddrLen = sizeof(struct sockaddr_in);
   int nRet = recvfrom( s, (char*)mb.ptr(), mb.size(), 0, (LPSOCKADDR)pAddr, &nAddrLen );
   if (nRet == SOCKET_ERROR) {
      _PP.printf( "recvfrom() err %d\n", WSAGetLastError() );      
      return -1;
   }
   
   // Test for presence of IP header.
   int ofs = (0x45 == mb[0]) ? sizeof(IP_HDR) : 0;
   
   ICMP_HDR *p = (ICMP_HDR*) &mb[ofs];      
   if (pId ) { *pId  = p->id ; }
   if (pSeq) { *pSeq = p->seq; }
   	
   // Send time follows the header.	
   ofs += sizeof(*p);
   int elapseTime = (int)(_TIME.Now() - *(DWORD*)&mb[ofs]);
   
   return elapseTime;
}


// ----------------------------------------------------------------------------
// IP checksum
// - checksum field must be set to zero prior to calling here.
//
// RFC 792:
//   The checksum is the 16-bit ones's complement of the one's
//   complement sum of the ICMP message starting with the ICMP Type.
//   For computing the checksum , the checksum field should be zero.
//   If the total length is odd, the received data is padded with one
//   octet of zeros for computing the checksum.  This checksum may be
//   replaced in the future.
//
// NOTE: This algorithm is optimized.  Carry-bits are allowed to accumulate
//       in the upper word of the 32-bit accumulator, then they're all added
//       in at the end.  (Which must be done twice in case the first addition
//       results in yet another carry.)
// ----------------------------------------------------------------------------
u_short ip_checksum (void *hdr, int len) {	
   
   unsigned long sum = 0;
   u_short *p = (u_short *)hdr;
   
   // Deal with odd length
   if (len % 2) { sum = ((BYTE*)p)[--len]; }
   
   // Sum all 16-bit words.
   while (len > 0) {
      sum += *p++;
      len -= 2;
      //if (sum & 0x80000000) { sum = (sum & 0xFFFF) + (sum >> 16); }   
   }
   
   // Add carry bits. (Twice: first one might produce a carry bit.)
   sum = (sum & 0xFFFF) + (sum >> 16);   
   sum = (sum & 0xFFFF) + (sum >> 16);      
 
   return (u_short)~sum;
} 

// ----------------------------------------------------------------------------
//
//  PPPPPP  ii               TTTTTT                  
//  PP   PP                    TT                 tt 
//  PP   PP                    TT                 tt 
//  PP   PP ii nnnnn   ggggg   TT     eeee   sss  ttt
//  PPPPPP  ii nnn nn gg  gg   TT    ee  ee ss ss tt 
//  PP      ii nn  nn gg  gg   TT    eeeeee  ss   tt 
//  PP      ii nn  nn gg  gg   TT    ee       ss  tt 
//  PP      ii nn  nn gg  gg   TT    ee  ee ss ss tt 
//  PP      ii nn  nn  ggggg   TT     eeee   sss   tt
//                        gg                         
//                    ggggg                          
//
// ----------------------------------------------------------------------------

// Config structure: given to ping thread
typedef struct {
   DWORD  addr ; // IP address
   int    count;      
   int    len  ;   
   SOCKET s    ;
   pingTestCallback_t fnCB;
} _pingTestCfg_t ;


// ----------------------------------------------------------------------------
// Ping Thread - the thread that does the pinging
//
// - create a socket (for echo req/reply traffic)
// - create ICMP id
// - create a mutex  (for results data structure)
// - create an event (for receive notification)
// - create recv thread
// - loop:
//   - send echo request
//   - wait for timeout or recv event
//   - grab mutex
//   - update results
//   - call call 
//   - release mutex
// ----------------------------------------------------------------------------
static DWORD WINAPI _pingThread( LPVOID lpParameter ) {

   // Get ping test configuration
   _pingTestCfg_t cfg = *(_pingTestCfg_t*)lpParameter;
   delete lpParameter;
   
   /*T*E*S*T*/
   std::string sIP;
   _PP.printf("_pingTestCfg_t:\n");
   _PP.printf( "addr  = %s\n", FmtIP( sIP, cfg.addr ));
   _PP.printf( "count = %d\n", cfg.count );      
   _PP.printf( "len   = %d\n", cfg.len   );   
   _PP.printf( "s     = %d\n", cfg.s     );
   _PP.printf( "fnCB  = %p\n", cfg.fnCB  );
   _PP.printf( "\n" );
   
   // what a normal fdset looks like
   {  fd_set fds = {1,cfg.s}; 
      _PP.printf( "fds: count = %d, a[0]= %u, a[1]= %u\n", fds.fd_count, fds.fd_array[0], fds.fd_array[1] );   
   }
   /*T*E*S*T*/   
  
   // Init socket address structure
   sockaddr_in sin;   
   sin.sin_family      = PF_INET;
   sin.sin_addr.s_addr = cfg.addr; 
   sin.sin_port        = htons( 0 ); // no port number 

   // Create a random ICMP ID for this test.
   srand( (UINT)_TIME.Now() );
   const u_short pingID = (u_short)rand();
   _PP.printf( "_pingThread: pingID = 0x%X (%u)\n", pingID, pingID );      
   
   #define MS_PER_S  1000
   #define US_PER_MS 1000   
   
   pingTestResults_t results; 
   memset( &results, 0, sizeof results );
   results.timeMin = INT_MAX;    
   results.timeMax = INT_MIN;

   // Ping loop.
   DWORD loopTime = _TIME.Now();
   
   int i = 1;   
   bool bDone = false;
   while (!bDone) {
     
      // send ICMP echo request
      int ret = icmp_sendto( cfg.s, &sin, pingID, i, cfg.len )  ;
      if (ret < 0) {
         results.status = PING_STATUS_ERROR;
         results.error  = WSAGetLastError(); 
         if (WSAENOTSOCK == results.error ) { bDone = true;   } 
            else                            { results.lost++; }         
         _PP.printf( "_pingThread[%d]: icmp_sendto failed, error = \n", i, results.error );         
      }
     
      // Calculate the ending time for this loop.
      
      bool bLoopDone = false;
      while (!bDone && !bLoopDone) {
         timeval tv = {3,0}; // Three second timeout        
         //printf( "_pingThread[%d]: select(timeval=%d)\n", i, tv.tv_usec );
         
         fd_set fds = {1,cfg.s};
         ret = select( 0, &fds, 0, 0, &tv );
         if (ret < 0) {
            bLoopDone = true;         
            results.status = PING_STATUS_ERROR;
            results.error  = WSAGetLastError();            
            _PP.printf( "_pingThread: select() returned %d: error = %d\n", ret, results.error );    
            if (WSAENOTSOCK == results.error) {
               bDone = true;
               _PP.printf( "_pingThread: socket dead, quitting...\n" );                
            }     
         }
         else if (ret == 0) {
            bLoopDone = true;
            results.status = PING_STATUS_TIMEOUT;
            results.error  = 0;            
            results.lost  += 1;
            _PP.printf( "_pingThread: loop %d timed out\n", i );
            _PP.printf( "fds: count = %d, a[0]= %u, a[1]= %u\n", fds.fd_count, fds.fd_array[0], fds.fd_array[1] );
         }
         else {
            int id, seq; 
            sockaddr_in sinFrom;
         
            int time = icmp_recvfrom( cfg.s, &id, &seq, &sinFrom );
            if (time <= 0) {
               bLoopDone = true;            
               results.status = PING_STATUS_ERROR;                  
               results.error    = WSAGetLastError();
               _PP.printf( "_pingThread: recvfrom() returned %d: error = %d\n", time, results.error );
               if (WSAENOTSOCK == results.error) {
                  bDone = true;
                  _PP.printf( "_pingThread: socket dead, quitting...\n" );                
               }                    
            }
            else if ((pingID != id) || (i != seq)) {
               _PP.printf( "dropping ECHO with unexpected ID(%d) or SEQ(%d)\n", id, seq );      
            }
            else {
               bLoopDone = true;
               results.status     = PING_STATUS_REPLYRECV;            
               results.error      = 0;
               results.recv      += 1;
               results.timeLast   = time; // ms
               results.timeTotal += time;
               results.timeMin    = min(results.timeMin, time); 
               results.timeMax    = max(results.timeMax, time);                
               _PP.printf( "Reply received: id(%d), seq(%d), elapse time(%dms)\n", id, seq, time );
            }
         }
      
         // If there's time left in this loop, sleep it off.
         if (!bDone) {
            DWORD now = _TIME.Now(); 
            while ((loopTime += MS_PER_S) < now) {}
            DWORD timeout = loopTime - now;          
            //printf( "_pingThread[%d]: Sleep( %d )\n", i, timeout );         
            Sleep( timeout );      
         }   
      }   
      
      // Call results callback.
      cfg.fnCB( &results );
      
      // If fixed count, are we done yet?
      i++;
      if ((0 != cfg.count) && (cfg.count < i)) {
         bDone = true;
      }
   }
   
   // Send last update
   results.status = PING_STATUS_FINISHED;
   cfg.fnCB( &results );  
   
   closesocket( cfg.s );
   
   _PP.printf( "_pingThread: out...\n" );
   return 0;
}

// WSAEFAULT         (10014) - The system detected an invalid pointer address in attempting to use a pointer argument in a call.
// WSAEINVAL         (10022) - An invalid argument was supplied.
// WSAENOTSOCK       (10038) - An operation was attempted on something that is not a socket.
// WSAENETUNREACH    (10051) - A socket operation was attempted to an unreachable network.
// WSASYSCALLFAILURE (10107) - A system call that should never fail has failed.

//
//-----------------------------------------------------------------------------
// Runs a ping test. 
// - count==0 means repeat until cancelled
// - handle pointer must be provided when count==0, optional otherwise.  If the 
//   ping test begins without error, on return handle contains a value that can 
//   be passed to CancelPingTest to terminate an in-progress ping test. 
//-----------------------------------------------------------------------------
DWORD StartPingTest( const char *pszAddr, int count, int len, pingTestCallback_t pfn, UINT *handle ) {
   
   // Init ping config
   _pingTestCfg_t *pcfg = (_pingTestCfg_t *)new _pingTestCfg_t;
   _pingTestCfg_t & cfg = *pcfg;
   cfg.addr  = inet_addr( pszAddr );   // NOTE: DNS lookup would be nice
   if (INADDR_NONE == cfg.addr) {
      _PP.printf( "StartPingTest: invalid IP address: %s\n", pszAddr );
      return WSAEINVAL;   
   } 
   cfg.count = count;   
   cfg.len   = len;
   cfg.fnCB  = pfn;
   cfg.s     = icmp_open();
   if (INVALID_SOCKET == cfg.s) {
      int err = WSAGetLastError() ;
      _PP.printf( "StartPingTest: icmp_open failed, error = %d\n", err );
      return err;
   }
   
   DWORD thID = 0;
   HANDLE h = CreateThread( 0, 0, _pingThread, &cfg, 0, &thID );
   if (0 == h) {
      _PP.printf( "StartPingTest: CreateThread() failed, gle = 0x%X\n", GetLastError());
      closesocket( cfg.s );         
      return WSASYSCALLFAILURE;
   }  CloseHandle( h );  // NOTE: Doesn't end thread.
   
   _PP.printf( "StartPingTest: CreateThread() succeeded: thread id = 0x%X\n", thID );   
  
   if (handle) *handle = cfg.s;
   return 0;  // good return
}

// ----------------------------------------------------------------------------
// Ends a ping test if one is in progress.
// ----------------------------------------------------------------------------
void CancelPingTest( UINT handle ) {
   int err = closesocket( handle );
   if (0 != err) {
      _PP.printf( "CancelPingTest: closesocket returned %d, error %d\n", err, WSAGetLastError()); 
   }
}



// Start of an auto-ptr for handles?
/*
template <typename T> class AutoClose {
public:
   typedef int (_stdcall * int_close) (T h);
   typedef int (_stdcall *void_close) (T h);   
   
   AutoClose( T handle, int_close close ) : _handle(handle), _close1( close ), _close2(0) {}
  ~AutoClose() { 
      if (_close1) _close1(_handle);
      if (_close2) _close2(_handle);      
   }
   
private:
   T _handle;
   
    int_close _close1;
   void_close _close2;   
};
*/
