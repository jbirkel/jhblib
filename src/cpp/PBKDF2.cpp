// ----------------------------------------------------------------------------
//
// PBKDF2.CPP
//  
//   A C++ implementation of PBKDF2 as described in RFC 2898. 
//
// ----------------------------------------------------------------------------
//
// From RFC 2898:
//
// 5.2 PBKDF2
// 
//    PBKDF2 applies a pseudorandom function (see Appendix B.1 for an
//    example) to derive keys. The length of the derived key is essentially
//    unbounded. (However, the maximum effective search space for the
//    derived key may be limited by the structure of the underlying
//    pseudorandom function. See Appendix B.1 for further discussion.)
//    PBKDF2 is recommended for new applications.
// 
//    PBKDF2 (P, S, c, dkLen)
// 
//    Options:        PRF        underlying pseudorandom function (hLen
//                               denotes the length in octets of the
//                               pseudorandom function output)
// 
//    Input:          P          password, an octet string
//                    S          salt, an octet string
//                    c          iteration count, a positive integer
//                    dkLen      intended length in octets of the derived
//                               key, a positive integer, at most
//                               (2^32 - 1) * hLen
// 
//    Output:         DK         derived key, a dkLen-octet string
// 
//    Steps:
// 
//       1. If dkLen > (2^32 - 1) * hLen, output "derived key too long" and
//          stop.
// 
//       2. Let l be the number of hLen-octet blocks in the derived key,
//          rounding up, and let r be the number of octets in the last
//          block:
// 
//                    l = CEIL (dkLen / hLen) ,
//                    r = dkLen - (l - 1) * hLen .
// 
//          Here, CEIL (x) is the "ceiling" function, i.e. the smallest
//          integer greater than, or equal to, x.
// 
//       3. For each block of the derived key apply the function F defined
//          below to the password P, the salt S, the iteration count c, and
//          the block index to compute the block:
// 
//                    T_1 = F (P, S, c, 1) ,
//                    T_2 = F (P, S, c, 2) ,
//                    ...
//                    T_l = F (P, S, c, l) ,
// 
//          where the function F is defined as the exclusive-or sum of the
//          first c iterates of the underlying pseudorandom function PRF
//          applied to the password P and the concatenation of the salt S
//          and the block index i:
// 
//                    F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
// 
//          where
// 
//                    U_1 = PRF (P, S || INT (i)) ,
//                    U_2 = PRF (P, U_1) ,
//                    ...
//                    U_c = PRF (P, U_{c-1}) .
// 
//          Here, INT (i) is a four-octet encoding of the integer i, most
//          significant octet first.
// 
//       4. Concatenate the blocks and extract the first dkLen octets to
//          produce a derived key DK:
// 
//                    DK = T_1 || T_2 ||  ...  || T_l<0..r-1>
// 
//       5. Output the derived key DK.
// 
//    Note. The construction of the function F follows a "belt-and-
//    suspenders" approach. The iterates U_i are computed recursively to
//    remove a degree of parallelism from an opponent; they are exclusive-
//    ored together to reduce concerns about the recursion degenerating
//    into a small set of values.
//
// 
//
//  Test Vectors (RFC 6070):
//  ------------------------
//
//  2. PBKDF2 HMAC-SHA1 Test Vectors
//
//   The input strings below are encoded using ASCII [ANSI.X3-4.1986].
//   The sequence "\0" (without quotation marks) means a literal ASCII NUL
//   value (1 octet).  "DK" refers to the Derived Key.
//
//      Input:
//        P = "password" (8 octets)
//        S = "salt" (4 octets)
//        c = 1
//        dkLen = 20
// 
//      Output:
//        DK = 0c 60 c8 0f 96 1f 0e 71
//             f3 a9 b5 24 af 60 12 06
//             2f e0 37 a6             (20 octets)
// 
//      Input:
//        P = "password" (8 octets)
//        S = "salt" (4 octets)
//        c = 2
//        dkLen = 20
// 
//      Output:
//        DK = ea 6c 01 4d c7 2d 6f 8c
//             cd 1e d9 2a ce 1d 41 f0
//             d8 de 89 57             (20 octets)
// 
// 
//      Input:
//        P = "password" (8 octets)
//        S = "salt" (4 octets)
//        c = 4096
//        dkLen = 20
// 
//      Output:
//        DK = 4b 00 79 01 b7 65 48 9a
//             be ad 49 d9 26 f7 21 d0
//             65 a4 29 c1             (20 octets)
// 
// 
//      Input:
//        P = "password" (8 octets)
//        S = "salt" (4 octets)
//        c = 16777216
//        dkLen = 20
// 
//      Output:
//        DK = ee fe 3d 61 cd 4d a4 e4
//             e9 94 5b 3d 6b a2 15 8c
//             26 34 e9 84             (20 octets)
// 
// 
//      Input:
//        P = "passwordPASSWORDpassword" (24 octets)
//        S = "saltSALTsaltSALTsaltSALTsaltSALTsalt" (36 octets)
//        c = 4096
//        dkLen = 25
// 
//      Output:
//        DK = 3d 2e ec 4f e4 1c 84 9b
//             80 c8 d8 36 62 c0 e4 4a
//             8b 29 1a 96 4c f2 f0 70
//             38                      (25 octets)
//               
//
//      Input:
//        P = "pass\0word" (9 octets)
//        S = "sa\0lt" (5 octets)
//        c = 4096
//        dkLen = 16
// 
//      Output:
//        DK = 56 fa 6a a7 55 48 09 9d
//             cc 37 d7 f0 34 25 e0 c3 (16 octets)
//
// ----------------------------------------------------------------------------

#include <string>
#include "jhbKrypto.h"

// --------------------------------------------------------------------------------
// F is defined as the exclusive-or sum of the first c iterates of the underlying 
// pseudorandom function PRF applied to the password P and the concatenation of the 
// salt S and the block index i:
// 
//           F (P, S, c, i) = U_1 \xor U_2 \xor ... \xor U_c
// 
// where
// 
//           U_1 = PRF (P, S || INT (i)) ,
//           U_2 = PRF (P, U_1) ,
//           ...
//           U_c = PRF (P, U_{c-1}) .
// 
// Here, INT (i) is a four-octet encoding of the integer i, most
// significant octet first.      
// --------------------------------------------------------------------------------
static BYTE * F(const MemBuf &P, const MemBuf &S, int count, int index, MemBuf &out)
{
   // Create a working salt that is the inputted salt appended with the index.
   MemBuf SI( S.size() + 4 ); 
   memcpy(SI, S, S.size() );
   SI[ S.size()     ] = (BYTE)( (index>>24)        );
   SI[ S.size() + 1 ] = (BYTE)( (index>>16) & 0xff );
   SI[ S.size() + 2 ] = (BYTE)( (index>> 8) & 0xff );
   SI[ S.size() + 3 ] = (BYTE)(  index      & 0xff );
   
   // U_1:
   MemBuf U_i( SHA1_LEN ); hmac_sha1( SI, SI.size(), P, P.size(), U_i );   
   out.copy(U_i);
   
   // U_2 thru U_c:
   for (int i=2; i<=count; i++) {
      MemBuf U_tmp( U_i );
      hmac_sha1( U_tmp, U_tmp.size(), P, P.size(), U_i );
      for (UINT j=0; j<out.size(); j++) { 
         out[j] ^= U_i[j];
      }
   }         

   return out;
}

// ----------------------------------------------------------------------------
// Password-based key derivation algorithm. 
// - text  : typically, a user-entered password or phrase
// - salt  : caller's "entropy"
// - count : number of times to iterate the hashing loop.
// - length: the desired number of bytes in the returned byte array
// - out   : memory buffer filled with the requested number of bytes
// ----------------------------------------------------------------------------
BYTE *PBKDF2(PCBYTE text, int textlen, PCBYTE salt, int saltlen, int count, int length, BYTE *out) 
{
    // Loop until we've generated the requested number of bytes.
   UINT more = length;
   for (int i=1; 0<more; i++)
   {
      // Where the magic happens.
      MemBuf outF;
      F( MemBuf( text, (UINT)textlen ), MemBuf( salt, (UINT)saltlen), count, i, outF );
      
      // Append as many bytes of hash as needed to the key buffer.  
      UINT nCopyCount = min(more, outF.size());
      memcpy( &out[length-more], outF, nCopyCount);

      // Reduce the "more" counter by the number of bytes we just copied.
      more -= nCopyCount;
   }
   
   return out;
}
      
// -- convenience alias
BYTE *PBKDF2(const char *text, const char *salt, int count, int length, MemBuf &out) { 
   MemBuf mText( (BYTE*)text, strlen( text ));
   MemBuf mSalt( (BYTE*)salt, strlen( salt ));   
   return PBKDF2( mText, mSalt, count, length, out );
}

// -- convenience alias
BYTE *PBKDF2( const MemBuf &text, const MemBuf &salt, int count, int length, MemBuf &out) {
   out.alloc( length );
   return PBKDF2( text, text.size(), salt, salt.size(), count, length, out);
}


// Test vectors from RFC 6070.  (See file header, above.)
bool PBKDF2_TEST()
{  
   MemBuf mDig(100);
   MemBuf mOut(100);   
   
   CvtHex( "0c60c80f961f0e71f3a9b524af6012062fe037a6", mDig );
   if (0 != memcmp( mDig, PBKDF2("password", "salt", 1, 20, mOut), 20 )) { return false; }

   CvtHex( "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957", mDig );
   if (0 != memcmp( mDig, PBKDF2("password", "salt", 2, 20, mOut), 20 )) { return false; }

   CvtHex( "4b007901b765489abead49d926f721d065a429c1", mDig );
   if (0 != memcmp( mDig, PBKDF2("password", "salt", 4096, 20, mOut), 20)) { return false; }

   // This one is rather time consuming.
   //CvtHex( "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984", mDig );
   //if (0 != memcmp( mDig, PBKDF2("password", "salt", 16777216, 20, mOut), 20)) { return false; }

   CvtHex( "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038", mDig );
   if (0 != memcmp( mDig, PBKDF2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25, mOut), 25)) { return false; }

   CvtHex( "56fa6aa75548099dcc37d7f03425e0c3", mDig );
   BYTE text[] = { 'p', 'a', 's', 's', 0, 'w', 'o', 'r', 'd' } ;
   BYTE salt[] = { 's', 'a', 0, 'l', 't' } ;   
   if (0 != memcmp( mDig, PBKDF2( MemBuf(text,NELEM(text)), MemBuf(salt,NELEM(salt)), 4096, 16, mOut), 16)) { return false; }

   return true;
}


// --------------------------------------------------------------------------------------
// From 802.11i-2004:  WPA Key = PBKDF2(passphrase, ssid, 4096, 32)
//
// NOTES: 
// -- out buffer must have room for 32 byes of output.
// -- passphrase length must be between 8 and 63 bytes.  (Returns NULL otherwise.)
// --------------------------------------------------------------------------------------
#define WPAPSK_COUNT 4096

BYTE *WPAPSK(PCBYTE text, int len, PCBYTE ssid, int ssidlen, BYTE *out) {
   if ((len < WPA_PASSPHRASE_LEN_MIN) || (WPA_PASSPHRASE_LEN_MAX < len)) { return NULL; }
   return PBKDF2( text, len, ssid, ssidlen, WPAPSK_COUNT, WPAPSK_LEN, out );
}
BYTE *WPAPSK(LPCSTR text, PCBYTE ssid, int ssidlen, MemBuf &out) {
   out.alloc(WPAPSK_LEN); return WPAPSK((BYTE*)text, strlen(text), ssid, ssidlen, out);
}
BYTE *WPAPSK(LPCSTR text, LPCSTR ssid, MemBuf &out) {
   out.alloc(WPAPSK_LEN); return WPAPSK((BYTE*)text, strlen(text), (BYTE*)ssid, strlen(ssid), out);
}

// H.4.3 Test vectors
//
// Test case 1
// Passphrase = “password”
// SSID = { ‘I’, ‘E’, ‘E’, ‘E’ }
// SSIDLength = 4
// PSK = f42c6fc52df0ebef9ebb4b90b38a5f90 2e83fe1b135a70e23aed762e9710a12e
//
// Test case 2
// Passphrase = “ThisIsAPassword”
// SSID = { ‘T’, ‘h’, ‘i’, ‘s’, ‘I’, ‘s’, ‘A’, ‘S’, ‘S’, ‘I’, ‘D’ }
// SSIDLength = 11
// PSK = 0dc0d6eb90555ed6419756b9a15ec3e3 209b63df707dd508d14581f8982721af
//
// Test case 3
// Password = “aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa”
// SSID = {‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’,
//         ‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’, ‘Z’,‘Z’,‘Z’,‘Z’}
// SSIDLength = 32
// PSK = becb93866bb8c3832cb777c2f559807c 8c59afcb6eae734885001300a981cc62
//

bool WPAPSK_TEST() {

   MemBuf mDig(32);
   MemBuf mOut(32);   
   
   CvtHex( "f42c6fc52df0ebef9ebb4b90b38a5f902e83fe1b135a70e23aed762e9710a12e", mDig );
   if (0 != memcmp( mDig, WPAPSK("password", "IEEE",  mOut), 32 )) { 
      return false; 
   }   
   
   CvtHex( "0dc0d6eb90555ed6419756b9a15ec3e3209b63df707dd508d14581f8982721af", mDig );
   if (0 != memcmp( mDig, WPAPSK("ThisIsAPassword", "ThisIsASSID",  mOut), 32 )) { return false; }      
   
   CvtHex( "becb93866bb8c3832cb777c2f559807c8c59afcb6eae734885001300a981cc62", mDig );   
   if (0 != memcmp( mDig, WPAPSK("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",  mOut), 32 )) { return false; }      

   return true;   
}




   