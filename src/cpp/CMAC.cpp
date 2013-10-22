// ----------------------------------------------------------------------------
//
// CMAC.CPP
//  
//   A CPP implementation of CMAC (NIST SP 800-38B) from RFC4493.
//
// ----------------------------------------------------------------------------
//
// 2. Specification of AES-CMAC
// 
// 2.3. Subkey Generation Algorithm
// 
// 
//    The subkey generation algorithm, Generate_Subkey(), takes a secret
//    key, K, which is just the key for AES-128.
// 
//    The outputs of the subkey generation algorithm are two subkeys, K1
//    and K2.  We write (K1,K2) := Generate_Subkey(K).
// 
//    Subkeys K1 and K2 are used in both MAC generation and MAC
//    verification algorithms.  K1 is used for the case where the length of
//    the last block is equal to the block length.  K2 is used for the case
//    where the length of the last block is less than the block length.
// 
//    Figure 2.2 specifies the subkey generation algorithm.
// 
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                    Algorithm Generate_Subkey                      +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                                                                   +
//    +   Input    : K (128-bit key)                                      +
//    +   Output   : K1 (128-bit first subkey)                            +
//    +              K2 (128-bit second subkey)                           +
//    +-------------------------------------------------------------------+
//    +                                                                   +
//    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
//    +              const_Rb   is 0x00000000000000000000000000000087     +
//    +   Variables: L          for output of AES-128 applied to 0^128    +
//    +                                                                   +
//    +   Step 1.  L := AES-128(K, const_Zero);                           +
//    +   Step 2.  if MSB(L) is equal to 0                                +
//    +            then    K1 := L << 1;                                  +
//    +            else    K1 := (L << 1) XOR const_Rb;                   +
//    +   Step 3.  if MSB(K1) is equal to 0                               +
//    +            then    K2 := K1 << 1;                                 +
//    +            else    K2 := (K1 << 1) XOR const_Rb;                  +
//    +   Step 4.  return K1, K2;                                         +
//    +                                                                   +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// 
//                 Figure 2.2.  Algorithm Generate_Subkey
// 
//    In step 1, AES-128 with key K is applied to an all-zero input block.
// 
//    In step 2, K1 is derived through the following operation:
// 
//    If the most significant bit of L is equal to 0, K1 is the left-shift
//    of L by 1 bit.
// 
//    Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L
//    by 1 bit.
// 
//    In step 3, K2 is derived through the following operation:
// 
//    If the most significant bit of K1 is equal to 0, K2 is the left-shift
//    of K1 by 1 bit.
// 
//    Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of
//    K1 by 1 bit.
// 
//    In step 4, (K1,K2) := Generate_Subkey(K) is returned.
// 
//    The mathematical meaning of the procedures in steps 2 and 3,
//    including const_Rb, can be found in [OMAC1a].
// 
// 2.4. MAC Generation Algorithm
// 
// 
//    The MAC generation algorithm, AES-CMAC(), takes three inputs, a
//    secret key, a message, and the length of the message in octets.  The
//    secret key, denoted by K, is just the key for AES-128.  The message
//    and its length in octets are denoted by M and len, respectively.  The
//    message M is denoted by the sequence of M_i, where M_i is the i-th
//    message block.  That is, if M consists of n blocks, then M is written
//    as
// 
//     -   M = M_1 || M_2 || ... || M_{n-1} || M_n
// 
//    The length of M_i is 128 bits for i = 1,...,n-1, and the length of
//    the last block M_n is less than or equal to 128 bits.
// 
//    The output of the MAC generation algorithm is a 128-bit string,
//    called a MAC, which is used to validate the input message.  The MAC
//    is denoted by T, and we write T := AES-CMAC(K,M,len).  Validating the
//    MAC provides assurance of the integrity and authenticity of the
//    message from the source.
// 
//    It is possible to truncate the MAC.  According to [NIST-CMAC], at
//    least a 64-bit MAC should be used as protection against guessing
//    attacks.  The result of truncation should be taken in most
//    significant bits first order.
// 
//    The block length of AES-128 is 128 bits (16 octets).  There is a
//    special treatment if the length of the message is not a positive
//    multiple of the block length.  The special treatment is to pad M with
//    the bit-string 10^i to adjust the length of the last block up to the
//    block length.
// 
//    For an input string x of r-octets, where 0 <= r < 16, the padding
//    function, padding(x), is defined as follows:
// 
//    -   padding(x) = x || 10^i      where i is 128-8*r-1
// 
//    That is, padding(x) is the concatenation of x and a single '1',
//    followed by the minimum number of '0's, so that the total length is
//    equal to 128 bits.
// 
//    Figure 2.3 describes the MAC generation algorithm.
// 
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                   Algorithm AES-CMAC                              +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                                                                   +
//    +   Input    : K    ( 128-bit key )                                 +
//    +            : M    ( message to be authenticated )                 +
//    +            : len  ( length of the message in octets )             +
//    +   Output   : T    ( message authentication code )                 +
//    +                                                                   +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +   Constants: const_Zero is 0x00000000000000000000000000000000     +
//    +              const_Bsize is 16                                    +
//    +                                                                   +
//    +   Variables: K1, K2 for 128-bit subkeys                           +
//    +              M_i is the i-th block (i=1..ceil(len/const_Bsize))   +
//    +              M_last is the last block xor-ed with K1 or K2        +
//    +              n      for number of blocks to be processed          +
//    +              r      for number of octets of last block            +
//    +              flag   for denoting if last block is complete or not +
//    +                                                                   +
//    +   Step 1.  (K1,K2) := Generate_Subkey(K);                         +
//    +   Step 2.  n := ceil(len/const_Bsize);                            +
//    +   Step 3.  if n = 0                                               +
//    +            then                                                   +
//    +                 n := 1;                                           +
//    +                 flag := false;                                    +
//    +            else                                                   +
//    +                 if len mod const_Bsize is 0                       +
//    +                 then flag := true;                                +
//    +                 else flag := false;                               +
//    +                                                                   +
//    +   Step 4.  if flag is true                                        +
//    +            then M_last := M_n XOR K1;                             +
//    +            else M_last := padding(M_n) XOR K2;                    +
//    +   Step 5.  X := const_Zero;                                       +
//    +   Step 6.  for i := 1 to n-1 do                                   +
//    +                begin                                              +
//    +                  Y := X XOR M_i;                                  +
//    +                  X := AES-128(K,Y);                               +
//    +                end                                                +
//    +            Y := M_last XOR X;                                     +
//    +            T := AES-128(K,Y);                                     +
//    +   Step 7.  return T;                                              +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// 
//                       Figure 2.3.  Algorithm AES-CMAC
// 
//    In step 1, subkeys K1 and K2 are derived from K through the subkey
//    generation algorithm.
// 
//    In step 2, the number of blocks, n, is calculated.  The number of
//    blocks is the smallest integer value greater than or equal to the
//    quotient determined by dividing the length parameter by the block
//    length, 16 octets.
// 
//    In step 3, the length of the input message is checked.  If the input
//    length is 0 (null), the number of blocks to be processed shall be 1,
//    and the flag shall be marked as not-complete-block (false).
//    Otherwise, if the last block length is 128 bits, the flag is marked
//    as complete-block (true); else mark the flag as not-complete-block
//    (false).
// 
//    In step 4, M_last is calculated by exclusive-OR'ing M_n and one of
//    the previously calculated subkeys.  If the last block is a complete
//    block (true), then M_last is the exclusive-OR of M_n and K1.
//    Otherwise, M_last is the exclusive-OR of padding(M_n) and K2.
// 
//    In step 5, the variable X is initialized.
// 
//    In step 6, the basic CBC-MAC is applied to M_1,...,M_{n-1},M_last.
// 
//    In step 7, the 128-bit MAC, T := AES-CMAC(K,M,len), is returned.
// 
//    If necessary, the MAC is truncated before it is returned.
// 
// 2.5. MAC Verification Algorithm
// 
// 
//    The verification of the MAC is simply done by a MAC recomputation.
//    We use the MAC generation algorithm, which is described in section
//    2.4.
// 
//    The MAC verification algorithm, Verify_MAC(), takes four inputs, a
//    secret key, a message, the length of the message in octets, and the
//    received MAC.  These are denoted by K, M, len, and T', respectively.
// 
//    The output of the MAC verification algorithm is either INVALID or
//    VALID.
// 
//    Figure 2.4 describes the MAC verification algorithm.
// 
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                      Algorithm Verify_MAC                         +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
//    +                                                                   +
//    +   Input    : K    ( 128-bit Key )                                 +
//    +            : M    ( message to be verified )                      +
//    +            : len  ( length of the message in octets )             +
//    +            : T'   ( the received MAC to be verified )             +
//    +   Output   : INVALID or VALID                                     +
//    +                                                                   +
//    +-------------------------------------------------------------------+
//    +                                                                   +
//    +   Step 1.  T* := AES-CMAC(K,M,len);                               +
//    +   Step 2.  if T* is equal to T'                                   +
//    +            then                                                   +
//    +                 return VALID;                                     +
//    +            else                                                   +
//    +                 return INVALID;                                   +
//    +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// 
//                     Figure 2.4.  Algorithm Verify_MAC
// 
//    In step 1, T* is derived from K, M, and len through the MAC
//    generation algorithm.
// 
//    In step 2, T* and T' are compared.  If T* is equal to T', then return
//    VALID; otherwise return INVALID.
// 
//    If the output is INVALID, then the message is definitely not
//    authentic, i.e., it did not originate from a source that executed the
//    generation process on the message to produce the purported MAC.
// 
//    If the output is VALID, then the design of the AES-CMAC provides
//    assurance that the message is authentic and, hence, was not corrupted
//    in transit; however, this assurance, as for any MAC algorithm, is not
//    absolute.
// 
// 3. Security Considerations
// 
// 
//    The security provided by AES-CMAC is built on the strong
//    cryptographic algorithm AES.  However, as is true with any
//    cryptographic algorithm, part of its strength lies in the secret key,
//    K, and the correctness of the implementation in all of the
//    participating systems.  If the secret key is compromised or
//    inappropriately shared, it guarantees neither authentication nor
//    integrity of message at all.  The secret key shall be generated in a
//    way that meets the pseudo randomness requirement of RFC 4086
//    [RFC4086] and should be kept safe.  If and only if AES-CMAC is used
//    properly it provides the authentication and integrity that meet the
//    best current practice of message authentication.
// 
// 4. Test Vectors
// 
//    The following test vectors are the same as those of [NIST-CMAC].  The
//    following vectors are also the output of the test program in Appendix
//    A.
// 
//    --------------------------------------------------
//    Subkey Generation
//    K              2b7e1516 28aed2a6 abf71588 09cf4f3c
//    AES-128(key,0) 7df76b0c 1ab899b3 3e42f047 b91b546f
//    K1             fbeed618 35713366 7c85e08f 7236a8de
//    K2             f7ddac30 6ae266cc f90bc11e e46d513b
//    --------------------------------------------------
// 
//    --------------------------------------------------
//    Example 1: len = 0
//    M              <empty string>
//    AES-CMAC       bb1d6929 e9593728 7fa37d12 9b756746
//    --------------------------------------------------
// 
//    Example 2: len = 16
//    M              6bc1bee2 2e409f96 e93d7e11 7393172a
//    AES-CMAC       070a16b4 6b4d4144 f79bdd9d d04a287c
//    --------------------------------------------------
// 
//    Example 3: len = 40
//    M              6bc1bee2 2e409f96 e93d7e11 7393172a
//                   ae2d8a57 1e03ac9c 9eb76fac 45af8e51
//                   30c81c46 a35ce411
//    AES-CMAC       dfa66747 de9ae630 30ca3261 1497c827
//    --------------------------------------------------
// 
//    Example 4: len = 64
//    M              6bc1bee2 2e409f96 e93d7e11 7393172a
//                   ae2d8a57 1e03ac9c 9eb76fac 45af8e51
//                   30c81c46 a35ce411 e5fbc119 1a0a52ef
//                   f69f2445 df4f9b17 ad2b417b e66c3710
//    AES-CMAC       51f0bebf 7e3b9d92 fc497417 79363cfe
//    --------------------------------------------------
//    
// ----------------------------------------------------------------------------    

#include "jhbKrypto.h"

#define BLK_SIZE 16

typedef BlockBuf<BLK_SIZE> BlkBuf;

// Internal AES function: 128-bit, no IV
// -- all byte buffers assumed to be 16 bytes long.
static void AES_128(BYTE *key, BYTE *in, BYTE *out) {
   BYTE iv[BLK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0} ;
   aes( in, out, 16, key, iv, 1 );
}   


// Special constant
static BYTE const_Rb[BLK_SIZE] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x87};

// 
static void GenSubkeys( BYTE *key, BlkBuf &K1, BlkBuf &K2 )
{
    BlkBuf Z, L; Z.zero();
    AES_128( key, Z, L );

    K1.lsh1( L );
    if (L[0]  & 0x80) { K1.xor( const_Rb ); }

    K2.lsh1( K1 ) ;                            
    if (K1[0] & 0x80) { K2.xor( const_Rb ); }
    
    return;
}

static void Pad( BYTE *buf, int len, BYTE *out ) {
   for (int i=0; i<BLK_SIZE; i++ ) {      
      out[i] = (i < len) ? buf[i] : (i == len) ? 0x80 : 0x00 ;      
   }           
}

void cmac_aes128 ( BYTE *key, BYTE *in, int length, BYTE *out )
{
   BlkBuf K1, K2;
   GenSubkeys( key, K1, K2 );
   
   int  Blks = max( 1, (length + BLK_SIZE - 1) / BLK_SIZE );
   bool bPad = (length < (Blks * BLK_SIZE));
   
   BlkBuf M_last;
   if (bPad) { 
      Pad( &in[BLK_SIZE*(Blks-1)], length % BLK_SIZE, M_last );
      M_last.xor( K2 );         
   } else {
      M_last.xor( &in[BLK_SIZE*(Blks-1)], K1 );      
   }

   BlkBuf X; X.zero();
   for (int i=0; i<(Blks-1); i++ ) {
      X.xor( &in[BLK_SIZE*i] );
      AES_128( key, X, X );
   }

   X.xor( M_last );
   AES_128( key, X, out );
}

// ----------------------------------------------------------------------------

bool cmac_TEST() {

   BYTE zero[BLK_SIZE]; memset( zero, 0, sizeof zero );
   BYTE key [BLK_SIZE]; CvtHex( "2b7e151628aed2a6abf7158809cf4f3c", key );
   BYTE ref [BLK_SIZE]; 
   
   {// Subkey generation.
      BlkBuf out, K1, K2;
      
      AES_128(key,zero,out);      
      GenSubkeys(key,K1,K2);   
      
      CvtHex( "7df76b0c1ab899b33e42f047b91b546f", ref );
      if (0 != memcmp( out, ref, sizeof ref )) { return false; }
         
      CvtHex( "fbeed618357133667c85e08f7236a8de", ref );   
      if (0 != memcmp( K1, ref, sizeof ref )) { return false; }      
      
      CvtHex( "f7ddac306ae266ccf90bc11ee46d513b", ref );
      if (0 != memcmp( K2, ref, sizeof ref )) { return false; }      
   }
   {// Example 1: len=0
      BYTE out [BLK_SIZE];      
      cmac_aes128(key,0,0,out);
      
      CvtHex( "bb1d6929e95937287fa37d129b756746", ref );
      if (0 != memcmp( out, ref, sizeof ref )) { return false; }            
   }
   {// Example 2: len=16
      BYTE out[BLK_SIZE]; 
      BYTE M  [    16]; CvtHex( "6bc1bee22e409f96e93d7e117393172a", M );     
      cmac_aes128(key,M,16,out);
      
      CvtHex( "070a16b46b4d4144f79bdd9dd04a287c", ref );
      if (0 != memcmp( out, ref, sizeof ref )) { return false; }            
   }
   {// Example 3: len = 40   
      BYTE out[BLK_SIZE]; 
      BYTE M  [      40]; CvtHex( "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", M );     
      cmac_aes128(key,M,40,out);
      
      CvtHex( "dfa66747de9ae63030ca32611497c827", ref );
      if (0 != memcmp( out, ref, sizeof ref )) { return false; }            
   }      
   {// Example 4: len = 64
      BYTE out[BLK_SIZE]; 
      BYTE M  [      64]; CvtHex( "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", M );           
      cmac_aes128(key,M,64,out);
      
      CvtHex( "51f0bebf7e3b9d92fc49741779363cfe", ref );
      if (0 != memcmp( out, ref, sizeof ref )) { return false; }            
   }   

   return true;
}