// --- File Header ------------------------------------------------------------
//
// HMAC.CS
//  
//   A C# implementation of HMAC as described in RFC2104. 
//
// From RFC 2104:
//
// 2. Definition of HMAC
// 
//    The definition of HMAC requires a cryptographic hash function, which
//    we denote by H, and a secret key K. We assume H to be a cryptographic
//    hash function where data is hashed by iterating a basic compression
//    function on blocks of data.   We denote by B the byte-length of such
//    blocks (B=64 for all the above mentioned examples of hash functions),
//    and by L the byte-length of hash outputs (L=16 for MD5, L=20 for
//    SHA-1).  The authentication key K can be of any length up to B, the
//    block length of the hash function.  Applications that use keys longer
//    than B bytes will first hash the key using H and then use the
//    resultant L byte string as the actual key to HMAC. In any case the
//    minimal recommended length for K is L bytes (as the hash output
//    length). See section 3 for more information on keys.
// 
//    We define two fixed and different strings ipad and opad as follows
//    (the 'i' and 'o' are mnemonics for inner and outer):
// 
//                   ipad = the byte 0x36 repeated B times
//                   opad = the byte 0x5C repeated B times.
// 
//    To compute HMAC over the data `text' we perform
// 
//                     H(K XOR opad, H(K XOR ipad, text))
// 
//    Namely,
// 
//     (1) append zeros to the end of K to create a B byte string
//         (e.g., if K is of length 20 bytes and B=64, then K will be
//          appended with 44 zero bytes 0x00)
//     (2) XOR (bitwise exclusive-OR) the B byte string computed in step
//         (1) with ipad
//     (3) append the stream of data 'text' to the B byte string resulting
//         from step (2)
//     (4) apply H to the stream generated in step (3)
//     (5) XOR (bitwise exclusive-OR) the B byte string computed in
//         step (1) with opad
//     (6) append the H result from step (4) to the B byte string
//         resulting from step (5)
//     (7) apply H to the stream generated in step (6) and output
//         the result
//
//
// ----------------------------------------------------------------------------
//  Test Vectors from http://en.wikipedia.org/wiki/HMAC
//
//  HMAC_MD5("", "") = 0x 74e6f7298a9c2d168935f58c001bad88
//  HMAC_MD5("key", "The quick brown fox jumps over the lazy dog") = 0x 80070713463e7749b90c2dc24911e275
//  
//  HMAC_SHA1("", "") = 0x fbdb1d1b18aa6c08324b7d64b71fb76370690e1d
//  HMAC_SHA1("key", "The quick brown fox jumps over the lazy dog") = 0x de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9
//
//  HMAC_SHA256("", "") = 0x b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad
//  HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 0x f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
//
// ----------------------------------------------------------------------------
//  Test Vectors from RFC 2202, "Test Cases for HMAC-MD5 and HMAC-SHA-1", September 1997
//
//  2. Test Cases for HMAC-MD5
//  
//  test_case =     1
//  key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
//  key_len =       16
//  data =          "Hi There"
//  data_len =      8
//  digest =        0x9294727a3638bb1c13f48ef8158bfc9d
//  
//  test_case =     2
//  key =           "Jefe"
//  key_len =       4
//  data =          "what do ya want for nothing?"
//  data_len =      28
//  digest =        0x750c783e6ab0b503eaa86e310a5db738
//  
//  test_case =     3
//  key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//  key_len         16
//  data =          0xdd repeated 50 times
//  data_len =      50
//  digest =        0x56be34521d144c88dbb8c733f0e8b3f6
//  
//  test_case =     4
//  key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
//  key_len         25
//  data =          0xcd repeated 50 times
//  data_len =      50
//  digest =        0x697eaf0aca3a3aea3a75164746ffaa79
//  
//  test_case =     5
//  key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
//  key_len =       16
//  data =          "Test With Truncation"
//  data_len =      20
//  digest =        0x56461ef2342edc00f9bab995690efd4c
//  digest-96       0x56461ef2342edc00f9bab995
//  
//  test_case =     6
//  key =           0xaa repeated 80 times
//  key_len =       80
//  data =          "Test Using Larger Than Block-Size Key - Hash Key First"
//  data_len =      54
//  digest =        0x6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd
//  
//  test_case =     7
//  key =           0xaa repeated 80 times
//  key_len =       80
//  data =          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
//  data_len =      73
//  digest =        0x6f630fad67cda0ee1fb1f562db3aa53e
//  
//  3. Test Cases for HMAC-SHA-1
//  
//  test_case =     1
//  key =           0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b
//  key_len =       20
//  data =          "Hi There"
//  data_len =      8
//  digest =        0xb617318655057264e28bc0b6fb378c8ef146be00
//  
//  test_case =     2
//  key =           "Jefe"
//  key_len =       4
//  data =          "what do ya want for nothing?"
//  data_len =      28
//  digest =        0xeffcdf6ae5eb2fa2d27416d5f184df9c259a7c79
//  
//  test_case =     3
//  key =           0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
//  key_len =       20
//  data =          0xdd repeated 50 times
//  data_len =      50
//  digest =        0x125d7342b9ac11cd91a39af48aa17b4f63f175d3
//  
//  test_case =     4
//  key =           0x0102030405060708090a0b0c0d0e0f10111213141516171819
//  key_len =       25
//  data =          0xcd repeated 50 times
//  data_len =      50
//  digest =        0x4c9007f4026250c6bc8414f9bf50c86c2d7235da
//  
//  test_case =     5
//  key =           0x0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c
//  key_len =       20
//  data =          "Test With Truncation"
//  data_len =      20
//  digest =        0x4c1a03424b55e07fe7f27be1d58bb9324a9a5a04
//  
//  test_case =     6
//  key =           0xaa repeated 80 times
//  key_len =       80
//  data =          "Test Using Larger Than Block-Size Key - Hash Key First"
//  data_len =      54
//  digest =        0xaa4ae5e15272d00e95705637ce8a3b55ed402112
//  
//  test_case =     7
//  key =           0xaa repeated 80 times
//  key_len =       80
//  data =          "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
//  data_len =      73
//  digest =        0xe8e99d0f45237d786d6bbaa7965c7808bbff1a91
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using System.Text;

using jhblib;

namespace jhblib
{
   public partial class Krypto
   {
      const int  HMAC_KEY_LEN   =   64;
      const byte HMAC_IPAD_BYTE = 0x36;
      const byte HMAC_OPAD_BYTE = 0x5C;
      
      // Use of a hash function delegate allows a generic HMAC implementation. 
      private delegate byte[] HashFunction( byte[] by );
      
      // HMAC per RFC 2104
      private static byte[] hmac(byte[] key, byte[] text, HashFunction hash)
      {
         // Working key buffer.  (If caller's key is too long, use a hash of it instead.)
         byte[] K = (key.Length <= HMAC_KEY_LEN) ? key : hash(key);

         // Build the inner hash buffer
         byte[] inner = new byte[HMAC_KEY_LEN + text.Length];
         Array.Copy(K, 0, inner, 0, K.Length);
         Array.Copy(text, 0, inner, HMAC_KEY_LEN, text.Length);
         for (int i = 0; i < HMAC_KEY_LEN; i++) { inner[i] ^= HMAC_IPAD_BYTE; }

         // Calculate the inner hash value.
         byte[] innerhash = hash(inner);

         // Build the outer hash buffer
         byte[] outer = new byte[HMAC_KEY_LEN + innerhash.Length];
         Array.Copy(K, 0, outer, 0, K.Length);
         Array.Copy(innerhash, 0, outer, HMAC_KEY_LEN, innerhash.Length);
         for (int i = 0; i < HMAC_KEY_LEN; i++) { outer[i] ^= HMAC_OPAD_BYTE; }

         // Compute and return the final hash value.
         return hash(outer);
      }

      // Aliases to allow strings to be used as input.
      private static byte[] hmac(byte[] key, string text, HashFunction hash) {
         return hmac(key, Encoding.UTF8.GetBytes(text), hash);
      }   
      private static byte[] hmac(string key, string text, HashFunction hash) {
         return hmac(Encoding.UTF8.GetBytes(key), Encoding.UTF8.GetBytes(text), hash);
      }
      
      //
      // --- Public members ---------------------------------------------------
      //

      // HMAC_SHA1
      public static byte[] hmac_sha1(byte[] key, byte[] text) { return hmac(key, text, hash_sha1); }
      public static byte[] hmac_sha1(byte[] key, string text) { return hmac(key, text, hash_sha1); }
      public static byte[] hmac_sha1(string key, string text) { return hmac(key, text, hash_sha1); }

      // HMAC_MD5
      //public static byte[] hmac_md5(byte[] key, byte[] text) { return hmac(key, text, hash_md5); }
      //public static byte[] hmac_md5(byte[] key, string text) { return hmac(key, text, hash_md5); }
      //public static byte[] hmac_md5(string key, string text) { return hmac(key, text, hash_md5); }
      
      //
      // --- TEST -------------------------------------------------------------
      //
      public bool SELFTEST() {
      
         byte[] res;
         
         {  // test_case =     1
            var key    = Misc.HexToBytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            var data   = "Hi There";
            var digest = Misc.HexToBytes("b617318655057264e28bc0b6fb378c8ef146be00");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }
         {  //  test_case =     2
            var key    = "Jefe";
            var data   = "what do ya want for nothing?";
            var digest = Misc.HexToBytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }            
         {  //  test_case =     3
            var key    = Misc.HexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            var data   = Misc.HexToBytes("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");
            var digest = Misc.HexToBytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }                        
         {  //  test_case =     4
            var key    = Misc.HexToBytes("0102030405060708090a0b0c0d0e0f10111213141516171819");
            var data   = Misc.HexToBytes("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");
            var digest = Misc.HexToBytes("4c9007f4026250c6bc8414f9bf50c86c2d7235da");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }   
         {  //  test_case =     5
            var key    = Misc.HexToBytes("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
            var data   = "Test With Truncation";
            var digest = Misc.HexToBytes("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }                        
         {  //  test_case =     6
            var key    = Misc.HexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
            var data   = "Test Using Larger Than Block-Size Key - Hash Key First";
            var digest = Misc.HexToBytes("aa4ae5e15272d00e95705637ce8a3b55ed402112");
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }                        
         {  //  test_case =     7
            var key    = Misc.HexToBytes("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");         
            var data   = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
            var digest = Misc.HexToBytes("e8e99d0f45237d786d6bbaa7965c7808bbff1a91");  
            res = hmac_sha1( key, data );
            if (!ArrayOp.Compare( res, digest )) return false;
         }                        
         return true;         
      }
   }
}  