// --- File Header ------------------------------------------------------------
//
// PBKDF2.CS
//  
//   A C# implementation of PBKDF2 as described in RFC 2898. 
//
// From RFC 2898:
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

using System;
using System.Collections.Generic;
using System.Text;

//using jhblib;

namespace jhblib
{
   public partial class Krypto
   {
      // Password-based key derivation algorithm. 
      // - text  : typically, a user-entered password or phrase
      // - salt  : caller's "entropy"
      // - count : number of times to iterate the hashing loop.
      // - length: the desired number of bytes in the returned byte array
      public static byte[] PBKDF2(byte[] text, byte[] salt, int count, int keylen)
      {
         // Size the key buffer to the caller's requested length.
         byte[] key = new byte[keylen];
         
          // Loop until we've generated the requested number of bytes.
         int more = keylen;
         for (int i=1; 0<more; i++)
         {
            // Where the magic happens.
            byte[] T = F( text, salt, count, i );
            
            // Append as many bytes of hash as needed to the key buffer.  
            int nCopyCount = Math.Min(more, T.Length);
            Array.Copy(T, 0, key, keylen - more, nCopyCount);

            // Reduce the "more" counter by the number of bytes we just copied.
            more -= nCopyCount;
         }
         return key;
      }
      
      // -- convenience alias
      public static byte[] PBKDF2(string text, string salt, int count, int keylen) { 
         return PBKDF2( Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(salt), count, keylen );
      }

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
      private static byte[] F(byte[] P, byte[] S, int count, int index)
      {
         // Convert the index value into a 4-byte byte array in big endian byte order.
         byte[] I = BitConverter.GetBytes((Int32)index);         
         if (BitConverter.IsLittleEndian) { 
            I = ArrayOp.Reverse( I ); 
         }  

         // U_1:
         byte[] U_i = hmac_sha1( P, ArrayOp.Append( S, I ));
         byte[] U   = U_i;
         
         // U_2 thru U_c:
         for (int i=2; i<=count; i++) {
            U_i = hmac_sha1( P, U_i );
            ArrayOp.XOR( U, U_i );
         }         
         
         return U;
      }
      
      // =========
      // *T*E*S*T*
      // =========      
      
      public static bool TestPBKDF2() { return _test_PBKDF2(); }

      // Test vectors from RFC 6070.  (See file header, above.)
      private static bool _test_PBKDF2()
      {  
         byte[] v;
         v = Misc.HexToBytes("0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6", ' ');
         if (!ArrayOp.Compare(v, PBKDF2("password", "salt", 1, 20))) { return false; }

         v = Misc.HexToBytes("ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57", ' ');
         if (!ArrayOp.Compare(v, PBKDF2("password", "salt", 2, 20))) { return false; }

         v = Misc.HexToBytes("4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1", ' ');
         if (!ArrayOp.Compare(v, PBKDF2("password", "salt", 4096, 20))) { return false; }

         // This one is rather time consuming.
         //v = Misc.HexToBytes( "ee fe 3d 61 cd 4d a4 e4 e9 94 5b 3d 6b a2 15 8c 26 34 e9 84", ' ' );
         //if (!ArrayOp.Compare( v, PBKDF2("password", "salt", 16777216, 20) )) { return false; }

         v = Misc.HexToBytes("3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38", ' ');
         if (!ArrayOp.Compare(v, PBKDF2("passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096, 25))) { return false; }

         v = Misc.HexToBytes("56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3", ' ');
         if (!ArrayOp.Compare(v, PBKDF2("pass\0word", "sa\0lt", 4096, 16))) { return false; }

         return true;
      }
   }
}
