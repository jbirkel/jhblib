// File Header 
// ----------------------------------------------------------------------------
//
// Common.cs - miscellaneous classes of the Common assembly
//
// ----------------------------------------------------------------------------

using System;

using System.Collections.Generic;
using System.Text;

using System.Xml;
using System.Xml.Serialization;
using System.IO;

using System.Security.Cryptography;

using jhblib;

namespace jhblib
{

   // A place to keep a hashed value (like a password).
   // NOTE: Use EasyXml to serialize/deserialize.
   public class HashStore
   {
      public byte[] hash;
      public byte[] salt;

      public Krypto.HashAlgoID algo;

      // private constructor for packing pieces parts together.
      private HashStore(byte[] hash, byte[] salt, Krypto.HashAlgoID algo) {
         this.hash = hash;
         this.salt = salt;
         this.algo = algo;
      }

      // Parameterless constructor required for XML deserialization.
      public HashStore() : this(new byte[0], new byte[0], Krypto.HashAlgoID.None) { }

      // --------------------------------------------------------------------------------
      // Creates the hash and returns 
      // NOTE: Why didn't I made this a constructor instead of a static function?
      // --------------------------------------------------------------------------------      
      public static HashStore Create(byte[] text, byte[] saltStatic, Krypto.HashAlgoID algo)
      {
         // Create a new random salt for every hash store instance. 
         byte[] saltRandom = Krypto.RandomBytes(16);

         // Hash a string made from the random salt, static salt, and text.      
         byte[] hash = _hash3(text, saltRandom, saltStatic, algo);

         // Return a key store containing both the hash and the random salt.
         return new HashStore(hash, saltRandom, algo);
      }
      public static HashStore Create(string text, byte[] saltStatic, Krypto.HashAlgoID algo) { 
         return Create(Encoding.UTF8.GetBytes(text), saltStatic, algo); 
      }
      
      // -- default algo is SHA-1
      public static HashStore Create(string text, byte[] saltStatic) {
         return Create(Encoding.UTF8.GetBytes(text), saltStatic, Krypto.HashAlgoID.SHA1 );
      }
      public static HashStore Create(byte[] text, byte[] saltStatic) {
         return Create( text, saltStatic, Krypto.HashAlgoID.SHA1);
      }      
      
      // --------------------------------------------------------------------------------
      // Computes the hash for the given text (and static salt) and compares it to this
      // object's hash.
      // --------------------------------------------------------------------------------      
      public bool Verify(byte[] text, byte[] saltStatic) 
      {
         byte[] hash = _hash3(text, this.salt, saltStatic, algo );
         return ArrayOp.Compare(this.hash, hash);
      }

      // alias
      public bool Verify(string text, byte[] saltStatic) { 
         return Verify(Encoding.UTF8.GetBytes(text), saltStatic); 
      }
      
      // --------------------------------------------------------------------------------      
      // Private definition of the hash operation used by this class.  It is:
      //
      //    SHA1( message-text + random-salt + static-salt )
      //
      // NOTE: We convert the inputted byte arrays into strings for code simplicity.
      //       (Probably slower than assembling a byte buffer with byte array copies.)
      // --------------------------------------------------------------------------------
      private static byte[] _hash3(byte[] text, byte[] saltR, byte[] saltS, Krypto.HashAlgoID algo) {
         switch (algo) {
         case Krypto.HashAlgoID.SHA1: 
            return Krypto.hash_sha1(ArrayOp.Append<byte>(text, saltR, saltS));
            
         case Krypto.HashAlgoID.PBKDF2: 
            return Krypto.PBKDF2( text, ArrayOp.Append<byte>(saltR, saltS), 2112, 32);

         default: 
            throw new System.ArgumentException( "_hash3: invalid HashAlgoID", String.Format( "{0}",algo ));                          
         }
      }
   }


   // --------------------------------------------------------------------------------   
   //
   // Uses AES in CBC mode with a 16-byte (128-bit) block size
   //
   // NOTE: Does not use the passed key directly, but instead uses it as a base key
   //       from which to derive an encryption key using PBKDF2. 
   // --------------------------------------------------------------------------------      

   public class CipherStore
   {

      private static int BLK_LEN { get { return Krypto.AES_BLOCK_LEN; } }
      private static int KEY_LEN { get { return Krypto.AES128_KEYLEN; } }

      static byte[] _salt { get { return Krypto.hash_sha1(Encoding.UTF8.GetBytes("CIPHER_STORE_SALT")); }}
      static byte[] _kpad { get { return Krypto.hash_sha1(Encoding.UTF8.GetBytes("CIPHER_STORE_KPAD")); }}
      
      static byte[] _deriveKeyBytes( byte[] key ) {
         return Krypto.PBKDF2(ArrayOp.Append(key, _kpad), _salt, 11717, Krypto.AES128_KEYLEN);      
      }

      public int Version;
      public Krypto.CiphAlgoID Algo;
      public HashStore PlaintextHash;
      public byte[] IV;
      public byte[] CipherText;

      public CipherStore()
      {
         Version = 1;
         Algo = Krypto.CiphAlgoID.AES128_CBC;
      }

      // ----------------------------------------------------------------------
      // Encrypt the given text using the given key and return a CipherStore object.
      // Note: This is, in effect, a static constructor.      
      // ----------------------------------------------------------------------      
      public static CipherStore Create(byte[] text, byte[] key)
      {
         var sa = GetSymAlgo();
         sa.Key = _deriveKeyBytes( key );

         // Calculate the size of the encrypted output.
         // NOTE: There will be between 1 and 16 pad bytes. (Never 0 pad bytes.)
         int encCount = BLK_LEN * (int)((text.Length + 1 + BLK_LEN) / BLK_LEN);

         CipherStore cs = new CipherStore();
         cs.PlaintextHash = HashStore.Create(text, _salt);
         cs.IV = sa.IV;
         cs.CipherText = _encrypt(sa, text, encCount);
         sa.Clear();
         return cs;
      }

      // -- convenience aliases
      public static CipherStore Create(string text, string key) { return Create(Encoding.UTF8.GetBytes(text), Encoding.UTF8.GetBytes(key)); }
      public static CipherStore Create(byte[] text, string key) { return Create(text, Encoding.UTF8.GetBytes(key)); }
      public static CipherStore Create(string text, byte[] key) { return Create(Encoding.UTF8.GetBytes(text), key); }

      // Decrypt the current object and return a string.   
      public byte[] Decrypt(byte[] key)
      {
         var sa = GetSymAlgo();
         sa.Key = _deriveKeyBytes(key);         
         sa.IV = this.IV;

         byte[] text = _decrypt(sa, this.CipherText);

         {  // *T*E*S*T*
            string sDec = Encoding.UTF8.GetString(text, 0, text.Length);
            (new Logger()).LogMsg(Logger.Level.Trace, "CipherStore.Decrypt:\n" + sDec);
         }  // *T*E*S*T* 

         if (!PlaintextHash.Verify(text, _salt)) {
            throw new InvalidOperationException("Error decrypting CipherStore");
         }         

         return text;
      }

      // -- convenience aliases
      public string DecryptString(byte[] key)
      {
         byte[] buf = Decrypt(key);
         return Encoding.UTF8.GetString(buf, 0, buf.Length);
      }

      public byte[] Decrypt(string key) { return Decrypt(Encoding.UTF8.GetBytes(key)); }
      public string DecryptString(string key) { return DecryptString(Encoding.UTF8.GetBytes(key)); }

      // We use 128-bit Rijndael with PKCS7 padding in CBC mode. (AES)
      private static SymmetricAlgorithm GetSymAlgo()
      {
         var sa = new RijndaelManaged();
         sa.BlockSize = BLK_LEN * 8;  // number of bits
         sa.KeySize   = KEY_LEN * 8;  // number of bits
         sa.Padding   = PaddingMode.PKCS7;
         sa.Mode      = CipherMode.CBC;
         return sa;
      }

      private static byte[] _encrypt(SymmetricAlgorithm sa, byte[] text, int outCount)
      {
         MemoryStream ms = new MemoryStream(outCount);
         CryptoStream ksEnc = new CryptoStream(ms, sa.CreateEncryptor(), CryptoStreamMode.Write);
         ksEnc.Write(text, 0, text.Length);
         ksEnc.FlushFinalBlock();  // Close?         
         ksEnc.Clear();

         return ms.GetBuffer();
      }

      private static byte[] _decrypt(SymmetricAlgorithm sa, byte[] text)
      {
         MemoryStream msDec = new MemoryStream(text);
         CryptoStream ksDec = new CryptoStream(msDec, sa.CreateDecryptor(), CryptoStreamMode.Read);
         byte[] buf = new byte[msDec.Length];
         int decCount = ksDec.Read(buf, 0, buf.Length);
         ksDec.Clear();

         // Copy the decrypted data into a buffer of the correct size.
         byte[] ret = new byte[decCount];
         Array.Copy(buf, ret, ret.Length);

         return ret;
      }


      // Test vectors from RFC 3602
      public static bool Test() { return _test(); }
      private static bool _test()
      {
         var sa = GetSymAlgo();
         sa.Padding = PaddingMode.None;

         // Case #1: Encrypting 16 bytes (1 block) using AES-CBC with 128-bit key         
         // Key       : 0x06a9214036b8a15b512e03d534120006
         // IV        : 0x3dafba429d9eb430b422da802c9fac41
         // Plaintext : "Single block msg"
         // Ciphertext: 0xe353779c1079aeb82708942dbe77181a
         // 
         sa.Key = Misc.HexToBytes("06a9214036b8a15b512e03d534120006");
         sa.IV  = Misc.HexToBytes("3dafba429d9eb430b422da802c9fac41");
         {
            byte[] pt = Encoding.ASCII.GetBytes("Single block msg");
            byte[] ct = Misc.HexToBytes("e353779c1079aeb82708942dbe77181a");
            if (!ArrayOp.Compare(ct, _encrypt(sa, pt, 16))) { return false; }
         }

         // Case #2: Encrypting 32 bytes (2 blocks) using AES-CBC with 128-bit key
         // Key       : 0xc286696d887c9aa0611bbb3e2025a45a
         // IV        : 0x562e17996d093d28ddb3ba695a2e6f58
         // Plaintext : 0x000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f
         // Ciphertext: 0xd296cd94c2cccf8a3a863028b5e1dc0a 7586602d253cfff91b8266bea6d61ab1
         sa.Key = Misc.HexToBytes("c286696d887c9aa0611bbb3e2025a45a");
         sa.IV  = Misc.HexToBytes("562e17996d093d28ddb3ba695a2e6f58");
         {
            byte[] pt = Misc.HexToBytes("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
            byte[] ct = Misc.HexToBytes("d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1");
            if (!ArrayOp.Compare(ct, _encrypt(sa, pt, 32))) { return false; }
         }

         // Case #3: Encrypting 48 bytes (3 blocks) using AES-CBC with 128-bit key
         // Key       : 0x6c3ea0477630ce21a2ce334aa746c2cd
         // IV        : 0xc782dc4c098c66cbd9cd27d825682c81
         // Plaintext : "This is a 48-byte message (exactly 3 AES blocks)"
         // Ciphertext: 0xd0a02b3836451753d493665d33f0e886 2dea54cdb293abc7506939276772f8d5 021c19216bad525c8579695d83ba2684
         sa.Key = Misc.HexToBytes("6c3ea0477630ce21a2ce334aa746c2cd");
         sa.IV  = Misc.HexToBytes("c782dc4c098c66cbd9cd27d825682c81");
         {
            byte[] pt = Encoding.ASCII.GetBytes("This is a 48-byte message (exactly 3 AES blocks)");
            byte[] ct = Misc.HexToBytes("d0a02b3836451753d493665d33f0e8862dea54cdb293abc7506939276772f8d5021c19216bad525c8579695d83ba2684");
            if (!ArrayOp.Compare(ct, _encrypt(sa, pt, 48))) { return false; }
         }

         // Case #4: Encrypting 64 bytes (4 blocks) using AES-CBC with 128-bit key
         // Key       : 0x56e47a38c5598974bc46903dba290349
         // IV        : 0x8ce82eefbea0da3c44699ed7db51b7d9
         // Plaintext : 0xa0a1a2a3a4a5a6a7a8a9aaabacadaeaf b0b1b2b3b4b5b6b7b8b9babbbcbdbebf c0c1c2c3c4c5c6c7c8c9cacbcccdcecf d0d1d2d3d4d5d6d7d8d9dadbdcdddedf
         // Ciphertext: 0xc30e32ffedc0774e6aff6af0869f71aa 0f3af07a9a31a9c684db207eb0ef8e4e 35907aa632c3ffdf868bb7b29d3d46ad 83ce9f9a102ee99d49a53e87f4c3da55
         //         
         sa.Key = Misc.HexToBytes("56e47a38c5598974bc46903dba290349");
         sa.IV  = Misc.HexToBytes("8ce82eefbea0da3c44699ed7db51b7d9");
         {
            byte[] pt = Misc.HexToBytes("a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf");
            byte[] ct = Misc.HexToBytes("c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55");
            if (!ArrayOp.Compare(ct, _encrypt(sa, pt, 64))) { return false; }
         }

         return true;
      }
   }

   public partial class Krypto
   {

      public enum HashAlgoID { None = 0, SHA1 = 1, PBKDF2 = 2 };

      public enum CiphAlgoID { None, AES128_CBC }; //, AES192_CBC, AES256_CBC };

      public const int AES_BLOCK_LEN = 16; // bytes
      public const int AES128_KEYLEN = 16; // bytes      
      public const int AES192_KEYLEN = 24; // bytes                  
      public const int AES256_KEYLEN = 32; // bytes    

      //public static byte[] hash_md5 (string s ) { return hash_md5(Encoding.UTF8.GetBytes(s));  }
      //public static byte[] hash_md5 (byte[] by) { return MD5.Create().ComputeHash(by);         }
      public static byte[] hash_sha1(string s ) { return hash_sha1(Encoding.UTF8.GetBytes(s)); }
      public static byte[] hash_sha1(byte[] by) { return SHA1.Create().ComputeHash(by);        }

      public static string base64(byte[] by) { return Convert.ToBase64String(by); }

      // --------------------------------------------------------------------------------
      // Produces a repeatable stream of bytes for a given input.  Intended for creating 
      // a symmetric encryption key from a text password or phrase.  (Uses PBKDF2 to make 
      // it harder to reverse engineer the password from the generated key.)
      //
      // === IMPORTANT ===
      // Once this code is released, the salt and count values can never change.  If need 
      // be, add a new function for new code, but ensure the old one is available for 
      // legacy use.
      // === IMPORTANT ===
      // --------------------------------------------------------------------------------      

      public static byte[] DeriveKeyBytes(byte[] text, int keylen) {
         byte[] SALT = (new Guid(0x7331c367, 0x5645, 0x4baa, 0x87, 0x5, 0x3d, 0x69, 0x12, 0xe9, 0xbc, 0x7)).ToByteArray();
         int COUNT = 4077; // M*A*S*H
         return PBKDF2(text, SALT, COUNT, keylen);
      }

      // Faster version of the above for non-cryptographic uses. 
      public static byte[] DeriveBytes(byte[] text, int keylen) {
         return PBKDF2(text, new byte[] { 1, 2, 3, 4 }, 5, keylen);
      }

      // convenience alias
      public static byte[] DeriveKeyBytes(string text, int keylen) { return DeriveKeyBytes(Encoding.UTF8.GetBytes(text), keylen); }
      public static byte[] DeriveBytes(string text, int keylen) { return DeriveBytes(Encoding.UTF8.GetBytes(text), keylen); }
      // --------------------------------------------------------------------------------      


      // --------------------------------------------------------------------------------
      // Generate a "nonce" string or byte array.  
      //
      private static int _nonce_ctr = 0;
      private static int NonceCounter { get { return _nonce_ctr++; } }
      //    
      // Note: The (DateTime + ticks + internal counter) portion of the string should be 
      //       enough to ensure that the same string can never be returned twice. The 
      //       random bytes are added as salt to make the return string less predictable.
      //
      private static string _nonce_base()
      {
         return DateTime.UtcNow.ToString("yyyyMMddHHmmss")
              + Environment.TickCount.ToString()
              + NonceCounter.ToString()
              + RandomBytes(8).ToString();
      }

      public static byte[] NonceBytes(int count) { return DeriveBytes(_nonce_base(), count); }
      public static string NonceString() { return base64(DeriveBytes(_nonce_base(), 15)); }

      // --------------------------------------------------------------------------------      


      // --------------------------------------------------------------------------------
      // Random number generator support.

      public static byte[] RandomBytes(int count)
      {
         byte[] by = new byte[count];
         (new RNGCryptoServiceProvider()).GetBytes(by);
         return by;
      }

      public static Int32 RandomInt()
      {
         return BitConverter.ToInt32(RandomBytes(sizeof(Int32)), 0);
      }
      // --------------------------------------------------------------------------------      
   }
}
