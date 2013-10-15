// File Header 
// ----------------------------------------------------------------------------
//
// Common.cs - miscellaneous classes of the Common assembly
//
// ----------------------------------------------------------------------------

using System;

using System.Collections.Generic;
using System.Reflection;
using System.Linq;
using System.Text;

using System.Xml;
using System.Xml.Serialization;
using System.Xml.Linq;
using System.IO;

//using System.Security.Cryptography;

using jhblib;

namespace jhblib
{
   public class EasyXml
   {
      // Creates an instance of class T from the given XML string.
      public static T Import<T>(string sXml) {
         using (var reader = new StringReader(sXml)) {
            var serializer = new XmlSerializer(typeof(T));
            return (T)serializer.Deserialize(reader);            
         }   
      }

      // Serializes an instance of class T and returns it as an XML string.
      public static string Export<T>(T that) {
         using(var writer = new StringWriter()) {
            var serializer = new XmlSerializer(typeof(T));
            serializer.Serialize(writer, that);
            return writer.ToString();             
         }   
      }

      public static T ImportFromFile<T>(string sFilename) {
         using (var reader = new StreamReader(sFilename)) {
            var serializer = new XmlSerializer(typeof(T));
            return (T)serializer.Deserialize(reader);
         }
      }

      public static void ExportToFile<T>(T that, string sFilename) {
         using (var writer = new StreamWriter(sFilename)) {
            var serializer = new XmlSerializer(typeof(T));
            serializer.Serialize(writer, that);
         }
      }

      public static string Pretty(string sXml) {
         using (var sw = new StringWriter()) {
            using (var xtw = new XmlTextWriter(sw)) { //, Encoding.Unicode);
               var doc = new XmlDocument();
               doc.LoadXml(sXml);
               xtw.Formatting = Formatting.Indented;
               xtw.IndentChar = '\t';
               doc.WriteContentTo(xtw);
               xtw.Flush();
               //sw.Flush();
               return sw.ToString();
            }
         }
      }

      
      // --------------------------------------------------------------------------------
      // The Dictionary type is not serializable via XmlSerializer -- these two functions
      // provide a way. The XML encoding is arbitrary so they will only work with each
      // other: what you export with ExportDict can be imported with ImportDict, but 
      // otherwise they don't work with any other serialization mechanisms.
      // --------------------------------------------------------------------------------      
      
      public static string ExportDict<KeyT, TVal>(Dictionary<KeyT, TVal> D) {
         return new XElement("Dictionary",
            from d in D
            select new XElement("item"
               , new XAttribute("key", d.Key)
               , new XAttribute("val", d.Value))
         ).ToString();
      }

      // FKey and FVal are functions that provide a way to convert from an XAttribute object
      // to TKey and TVal, respectively.
      public static void ImportDict<TKey, TVal>(ref Dictionary<TKey, TVal> D, string sXml, Func<XAttribute, TKey> FKey, Func<XAttribute, TVal> FVal) {
         XElement xe = XElement.Parse(sXml);
         D = (from item in xe.Descendants("item") select item)
             .ToDictionary(a => FKey(a.Attribute("key")),
                           a => FVal(a.Attribute("val")));
      } 
   }

   public class ArrayOp { // Array operations that .NET left out.
      
      // Compare two arrays, element by element.
      public static bool Compare<T>( T[] a1, T[] a2 ) {
         if ((a1==null) && (a2==null)) { return true;  }
         if ((a1==null) || (a2==null)) { return false; }
         if (a1.Length != a2.Length)   { return false; }
         for (int i = 0; i < a1.Length; i++) { if (! a1[i].Equals( a2[i])) { return false; } }
         return true;      
      }

      // XORs all bytes of a2 into a1.  
      // NOTE: Modifies a1.
      public static void XOR(byte[] a1, byte[] a2) {
         if (a1.Length != a2.Length) { 
            throw new ArgumentException( "Arrays are of different length." ); 
         }
         for (int i=0; i<a1.Length; i++) {
            a1[i] ^= a2[i];
         }
      }
      
      public static T[] Append<T>( T[] a1, T[] a2 ) {
         T[] buf = new T[a1.Length + a2.Length] ;
         Array.Copy(a1, 0, buf, 0, a1.Length);         
         Array.Copy(a2, 0, buf, a1.Length, a2.Length);
         return buf;
      }

      public static T[] Append<T>(T[] a1, T[] a2, T[] a3) {
         return Append<T>(a1, Append<T>(a2, a3));
      }

      public static T[] Reverse<T>(T[] a) {
         for (int i = 0, n = a.Length - 1; i < n; i++, n--)
         {
            Misc.Swap(ref a[i], ref a[n]);
         } 
         return a;
      }

      // This is in .NET if you include "using System.Linq;"
      //public bool Contains<T>( ref T[] A, T a ) {
      //   for (int i = 0; i < A.Length; i++) {
      //      if (A[i].Equals( a )) { 
      //         return true; 
      //      } 
      //   }      
      //   return false;   
      //}      
      
   }   
    
   public class Misc {  
      
      public static void Swap<T>( ref T a, ref T b ) {
         T c = a; a = b; b = c;
      }

      public static T Clip<T>( T a, T min, T max) where T : IComparable {
         return (a.CompareTo(min) < 0) ? min : 
                (a.CompareTo(max) > 0) ? max : a;
      }

      // Useful on CE since foreach does not work with Enums
      // -- NOTE: Omits NoValue from the array, if found.
      public static T[] EnumToArray<T>(T e)
      {
         // Use Reflection to get at the RTTI for this enum type.
         System.Reflection.FieldInfo[] fi = e.GetType().GetFields(BindingFlags.Static | BindingFlags.Public);

         // Build an array from the enumerated type values.
         T[] values = new T[fi.Length];
         for (int i = 0; i < fi.Length; i++) {
            values[i] = (T)fi[i].GetValue(e);
         }
         return values;
      }

      // Utilities for reading and writing individual bits in an
      // an integer value used as a bit field.
      public static void FlagChg(ref int val, int bit, bool bSetClr) {
         val = bSetClr ? (val | bit) : (val &= ~bit);
      }
      public static bool FlagTst(int val, int bit) {
         return (bit == (val & bit));
      }
       
      // Converts a string of delimited hex bytes to a byte array.  Suitable for use
      // with array initializers, for example:
      // byte[] buffer = HexToBytes("12 34 56", ' '); // same as { 0x12, 0x34, 0x56 }
      public static byte[] HexToBytes( string hexBytes, char delim ) {
         string[] hex = hexBytes.Split( delim );
         byte[] buf = new byte[hex.Length];
         for (int i=0; i<hex.Length; i++) {
            buf[i] = Convert.ToByte( hex[i], 16 );
         } 
         return buf;
      }
      
      public static byte[] HexToBytes(string hexBytes) {
         if (0 != (hexBytes.Length % 2)) {
            throw new ArgumentException("HexToBytes: hex string length must be even.");
         }
         
         byte[] buf = new byte[hexBytes.Length / 2];
         for (int i = 0; i < buf.Length; i++) {
            buf[i] = Convert.ToByte(hexBytes.Substring( i*2, 2), 16);
         }
         return buf;
      }
      
      public static bool IsValidHexStr(string hexBytes            ) { try { var a = HexToBytes( hexBytes        ); } catch { return false; } return true; }
      public static bool IsValidHexStr(string hexBytes, char delim) { try { var a = HexToBytes( hexBytes, delim ); } catch { return false; } return true; }      
   }

   // --------------------------------------------------------------------------------------
   // ---    Maths    ----------------------------------------------------------------------
   // --------------------------------------------------------------------------------------
   
   public class Maths {

      // -----------------------------------------------------------------------------------
      //
      // Euclidean algorithm -- calculates GCD of two integers
      //
      //   The Euclidean algorithm is based on the principle that the greatest common 
      //   divisor of two numbers does not change if the smaller number is subtracted 
      //   from the larger number. For example, 21 is the GCD of 252 and 105 (252 = 21 
      //   × 12; 105 = 21 × 5); since 252 − 105 = 147, the GCD of 147 and 105 is also 
      //   21. Since the larger of the two numbers is reduced, repeating this process 
      //   gives successively smaller numbers until one of them is zero. When that 
      //   occurs, the GCD is the remaining nonzero number.  -- Wikipedia
      //
      // -----------------------------------------------------------------------------------
      public static int Euclid_GCD(int a, int b) {
         while ((0 < a) && (0 < b)) {
            if (a < b) b -= a; else a -= b;
         }
         return Math.Max(a,b);
      }
   }

   // ---------------------------------------------------------------------------------------------   
   // UsingBlock
   //                                                                                                      
   // Abstract base class that allows a class to be used with a 'using' statement to force some action 
   // to take place automatically at the end of the 'using' block. Derived class may use the 
   // constructor to initialize the object instance and must override the abstract Finally() method, 
   // which will be executed at the end of the block.
   //
   // NOTE: This is for a special usage of the using statement and iDisposable interfaces, not 
   //       not necessarily related to the their intended purpose of freeing unmanaged resources.
   //
   // Example:
   //
   //    class UB1 : UsingBlock {
   //       string s1, s2;
   //       public UB1(string s1, s2) { this.s1 = s1; this.s2 = s2; Debug.WriteLine( s1 ); }
   //       public override Finally() { Debug.WriteLine( s2 ); }
   //    }
   //
   //    using (var a = new UB1("Entering block", "Exiting block")      // prints "Entering block"
   //    {
   //      // do something in between ...
   //    }                                                              // prints "Exiting block" 
   //
   // ---------------------------------------------------------------------------------------------
   public abstract class UsingBlock : IDisposable
   {
      public abstract void Finally();

      private bool _disposed = true;
      public UsingBlock() { _disposed = false; }

      public void Dispose()
      {
         Dispose(true);
         GC.SuppressFinalize(this);
      }

      protected virtual void Dispose(bool disposing)
      {
         if (!_disposed)
         {
            if (disposing)
            {
               Finally();
            }
            _disposed = true;
         }
      }
   }
}
