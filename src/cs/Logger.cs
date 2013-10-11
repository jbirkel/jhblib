// File Header 
// ----------------------------------------------------------------------------
//
// Logger.cs - classes related to logging 
//
// ----------------------------------------------------------------------------

using System;
using System.Collections.Generic;
//using System.Windows.Forms;
using System.IO;
using System.Linq;
using System.Text;
using System.Reflection;

namespace jhblib
{
   // Provides log target semantics
   public abstract class LogTgt {
      public abstract void Output(string s); 
   }
   
   // Logs to the CLR system diagnostics debug output
   public class LogTgtDiag : LogTgt {
      public override void Output(string s) {
         const int max = 256;  // debug console limit                         
         int i; for (i=0; max < (s.Length - i); i+=max) {
            System.Diagnostics.Debug.Write(s.Substring(i, max));
         }
         System.Diagnostics.Debug.WriteLine(s.Substring(i));         
      }
   }   

   public class LogTgtFile : LogTgt {
      public LogTgtFile( string file ) { _construct( file, 0, 0 ); }   
      
      // for ping-pong behavior
      public LogTgtFile( string file, int count, int maxLen ) {      
         _construct( file, count, maxLen );
      } 
      
      private void _construct( string file, int count, int maxLen ) {
         _fileName   = file;             // file name base, path optional
         _filePath   = _buildFileName(); // complete, working file path
         _fileCount  = count;
         _fileMaxLen = maxLen;
      }         
     
      public override void Output(string s) {
         _overflowIfNeeded();
         try { 
            using (FileStream fs = new FileStream( _filePath, FileMode.OpenOrCreate | FileMode.Append )) {
               byte[] byOut = Encoding.ASCII.GetBytes(s);
               fs.Write(byOut, 0, byOut.Length);    
            }
         }
         catch {} // what to do? (can't log it) 
      } 
       
      // Do we need to overflow?  If so, do so.
      private void _overflowIfNeeded() { 
         bool bOverflow = false;     
         try {  using (FileStream fs = new FileStream( _filePath, FileMode.OpenOrCreate )) {
                   bOverflow = (0 < _fileMaxLen && _fileMaxLen < fs.Length);
                }    
         } catch {}   
         
         if (bOverflow) { _overflow(); }
      }

      // When main file is full, delete the last overflow file and then increment
      // the names of the log and other overflow files.
      private void _overflow() {
      
         // Start by deleting the last overflow file. // NOTE: It may not exist.
         try { File.Delete(_buildFileName(_fileCount - 1)); } catch { }

         // Now rename all the existing overflows, some or all which may not exist.
         for (int i = _fileCount - 1; 2 <= i; i--) {
            try { File.Move(_buildFileName(i - 1), _buildFileName(i)); } catch { }
         }

         // Finally rename the current log file to index 1.
         try { File.Move(_filePath, _buildFileName(1)); } catch { }     
         
         // This last step shouldn't be necessary.  After renaming the log file to be the
         // the first overflow file it should be effectively deleted.  However, on WinCE 
         // this doesn't seem to happen. 
         //try { File.Delete(_filePath); } catch { }              
         
      }
     
      private string _buildFileName() { return _buildFileName( -1 ); }
     
      private string _buildFileName( int index ) {
 
         // Get pieces-parts.     
         string sRoot = Path.GetPathRoot                ( _fileName ); 
         string sFile = Path.GetFileNameWithoutExtension( _fileName );
         string sExt  = Path.GetExtension               ( _fileName );
         
         // If there is a file index, add it. 
         if (0 <= index) { 
            sFile += index.ToString(); 
         } 
         
         // If no path, put it with the EXE
         if (0 == sRoot.Length) {
            sRoot = Path.GetDirectoryName( Assembly.GetExecutingAssembly().ManifestModule.FullyQualifiedName );
         }   
         
         return sRoot + Path.DirectorySeparatorChar + sFile + sExt;         
      }
      
      
      private string _fileName;
      private string _filePath;            
      private int    _fileMaxLen;
      private int    _fileCount;  // total of log file + overflow files    
   }
   

   // Provides logging semantics
   public class Logger
   {
      private Level  _level ;
      private Header _header;
      private LogTgt _logTgt;
      
      private uint _lineNum;
      
      [FlagsAttribute]
      public enum Header { None = 0, Date = 1, Time = 2, Level = 4, Line = 8 };
      public enum Level  { None = 0, Error, Warning, Trace, Debug } ;

      private void _init() {
         _logTgt = new LogTgtDiag();
         _header = Header.Time | Header.Level | Header.Line ;
         _level  = Level.Trace;      
         _lineNum = 0;
      }
      public Logger() {      
         _init();
      }
      public Logger(LogTgt tgt) {
         _init(); _logTgt = tgt;
      }   
      public Logger(LogTgt tgt, Level lvl ) {
         _init(); _logTgt = tgt; _level = lvl;
      }
      public Logger(LogTgt tgt, Level lvl, Header hdr) {
         _logTgt = tgt; _level = lvl; _header = hdr;  
      }      
      
      public void SetLevel ( Level  value ) { _level  = value; }
      public void SetHeader( Header value ) { _header = value; }
      public void SetTarget( LogTgt value ) { _logTgt = value; }            
      
      public class LevelProps_t {
         public Level  lvl;
         public string sShort;
         public string sLong;
         public LevelProps_t(Level lvl, string sShort, string sLong) {
            this.lvl = lvl; this.sShort = sShort; this.sLong = sLong;
         }
         
         // Required by LevelTable.
         public Level Index { get { return lvl; } }
      }

      private static LevelProps_t[] _level_props = 
      {  new LevelProps_t( Level.None   , "???", "None"    )  // Can we pull the long name from the RTTI?
      ,  new LevelProps_t( Level.Error  , "ERR", "Error"   )            
      ,  new LevelProps_t( Level.Warning, "WRN", "Warning" )            
      ,  new LevelProps_t( Level.Trace  , "TRC", "Trace"   )      
      ,  new LevelProps_t( Level.Debug  , "DBG", "Debug"   )            
      };
      private static Dictionary<Level, LevelProps_t> _level_table = _level_props.ToDictionary(a => a.lvl);

      public void LogMsg(Level lvl, string source, string message) {
         LogMsg(lvl, String.Format("[SRC:{0}] {1}", source, message ));
      }
      public void LogMsg(Level lvl, string message)
      {
         if (lvl > _level) return;
         
         // Format header                                                                             .
         var sb = new StringBuilder(100);
         
         if (Header.None != _header) {
         
            if (Header.Line == (Header.Line & _header)) {
               sb.AppendFormat("{0:D4} ", _lineNum++ );            
            }       
         
            // For date and time headers   
            DateTime dtNow = DateTime.Now;

// How to get millisecond resolution?
// -- Environment.Ticks provides ms, but it's not synchronized with the real time clock.
// -- Note, it depends on h/w.  Do some devices provide it?
            
            if (Header.Date == (Header.Date & _header)) {
               sb.AppendFormat( "{0:YYYY-MM-dd} ", dtNow );
            }
            if (Header.Time == (Header.Time & _header)) {
               sb.AppendFormat( "{0:HH:mm:ss.fff} ", dtNow );            
            }
            if (Header.Level == (Header.Level & _header)) {            
               sb.AppendFormat( "{0} ", _level_table[lvl].sShort ); 
            }
         }
         
         sb.AppendFormat("{0}{1}", message, Environment.NewLine);
         
         // Print header and message.
         _logTgt.Output(sb.ToString());
      }

      public void Error  (string message) { LogMsg(Level.Error  , message); }
      public void Warning(string message) { LogMsg(Level.Warning, message); }
      public void Trace  (string message) { LogMsg(Level.Trace  , message); }
      public void Debug  (string message) { LogMsg(Level.Debug  , message); }      
      
      // Log an instance of a System.Exception type.
      // NOTES:
      // -- StackTrace.GetFrames() not supported in CF
      // -- Apparently System.Diagnostics.StackTrace/StackFrame is not available n CF?   
      //
      public void LogException( Exception e ) { 
         LogException( e, "" ); 
      }
      public void LogException( Exception e, string message ) {
         var sb = new StringBuilder ();
         sb.AppendFormat( "Exception! ({2}): {0}: {1}", e.GetType().Name, e.Message, message );
         
         Exception ei = e;
         while (null != (ei = ei.InnerException)) {
            sb.AppendFormat(", Inner Exception: {0}", ei.Message );  
         }
         LogMsg(Level.Error, sb.ToString());         
      }
      public void LogStackTrace( Exception e ) {
         LogMsg(Level.Debug, String.Format( "Stack Trace\n{0}", e.StackTrace ));

         // Only print the first line of the stack trace, which will indicate the function
         // closest to the point of exception.  
         //string tr = e.StackTrace;
         //String[] lines =  tr.Split( new Char[] { '\r', '\n' } );
         //if (0 < lines.Length) { s += String.Format(" ({0})", lines[0] ); }         
      }

// This is what e.ToString looks like:
/*           
System.InvalidOperationException: There is an error in XML document (1, 41). ---> System.InvalidOperationException: Common.HashedKeyStore cannot be serialized because it does not have a parameterless constructor.

at System.Xml.Serialization.SerializationHelper.CreateInstance()
at System.Xml.Serialization.XmlSerializationReader.DeserializeComplexElement()
at System.Xml.Serialization.XmlSerializationReader.deserializeElement()
at System.Xml.Serialization.XmlSerializationReader.DeserializeElement()
at System.Xml.Serialization.XmlSerializer.Deserialize()
at System.Xml.Serialization.XmlSerializer.Deserialize()
at System.Xml.Serialization.XmlSerializer.Deserialize()
at Common.EasyXml.CreateFromXml()
at wim.LoginDlg..ctor()
at wim.Form1.mnuLogin_Click()
at System.Windows.Forms.MenuItem.OnClick()
at System.Windows.Forms.Menu.ProcessMnuProc()
at System.Windows.Forms.Form.WnProc()
at System.Windows.Forms.Control._InternalWnProc()
at Microsoft.AGL.Forms.EVL.EnterMainLoop()
at System.Windows.Forms.Application.Run()
at wim.Program.Main()

Notes:
-- e.GetType().Name = "System.InvalidOperationException"
-- e.Message = "There is an error in XML document (1, 41)"
-- e.InnerException.Message = "Common.HashedKeyStore cannot be serialized because it does not have a parameterless constructor."
*/
   }
   
/*
   public class UsrMsg {
   
      static string AppName;
   
      // Optional initialization.  
      // Use: UsrMsg.InitApp( Assembly.GetExecutingAssembly() ) from main form class.
      static void InitApp( Assembly app ) {
         
         object[] ret = app.GetCustomAttributes(typeof(AssemblyProductAttribute), false);
         if (0 < ret.Length) {
            AppName = ((AssemblyProductAttribute)attributes[0]).Product;
         }   
      }
      
      public static void UsrMsgWrn(string sMsg) { MessageBox.Show(sMsg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation, MessageBoxDefaultButton.Button1); }
      public static void UsrMsgErr(string sMsg) { MessageBox.Show(sMsg, AppName, MessageBoxButtons.OK, MessageBoxIcon.Asterisk, MessageBoxDefaultButton.Button1); }      
   }
*/
}


         
