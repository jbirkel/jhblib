using System;
using System.Windows.Forms;

namespace jhblib
{
   public class FormHelp
   {
      // Set focus to the control with the least tabIndex in the given control container.
      public static void SetFirstFocus(Panel panel) {
         Control cFirst = null;
         foreach (Control c in panel.Controls) {
            if (c.TabStop && ((null == cFirst) || (c.TabIndex < cFirst.TabIndex)))
            {
               cFirst = c;
            }
         }
         if (null != cFirst) { 
            cFirst.Focus();         
         }   
      }
   }
}
