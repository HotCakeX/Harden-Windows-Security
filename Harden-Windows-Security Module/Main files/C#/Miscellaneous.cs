using System;
using System.IO;

namespace HardeningModule
{
    public class Miscellaneous
    {
        // Clean up the working directory at the end of each cmdlet
        public static void CleanUp()
        {
            if (Directory.Exists(GlobalVars.WorkingDir))
            {
                Directory.Delete(GlobalVars.WorkingDir, true);
            }
        }
    }
}