using System;
using System.IO;

namespace WDACConfig
{
    public static class StagingArea
    {
        public static DirectoryInfo NewStagingArea(string cmdletName)
        {
            if (string.IsNullOrEmpty(cmdletName))
            {
                throw new ArgumentException("CmdletName cannot be null or empty", nameof(cmdletName));
            }

            string userConfigDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WDACConfig");

            // Define a staging area for the cmdlet
            string stagingArea = Path.Combine(userConfigDir, "StagingArea", cmdletName);

            // Delete it if it already exists with possible content from previous runs
            if (Directory.Exists(stagingArea))
            {
                Directory.Delete(stagingArea, true);
            }

            // Create the staging area for the cmdlet
            DirectoryInfo stagingAreaInfo = Directory.CreateDirectory(stagingArea);

            return stagingAreaInfo;
        }
    }
}
