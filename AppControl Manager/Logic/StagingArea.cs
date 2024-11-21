using System;
using System.IO;

namespace WDACConfig
{
    public static class StagingArea
    {
        /// <summary>
        /// Creating a directory as a staging area for a job and returns the path to that directory
        /// </summary>
        /// <param name="cmdletName"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static DirectoryInfo NewStagingArea(string cmdletName)
        {
            if (string.IsNullOrWhiteSpace(cmdletName))
            {
                throw new ArgumentException("CmdletName cannot be null or whitespace", nameof(cmdletName));
            }

            // Define a staging area for the cmdlet
            string stagingArea = Path.Combine(GlobalVars.StagingArea, cmdletName);

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
