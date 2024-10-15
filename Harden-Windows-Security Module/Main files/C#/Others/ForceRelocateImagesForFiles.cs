using System;
using System.Collections.ObjectModel;
using System.Management.Automation;

#nullable enable

namespace HardenWindowsSecurity
{
    public class ForceRelocateImagesForFiles
    {

        /// <summary>
        /// Method that accepts a string array and disables Mandatory ASLR for them
        /// </summary>
        /// <param name="items">program names to disable mandatory ASLR for</param>
        public static void SetProcessMitigationForFiles(string[] items)
        {
            // Initialize PowerShell instance
            using PowerShell powerShell = PowerShell.Create();

            foreach (string item in items)
            {
                // Create a command to set process mitigation
                powerShell.Commands.Clear();
                _ = powerShell.AddCommand("Set-ProcessMitigation")
                           .AddParameter("Name", item)
                           .AddParameter("Disable", "ForceRelocateImages");

                // Execute the command and get the result
                try
                {
                    Collection<PSObject> results = powerShell.Invoke();

                    // Check for errors
                    if (powerShell.Streams.Error.Count > 0)
                    {
                        foreach (ErrorRecord error in powerShell.Streams.Error)
                        {
                            Logger.LogMessage($"Error: {error.Exception.Message}", LogTypeIntel.Error);
                        }
                    }
                    else
                    {
                        Logger.LogMessage($"Excluding {item} from mandatory ASLR.", LogTypeIntel.Information);
                    }
                }
                catch (Exception ex)
                {
                    Logger.LogMessage($"An exception occurred: {ex.Message}", LogTypeIntel.Error);
                }
            }
        }
    }
}
