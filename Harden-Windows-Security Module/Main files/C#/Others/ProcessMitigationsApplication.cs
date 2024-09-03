using System;
using System.Collections.Generic;
using System.Linq;
using System.Management.Automation;
using Microsoft.Win32;

#nullable enable

namespace HardenWindowsSecurity
{
    internal static class ProcessMitigationsApplication
    {
        internal static void Apply()
        {

            if (GlobalVars.ProcessMitigations == null)
            {
                throw new Exception("No process mitigations found in the global variable.");
            }

            // Group the data by ProgramName
            var groupedMitigations = GlobalVars.ProcessMitigations
                .GroupBy(pm => pm.ProgramName)
                .ToArray();

            // Get the current process mitigations from the registry
            var allAvailableMitigations = Registry.LocalMachine
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
                ?.GetSubKeyNames();

            if (allAvailableMitigations == null)
            {
                throw new Exception("Failed to read registry keys.");
            }

            // Create a PowerShell instance
            using (var ps = PowerShell.Create())
            {
                // Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
                HardenWindowsSecurity.Logger.LogMessage("Removing the existing process mitigations", LogTypeIntel.Information);
                foreach (var group in groupedMitigations)
                {
                    string? fileName = System.IO.Path.GetFileName(group.Key);

                    if (allAvailableMitigations.Contains(fileName))
                    {
                        try
                        {
                            Registry.LocalMachine.DeleteSubKeyTree(
                                $@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{fileName}",
                                false);
                        }
                        catch (Exception ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage($"Failed to remove {fileName}, it's probably protected by the system. {ex.Message}", LogTypeIntel.Error);
                        }
                    }
                }

                // Adding the process mitigations
                HardenWindowsSecurity.Logger.LogMessage("Adding the process mitigations", LogTypeIntel.Information);
                foreach (var group in groupedMitigations)
                {
                    // Clear previous commands
                    ps.Commands.Clear();

                    var programName = group.Key;
                    HardenWindowsSecurity.Logger.LogMessage($"Adding process mitigations for {programName}", LogTypeIntel.Information);

                    var enableMitigations = group.Where(g => string.Equals(g.Action, "Enable", StringComparison.OrdinalIgnoreCase))
                                                 .Select(g => g.Mitigation)
                                                 .ToArray();

                    var disableMitigations = group.Where(g => string.Equals(g.Action, "Disable", StringComparison.OrdinalIgnoreCase))
                                                  .Select(g => g.Mitigation)
                                                  .ToArray();

                    // Create the command and add parameters
                    var command = new PSCommand();
                    command.AddCommand("Set-ProcessMitigation");
                    command.AddParameter("Name", programName);

                    if (enableMitigations.Length > 0)
                    {
                        command.AddParameter("Enable", enableMitigations);
                    }

                    if (disableMitigations.Length > 0)
                    {
                        command.AddParameter("Disable", disableMitigations);
                    }

                    // Add the command to the PowerShell instance
                    ps.Commands = command;
                    ps.Invoke();

                    // Check for errors
                    if (ps.HadErrors)
                    {
                        var errors = ps.Streams.Error.ReadAll();
                        foreach (var error in errors)
                        {
                            HardenWindowsSecurity.Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
                        }
                    }
                }
            }
        }
    }
}
