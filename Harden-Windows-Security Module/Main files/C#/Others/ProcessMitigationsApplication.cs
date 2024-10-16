using Microsoft.Win32;
using System;
using System.Linq;
using System.Management.Automation;

#nullable enable

namespace HardenWindowsSecurity
{
    public static class ProcessMitigationsApplication
    {
        public static void Apply()
        {

            if (GlobalVars.ProcessMitigations is null)
            {
                throw new InvalidOperationException("No process mitigations found in the global variable.");
            }

            // Group the data by ProgramName
            var groupedMitigations = GlobalVars.ProcessMitigations
                .GroupBy(pm => pm.ProgramName)
                .ToArray();

            // Get the current process mitigations from the registry
            var allAvailableMitigations = (Registry.LocalMachine
                .OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
                ?.GetSubKeyNames()) ?? throw new InvalidOperationException("Failed to read registry keys.");

            // Create a PowerShell instance
            using var ps = PowerShell.Create();

            // Loop through each group to remove the mitigations, this way we apply clean set of mitigations in the next step
            Logger.LogMessage("Removing the existing process mitigations", LogTypeIntel.Information);
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
                        Logger.LogMessage($"Failed to remove {fileName}, it's probably protected by the system. {ex.Message}", LogTypeIntel.Error);
                    }
                }
            }

            // Adding the process mitigations
            Logger.LogMessage("Adding the process mitigations", LogTypeIntel.Information);
            foreach (var group in groupedMitigations)
            {
                // Clear previous commands
                ps.Commands.Clear();

                var programName = group.Key;
                Logger.LogMessage($"Adding process mitigations for {programName}", LogTypeIntel.Information);

                var enableMitigations = group.Where(g => string.Equals(g.Action, "Enable", StringComparison.OrdinalIgnoreCase))
                                             .Select(g => g.Mitigation)
                                             .ToArray();

                var disableMitigations = group.Where(g => string.Equals(g.Action, "Disable", StringComparison.OrdinalIgnoreCase))
                                              .Select(g => g.Mitigation)
                                              .ToArray();

                // Create the command and add parameters
                var command = new PSCommand();
                _ = command.AddCommand("Set-ProcessMitigation");
                _ = command.AddParameter("Name", programName);

                if (enableMitigations.Length > 0)
                {
                    _ = command.AddParameter("Enable", enableMitigations);
                }

                if (disableMitigations.Length > 0)
                {
                    _ = command.AddParameter("Disable", disableMitigations);
                }

                // Add the command to the PowerShell instance
                ps.Commands = command;
                _ = ps.Invoke();

                // Check for errors
                if (ps.HadErrors)
                {
                    var errors = ps.Streams.Error.ReadAll();
                    foreach (var error in errors)
                    {
                        Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
                    }
                }
            }
        }
    }
}
