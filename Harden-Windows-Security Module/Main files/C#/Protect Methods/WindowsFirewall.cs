using System;
using System.IO;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Collections.Generic;
using System.Globalization;

#nullable enable

namespace HardenWindowsSecurity
{
    public class WindowsFirewall
    {
        public static void Invoke()
        {
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            HardenWindowsSecurity.Logger.LogMessage("Running the Windows Firewall category");
            HardenWindowsSecurity.LGPORunner.RunLGPOCommand(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Security-Baselines-X", "Windows Firewall Policies", "registry.pol"), LGPORunner.FileType.POL);


            HardenWindowsSecurity.Logger.LogMessage("Disabling Multicast DNS (mDNS) UDP-in Firewall Rules for all 3 Firewall profiles - disables only 3 rules");



            // The PowerShell script as a string
            string script = """
                Get-NetFirewallRule |
                Where-Object -FilterScript { ($_.RuleGroup -eq '@%SystemRoot%\system32\firewallapi.dll,-37302') -and ($_.Direction -eq 'inbound') } |
                ForEach-Object -Process { Disable-NetFirewallRule -DisplayName $_.DisplayName }
            """;

            // Create a PowerShell instance
            using (PowerShell psInstance = PowerShell.Create())
            {
                // Add the script to the PowerShell instance
                psInstance.AddScript(script);

                try
                {
                    // Execute the script
                    Collection<PSObject> results = psInstance.Invoke();

                    // Check for any errors during execution
                    if (psInstance.HadErrors)
                    {
                        // Iterate over the errors and throw an exception
                        foreach (ErrorRecord error in psInstance.Streams.Error)
                        {
                            throw new Exception($"PowerShell error: {error.ToString()}");
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Handle the exception or rethrow it
                    HardenWindowsSecurity.Logger.LogMessage($"An error occurred: {ex.Message}");
                    throw;
                }
            }
        }
    }
}
