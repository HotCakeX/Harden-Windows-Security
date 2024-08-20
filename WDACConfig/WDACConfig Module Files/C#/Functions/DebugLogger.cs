using System;
using System.Management.Automation.Host;

#nullable enable

namespace WDACConfig
{
    public static class DebugLogger
    {
        /// <summary>
        /// Write a Debug message to the console
        /// The Debug messages are not redirectable in PowerShell
        /// https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface
        /// </summary>
        /// <param name="message"></param>
        public static void Write(string message)
        {
            try
            {
                if (string.Equals(WDACConfig.GlobalVars.DebugPreference, "Continue", StringComparison.OrdinalIgnoreCase) ||
     string.Equals(WDACConfig.GlobalVars.DebugPreference, "Inquire", StringComparison.OrdinalIgnoreCase))
                {
                    WDACConfig.GlobalVars.Host.UI.WriteDebugLine(message);
                }

            }
            // Do not do anything if errors occur
            // Since many methods write to the console asynchronously this can throw errors
            // implement better ways such as using log file or in the near future a GUI for writing Debug messages when -Debug is used
            catch { }
        }
    }
}
