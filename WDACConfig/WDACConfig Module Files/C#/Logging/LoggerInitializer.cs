using System;
using System.Management.Automation.Host;

#nullable enable

namespace WDACConfig
{
    public class LoggerInitializer
    {
        /// <summary>
        /// Gets the VerbosePreference, DebugPreference, and Host from the PowerShell session, each main cmdlet of the WDACConfig module
        /// </summary>
        /// <param name="verbosePreference"></param>
        /// <param name="debugPreference"></param>
        /// <param name="host"></param>
        public static void Initialize(string verbosePreference, string debugPreference, PSHost host)
        {

            if (!string.IsNullOrWhiteSpace(verbosePreference))
            {
                if (string.Equals(verbosePreference, "Continue", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(verbosePreference, "Inquire", StringComparison.OrdinalIgnoreCase))
                {
                    GlobalVars.VerbosePreference = true;
                }
            }

            if (!string.IsNullOrWhiteSpace(debugPreference))
            {
                if (string.Equals(debugPreference, "Continue", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(debugPreference, "Inquire", StringComparison.OrdinalIgnoreCase))
                {
                    GlobalVars.DebugPreference = true;
                }
            }

            if (host != null)
            {
                GlobalVars.Host = host;
            }
        }
    }
}
