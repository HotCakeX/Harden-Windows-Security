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
                WDACConfig.GlobalVars.VerbosePreference = verbosePreference;
            }

            if (!string.IsNullOrWhiteSpace(debugPreference))
            {
                WDACConfig.GlobalVars.DebugPreference = debugPreference;
            }

            if (host != null)
            {
                WDACConfig.GlobalVars.Host = host;
            }
        }
    }
}
