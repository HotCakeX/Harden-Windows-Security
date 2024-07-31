using System;
using System.Management.Automation.Host;

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
            WDACConfig.GlobalVars.VerbosePreference = verbosePreference;
            WDACConfig.GlobalVars.DebugPreference = debugPreference;
            WDACConfig.GlobalVars.Host = host;
        }
    }
}
