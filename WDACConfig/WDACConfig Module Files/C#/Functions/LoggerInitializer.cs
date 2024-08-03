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

            // If they are changed once to Continue/Inquire then another cmdlet in the middle of the operation should not change that
            // Until another cmdlet is called, which is the same behavior PowerShell employs

            // Check and assign verbosePreference only if it's neither "Continue" nor "Inquire"
            if (!string.Equals(WDACConfig.GlobalVars.VerbosePreference, "Continue", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(WDACConfig.GlobalVars.VerbosePreference, "Inquire", StringComparison.OrdinalIgnoreCase))
            {
                WDACConfig.GlobalVars.VerbosePreference = verbosePreference;
            }

            // Check and assign debugPreference only if it's neither "Continue" nor "Inquire"
            if (!string.Equals(WDACConfig.GlobalVars.DebugPreference, "Continue", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(WDACConfig.GlobalVars.DebugPreference, "Inquire", StringComparison.OrdinalIgnoreCase))
            {
                WDACConfig.GlobalVars.DebugPreference = debugPreference;
            }

            WDACConfig.GlobalVars.Host = host;
        }
    }
}
