using System;
using System.Management.Automation.Host;

namespace HardeningModule
{
    public static class VerboseLogger
    {
        /// <summary>
        /// Write a verbose message to the console
        /// The verbose messages are not redirectable in PowerShell
        /// https://learn.microsoft.com/en-us/dotnet/api/system.management.automation.host.pshostuserinterface
        /// </summary>
        /// <param name="message"></param>
        public static void Write(string message)
        {
            if (HardeningModule.GlobalVars.VerbosePreference == "Continue" || HardeningModule.GlobalVars.VerbosePreference == "Inquire")
            {
                HardeningModule.GlobalVars.Host.UI.WriteVerboseLine(message);
            }
        }
    }
}