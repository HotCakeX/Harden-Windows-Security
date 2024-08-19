using System;
using System.IO;
using System.Diagnostics;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class MicrosoftDefender
    {
        /// <summary>
        /// Turns on Smart App Control
        /// </summary>
        public static void MSFTDefender_SAC()
        {
            HardenWindowsSecurity.Logger.LogMessage("Turning on Smart App Control");

            HardenWindowsSecurity.RegistryEditor.EditRegistry(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\CI\Policy", "VerifiedAndReputablePolicyState", "1", "DWORD", "AddOrModify");

            // Let the optional diagnostic data be enabled automatically
            HardenWindowsSecurity.GlobalVars.ShouldEnableOptionalDiagnosticData = true;
        }
    }
}
