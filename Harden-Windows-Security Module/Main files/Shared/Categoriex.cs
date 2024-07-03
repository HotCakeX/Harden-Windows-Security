using System;
using System.Management.Automation;

namespace HardeningModule
{
    public class Categoriex : IValidateSetValuesGenerator
    {
        public string[] GetValidValues()
        {
            string[] categoriex = new string[]
            {
            "MicrosoftDefender", // 55 - 3x(N/A) = 46
            "AttackSurfaceReductionRules", // 19
            "BitLockerSettings", // 22 + Number of Non-OS drives which are dynamically increased
            "TLSSecurity", // 21
            "LockScreen", // 14
            "UserAccountControl", // 4
            "DeviceGuard", // 8
            "WindowsFirewall", // 20
            "OptionalWindowsFeatures", // 13
            "WindowsNetworking", // 9
            "MiscellaneousConfigurations", // 17
            "WindowsUpdateConfigurations", // 14
            "EdgeBrowserConfigurations", // 14
            "NonAdminCommands" // 11
            };
            return categoriex;
        }
    }
}
