using System;
using System.Collections.Generic;
using System.IO;
using System.Windows.Input;

namespace HardenWindowsSecurity
{
    class Program
    {
        static void Main(string[] args)
        {
            #region
            // The following are the required code that are handled in module manifest .psm1 file

            // Acts as PSScriptRoot assignment in the module manifest for the GlobalVars.path variable
            GlobalVars.path = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Main files");

            // Save the valid values of the Protect-WindowsSecurity categories to a variable since the process can be time consuming and shouldn't happen every time the categories are fetched
            GlobalVars.HardeningCategorieX = ProtectionCategoriex.GetValidValues();

            Initializer.Initialize();

            if (HardenWindowsSecurity.UserPrivCheck.IsAdmin())
            {
                HardenWindowsSecurity.ControlledFolderAccessHandler.Start();
                HardenWindowsSecurity.Miscellaneous.RequirementsCheck();
            }
            #endregion


        //



            HardenWindowsSecurity.GUIBootStrapper.Boot();

            //   System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<HardenWindowsSecurity.IndividualResult>>? FinalResults = HardenWindowsSecurity.GlobalVars.FinalMegaObject;


            /*

            // Declare the variables outside the block
            List<HardenWindowsSecurity.IndividualResult>? MicrosoftDefenderResults;
            List<HardenWindowsSecurity.IndividualResult>? AttackSurfaceReductionRulesResults;
            List<HardenWindowsSecurity.IndividualResult>? BitLockerSettingsResults;
            List<HardenWindowsSecurity.IndividualResult>? TLSSecurityResults;
            List<HardenWindowsSecurity.IndividualResult>? LockScreenResults;
            List<HardenWindowsSecurity.IndividualResult>? UserAccountControlResults;
            List<HardenWindowsSecurity.IndividualResult>? DeviceGuardResults;
            List<HardenWindowsSecurity.IndividualResult>? WindowsFirewallResults;
            List<HardenWindowsSecurity.IndividualResult>? OptionalWindowsFeaturesResults;
            List<HardenWindowsSecurity.IndividualResult>? WindowsNetworkingResults;
            List<HardenWindowsSecurity.IndividualResult>? MiscellaneousConfigurationsResults;
            List<HardenWindowsSecurity.IndividualResult>? WindowsUpdateConfigurationsResults;
            List<HardenWindowsSecurity.IndividualResult>? EdgeBrowserConfigurationsResults;
            List<HardenWindowsSecurity.IndividualResult>? NonAdminCommandsResults;

            // Check if FinalResults is not null and get values
            if (HardenWindowsSecurity.GlobalVars.FinalMegaObject != null)
            {
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("MicrosoftDefender", out MicrosoftDefenderResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("AttackSurfaceReductionRules", out AttackSurfaceReductionRulesResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("BitLockerSettings", out BitLockerSettingsResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("TLSSecurity", out TLSSecurityResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("LockScreen", out LockScreenResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("UserAccountControl", out UserAccountControlResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("DeviceGuard", out DeviceGuardResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("WindowsFirewall", out WindowsFirewallResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("OptionalWindowsFeatures", out OptionalWindowsFeaturesResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("WindowsNetworking", out WindowsNetworkingResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("MiscellaneousConfigurations", out MiscellaneousConfigurationsResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("WindowsUpdateConfigurations", out WindowsUpdateConfigurationsResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("EdgeBrowserConfigurations", out EdgeBrowserConfigurationsResults);
                HardenWindowsSecurity.GlobalVars.FinalMegaObject.TryGetValue("NonAdminCommands", out NonAdminCommandsResults);
            }

            // Now you can use these variables outside the if block

            */

            Console.WriteLine("end");



        }
    }
}
