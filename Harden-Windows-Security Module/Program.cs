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


            HardenWindowsSecurity.GUIBootStrapper.Boot();

        }
    }
}
