using System;
using System.IO;
using Microsoft.Win32;
using System.Management.Automation;
using System.Collections.Generic;

namespace HardeningModule
{
    // prepares the environment. It also runs commands that would otherwise run in the default constructors of each method
    public class Initializer
    {
        // This method runs once in the module root and in the beginning of each cmdlet
        public static void Initialize()
        {
            using (RegistryKey key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
            {
                if (key != null)
                {
                    object ubrValue = key.GetValue("UBR");
                    if (ubrValue != null && int.TryParse(ubrValue.ToString(), out int ubr))
                    {
                        HardeningModule.GlobalVars.UBR = ubr;
                    }
                    else
                    {
                        throw new InvalidOperationException("The UBR value could not be retrieved from the registry: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
                    }
                }
                else
                {
                    throw new InvalidOperationException("The UBR key does not exist in the registry path: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
                }
            }

            // Concatenate OSBuildNumber and UBR to form the final string
            HardeningModule.GlobalVars.FullOSBuild = $"{HardeningModule.GlobalVars.OSBuildNumber}.{HardeningModule.GlobalVars.UBR}";

            // Create the working directory if it does not exist
            if (!Directory.Exists(HardeningModule.GlobalVars.WorkingDir))
            {
                Directory.CreateDirectory(HardeningModule.GlobalVars.WorkingDir);
            }

            // Initialize the RegistryCSVItems list so that the HardeningModule.HardeningRegistryKeys.ReadCsv() method can write to it
            HardeningModule.GlobalVars.RegistryCSVItems = new List<HardeningModule.HardeningRegistryKeys.CsvRecord>();

            // Parse the Registry.csv and save it to the global HardeningModule.GlobalVars.RegistryCSVItems list
            HardeningModule.HardeningRegistryKeys.ReadCsv();

            // Initialize the ProcessMitigations list so that the HardeningModule.ProcessMitigationsParser.ReadCsv() method can write to it
            HardeningModule.GlobalVars.ProcessMitigations = new List<HardeningModule.ProcessMitigationsParser.ProcessMitigationsRecords>();

            // Parse the ProcessMitigations.csv and save it to the global HardeningModule.GlobalVars.ProcessMitigations list
            HardeningModule.ProcessMitigationsParser.ReadCsv();

            // Save the valid values of the Protect-WindowsSecurity categories to a variable since the process can be time consuming and shouldn't happen every time the categories are fetched
            HardeningModule.GlobalVars.HardeningCategorieX = HardeningModule.ProtectionCategoriex.GetValidValues();

            // Convert the FullOSBuild and RequiredBuild strings to decimals so that we can compare them
            decimal fullOSBuild = Convert.ToDecimal(GlobalVars.FullOSBuild);
            decimal requiredBuild = Convert.ToDecimal(GlobalVars.Requiredbuild);

            // Make sure the current OS build is equal or greater than the required build number
            if (!(fullOSBuild >= requiredBuild))
            {
                throw new PlatformNotSupportedException($"You are not using the latest build of the Windows OS. A minimum build of {requiredBuild} is required but your OS build is {fullOSBuild}\nPlease go to Windows Update to install the updates and then try again.");
            }

            // Resets the current main step to 0 which is used for Write-Progress when using in GUI mode
            HardeningModule.GlobalVars.CurrentMainStep = 0;

            // Get the MSFT_MpPreference WMI results and save them to the global variable HardeningModule.GlobalVars.MDAVPreferencesCurrent
            HardeningModule.GlobalVars.MDAVPreferencesCurrent = HardeningModule.MpPreferenceHelper.GetMpPreference();

            // Get the MSFT_MpComputerStatus and save them to the global variable HardeningModule.GlobalVars.MDAVConfigCurrent
            HardeningModule.GlobalVars.MDAVConfigCurrent = HardeningModule.MpComputerStatusHelper.GetMpComputerStatus();

            // Total number of Compliant values not equal to N/A
            HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues = 239;
        }
    }
}
