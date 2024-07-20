using System;
using System.IO;
using Microsoft.Win32;
using System.Management.Automation;
using System.Collections.Generic;
using System.Globalization;

namespace HardeningModule
{
    // prepares the environment. It also runs commands that would otherwise run in the default constructors of each method
    public class Initializer
    {
        /// <summary>
        /// This method runs once in the module root and in the beginning of each cmdlet
        /// </summary>
        /// <param name="VerbosePreference"></param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="PlatformNotSupportedException"></exception>
        public static void Initialize(string VerbosePreference)
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

            // If the working directory exists, delete it
            if (Directory.Exists(HardeningModule.GlobalVars.WorkingDir))
            {
                Directory.Delete(HardeningModule.GlobalVars.WorkingDir, true);
            }

            // Create the working directory
            Directory.CreateDirectory(HardeningModule.GlobalVars.WorkingDir);

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
            if (!TryParseBuildVersion(HardeningModule.GlobalVars.FullOSBuild, out decimal fullOSBuild))
            {
                throw new FormatException("The OS build version strings are not in a correct format.");
            }

            // Make sure the current OS build is equal or greater than the required build number
            if (!(fullOSBuild >= HardeningModule.GlobalVars.Requiredbuild))
            {
                throw new PlatformNotSupportedException($"You are not using the latest build of the Windows OS. A minimum build of {HardeningModule.GlobalVars.Requiredbuild} is required but your OS build is {fullOSBuild}\nPlease go to Windows Update to install the updates and then try again.");
            }

            // Resets the current main step to 0 which is used for Write-Progress when using in GUI mode
            HardeningModule.GlobalVars.CurrentMainStep = 0;

            // Get the MSFT_MpPreference WMI results and save them to the global variable HardeningModule.GlobalVars.MDAVPreferencesCurrent
            HardeningModule.GlobalVars.MDAVPreferencesCurrent = HardeningModule.MpPreferenceHelper.GetMpPreference();

            // Get the MSFT_MpComputerStatus and save them to the global variable HardeningModule.GlobalVars.MDAVConfigCurrent
            HardeningModule.GlobalVars.MDAVConfigCurrent = HardeningModule.MpComputerStatusHelper.GetMpComputerStatus();

            // Total number of Compliant values not equal to N/A
            HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues = 239;

            // Getting the $VerbosePreference from the calling cmdlet and saving it in the global variable
            HardeningModule.GlobalVars.VerbosePreference = VerbosePreference;

            // Create an empty ConcurrentDictionary to store the final results of the cmdlets
            HardeningModule.GlobalVars.FinalMegaObject = new System.Collections.Concurrent.ConcurrentDictionary<System.String, System.Collections.Generic.List<HardeningModule.IndividualResult>>();

            // Create an empty dictionary to store the System Security Policies from the security_policy.inf file
            HardeningModule.GlobalVars.SystemSecurityPoliciesIniObject = new Dictionary<string, Dictionary<string, string>>();
        }

        // This method gracefully parses the OS build version strings to decimals
        private static bool TryParseBuildVersion(string buildVersion, out decimal result)
        {
            // Use CultureInfo.InvariantCulture for parsing
            return Decimal.TryParse(buildVersion, NumberStyles.Number, CultureInfo.InvariantCulture, out result);
        }
    }
}
