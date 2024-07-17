using System;
using System.Collections.Generic;
using Microsoft.Win32;
using System.Linq;

namespace HardeningModule
{
    /// <summary>
    /// Methods that are responsible for each category of the Confirm-SystemCompliance cmdlet
    /// </summary>
    public static class ConfirmSystemComplianceMethods
    {

        /// <summary>
        /// Performs all of the tasks for the Attack Surface Reduction Rules category during system compliance checking
        /// </summary>
        /// <returns></returns>
        public static void VerifyAttackSurfaceReductionRules()
        {
            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            string CatName = "AttackSurfaceReductionRules";

            // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
            {
                nestedObjectArray.Add(Result);
            }

            object idsObj = HardeningModule.GlobalVars.MDAVPreferencesCurrent.AttackSurfaceReductionRules_Ids;
            object actionsObj = HardeningModule.GlobalVars.MDAVPreferencesCurrent.AttackSurfaceReductionRules_Actions;

            // Individual ASR rules verification
            string[] ids = ConvertToStringArray(idsObj);
            string[] actions = ConvertToStringArray(actionsObj);

            // If $Ids variable is not empty, convert them to lower case because some IDs can be in upper case and result in inaccurate comparison
            if (ids != null)
            {
                ids = ids.Select(id => id.ToLower()).ToArray();
            }

            Dictionary<string, string> asrsTable = new Dictionary<string, string>
            {
                // Hashtable to store the descriptions for each ID
                { "26190899-1602-49e8-8b27-eb1d0a1ce869", "Block Office communication application from creating child processes" },
                { "d1e49aac-8f56-4280-b9ba-993a6d77406c", "Block process creations originating from PSExec and WMI commands" },
                { "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4", "Block untrusted and unsigned processes that run from USB" },
                { "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b", "Block Win32 API calls from Office macros" },
                { "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c", "Block Adobe Reader from creating child processes" },
                { "3b576869-a4ec-4529-8536-b80a7769e899", "Block Office applications from creating executable content" },
                { "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "Block all Office applications from creating child processes" },
                { "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2", "Block credential stealing from the Windows local security authority subsystem (lsass.exe)" },
                { "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "Block executable content from email client and webmail" },
                { "01443614-cd74-433a-b99e-2ecdc07bfc25", "Block executable files from running unless they meet a prevalence; age or trusted list criterion" },
                { "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "Block execution of potentially obfuscated scripts" },
                { "e6db77e5-3df2-4cf1-b95a-636979351e5b", "Block persistence through WMI event subscription" },
                { "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", "Block Office applications from injecting code into other processes" },
                { "56a863a9-875e-4185-98a7-b882c64b5ce5", "Block abuse of exploited vulnerable signed drivers" },
                { "c1db55ab-c21a-4637-bb3f-a12568109d35", "Use advanced protection against ransomware" },
                { "d3e037e1-3eb8-44c8-a917-57927947596d", "Block JavaScript or VBScript from launching downloaded executable content" },
                { "33ddedf1-c6e0-47cb-833e-de6133960387", "Block rebooting machine in Safe Mode" },
                { "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb", "Block use of copied or impersonated system tools" },
                { "a8f5898e-1dc8-49a9-9878-85004b8a61e6", "Block Webshell creation for Servers" }
            };

            // Loop over each ID in the hashtable
            foreach (var kvp in asrsTable)
            {
                string name = kvp.Key;
                string friendlyName = kvp.Value;

                // Default action is set to 0 (Not configured)
                string action = "0";

                // Check if the $Ids array is not empty and current ID is present in the $Ids array
                if (ids != null && ids.Contains(name))
                {
                    // If yes, check if the $Actions array is not empty
                    if (actions != null)
                    {
                        // If yes, use the index of the ID in the array to access the action value
                        action = actions[Array.IndexOf(ids, name)];
                    }
                }

                // The following ASR Rules are compliant either if they are set to block or warn + block
                // 'Block use of copied or impersonated system tools' -> because it's in preview and is set to 6 for Warn instead of 1 for block in Protect-WindowsSecurity cmdlet
                // "Block executable files from running unless they meet a prevalence; age or trusted list criterion" -> for ease of use it's compliant if set to 6 (Warn) or 1 (Block)
                bool compliant = name switch
                {
                    "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" => new[] { "6", "1" }.Contains(action),
                    "01443614-cd74-433a-b99e-2ecdc07bfc25" => new[] { "6", "1" }.Contains(action),
                    // All other ASR rules are compliant if they are set to block (1)
                    _ => action == "1"
                };

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = friendlyName,
                    Compliant = compliant ? "True" : "False",
                    Value = action,
                    Name = name,
                    Category = CatName,
                    Method = "Cmdlet"
                });
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }

        // Helper function to convert object to string array
        private static string[] ConvertToStringArray(object input)
        {
            if (input is string[] stringArray)
            {
                return stringArray;
            }
            if (input is byte[] byteArray)
            {
                return byteArray.Select(b => b.ToString()).ToArray();
            }
            return null;
        }

        /// <summary>
        /// Performs all of the tasks for the Windows Update Configurations category during system compliance checking
        /// </summary>
        public static void VerifyWindowsUpdateConfigurations()
        {

            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            string CatName = "WindowsUpdateConfigurations";

            // Process items in Registry resources.csv file with "Group Policy" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
            {
                nestedObjectArray.Add(Result);
            }

            // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
            {
                nestedObjectArray.Add(Result);
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }

        /// <summary>
        /// Performs all of the tasks for the Non-Admin Commands category during system compliance checking
        /// </summary>
        public static void VerifyNonAdminCommands()
        {
            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            string CatName = "NonAdminCommands";

            // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
            {
                nestedObjectArray.Add(Result);
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }

        /// <summary>
        /// Performs all of the tasks for the Edge Browser Configurations category during system compliance checking
        /// </summary>
        public static void VerifyEdgeBrowserConfigurations()
        {
            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            string CatName = "EdgeBrowserConfigurations";

            // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
            {
                nestedObjectArray.Add(Result);
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }

        /// <summary>
        /// Performs all of the tasks for the Device Guard category during system compliance checking
        /// </summary>
        public static void VerifyDeviceGuard()
        {
            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            string CatName = "DeviceGuard";

            // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
            {
                nestedObjectArray.Add(Result);
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }

        /// <summary>
        /// Performs all of the tasks for the BitLocker Settings category during system compliance checking
        /// </summary>
        public static void VerifyBitLockerSettings()
        {

            // Create a new list to store the results
            List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

            // Defining the category name
            string CatName = "BitLockerSettings";

            // Returns true or false depending on whether Kernel DMA Protection is on or off
            bool BootDMAProtection = SystemInfo.NativeMethods.BootDmaCheck() != 0;

            if (BootDMAProtection)
            {
                HardeningModule.VerboseLogger.Write("Kernel DMA protection is enabled");
            }
            else
            {
                HardeningModule.VerboseLogger.Write("Kernel DMA protection is disabled");
            }


            // Get the status of Bitlocker DMA protection
            int BitlockerDMAProtectionStatus = 0;
            try
            {
                // Get the value of the registry key and return 0 if it doesn't exist
                BitlockerDMAProtectionStatus = (int)Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE", "DisableExternalDMAUnderLock", 0);
            }
            catch
            {
                // if the path doesn't exist do nothing
            }

            // Bitlocker DMA counter measure status
            // Returns true if only either Kernel DMA protection is on and Bitlocker DMA protection if off
            // or Kernel DMA protection is off and Bitlocker DMA protection is on
            bool ItemState = BootDMAProtection ^ (BitlockerDMAProtectionStatus == 1);

            nestedObjectArray.Add(new HardeningModule.IndividualResult
            {
                FriendlyName = "DMA protection",
                Compliant = ItemState ? "True" : "False",
                Value = ItemState ? "True" : "False",
                Name = "DMA protection",
                Category = CatName,
                Method = "Group Policy"
            });

            // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
            foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
            {
                nestedObjectArray.Add(Result);
            }


            // To detect if Hibernate is enabled and set to full
            // Only perform the check if the system is not a virtual machine
            if (!HardeningModule.GlobalVars.MDAVConfigCurrent.IsVirtualMachine)
            {
                bool IndividualItemResult = false;
                try
                {
                    object hiberFileType = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power", "HiberFileType", null);
                    if (hiberFileType != null && (int)hiberFileType == 2)
                    {
                        IndividualItemResult = true;
                    }
                }
                catch
                {
                    // suppress the errors if any
                }

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Hibernate is set to full",
                    Compliant = IndividualItemResult ? "True" : "False",
                    Value = IndividualItemResult ? "True" : "False",
                    Name = "Hibernate is set to full",
                    Category = CatName,
                    Method = "Cmdlet"
                });
            }
            else
            {
                HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues--;
            }


            // OS Drive encryption verifications
            // Check if BitLocker is on for the OS Drive
            // The ProtectionStatus remains off while the drive is encrypting or decrypting
            var volumeInfo = HardeningModule.BitLockerInfo.GetEncryptedVolumeInfo(Environment.GetEnvironmentVariable("SystemDrive"));
            if (volumeInfo.ProtectionStatus == "Protected")
            {
                // Get the key protectors of the OS Drive
                string[] KeyProtectors = volumeInfo.KeyProtector.Select(kp => kp.KeyProtectorType).ToArray();

                //  HardeningModule.VerboseLogger.Write(string.Join(", ", KeyProtectors));


                // Check if TPM+PIN and recovery password are being used - Normal Security level
                if (KeyProtectors.Contains("TpmPin") && KeyProtectors.Contains("RecoveryPassword"))
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "Secure OS Drive encryption",
                        Compliant = "True",
                        Value = "Normal Security Level",
                        Name = "Secure OS Drive encryption",
                        Category = CatName,
                        Method = "Cmdlet"
                    });
                }
                // Check if TPM+PIN+StartupKey and recovery password are being used - Enhanced security level
                else if (KeyProtectors.Contains("TpmPinStartupKey") && KeyProtectors.Contains("RecoveryPassword"))
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "Secure OS Drive encryption",
                        Compliant = "True",
                        Value = "Enhanced Security Level",
                        Name = "Secure OS Drive encryption",
                        Category = CatName,
                        Method = "Cmdlet"
                    });
                }
                else
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "Secure OS Drive encryption",
                        Compliant = "False",
                        Value = "False",
                        Name = "Secure OS Drive encryption",
                        Category = CatName,
                        Method = "Cmdlet"
                    });
                }
            }
            else
            {
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Secure OS Drive encryption",
                    Compliant = "False",
                    Value = "False",
                    Name = "Secure OS Drive encryption",
                    Category = CatName,
                    Method = "Cmdlet"
                });
            }


            // Non-OS-Drive-BitLocker-Drives-Encryption-Verification
            List<HardeningModule.BitLockerVolume> NonRemovableNonOSDrives = new List<HardeningModule.BitLockerVolume>();

            foreach (HardeningModule.BitLockerVolume Drive in HardeningModule.BitLockerInfo.GetAllEncryptedVolumeInfo())
            {
                if (Drive.VolumeType == "FixedDisk")
                {
                    // Increase the number of available compliant values for each non-OS drive that was found
                    HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues++;
                    NonRemovableNonOSDrives.Add(Drive);
                }
            }

            // Check if there are any non-OS volumes
            if (NonRemovableNonOSDrives.Any())
            {
                // Loop through each non-OS volume and verify their encryption
                foreach (var BitLockerDrive in NonRemovableNonOSDrives.OrderBy(d => d.MountPoint))
                {
                    // If status is unknown, that means the non-OS volume is encrypted and locked, if it's on then it's on
                    if (BitLockerDrive.ProtectionStatus == "Protected" || BitLockerDrive.ProtectionStatus == "Unknown")
                    {
                        // Check if the non-OS non-Removable drive has one of the following key protectors: RecoveryPassword, Password or ExternalKey (Auto-Unlock)

                        string[] KeyProtectors = BitLockerDrive.KeyProtector.Select(kp => kp.KeyProtectorType).ToArray();

                        if (KeyProtectors.Contains("RecoveryPassword") || KeyProtectors.Contains("Password") || KeyProtectors.Contains("ExternalKey"))
                        {
                            nestedObjectArray.Add(new HardeningModule.IndividualResult
                            {
                                FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Compliant = "True",
                                Value = "Encrypted",
                                Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                        else
                        {
                            nestedObjectArray.Add(new HardeningModule.IndividualResult
                            {
                                FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Compliant = "False",
                                Value = "Not properly encrypted",
                                Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                    }
                    else
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                            Compliant = "False",
                            Value = "Not encrypted",
                            Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                            Category = CatName,
                            Method = "Cmdlet"
                        });
                    }
                }
            }

            HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
        }
    }
}
