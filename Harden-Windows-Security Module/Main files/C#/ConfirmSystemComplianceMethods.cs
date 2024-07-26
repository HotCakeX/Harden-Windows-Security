using System;
using System.Collections.Generic;
using Microsoft.Win32;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Management;
using System.Management.Automation;
using System.Collections.ObjectModel;
using System.Threading;
using System.Threading.Tasks;

namespace HardeningModule
{
    public partial class ConfirmSystemComplianceMethods
    {

        /// <summary>
        /// The main Orchestrator of the Confirm-SystemCompliance cmdlet
        /// It will do all of the required tasks
        /// </summary>
        /// <param name="methodNames"></param>
        /// <exception cref="Exception"></exception>
        public static void OrchestrateComplianceChecks(params string[] methodNames)
        {
            // call the method to get the security group policies to be exported to a file
            HardeningModule.ConfirmSystemComplianceMethods.ExportSecurityPolicy();

            // Storing the output of the ini file parsing function
            HardeningModule.GlobalVars.SystemSecurityPoliciesIniObject = HardeningModule.IniFileConverter.ConvertFromIniFile(HardeningModule.GlobalVars.securityPolicyInfPath);

            // Process the SecurityPoliciesVerification.csv and save the output to the global variable HardeningModule.GlobalVars.SecurityPolicyRecords
            HardeningModule.GlobalVars.SecurityPolicyRecords = HardeningModule.SecurityPolicyCsvProcessor.ProcessSecurityPolicyCsvFile(Path.Combine(HardeningModule.GlobalVars.path, "Resources", "SecurityPoliciesVerification.csv"));

            // Call the method and supply the category names if any
            // Will run them async
            Task MethodsTaskOutput = RunComplianceMethodsInParallelAsync(methodNames);

            // Since this parent method is not async and we did not use await when calling RunComplianceMethodsInParallelAsync method
            // We need to implement our own manual await process
            while (!MethodsTaskOutput.IsCompleted)
            {
                // Wait for 500 milliseconds before checking again
                System.Threading.Thread.Sleep(50);
            }

            // Check if the task failed
            if (MethodsTaskOutput.IsFaulted)
            {
                // throw the exceptions
                throw new Exception(MethodsTaskOutput.Exception.Message);
            }
            else if (MethodsTaskOutput.IsCompletedSuccessfully)
            {
                //   Console.WriteLine("Download completed successfully");
            }
        }

        // Defining delegates for the methods
        private static readonly Dictionary<string, Func<Task>> methodDictionary = new Dictionary<string, Func<Task>>
    {
        { "AttackSurfaceReductionRules", VerifyAttackSurfaceReductionRules },
        { "WindowsUpdateConfigurations", VerifyWindowsUpdateConfigurations },
        { "NonAdminCommands", VerifyNonAdminCommands },
        { "EdgeBrowserConfigurations", VerifyEdgeBrowserConfigurations },
        { "DeviceGuard", VerifyDeviceGuard },
        { "BitLockerSettings", VerifyBitLockerSettings },
        { "MiscellaneousConfigurations", VerifyMiscellaneousConfigurations },
        { "WindowsNetworking", VerifyWindowsNetworking },
        { "LockScreen", VerifyLockScreen },
        { "UserAccountControl", VerifyUserAccountControl },
        { "OptionalWindowsFeatures", VerifyOptionalWindowsFeatures },
        { "TLSSecurity", VerifyTLSSecurity },
        { "WindowsFirewall", VerifyWindowsFirewall },
        { "MicrosoftDefender", VerifyMicrosoftDefender }
    };

        // Task status codes: https://learn.microsoft.com/en-us/dotnet/api/system.threading.tasks.taskstatus
        /// <summary>
        /// this method runs the compliance checking methods asynchronously
        /// </summary>
        /// <param name="methodNames">These are the parameter names from the official category names
        /// if no input is supplied for this parameter, all categories will run</param>
        /// <returns>Returns the Task object</returns>
        public static async Task RunComplianceMethodsInParallelAsync(params string[] methodNames)
        {
            // Define a list to store the methods to run
            List<Func<Task>> methodsToRun;

            // if the methodNames parameter wasn't specified
            if (methodNames == null || methodNames.Length == 0)
            {
                // Get all methods from the dictionary
                methodsToRun = methodDictionary.Values.ToList();
            }
            else
            {
                // Only run the specified methods
                methodsToRun = methodNames
                    .Where(methodName => methodDictionary.ContainsKey(methodName))
                    .Select(methodName => methodDictionary[methodName])
                    .ToList();
            }

            // Run all selected methods in parallel
            var tasks = methodsToRun.Select(method => method());
            await Task.WhenAll(tasks);
        }


        /// <summary>
        /// Methods that are responsible for each category of the Confirm-SystemCompliance cmdlet
        /// </summary>


        /// <summary>
        /// Performs all of the tasks for the Attack Surface Reduction Rules category during system compliance checking
        /// </summary>
        /// <returns></returns>
        public static Task VerifyAttackSurfaceReductionRules()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                string CatName = "AttackSurfaceReductionRules";

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

                Dictionary<string, string> ASRTable = new Dictionary<string, string>
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
                foreach (var kvp in ASRTable)
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
                        Method = "CIM"
                    });
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);

            });
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
        public static Task VerifyWindowsUpdateConfigurations()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                string CatName = "WindowsUpdateConfigurations";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Non-Admin Commands category during system compliance checking
        /// </summary>
        public static Task VerifyNonAdminCommands()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                string CatName = "NonAdminCommands";

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Edge Browser Configurations category during system compliance checking
        /// </summary>
        public static Task VerifyEdgeBrowserConfigurations()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                string CatName = "EdgeBrowserConfigurations";

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Device Guard category during system compliance checking
        /// </summary>
        public static Task VerifyDeviceGuard()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                string CatName = "DeviceGuard";

                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#enablevirtualizationbasedsecurity
                bool EnableVirtualizationBasedSecurity = HardeningModule.GetMDMResultValue.Get("EnableVirtualizationBasedSecurity", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Virtualization Based Security",
                    Compliant = EnableVirtualizationBasedSecurity ? "True" : "False",
                    Value = EnableVirtualizationBasedSecurity ? "True" : "False",
                    Name = "EnableVirtualizationBasedSecurity",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#requireplatformsecurityfeatures
                string RequirePlatformSecurityFeatures = HardeningModule.GlobalVars.MDMResults
     .Where(element => element.Name == "RequirePlatformSecurityFeatures")
     .Select(element => element.Value)
     .FirstOrDefault();

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Require Platform Security Features",
                    Compliant = (RequirePlatformSecurityFeatures != null &&
                                (RequirePlatformSecurityFeatures.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                                 RequirePlatformSecurityFeatures.Equals("3", StringComparison.OrdinalIgnoreCase))) ? "True" : "False",
                    Value = (RequirePlatformSecurityFeatures != null && RequirePlatformSecurityFeatures.Equals("1", StringComparison.OrdinalIgnoreCase)) ?
                            "VBS with Secure Boot" :
                            (RequirePlatformSecurityFeatures != null && RequirePlatformSecurityFeatures.Equals("3", StringComparison.OrdinalIgnoreCase)) ?
                            "VBS with Secure Boot and direct memory access (DMA) Protection" :
                            "False",
                    Name = "RequirePlatformSecurityFeatures",
                    Category = CatName,
                    Method = "MDM"
                });



                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#hypervisorenforcedcodeintegrity
                bool HypervisorEnforcedCodeIntegrity = HardeningModule.GetMDMResultValue.Get("HypervisorEnforcedCodeIntegrity", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Hypervisor Enforced Code Integrity - UEFI Lock",
                    Compliant = HypervisorEnforcedCodeIntegrity ? "True" : "False",
                    Value = HypervisorEnforcedCodeIntegrity ? "True" : "False",
                    Name = "HypervisorEnforcedCodeIntegrity",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#requireuefimemoryattributestable
                bool RequireUEFIMemoryAttributesTable = HardeningModule.GetMDMResultValue.Get("RequireUEFIMemoryAttributesTable", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Require HVCI MAT (Memory Attribute Table)",
                    Compliant = RequireUEFIMemoryAttributesTable ? "True" : "False",
                    Value = RequireUEFIMemoryAttributesTable ? "True" : "False",
                    Name = "HVCIMATRequired",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#lsacfgflags
                bool LsaCfgFlags = HardeningModule.GetMDMResultValue.Get("LsaCfgFlags", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Credential Guard Configuration - UEFI Lock",
                    Compliant = LsaCfgFlags ? "True" : "False",
                    Value = LsaCfgFlags ? "True" : "False",
                    Name = "LsaCfgFlags",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#configuresystemguardlaunch
                bool ConfigureSystemGuardLaunch = HardeningModule.GetMDMResultValue.Get("ConfigureSystemGuardLaunch", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "System Guard Launch",
                    Compliant = ConfigureSystemGuardLaunch ? "True" : "False",
                    Value = ConfigureSystemGuardLaunch ? "True" : "False",
                    Name = "ConfigureSystemGuardLaunch",
                    Category = CatName,
                    Method = "MDM"
                });

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the BitLocker Settings category during system compliance checking
        /// </summary>
        public static Task VerifyBitLockerSettings()
        {
            return Task.Run(() =>
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
                    Method = "Windows API"
                });


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
                        Method = "Registry Keys"
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
                            Method = "CIM"
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
                            Method = "CIM"
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
                            Method = "CIM"
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
                        Method = "CIM"
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
                                    Method = "CIM"
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
                                    Method = "CIM"
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
                                Method = "CIM"
                            });
                        }
                    }
                }


                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Miscellaneous Configurations category during system compliance checking
        /// </summary>
        public static Task VerifyMiscellaneousConfigurations()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "MiscellaneousConfigurations";

                // Checking if all user accounts are part of the Hyper-V security Group
                // Get all the enabled user accounts that are not part of the Hyper-V Security group based on SID
                var usersNotInHyperVGroup = HardeningModule.LocalUserRetriever.Get().Where(user => user.Enabled && !user.GroupsSIDs.Contains("S-1-5-32-578")).ToList();

                string compliant = usersNotInHyperVGroup != null && usersNotInHyperVGroup.Count > 0 ? "False" : "True";

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "All users are part of the Hyper-V Administrators group",
                    Compliant = compliant,
                    Value = compliant,
                    Name = "All users are part of the Hyper-V Administrators group",
                    Category = CatName,
                    Method = "CIM"
                });


                /// PS Equivalent: (auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv).'Inclusion Setting'
                // Verify an Audit policy is enabled - only supports systems with English-US language
                var cultureInfoHelper = HardeningModule.CultureInfoHelper.Get();
                string currentCulture = cultureInfoHelper.Name;

                if (currentCulture == "en-US")
                {
                    // Start a new process to run the auditpol command
                    var process = new Process
                    {
                        StartInfo = new ProcessStartInfo
                        {
                            FileName = "auditpol",
                            Arguments = "/get /subcategory:\"Other Logon/Logoff Events\" /r",
                            RedirectStandardOutput = true,
                            UseShellExecute = false,
                            CreateNoWindow = true
                        }
                    };

                    process.Start();

                    // Read the output from the process
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Check if the output is empty
                    if (string.IsNullOrWhiteSpace(output))
                    {
                        HardeningModule.VerboseLogger.Write("No output from the auditpol command.");
                        return;
                    }

                    // Convert the CSV output to a dictionary
                    using (var reader = new StringReader(output))
                    {
                        // Initialize the inclusion setting
                        string inclusionSetting = null;

                        // Read the first line to get the headers
                        string headers = reader.ReadLine();

                        // Check if the headers are not null
                        if (headers != null)
                        {
                            // Get the index of the "Inclusion Setting" column
                            var headerColumns = headers.Split(',');

                            int inclusionSettingIndex = Array.IndexOf(headerColumns, "Inclusion Setting");

                            // Read subsequent lines to get the values
                            string values;
                            while ((values = reader.ReadLine()) != null)
                            {
                                var valueColumns = values.Split(',');
                                if (inclusionSettingIndex != -1 && inclusionSettingIndex < valueColumns.Length)
                                {
                                    inclusionSetting = valueColumns[inclusionSettingIndex].Trim();
                                    break; // break because we are only interested in the first line of values
                                }
                            }
                        }

                        // Verify the inclusion setting
                        bool individualItemResult = inclusionSetting == "Success and Failure";

                        // Add the result to the nested object array
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "Audit policy for Other Logon/Logoff Events",
                            Compliant = individualItemResult ? "True" : "False",
                            Value = individualItemResult ? "Success and Failure" : inclusionSetting,
                            Name = "Audit policy for Other Logon/Logoff Events",
                            Category = CatName,
                            Method = "Cmdlet"
                        });
                    }
                }
                else
                {
                    // Decrement the total number of true compliant values
                    HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues--;
                }

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Windows Networking category during system compliance checking
        /// </summary>
        public static Task VerifyWindowsNetworking()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "WindowsNetworking";

                // Check network location of all connections to see if they are public
                bool individualItemResult = HardeningModule.NetConnectionProfiles.Get().All(profile =>
                {
                    // Ensure the property exists and is not null before comparing
                    return profile["NetworkCategory"] != null && (uint)profile["NetworkCategory"] == 0;
                });
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Network Location of all connections set to Public",
                    Compliant = individualItemResult ? "True" : "False",
                    Value = individualItemResult ? "True" : "False",
                    Name = "Network Location of all connections set to Public",
                    Category = CatName,
                    Method = "CIM"
                });

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (HardeningModule.SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Lock Screen category during system compliance checking
        /// </summary>
        public static Task VerifyLockScreen()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "LockScreen";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (HardeningModule.SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);

            });
        }


        /// <summary>
        /// Performs all of the tasks for the User Account Control category during system compliance checking
        /// </summary>
        public static Task VerifyUserAccountControl()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "UserAccountControl";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (HardeningModule.SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Optional Windows Features category during system compliance checking
        /// </summary>
        public static Task VerifyOptionalWindowsFeatures()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "OptionalWindowsFeatures";

                // Get the results of all optional features
                HardeningModule.WindowsFeatureChecker.FeatureStatus FeaturesCheckResults = HardeningModule.WindowsFeatureChecker.CheckWindowsFeatures();

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "PowerShell v2 is disabled",
                    Compliant = FeaturesCheckResults.PowerShellv2 == "Disabled" ? "True" : "False",
                    Value = FeaturesCheckResults.PowerShellv2,
                    Name = "PowerShell v2 is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "PowerShell v2 Engine is disabled",
                    Compliant = FeaturesCheckResults.PowerShellv2Engine == "Disabled" ? "True" : "False",
                    Value = FeaturesCheckResults.PowerShellv2Engine,
                    Name = "PowerShell v2 Engine is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Work Folders client is disabled",
                    Compliant = FeaturesCheckResults.WorkFoldersClient == "Disabled" ? "True" : "False",
                    Value = FeaturesCheckResults.WorkFoldersClient,
                    Name = "Work Folders client is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Internet Printing Client is disabled",
                    Compliant = FeaturesCheckResults.InternetPrintingClient == "Disabled" ? "True" : "False",
                    Value = FeaturesCheckResults.InternetPrintingClient,
                    Name = "Internet Printing Client is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Windows Media Player (legacy) is disabled",
                    Compliant = FeaturesCheckResults.WindowsMediaPlayer == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.WindowsMediaPlayer,
                    Name = "Windows Media Player (legacy) is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Microsoft Defender Application Guard is not present",
                    Compliant = FeaturesCheckResults.MDAG == "Disabled" || FeaturesCheckResults.MDAG == "Unknown" ? "True" : "False",
                    Value = FeaturesCheckResults.MDAG,
                    Name = "Microsoft Defender Application Guard is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Windows Sandbox is enabled",
                    Compliant = FeaturesCheckResults.WindowsSandbox == "Enabled" ? "True" : "False",
                    Value = FeaturesCheckResults.WindowsSandbox,
                    Name = "Windows Sandbox is enabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Hyper-V is enabled",
                    Compliant = FeaturesCheckResults.HyperV == "Enabled" ? "True" : "False",
                    Value = FeaturesCheckResults.HyperV,
                    Name = "Hyper-V is enabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "WMIC is not present",
                    Compliant = FeaturesCheckResults.WMIC == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.WMIC,
                    Name = "WMIC is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Internet Explorer mode functionality for Edge is not present",
                    Compliant = FeaturesCheckResults.IEMode == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.IEMode,
                    Name = "Internet Explorer mode functionality for Edge is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Legacy Notepad is not present",
                    Compliant = FeaturesCheckResults.LegacyNotepad == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.LegacyNotepad,
                    Name = "Legacy Notepad is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "WordPad is not present",
                    Compliant = FeaturesCheckResults.LegacyWordPad == "Not Present" || FeaturesCheckResults.LegacyWordPad == "Unknown" ? "True" : "False",
                    Value = FeaturesCheckResults.LegacyWordPad,
                    Name = "WordPad is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "PowerShell ISE is not present",
                    Compliant = FeaturesCheckResults.PowerShellISE == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.PowerShellISE,
                    Name = "PowerShell ISE is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Steps Recorder is not present",
                    Compliant = FeaturesCheckResults.StepsRecorder == "Not Present" ? "True" : "False",
                    Value = FeaturesCheckResults.StepsRecorder,
                    Name = "Steps Recorder is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }

        /// <summary>
        /// Performs all of the tasks for the TLS Security category during system compliance checking
        /// </summary>
        public static Task VerifyTLSSecurity()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "TLSSecurity";

                HardeningModule.EccCurveComparisonResult ECCCurvesComparisonResults = HardeningModule.EccCurveComparer.GetEccCurveComparison();

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "ECC Curves and their positions",
                    Compliant = ECCCurvesComparisonResults.AreCurvesCompliant ? "True" : "False",
                    Value = string.Join(", ", ECCCurvesComparisonResults.CurrentEccCurves),
                    Name = "ECC Curves and their positions",
                    Category = CatName,
                    Method = "Cmdlet"
                });

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Windows Firewall category during system compliance checking
        /// </summary>
        public static Task VerifyWindowsFirewall()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "WindowsFirewall";

                // Use the GetFirewallRules method and check the Enabled status of each rule
                List<ManagementObject> firewallRuleGroupResultEnabledArray = HardeningModule.FirewallHelper.GetFirewallRules("@%SystemRoot%\\system32\\firewallapi.dll,-37302", 1);

                // Check if all the rules are disabled
                bool firewallRuleGroupResultEnabledStatus = true;

                // Loop through each rule and check if it's enabled
                foreach (var rule in firewallRuleGroupResultEnabledArray)
                {
                    if (rule["Enabled"]?.ToString() == "1")
                    {
                        firewallRuleGroupResultEnabledStatus = false;
                        break;
                    }
                }

                // Verify the 3 built-in Firewall rules (for all 3 profiles) for Multicast DNS (mDNS) UDP-in are disabled
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "mDNS UDP-In Firewall Rules are disabled",
                    Compliant = firewallRuleGroupResultEnabledStatus ? "True" : "False",
                    Value = firewallRuleGroupResultEnabledStatus ? "True" : "False",
                    Name = "mDNS UDP-In Firewall Rules are disabled",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PublicProfile02_EnableFirewall = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PublicProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_EnableFirewall.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PublicProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PublicProfile02_DisableInboundNotifications = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PublicProfile02, "DisableInboundNotifications", "false");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Display notifications for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_DisableInboundNotifications.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PublicProfile02_DisableInboundNotifications.Value,
                    Name = "Display notifications for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PublicProfile02_LogMaxFileSize = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PublicProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file size for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_LogMaxFileSize.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PublicProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PublicProfile02_EnableLogDroppedPackets = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PublicProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Log blocked connections for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_EnableLogDroppedPackets.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PublicProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PublicProfile02_LogFilePath = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PublicProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Publicfirewall.log");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file path for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_LogFilePath.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PublicProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PrivateProfile02_EnableFirewall = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PrivateProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_EnableFirewall.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PrivateProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PrivateProfile02_DisableInboundNotifications = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PrivateProfile02, "DisableInboundNotifications", "false");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Display notifications for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_DisableInboundNotifications.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PrivateProfile02_DisableInboundNotifications.Value,
                    Name = "Display notifications for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PrivateProfile02_LogMaxFileSize = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PrivateProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file size for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_LogMaxFileSize.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PrivateProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PrivateProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Log blocked connections for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_PrivateProfile02_LogFilePath = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_PrivateProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Privatefirewall.log");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file path for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_LogFilePath.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_PrivateProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableFirewall = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableFirewall.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_DefaultOutboundAction = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "DefaultOutboundAction", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Set Default Outbound Action for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_DefaultOutboundAction.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_DefaultOutboundAction.Value,
                    Name = "Set Default Outbound Action for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_DefaultInboundAction = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "DefaultInboundAction", "1");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Set Default Inbound Action for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_DefaultInboundAction.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_DefaultInboundAction.Value,
                    Name = "Set Default Inbound Action for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_Shielded = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "Shielded", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Block all Domain profile connections",
                    Compliant = MDM_Firewall_DomainProfile02_Shielded.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_Shielded.Value,
                    Name = "Shielded",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_LogFilePath = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Domainfirewall.log");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file path for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_LogFilePath.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_LogMaxFileSize = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Configure Log file size for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_LogMaxFileSize.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableLogDroppedPackets = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Log blocked connections for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableLogDroppedPackets.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HardeningModule.HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableLogSuccessConnections = HardeningModule.HashtableChecker.CheckValue<string>(HardeningModule.GlobalVars.MDM_Firewall_DomainProfile02, "EnableLogSuccessConnections", "true");

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Log successful connections for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableLogSuccessConnections.IsMatch ? "True" : "False",
                    Value = MDM_Firewall_DomainProfile02_EnableLogSuccessConnections.Value,
                    Name = "Log successful connections for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Microsoft Defender category during system compliance checking
        /// </summary>
        public static Task VerifyMicrosoftDefender()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<HardeningModule.IndividualResult> nestedObjectArray = new List<HardeningModule.IndividualResult>();

                // Defining the category name
                string CatName = "MicrosoftDefender";

                #region NX Bit Verification

                //Verify the NX bit as shown in bcdedit /enum or Get-BcdEntry, info about numbers and values correlation: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcdosloader-nxpolicy
                using (PowerShell ps = PowerShell.Create())
                {
                    // Add the PowerShell script to the instance
                    ps.AddScript(@"
                    (Get-BcdEntry).Elements | Where-Object -FilterScript { $_.Name -ieq 'nx' } | Select-Object -ExpandProperty Value
                ");

                    try
                    {
                        // Invoke the command and get the results
                        var results = ps.Invoke();

                        if (ps.Streams.Error.Count > 0)
                        {
                            // Handle errors
                            foreach (var error in ps.Streams.Error)
                            {
                                HardeningModule.VerboseLogger.Write($"Error: {error.ToString()}");
                            }
                        }

                        // Extract the NX value
                        if (results.Count > 0)
                        {
                            string nxValue = results[0].BaseObject.ToString();

                            // Determine compliance based on the value
                            bool compliant = nxValue == "3";

                            // Add the result to the list
                            nestedObjectArray.Add(new IndividualResult
                            {
                                FriendlyName = "Boot Configuration Data (BCD) No-eXecute (NX) Value",
                                Compliant = compliant ? "True" : "False",
                                Value = nxValue,
                                Name = "Boot Configuration Data (BCD) No-eXecute (NX) Value",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                        else
                        {
                            HardeningModule.VerboseLogger.Write("No results retrieved from Get-BcdEntry command.");
                        }
                    }
                    catch (Exception ex)
                    {
                        HardeningModule.VerboseLogger.Write($"Exception: {ex.Message}");
                    }
                }

                #endregion

                #region Process Mitigations

                // Create a PowerShell instance and run the Get-ProcessMitigation -System command
                // Getting the ForceRelocateImages directly from the PowerShell script because processing it outside in C# wouldn't work
                using (PowerShell ps = PowerShell.Create())
                {
                    // Define the script to be executed
                    string script = @"
                        return (Get-ProcessMitigation -System).ASLR.ForceRelocateImages
                        ";

                    try
                    {
                        // Add the script to the PowerShell instance
                        ps.AddScript(script);

                        // Invoke the command and get the results
                        var results = ps.Invoke();

                        // Check if there are any errors
                        if (ps.Streams.Error.Count > 0)
                        {
                            // Handle errors
                            foreach (var error in ps.Streams.Error)
                            {
                                HardeningModule.VerboseLogger.Write($"Error: {error.ToString()}");
                            }
                        }

                        // Check if results are not null or empty
                        if (results != null && results.Count > 0)
                        {
                            // initialize a variable to store the ForceRelocateImages value
                            string ForceRelocateImages = null;

                            // Extract the ForceRelocateImages value and store it in the variable
                            ForceRelocateImages = results[0].ToString();

                            // Check if the value is not null
                            if (ForceRelocateImages != null)
                            {
                                // Determine compliance based on the value
                                bool compliant = string.Equals(ForceRelocateImages, "ON", StringComparison.OrdinalIgnoreCase);

                                nestedObjectArray.Add(new HardeningModule.IndividualResult
                                {
                                    FriendlyName = "Mandatory ASLR",
                                    Compliant = compliant ? "True" : "False",
                                    Value = ForceRelocateImages,
                                    Name = "Mandatory ASLR",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });

                            }
                            else
                            {
                                nestedObjectArray.Add(new HardeningModule.IndividualResult
                                {
                                    FriendlyName = "Mandatory ASLR",
                                    Compliant = "False",
                                    Value = "False",
                                    Name = "Mandatory ASLR",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });
                            }
                        }
                        else
                        {
                            nestedObjectArray.Add(new HardeningModule.IndividualResult
                            {
                                FriendlyName = "Mandatory ASLR",
                                Compliant = "False",
                                Value = "False",
                                Name = "Mandatory ASLR",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        HardeningModule.VerboseLogger.Write($"Exception: {ex.Message}");
                    }
                }


                // Get the current system's exploit mitigation policy XML file using the Get-ProcessMitigation cmdlet
                using (PowerShell ps = PowerShell.Create())
                {
                    ps.AddCommand("Get-ProcessMitigation")
                    .AddParameter("RegistryConfigFilePath", HardeningModule.GlobalVars.CurrentlyAppliedMitigations);

                    try
                    {
                        Collection<PSObject> results = ps.Invoke();

                        if (ps.Streams.Error.Count > 0)
                        {
                            // Handle errors
                            foreach (var error in ps.Streams.Error)
                            {
                                HardeningModule.VerboseLogger.Write($"Error: {error.ToString()}");
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        HardeningModule.VerboseLogger.Write($"Exception: {ex.Message}");
                    }
                }

                // Process the system mitigations result from the XML file
                Dictionary<string, HashSet<string>> RevisedProcessMitigationsOnTheSystem = MitigationPolicyProcessor.ProcessMitigationPolicies(HardeningModule.GlobalVars.CurrentlyAppliedMitigations);

                // Import the CSV file as an object
                List<HardeningModule.ProcessMitigationsParser.ProcessMitigationsRecords> ProcessMitigations = HardeningModule.GlobalVars.ProcessMitigations;

                // Only keep the enabled mitigations in the CSV, then group the data by ProgramName
                var GroupedMitigations = ProcessMitigations
          .Where(x => x.Action == "Enable")
          .GroupBy(x => x.ProgramName)
          .Select(g => new { ProgramName = g.Key, Mitigations = g.Select(x => x.Mitigation).ToArray() })
          .ToList();

                // A dictionary to store the output of the CSV file
                Dictionary<string, string[]> TargetMitigations = new Dictionary<string, string[]>();

                // Loop through each group in the grouped mitigations array and add the ProgramName and Mitigations to the dictionary
                foreach (var item in GroupedMitigations)
                {
                    TargetMitigations[item.ProgramName] = item.Mitigations;
                }

                // Comparison
                // Compare the values of the two hashtables if the keys match
                foreach (var targetMitigationItem in TargetMitigations)
                {
                    // Get the current key and value from dictionary containing the CSV data
                    string ProcessName_Target = targetMitigationItem.Key;
                    string[] ProcessMitigations_Target = targetMitigationItem.Value;

                    // Check if the dictionary containing the currently applied mitigations contains the same key
                    // Meaning the same executable is present in both dictionaries
                    if (RevisedProcessMitigationsOnTheSystem.ContainsKey(ProcessName_Target))
                    {
                        // Get the value from the applied mitigations dictionary
                        HashSet<string> ProcessMitigations_Applied = RevisedProcessMitigationsOnTheSystem[ProcessName_Target];

                        // Convert the arrays to HashSet for order-agnostic comparison
                        HashSet<string> targetSet = new HashSet<string>(ProcessMitigations_Target);

                        // Compare the values of the two dictionaries to see if they are the same without considering the order of the elements (process mitigations)
                        if (!targetSet.SetEquals(ProcessMitigations_Applied))
                        {
                            // If the values are different, it means the process has different mitigations applied to it than the ones in the CSV file
                            HardeningModule.VerboseLogger.Write($"Mitigations for {ProcessName_Target} were found but are not compliant");
                            HardeningModule.VerboseLogger.Write($"Applied Mitigations: {string.Join(",", ProcessMitigations_Applied)}");
                            HardeningModule.VerboseLogger.Write($"Target Mitigations: {string.Join(",", ProcessMitigations_Target)}");

                            // Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                            HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues++;

                            nestedObjectArray.Add(new HardeningModule.IndividualResult
                            {
                                FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                                Compliant = "False",
                                Value = string.Join(",", ProcessMitigations_Applied),
                                Name = $"Process Mitigations for: {ProcessName_Target}",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                        else
                        {
                            // If the values are the same, it means the process has the same mitigations applied to it as the ones in the CSV file
                            HardeningModule.VerboseLogger.Write($"Mitigations for {ProcessName_Target} are compliant");

                            // Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                            HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues++;

                            nestedObjectArray.Add(new HardeningModule.IndividualResult
                            {
                                FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                                Compliant = "True",
                                Value = string.Join(",", ProcessMitigations_Target), // Join the array elements into a string to display them properly in the output CSV file
                                Name = $"Process Mitigations for: {ProcessName_Target}",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                    }
                    else
                    {
                        //If the process name is not found in the hashtable containing the currently applied mitigations, it means the process doesn't have any mitigations applied to it
                        HardeningModule.VerboseLogger.Write($"Mitigations for {ProcessName_Target} were not found");

                        // Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                        HardeningModule.GlobalVars.TotalNumberOfTrueCompliantValues++;

                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                            Compliant = "False",
                            Value = "N/A",
                            Name = $"Process Mitigations for: {ProcessName_Target}",
                            Category = CatName,
                            Method = "Cmdlet"
                        });
                    }
                }

                #endregion

                #region Drivers BlockList Scheduled Task Verification

                bool DriverBlockListScheduledTaskResult = false;

                // Initialize the variable at the time of declaration
                var DriverBlockListScheduledTaskResultObject = HardeningModule.TaskSchedulerHelper.Get(
          "MSFT Driver Block list update",
          "\\MSFT Driver Block list update\\",
          HardeningModule.TaskSchedulerHelper.OutputType.Boolean
      );

                // Convert to boolean
                DriverBlockListScheduledTaskResult = Convert.ToBoolean(DriverBlockListScheduledTaskResultObject);
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Fast weekly Microsoft recommended driver block list update",
                    Compliant = DriverBlockListScheduledTaskResult ? "True" : "False",
                    Value = DriverBlockListScheduledTaskResult ? "True" : "False",
                    Name = "Fast weekly Microsoft recommended driver block list update",
                    Category = CatName,
                    Method = "CIM"
                });

                #endregion


                // Get the value and convert it to unsigned int16
                ushort PlatformUpdatesChannel = Convert.ToUInt16(HardeningModule.GlobalVars.MDAVPreferencesCurrent.PlatformUpdatesChannel);
                // resolve the number to a string using the dictionary
                HardeningModule.DefenderPlatformUpdatesChannels.Channels.TryGetValue(PlatformUpdatesChannel, out string PlatformUpdatesChannelName);
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Microsoft Defender Platform Updates Channel",
                    Compliant = "N/A",
                    Value = PlatformUpdatesChannelName,
                    Name = "Microsoft Defender Platform Updates Channel",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to unsigned int16
                ushort EngineUpdatesChannel = Convert.ToUInt16(HardeningModule.GlobalVars.MDAVPreferencesCurrent.EngineUpdatesChannel);

                // resolve the number to a string using the dictionary
                HardeningModule.DefenderPlatformUpdatesChannels.Channels.TryGetValue(EngineUpdatesChannel, out string EngineUpdatesChannelName);
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Microsoft Defender Engine Updates Channel",
                    Compliant = "N/A",
                    Value = EngineUpdatesChannelName,
                    Name = "Microsoft Defender Engine Updates Channel",
                    Category = CatName,
                    Method = "CIM"
                });


                // the type of ControlledFolderAccessAllowedApplications is List<string>
                // Cast to a more general collection type
                var ControlledFolderAccessExclusionsApplications = HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "ControlledFolderAccessAllowedApplications") as IEnumerable<string>;

                // Convert the list to a comma-separated string to be easier to display in the output CSV file and console
                string ControlledFolderAccessExclusionsResults = ControlledFolderAccessExclusionsApplications != null ? string.Join(", ", ControlledFolderAccessExclusionsApplications) : string.Empty;

                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Controlled Folder Access Exclusions",
                    Compliant = "N/A",
                    Value = ControlledFolderAccessExclusionsResults,
                    Name = "Controlled Folder Access Exclusions",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool AllowSwitchToAsyncInspectionResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "AllowSwitchToAsyncInspection"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Allow Switch To Async Inspection",
                    Compliant = AllowSwitchToAsyncInspectionResult ? "True" : "False",
                    Value = AllowSwitchToAsyncInspectionResult ? "True" : "False",
                    Name = "Allow Switch To Async Inspection",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool OOBEEnableRtpAndSigUpdateResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "oobeEnableRTpAndSigUpdate"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "OOBE Enable Rtp And Sig Update",
                    Compliant = OOBEEnableRtpAndSigUpdateResult ? "True" : "False",
                    Value = OOBEEnableRtpAndSigUpdateResult ? "True" : "False",
                    Name = "OOBE Enable Rtp And Sig Update",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool IntelTDTEnabledResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "IntelTDTEnabled"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Intel TDT Enabled",
                    Compliant = IntelTDTEnabledResult ? "True" : "False",
                    Value = IntelTDTEnabledResult ? "True" : "False",
                    Name = "Intel TDT Enabled",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string SmartAppControlStateResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVConfigCurrent, "SmartAppControlState"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Smart App Control State",
                    Compliant = SmartAppControlStateResult.Equals("on", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = SmartAppControlStateResult,
                    Name = "Smart App Control State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string EnableControlledFolderAccessResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "EnableControlledFolderAccess"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Controlled Folder Access",
                    Compliant = EnableControlledFolderAccessResult.Equals("1", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = EnableControlledFolderAccessResult,
                    Name = "Controlled Folder Access",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool DisableRestorePointResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "DisableRestorePoint"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Restore Point scanning",
                    Compliant = DisableRestorePointResult ? "False" : "True",
                    Value = DisableRestorePointResult ? "False" : "True",
                    Name = "Enable Restore Point scanning",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // Set-MpPreference -PerformanceModeStatus Enabled => (Get-MpPreference).PerformanceModeStatus == 1 => Turns on Dev Drive Protection in Microsoft Defender GUI
                // Set-MpPreference -PerformanceModeStatus Disabled => (Get-MpPreference).PerformanceModeStatus == 0 => Turns off Dev Drive Protection in Microsoft Defender GUI
                string PerformanceModeStatusResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "PerformanceModeStatus"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Performance Mode Status",
                    Compliant = PerformanceModeStatusResult.Equals("0", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = PerformanceModeStatusResult,
                    Name = "Performance Mode Status",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool EnableConvertWarnToBlockResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "EnableConvertWarnToBlock"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Convert Warn To Block",
                    Compliant = EnableConvertWarnToBlockResult ? "True" : "False",
                    Value = EnableConvertWarnToBlockResult ? "True" : "False",
                    Name = "Enable Convert Warn To Block",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string BruteForceProtectionAggressivenessResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionAggressiveness"));

                // Check if the value is not null
                if (BruteForceProtectionAggressivenessResult != null)
                {
                    // Check if the value is 1 or 2, both are compliant
                    if (
              BruteForceProtectionAggressivenessResult.Equals("1", StringComparison.OrdinalIgnoreCase) ||
              BruteForceProtectionAggressivenessResult.Equals("2", StringComparison.OrdinalIgnoreCase)
          )
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Aggressiveness",
                            Compliant = "True",
                            Value = BruteForceProtectionAggressivenessResult,
                            Name = "BruteForce Protection Aggressiveness",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Aggressiveness",
                            Compliant = "False",
                            Value = "N/A",
                            Name = "BruteForce Protection Aggressiveness",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "BruteForce Protection Aggressiveness",
                        Compliant = "False",
                        Value = "N/A",
                        Name = "BruteForce Protection Aggressiveness",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string BruteForceProtectionMaxBlockTimeResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionMaxBlockTime"));

                // Check if the value is not null
                if (BruteForceProtectionMaxBlockTimeResult != null)
                {
                    // Check if the value is 0 or 4294967295, both are compliant
                    if (
              BruteForceProtectionMaxBlockTimeResult.Equals("0", StringComparison.OrdinalIgnoreCase) ||
              BruteForceProtectionMaxBlockTimeResult.Equals("4294967295", StringComparison.OrdinalIgnoreCase)
          )
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Max Block Time",
                            Compliant = "True",
                            Value = BruteForceProtectionMaxBlockTimeResult,
                            Name = "BruteForce Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Max Block Time",
                            Compliant = "False",
                            Value = "N/A",
                            Name = "BruteForce Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "BruteForce Protection Max Block Time",
                        Compliant = "False",
                        Value = "N/A",
                        Name = "BruteForce Protection Max Block Time",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string BruteForceProtectionConfiguredStateResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionConfiguredState"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "BruteForce Protection Configured State",
                    Compliant = BruteForceProtectionConfiguredStateResult.Equals("1", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = BruteForceProtectionConfiguredStateResult,
                    Name = "BruteForce Protection Configured State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string RemoteEncryptionProtectionMaxBlockTimeResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionMaxBlockTime"));

                // Check if the value is not null
                if (RemoteEncryptionProtectionMaxBlockTimeResult != null)
                {
                    // Check if the value is 0 or 4294967295, both are compliant
                    if (
              RemoteEncryptionProtectionMaxBlockTimeResult.Equals("0", StringComparison.OrdinalIgnoreCase) ||
              RemoteEncryptionProtectionMaxBlockTimeResult.Equals("4294967295", StringComparison.OrdinalIgnoreCase)
                  )
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "Remote Encryption Protection Max Block Time",
                            Compliant = "True",
                            Value = RemoteEncryptionProtectionMaxBlockTimeResult,
                            Name = "Remote Encryption Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new HardeningModule.IndividualResult
                        {
                            FriendlyName = "Remote Encryption Protection Max Block Time",
                            Compliant = "False",
                            Value = "N/A",
                            Name = "Remote Encryption Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new HardeningModule.IndividualResult
                    {
                        FriendlyName = "Remote Encryption Protection Max Block Time",
                        Compliant = "False",
                        Value = "N/A",
                        Name = "Remote Encryption Protection Max Block Time",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string RemoteEncryptionProtectionAggressivenessResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionAggressiveness"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Remote Encryption Protection Aggressiveness",
                    // Check if the value is 1 or 2, both are compliant
                    Compliant = RemoteEncryptionProtectionAggressivenessResult.Equals("1", StringComparison.OrdinalIgnoreCase) || RemoteEncryptionProtectionAggressivenessResult.Equals("2", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = RemoteEncryptionProtectionAggressivenessResult,
                    Name = "Remote Encryption Protection Aggressiveness",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string RemoteEncryptionProtectionConfiguredStateResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionConfiguredState"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Remote Encryption Protection Configured State",
                    Compliant = RemoteEncryptionProtectionConfiguredStateResult.Equals("1", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = RemoteEncryptionProtectionConfiguredStateResult,
                    Name = "Remote Encryption Protection Configured State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#cloudblocklevel
                string CloudBlockLevelResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "CloudBlockLevel"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Cloud Block Level",
                    Compliant = CloudBlockLevelResult.Equals("6", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = CloudBlockLevelResult,
                    Name = "Cloud Block Level",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowemailscanning
                bool DisableEmailScanningResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "DisableEmailScanning"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Email Scanning",
                    Compliant = DisableEmailScanningResult ? "False" : "True",
                    Value = DisableEmailScanningResult ? "False" : "True",
                    Name = "Email Scanning",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent
                string SubmitSamplesConsentResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "SubmitSamplesConsent"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Send file samples when further analysis is required",
                    Compliant = SubmitSamplesConsentResult.Equals("3", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = SubmitSamplesConsentResult,
                    Name = "Send file samples when further analysis is required",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowcloudprotection
                string MAPSReportingResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "MAPSReporting"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Join Microsoft MAPS (aka SpyNet)",
                    Compliant = MAPSReportingResult.Equals("2", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = MAPSReportingResult,
                    Name = "Join Microsoft MAPS (aka SpyNet)",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#mpengine_enablefilehashcomputation
                bool EnableFileHashComputationResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "EnableFileHashComputation"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "File Hash Computation",
                    Compliant = EnableFileHashComputationResult ? "True" : "False",
                    Value = EnableFileHashComputationResult ? "True" : "False",
                    Name = "File Hash Computation",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#cloudextendedtimeout
                string CloudExtendedTimeoutResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "CloudExtendedTimeout"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Extended cloud check (Seconds)",
                    Compliant = CloudExtendedTimeoutResult.Equals("50", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = CloudExtendedTimeoutResult,
                    Name = "Extended cloud check (Seconds)",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#puaprotection
                string PUAProtectionResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "PUAProtection"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Detection for potentially unwanted applications",
                    Compliant = PUAProtectionResult.Equals("1", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = PUAProtectionResult,
                    Name = "Detection for potentially unwanted applications",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#disablecatchupquickscan
                bool DisableCatchupQuickScanResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "DisableCatchupQuickScan"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Catchup Quick Scan",
                    Compliant = DisableCatchupQuickScanResult ? "False" : "True",
                    Value = DisableCatchupQuickScanResult ? "False" : "True",
                    Name = "Catchup Quick Scan",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#checkforsignaturesbeforerunningscan
                bool CheckForSignaturesBeforeRunningScanResult = Convert.ToBoolean(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "CheckForSignaturesBeforeRunningScan"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Check For Signatures Before Running Scan",
                    Compliant = CheckForSignaturesBeforeRunningScanResult ? "True" : "False",
                    Value = CheckForSignaturesBeforeRunningScanResult ? "True" : "False",
                    Name = "Check For Signatures Before Running Scan",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#enablenetworkprotection
                string EnableNetworkProtectionResult = Convert.ToString(HardeningModule.PropertyHelper.GetPropertyValue(HardeningModule.GlobalVars.MDAVPreferencesCurrent, "EnableNetworkProtection"));
                nestedObjectArray.Add(new HardeningModule.IndividualResult
                {
                    FriendlyName = "Enable Network Protection",
                    Compliant = EnableNetworkProtectionResult.Equals("1", StringComparison.OrdinalIgnoreCase) ? "True" : "False",
                    Value = EnableNetworkProtectionResult,
                    Name = "Enable Network Protection",
                    Category = CatName,
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (HardeningModule.CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    HardeningModule.ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                HardeningModule.GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
            });
        }
    }
}
