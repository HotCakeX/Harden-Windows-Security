using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management;
using System.Management.Automation;
using System.Threading.Tasks;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class ConfirmSystemComplianceMethods
    {

        /// <summary>
        /// The main Orchestrator of the Confirm-SystemCompliance cmdlet
        /// It will do all of the required tasks
        /// </summary>
        /// <param name="methodNames"></param>
        /// <exception cref="Exception"></exception>
        internal static void OrchestrateComplianceChecks(params string[] methodNames)
        {

            string scriptToStartLanmanWorkstationService = """
sc.exe config LanmanWorkstation start=auto
sc.exe start LanmanWorkstation
""";

            // The "LanmanWorkstation" with the display name of "Workstation" is necessary to be running for at least one category to perform successfully, which is the Miscellaneous Category
            _ = PowerShellExecutor.ExecuteScript(scriptToStartLanmanWorkstationService);


            // Call the method to get the security group policies to be exported to a file
            ConfirmSystemComplianceMethods.ExportSecurityPolicy();

            // Storing the output of the ini file parsing function
            GlobalVars.SystemSecurityPoliciesIniObject = IniFileConverter.ConvertFromIniFile(GlobalVars.securityPolicyInfPath);

            // Process the SecurityPoliciesVerification.csv and save the output to the global variable GlobalVars.SecurityPolicyRecords
            string basePath = GlobalVars.path ?? throw new InvalidOperationException("GlobalVars.path cannot be null.");
            string fullPath = Path.Combine(basePath, "Resources", "SecurityPoliciesVerification.csv");
            GlobalVars.SecurityPolicyRecords = SecurityPolicyCsvProcessor.ProcessSecurityPolicyCsvFile(fullPath);

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
                throw MethodsTaskOutput.Exception;

                // this should automatically throw ?
                // MethodsTaskOutput.GetAwaiter().GetResult()
            }
            else if (MethodsTaskOutput.IsCompletedSuccessfully)
            {
                // Logger.LogMessage("successful", LogTypeIntel.Information);
            }
        }

        // Defining delegates for the methods
        private static readonly Dictionary<string, Func<Task>> methodDictionary = new(StringComparer.OrdinalIgnoreCase)
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
        private static async Task RunComplianceMethodsInParallelAsync(params string[] methodNames)
        {
            // Define a list to store the methods to run
            List<Func<Task>> methodsToRun;

            // if the methodNames parameter wasn't specified
            if (methodNames is null || methodNames.Length == 0)
            {
                // Get all methods from the dictionary
                methodsToRun = [.. methodDictionary.Values];
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
        private static Task VerifyAttackSurfaceReductionRules()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                string CatName = "AttackSurfaceReductionRules";

                // Warn + Block array - meaning either states are acceptable
                string[] MultipleAcceptableStates = ["6", "1"];

                // variables to store the ASR rules IDs and their corresponding actions
                object idsObj;
                object actionsObj;

                if (GlobalVars.MDAVPreferencesCurrent is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.MDAVPreferencesCurrent), "MDAVPreferencesCurrent cannot be null.");
                }
                else
                {
                    idsObj = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionRules_Ids");
                    actionsObj = PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AttackSurfaceReductionRules_Actions");
                }

                // Individual ASR rules verification
                string[]? ids = HelperMethods.ConvertToStringArray(idsObj);
                string[]? actions = HelperMethods.ConvertToStringArray(actionsObj);

                // If $Ids variable is not empty, convert them to lower case because some IDs can be in upper case and result in inaccurate comparison
                if (ids is not null)
                {
                    ids = ids.Select(id => id.ToLowerInvariant()).ToArray();
                }

                // Loop over each item in the HashTable
                foreach (var kvp in AttackSurfaceReductionIntel.ASRTable)
                {
                    // Assign each key/value to local variables
                    string name = kvp.Key.ToLowerInvariant();
                    string friendlyName = kvp.Value;

                    // Default action is set to 0 (Not configured)
                    string action = "0";

                    // Check if the $Ids array is not empty and current ID is present in the $Ids array
                    if (ids is not null && ids.Contains(name, StringComparer.OrdinalIgnoreCase))
                    {
                        // If yes, check if the $Actions array is not empty
                        if (actions is not null)
                        {
                            // If yes, use the index of the ID in the array to access the action value
                            action = actions[Array.FindIndex(ids, id => id.Equals(name, StringComparison.OrdinalIgnoreCase))];
                        }
                    }

                    // The following ASR Rules are compliant either if they are set to block or warn + block
                    // 'Block use of copied or impersonated system tools' -> because it's in preview and is set to 6 for Warn instead of 1 for block in Protect-WindowsSecurity cmdlet
                    // "Block executable files from running unless they meet a prevalence; age or trusted list criterion" -> for ease of use it's compliant if set to 6 (Warn) or 1 (Block)
                    bool compliant = name switch
                    {
                        "c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb" => MultipleAcceptableStates.Contains(action),
                        "01443614-cd74-433a-b99e-2ecdc07bfc25" => MultipleAcceptableStates.Contains(action),
                        // All other ASR rules are compliant if they are set to block (1)
                        _ => string.Equals(action, "1", StringComparison.OrdinalIgnoreCase)
                    };

                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = friendlyName,
                        Compliant = compliant,
                        Value = action,
                        Name = name,
                        Category = CatName,
                        Method = "CIM"
                    });
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Windows Update Configurations category during system compliance checking
        /// </summary>
        private static Task VerifyWindowsUpdateConfigurations()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                string CatName = "WindowsUpdateConfigurations";

                // Get the control from MDM CIM
                var mdmPolicy = GlobalVars.MDM_Policy_Result01_Update02
                ?? throw new InvalidOperationException("MDM_Policy_Result01_Update02 is null");

                HashtableCheckerResult MDM_Policy_Result01_Update02_AllowAutoWindowsUpdateDownloadOverMeteredNetwork =
                    HashtableChecker.CheckValue<string>(mdmPolicy, "AllowAutoWindowsUpdateDownloadOverMeteredNetwork", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Allow updates to be downloaded automatically over metered connections",
                    Compliant = MDM_Policy_Result01_Update02_AllowAutoWindowsUpdateDownloadOverMeteredNetwork.IsMatch,
                    Value = MDM_Policy_Result01_Update02_AllowAutoWindowsUpdateDownloadOverMeteredNetwork.Value,
                    Name = "Allow updates to be downloaded automatically over metered connections",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Policy_Result01_Update02_AllowAutoUpdate = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Policy_Result01_Update02, "AllowAutoUpdate", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Automatically download updates and install them on maintenance day",
                    Compliant = MDM_Policy_Result01_Update02_AllowAutoUpdate.IsMatch,
                    Value = MDM_Policy_Result01_Update02_AllowAutoUpdate.Value,
                    Name = "Automatically download updates and install them on maintenance day",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Policy_Result01_Update02_AllowMUUpdateService = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Policy_Result01_Update02, "AllowMUUpdateService", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Install updates for other Microsoft products",
                    Compliant = MDM_Policy_Result01_Update02_AllowMUUpdateService.IsMatch,
                    Value = MDM_Policy_Result01_Update02_AllowMUUpdateService.Value,
                    Name = "Install updates for other Microsoft products",
                    Category = CatName,
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Non-Admin Commands category during system compliance checking
        /// </summary>
        private static Task VerifyNonAdminCommands()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                string CatName = "NonAdminCommands";

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Edge Browser Configurations category during system compliance checking
        /// </summary>
        private static Task VerifyEdgeBrowserConfigurations()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                string CatName = "EdgeBrowserConfigurations";

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Device Guard category during system compliance checking
        /// </summary>
        private static Task VerifyDeviceGuard()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                string CatName = "DeviceGuard";

                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#enablevirtualizationbasedsecurity
                bool EnableVirtualizationBasedSecurity = GetMDMResultValue.Get("EnableVirtualizationBasedSecurity", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Virtualization Based Security",
                    Compliant = EnableVirtualizationBasedSecurity,
                    Value = EnableVirtualizationBasedSecurity ? "True" : "False",
                    Name = "EnableVirtualizationBasedSecurity",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#requireplatformsecurityfeatures
                string? RequirePlatformSecurityFeatures = GlobalVars.MDMResults!
                 .Where(element => string.Equals(element.Name, "RequirePlatformSecurityFeatures", StringComparison.OrdinalIgnoreCase))
                 .Select(element => element.Value)
                 .FirstOrDefault();

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Require Platform Security Features",
                    Compliant = RequirePlatformSecurityFeatures is not null &&
                                (RequirePlatformSecurityFeatures.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                                 RequirePlatformSecurityFeatures.Equals("3", StringComparison.OrdinalIgnoreCase)),
                    Value = (RequirePlatformSecurityFeatures is not null && RequirePlatformSecurityFeatures.Equals("1", StringComparison.OrdinalIgnoreCase)) ?
                            "VBS with Secure Boot" :
                            (RequirePlatformSecurityFeatures is not null && RequirePlatformSecurityFeatures.Equals("3", StringComparison.OrdinalIgnoreCase)) ?
                            "VBS with Secure Boot and direct memory access (DMA) Protection" :
                            "False",
                    Name = "RequirePlatformSecurityFeatures",
                    Category = CatName,
                    Method = "MDM"
                });



                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#hypervisorenforcedcodeintegrity
                bool HypervisorEnforcedCodeIntegrity = GetMDMResultValue.Get("HypervisorEnforcedCodeIntegrity", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Hypervisor Enforced Code Integrity - UEFI Lock",
                    Compliant = HypervisorEnforcedCodeIntegrity,
                    Value = HypervisorEnforcedCodeIntegrity ? "True" : "False",
                    Name = "HypervisorEnforcedCodeIntegrity",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-VirtualizationBasedTechnology?WT.mc_id=Portal-fx#requireuefimemoryattributestable
                bool RequireUEFIMemoryAttributesTable = GetMDMResultValue.Get("RequireUEFIMemoryAttributesTable", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Require HVCI MAT (Memory Attribute Table)",
                    Compliant = RequireUEFIMemoryAttributesTable,
                    Value = RequireUEFIMemoryAttributesTable ? "True" : "False",
                    Name = "HVCIMATRequired",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#lsacfgflags
                bool LsaCfgFlags = GetMDMResultValue.Get("LsaCfgFlags", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Credential Guard Configuration - UEFI Lock",
                    Compliant = LsaCfgFlags,
                    Value = LsaCfgFlags ? "True" : "False",
                    Name = "LsaCfgFlags",
                    Category = CatName,
                    Method = "MDM"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-deviceguard?WT.mc_id=Portal-fx#configuresystemguardlaunch
                bool ConfigureSystemGuardLaunch = GetMDMResultValue.Get("ConfigureSystemGuardLaunch", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "System Guard Launch",
                    Compliant = ConfigureSystemGuardLaunch,
                    Value = ConfigureSystemGuardLaunch ? "True" : "False",
                    Name = "ConfigureSystemGuardLaunch",
                    Category = CatName,
                    Method = "MDM"
                });

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the BitLocker Settings category during system compliance checking
        /// </summary>
        private static Task VerifyBitLockerSettings()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "BitLockerSettings";

                // Returns true or false depending on whether Kernel DMA Protection is on or off
                bool BootDMAProtection = SystemInformationClass.BootDmaCheck() != 0;

                if (BootDMAProtection)
                {
                    Logger.LogMessage("Kernel DMA protection is enabled", LogTypeIntel.Information);
                }
                else
                {
                    Logger.LogMessage("Kernel DMA protection is disabled", LogTypeIntel.Information);
                }


                // Get the status of Bitlocker DMA protection
                int BitlockerDMAProtectionStatus = 0;

                // Get the value of the registry key and return 0 if it doesn't exist
                object? regValue = Registry.GetValue(@"HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\FVE", "DisableExternalDMAUnderLock", 0);

                // Explicitly check if regValue is null before casting
                if (regValue is int intValue)
                {
                    BitlockerDMAProtectionStatus = intValue;
                }
                else
                {
                    // regValue should not be null due to the default value set in GetValue method
                    BitlockerDMAProtectionStatus = 0;
                }

                // Bitlocker DMA counter measure status
                // Returns true if only either Kernel DMA protection is on and Bitlocker DMA protection if off
                // or Kernel DMA protection is off and Bitlocker DMA protection is on
                bool ItemState = BootDMAProtection ^ (BitlockerDMAProtectionStatus == 1);

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "DMA protection",
                    Compliant = ItemState,
                    Value = ItemState ? "True" : "False",
                    Name = "DMA protection",
                    Category = CatName,
                    Method = "Windows API"
                });


                // To detect if Hibernate is enabled and set to full
                // Only perform the check if the system is not a virtual machine
                var isVirtualMachine = PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "IsVirtualMachine");

                if (isVirtualMachine is not null && !(bool)isVirtualMachine)
                {
                    bool IndividualItemResult = false;

                    object? hiberFileType = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Power", "HiberFileType", null);
                    if (hiberFileType is not null && (int)hiberFileType == 2)
                    {
                        IndividualItemResult = true;
                    }

                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "Hibernate is set to full",
                        Compliant = IndividualItemResult,
                        Value = IndividualItemResult ? "True" : "False",
                        Name = "Hibernate is set to full",
                        Category = CatName,
                        Method = "Registry Keys"
                    });
                }
                else
                {
                    GlobalVars.TotalNumberOfTrueCompliantValues--;
                }


                // OS Drive encryption verifications
                // Check if BitLocker is on for the OS Drive
                // The ProtectionStatus remains off while the drive is encrypting or decrypting
                var volumeInfo = BitLocker.GetEncryptedVolumeInfo(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:\\");

                if (volumeInfo.ProtectionStatus is BitLocker.ProtectionStatus.Protected)
                {
                    // Get the key protectors of the OS Drive after making sure it is encrypted
                    IEnumerable<BitLocker.KeyProtectorType?> KeyProtectors = volumeInfo.KeyProtector!
                    .Select(kp => kp.KeyProtectorType);

                    // Display the key protectors
                    // Logger.LogMessage(string.Join(", ", KeyProtectors));

                    // Check if TPM+PIN and recovery password are being used - Normal Security level
                    if (KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPin) && KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword))
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "Secure OS Drive encryption",
                            Compliant = true,
                            Value = "Normal Security Level",
                            Name = "Secure OS Drive encryption",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    // Check if TPM+PIN+StartupKey and recovery password are being used - Enhanced security level
                    else if (KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPinStartupKey) && KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword))
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "Secure OS Drive encryption",
                            Compliant = true,
                            Value = "Enhanced Security Level",
                            Name = "Secure OS Drive encryption",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        Logger.LogMessage("BitLocker is enabled for the OS Drive but it does not conform to the Normal or Enhanced Security levels requirements.", LogTypeIntel.Information);

                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "Secure OS Drive encryption",
                            Compliant = false,
                            Value = "False",
                            Name = "Secure OS Drive encryption",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    Logger.LogMessage("BitLocker is not enabled for the OS Drive.", LogTypeIntel.Information);

                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "Secure OS Drive encryption",
                        Compliant = false,
                        Value = "False",
                        Name = "Secure OS Drive encryption",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Non-OS-Drive-BitLocker-Drives-Encryption-Verification
                List<BitLocker.BitLockerVolume> NonRemovableNonOSDrives = [];

                foreach (BitLocker.BitLockerVolume Drive in BitLocker.GetAllEncryptedVolumeInfo(true, false))
                {
                    // Increase the number of available compliant values for each non-OS drive that was found
                    GlobalVars.TotalNumberOfTrueCompliantValues++;
                    NonRemovableNonOSDrives.Add(Drive);
                }

                // Check if there are any non-OS volumes
                if (NonRemovableNonOSDrives.Count != 0)
                {
                    // Loop through each non-OS volume and verify their encryption
                    foreach (var BitLockerDrive in NonRemovableNonOSDrives.OrderBy(d => d.MountPoint))
                    {
                        // If status is unknown, that means the non-OS volume is encrypted and locked, if it's on then it's on
                        if (BitLockerDrive.ProtectionStatus is BitLocker.ProtectionStatus.Protected or BitLocker.ProtectionStatus.Unknown)
                        {

                            // Check if the non-OS non-Removable drive has one of the following key protectors: RecoveryPassword, Password or ExternalKey (Auto-Unlock)
                            IEnumerable<BitLocker.KeyProtectorType?> KeyProtectors = volumeInfo.KeyProtector!
                             .Select(kp => kp.KeyProtectorType);


                            if (KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword) || KeyProtectors.Contains(BitLocker.KeyProtectorType.Password) || KeyProtectors.Contains(BitLocker.KeyProtectorType.ExternalKey))
                            {
                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                    Compliant = true,
                                    Value = "Encrypted",
                                    Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                    Category = CatName,
                                    Method = "CIM"
                                });
                            }
                            else
                            {
                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                    Compliant = false,
                                    Value = "Not properly encrypted",
                                    Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                    Category = CatName,
                                    Method = "CIM"
                                });
                            }
                        }
                        else
                        {
                            nestedObjectArray.Add(new IndividualResult
                            {
                                FriendlyName = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Compliant = false,
                                Value = "Not encrypted",
                                Name = $"Secure Drive {BitLockerDrive.MountPoint} encryption",
                                Category = CatName,
                                Method = "CIM"
                            });
                        }
                    }
                }


                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the Miscellaneous Configurations category during system compliance checking
        /// </summary>
        private static Task VerifyMiscellaneousConfigurations()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "MiscellaneousConfigurations";

                // Checking if all user accounts are part of the Hyper-V security Group
                // Get all the enabled user accounts that are not part of the Hyper-V Security group based on SID

                // The SID for the Hyper-V Administrators group
                string hyperVAdminGroupSID = "S-1-5-32-578";

                // Retrieve the list of local users and filter them based on the enabled status
                var usersNotInHyperVGroup = LocalUserRetriever.Get()
                    ?.Where(user => user.Enabled && user.GroupsSIDs is not null && !user.GroupsSIDs.Contains(hyperVAdminGroupSID, StringComparer.OrdinalIgnoreCase))
                    .ToList();

                // Determine compliance based on the filtered list to see if the list has any elements
                bool compliant = usersNotInHyperVGroup?.Count == 0;

                // Add result to the nested object array
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "All users are part of the Hyper-V Administrators group",
                    Compliant = compliant,
                    Value = compliant ? "True" : "False",
                    Name = "All users are part of the Hyper-V Administrators group",
                    Category = CatName,
                    Method = "CIM"
                });


                /// PS Equivalent: (auditpol /get /subcategory:"Other Logon/Logoff Events" /r | ConvertFrom-Csv).'Inclusion Setting'
                // Verify an Audit policy is enabled - only supports systems with English-US language
                CultureInfoProperties cultureInfoHelper = CultureInfoHelper.Get();
                string currentCulture = cultureInfoHelper.Name;

                if (string.Equals(currentCulture, "en-US", StringComparison.OrdinalIgnoreCase))
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

                    _ = process.Start();

                    // Read the output from the process
                    var output = process.StandardOutput.ReadToEnd();
                    process.WaitForExit();

                    // Check if the output is empty
                    if (string.IsNullOrWhiteSpace(output))
                    {
                        Logger.LogMessage("No output from the auditpol command.", LogTypeIntel.Information);
                        return;
                    }

                    // Convert the CSV output to a dictionary
                    using var reader = new StringReader(output);

                    // Initialize the inclusion setting
                    string? inclusionSetting = null;

                    // Read the first line to get the headers
                    string? headers = reader.ReadLine();

                    // Check if the headers are not null
                    if (headers is not null)
                    {
                        // Get the index of the "Inclusion Setting" column
                        var headerColumns = headers.Split(',');

                        int inclusionSettingIndex = Array.IndexOf(headerColumns, "Inclusion Setting");

                        // Read subsequent lines to get the values
                        string? values;
                        while ((values = reader.ReadLine()) is not null)
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
                    bool individualItemResult = string.Equals(inclusionSetting, "Success and Failure", StringComparison.OrdinalIgnoreCase);

                    // Add the result to the nested object array
                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "Audit policy for Other Logon/Logoff Events",
                        Compliant = individualItemResult,
                        Value = individualItemResult ? "Success and Failure" : inclusionSetting ?? string.Empty, // just to suppress the warning
                        Name = "Audit policy for Other Logon/Logoff Events",
                        Category = CatName ?? string.Empty, // just to suppress the warning
                        Method = "Cmdlet"
                    });
                }
                else
                {
                    // Decrement the total number of true compliant values
                    GlobalVars.TotalNumberOfTrueCompliantValues--;
                }


                // Get the control from MDM CIM
                if (GlobalVars.MDM_Policy_Result01_System02 is null)
                {
                    // Handle the case where the global variable is null
                    throw new InvalidOperationException("MDM_Policy_Result01_System02 is null.");
                }
                HashtableCheckerResult MDM_Policy_Result01_System02_AllowLocation = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Policy_Result01_System02, "AllowLocation", "0");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Disable Location",
                    Compliant = MDM_Policy_Result01_System02_AllowLocation.IsMatch,
                    Value = MDM_Policy_Result01_System02_AllowLocation.Value,
                    Name = "Disable Location",
                    Category = CatName ?? string.Empty, // just to suppress the warning
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName ?? string.Empty, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName ?? string.Empty, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else if (CatName is null)
                {
                    throw new ArgumentNullException(nameof(CatName), "CatName cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                }


                bool testSecureMacsResult = SSHConfigurations.TestSecureMACs();

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "SSH Secure MACs",
                    Compliant = testSecureMacsResult,
                    Value = testSecureMacsResult ? "True" : "False",
                    Name = "SSH Secure MACs",
                    Category = CatName ?? string.Empty, // just to suppress the warning
                    Method = "CIM"
                });

            });
        }


        /// <summary>
        /// Performs all of the tasks for the Windows Networking category during system compliance checking
        /// </summary>
        private static Task VerifyWindowsNetworking()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "WindowsNetworking";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Lock Screen category during system compliance checking
        /// </summary>
        private static Task VerifyLockScreen()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "LockScreen";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the User Account Control category during system compliance checking
        /// </summary>
        private static Task VerifyUserAccountControl()
        {

            return Task.Run(() =>
            {
                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "UserAccountControl";

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process the Security Policies for the current category that reside in the "SecurityPoliciesVerification.csv" file
                foreach (var Result in (SecurityPolicyChecker.CheckPolicyCompliance(CatName)))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Optional Windows Features category during system compliance checking
        /// </summary>
        private static Task VerifyOptionalWindowsFeatures()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "OptionalWindowsFeatures";

                // Get the results of all optional features
                WindowsFeatureChecker.FeatureStatus FeaturesCheckResults = WindowsFeatureChecker.CheckWindowsFeatures();

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "PowerShell v2 is disabled",
                    Compliant = string.Equals(FeaturesCheckResults.PowerShellv2, "Disabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.PowerShellv2,
                    Name = "PowerShell v2 is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "PowerShell v2 Engine is disabled",
                    Compliant = string.Equals(FeaturesCheckResults.PowerShellv2Engine, "Disabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.PowerShellv2Engine,
                    Name = "PowerShell v2 Engine is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Work Folders client is disabled",
                    Compliant = string.Equals(FeaturesCheckResults.WorkFoldersClient, "Disabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.WorkFoldersClient,
                    Name = "Work Folders client is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Internet Printing Client is disabled",
                    Compliant = string.Equals(FeaturesCheckResults.InternetPrintingClient, "Disabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.InternetPrintingClient,
                    Name = "Internet Printing Client is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Windows Media Player (legacy) is disabled",
                    Compliant = string.Equals(FeaturesCheckResults.WindowsMediaPlayer, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.WindowsMediaPlayer,
                    Name = "Windows Media Player (legacy) is disabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Microsoft Defender Application Guard is not present",
                    Compliant = string.Equals(FeaturesCheckResults.MDAG, "Disabled", StringComparison.OrdinalIgnoreCase) || string.Equals(FeaturesCheckResults.MDAG, "Unknown", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.MDAG,
                    Name = "Microsoft Defender Application Guard is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Windows Sandbox is enabled",
                    Compliant = string.Equals(FeaturesCheckResults.WindowsSandbox, "Enabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.WindowsSandbox,
                    Name = "Windows Sandbox is enabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Hyper-V is enabled",
                    Compliant = string.Equals(FeaturesCheckResults.HyperV, "Enabled", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.HyperV,
                    Name = "Hyper-V is enabled",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "WMIC is not present",
                    Compliant = string.Equals(FeaturesCheckResults.WMIC, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.WMIC,
                    Name = "WMIC is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Internet Explorer mode functionality for Edge is not present",
                    Compliant = string.Equals(FeaturesCheckResults.IEMode, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.IEMode,
                    Name = "Internet Explorer mode functionality for Edge is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Legacy Notepad is not present",
                    Compliant = string.Equals(FeaturesCheckResults.LegacyNotepad, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.LegacyNotepad,
                    Name = "Legacy Notepad is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "WordPad is not present",
                    Compliant = string.Equals(FeaturesCheckResults.LegacyWordPad, "Not Present", StringComparison.OrdinalIgnoreCase) || string.Equals(FeaturesCheckResults.LegacyWordPad, "Unknown", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.LegacyWordPad,
                    Name = "WordPad is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "PowerShell ISE is not present",
                    Compliant = string.Equals(FeaturesCheckResults.PowerShellISE, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.PowerShellISE,
                    Name = "PowerShell ISE is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Steps Recorder is not present",
                    Compliant = string.Equals(FeaturesCheckResults.StepsRecorder, "Not Present", StringComparison.OrdinalIgnoreCase),
                    Value = FeaturesCheckResults.StepsRecorder,
                    Name = "Steps Recorder is not present",
                    Category = CatName,
                    Method = "DISM"
                });

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }

        /// <summary>
        /// Performs all of the tasks for the TLS Security category during system compliance checking
        /// </summary>
        private static Task VerifyTLSSecurity()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "TLSSecurity";

                EccCurveComparisonResult ECCCurvesComparisonResults = EccCurveComparer.GetEccCurveComparison();

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "ECC Curves and their positions",
                    Compliant = ECCCurvesComparisonResults.AreCurvesCompliant,
                    Value = string.Join(", ", ECCCurvesComparisonResults.CurrentEccCurves ?? Enumerable.Empty<string>()),
                    Name = "ECC Curves and their positions",
                    Category = CatName,
                    Method = "Cmdlet"
                });


                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-cryptography#tlsciphersuites
                bool TLSCipherSuites = GetMDMResultValue.Get("TLSCipherSuites", "TLS_CHACHA20_POLY1305_SHA256,TLS_AES_256_GCM_SHA384,TLS_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_DHE_RSA_WITH_AES_128_GCM_SHA256");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure the correct TLS Cipher Suites",
                    Compliant = TLSCipherSuites,
                    Value = TLSCipherSuites ? "True" : "False",
                    Name = "Configure the correct TLS Cipher Suites",
                    Category = CatName,
                    Method = "MDM"
                });

                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                // Process items in Registry resources.csv file with "Registry Keys" origin and add them to the nestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Registry Keys")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Windows Firewall category during system compliance checking
        /// </summary>
        private static Task VerifyWindowsFirewall()
        {
            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "WindowsFirewall";


                // Check network location of all connections to see if they are public
                bool individualItemResult = NetConnectionProfiles.Get().All(profile =>
                {
                    // Ensure the property exists and is not null before comparing
                    return profile["NetworkCategory"] is not null && (uint)profile["NetworkCategory"] == 0;
                });
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Network Location of all connections set to Public",
                    Compliant = individualItemResult,
                    Value = individualItemResult ? "True" : "False",
                    Name = "Network Location of all connections set to Public",
                    Category = CatName,
                    Method = "CIM"
                });


                // Use the GetFirewallRules method and check the Enabled status of each rule
                List<ManagementObject> firewallRuleGroupResultEnabledArray = FirewallHelper.GetFirewallRules("""@%SystemRoot%\system32\firewallapi.dll,-37302""", 1);

                // Check if all the rules are disabled
                bool firewallRuleGroupResultEnabledStatus = true;

                // Loop through each rule and check if it's enabled
                foreach (var rule in firewallRuleGroupResultEnabledArray)
                {
                    if (string.Equals(rule["Enabled"]?.ToString(), "1", StringComparison.OrdinalIgnoreCase))
                    {
                        firewallRuleGroupResultEnabledStatus = false;
                        break;
                    }
                }

                // Verify the 3 built-in Firewall rules (for all 3 profiles) for Multicast DNS (mDNS) UDP-in are disabled
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "mDNS UDP-In Firewall Rules are disabled",
                    Compliant = firewallRuleGroupResultEnabledStatus,
                    Value = firewallRuleGroupResultEnabledStatus ? "True" : "False",
                    Name = "mDNS UDP-In Firewall Rules are disabled",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                if (GlobalVars.MDM_Firewall_PublicProfile02 is null)
                {
                    // Handle the case where the global variable is null
                    throw new InvalidOperationException("MDM_Firewall_PublicProfile02 is null.");
                }
                HashtableCheckerResult MDM_Firewall_PublicProfile02_EnableFirewall = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PublicProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_EnableFirewall.IsMatch,
                    Value = MDM_Firewall_PublicProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PublicProfile02_DisableInboundNotifications = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PublicProfile02, "DisableInboundNotifications", "false");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Display notifications for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_DisableInboundNotifications.IsMatch,
                    Value = MDM_Firewall_PublicProfile02_DisableInboundNotifications.Value,
                    Name = "Display notifications for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PublicProfile02_LogMaxFileSize = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PublicProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file size for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_LogMaxFileSize.IsMatch,
                    Value = MDM_Firewall_PublicProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PublicProfile02_EnableLogDroppedPackets = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PublicProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Log blocked connections for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_EnableLogDroppedPackets.IsMatch,
                    Value = MDM_Firewall_PublicProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PublicProfile02_LogFilePath = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PublicProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Publicfirewall.log");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file path for Public profile",
                    Compliant = MDM_Firewall_PublicProfile02_LogFilePath.IsMatch,
                    Value = MDM_Firewall_PublicProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for Public profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                if (GlobalVars.MDM_Firewall_PrivateProfile02 is null)
                {
                    // Handle the case where the global variable is null
                    throw new InvalidOperationException("MDM_Firewall_PrivateProfile02 is null.");
                }
                HashtableCheckerResult MDM_Firewall_PrivateProfile02_EnableFirewall = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PrivateProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_EnableFirewall.IsMatch,
                    Value = MDM_Firewall_PrivateProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PrivateProfile02_DisableInboundNotifications = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PrivateProfile02, "DisableInboundNotifications", "false");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Display notifications for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_DisableInboundNotifications.IsMatch,
                    Value = MDM_Firewall_PrivateProfile02_DisableInboundNotifications.Value,
                    Name = "Display notifications for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PrivateProfile02_LogMaxFileSize = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PrivateProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file size for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_LogMaxFileSize.IsMatch,
                    Value = MDM_Firewall_PrivateProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PrivateProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Log blocked connections for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets.IsMatch,
                    Value = MDM_Firewall_PrivateProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_PrivateProfile02_LogFilePath = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_PrivateProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Privatefirewall.log");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file path for Private profile",
                    Compliant = MDM_Firewall_PrivateProfile02_LogFilePath.IsMatch,
                    Value = MDM_Firewall_PrivateProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for Private profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                if (GlobalVars.MDM_Firewall_DomainProfile02 is null)
                {
                    // Handle the case where the global variable is null
                    throw new InvalidOperationException("MDM_Firewall_DomainProfile02 is null.");
                }
                HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableFirewall = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "EnableFirewall", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Windows Firewall for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableFirewall.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_EnableFirewall.Value,
                    Name = "Enable Windows Firewall for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_DefaultOutboundAction = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "DefaultOutboundAction", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Set Default Outbound Action for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_DefaultOutboundAction.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_DefaultOutboundAction.Value,
                    Name = "Set Default Outbound Action for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_DefaultInboundAction = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "DefaultInboundAction", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Set Default Inbound Action for Domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_DefaultInboundAction.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_DefaultInboundAction.Value,
                    Name = "Set Default Inbound Action for Domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_Shielded = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "Shielded", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Block all Domain profile connections",
                    Compliant = MDM_Firewall_DomainProfile02_Shielded.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_Shielded.Value,
                    Name = "Shielded",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_LogFilePath = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "LogFilePath", @"%systemroot%\system32\LogFiles\Firewall\Domainfirewall.log");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file path for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_LogFilePath.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_LogFilePath.Value,
                    Name = "Configure Log file path for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_LogMaxFileSize = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "LogMaxFileSize", "32767");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure Log file size for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_LogMaxFileSize.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_LogMaxFileSize.Value,
                    Name = "Configure Log file size for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableLogDroppedPackets = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "EnableLogDroppedPackets", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Log blocked connections for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableLogDroppedPackets.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_EnableLogDroppedPackets.Value,
                    Name = "Log blocked connections for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Firewall_DomainProfile02_EnableLogSuccessConnections = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Firewall_DomainProfile02, "EnableLogSuccessConnections", "true");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Log successful connections for domain profile",
                    Compliant = MDM_Firewall_DomainProfile02_EnableLogSuccessConnections.IsMatch,
                    Value = MDM_Firewall_DomainProfile02_EnableLogSuccessConnections.Value,
                    Name = "Log successful connections for domain profile",
                    Category = CatName,
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };
            });
        }


        /// <summary>
        /// Performs all of the tasks for the Microsoft Defender category during system compliance checking
        /// </summary>
        private static Task VerifyMicrosoftDefender()
        {

            return Task.Run(() =>
            {

                // Create a new list to store the results
                List<IndividualResult> nestedObjectArray = [];

                // Defining the category name
                string CatName = "MicrosoftDefender";

                #region NX Bit Verification

                //Verify the NX bit as shown in bcdedit /enum or Get-BcdEntry, info about numbers and values correlation: https://learn.microsoft.com/en-us/previous-versions/windows/desktop/bcd/bcdosloader-nxpolicy
                using (PowerShell ps = PowerShell.Create())
                {
                    // Add the PowerShell script to the instance
                    _ = ps.AddScript(@"
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
                                Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
                            }
                        }

                        // Extract the NX value
                        if (results.Count > 0)
                        {
                            string? nxValue = results[0].BaseObject.ToString();

                            // Determine compliance based on the value
                            bool compliant = string.Equals(nxValue, "3", StringComparison.OrdinalIgnoreCase);

                            // Add the result to the list
                            nestedObjectArray.Add(new IndividualResult
                            {
                                FriendlyName = "Boot Configuration Data (BCD) No-eXecute (NX) Value",
                                Compliant = compliant,
                                Value = nxValue ?? string.Empty,
                                Name = "Boot Configuration Data (BCD) No-eXecute (NX) Value",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                        else
                        {
                            Logger.LogMessage("No results retrieved from Get-BcdEntry command.", LogTypeIntel.Warning);
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogMessage($"Exception: {ex.Message}", LogTypeIntel.Error);
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
                        _ = ps.AddScript(script);

                        // Invoke the command and get the results
                        var results = ps.Invoke();

                        // Check if there are any errors
                        if (ps.Streams.Error.Count > 0)
                        {
                            // Handle errors
                            foreach (var error in ps.Streams.Error)
                            {
                                Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
                            }
                        }

                        // Check if results are not null or empty
                        if (results is not null && results.Count > 0)
                        {
                            // initialize a variable to store the ForceRelocateImages value
                            string? ForceRelocateImages = null;

                            // Extract the ForceRelocateImages value and store it in the variable
                            ForceRelocateImages = results[0].ToString();

                            // Check if the value is not null
                            if (ForceRelocateImages is not null)
                            {
                                // Determine compliance based on the value
                                bool compliant = string.Equals(ForceRelocateImages, "ON", StringComparison.OrdinalIgnoreCase);

                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = "Mandatory ASLR",
                                    Compliant = compliant,
                                    Value = ForceRelocateImages,
                                    Name = "Mandatory ASLR",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });

                            }
                            else
                            {
                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = "Mandatory ASLR",
                                    Compliant = false,
                                    Value = "False",
                                    Name = "Mandatory ASLR",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });
                            }
                        }
                        else
                        {
                            nestedObjectArray.Add(new IndividualResult
                            {
                                FriendlyName = "Mandatory ASLR",
                                Compliant = false,
                                Value = "False",
                                Name = "Mandatory ASLR",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogMessage($"Exception: {ex.Message}", LogTypeIntel.Error);
                    }
                }


                // Get the current system's exploit mitigation policy XML file using the Get-ProcessMitigation cmdlet
                using (PowerShell ps = PowerShell.Create())
                {
                    _ = ps.AddCommand("Get-ProcessMitigation")
                    .AddParameter("RegistryConfigFilePath", GlobalVars.CurrentlyAppliedMitigations);

                    try
                    {
                        Collection<PSObject> results = ps.Invoke();

                        if (ps.Streams.Error.Count > 0)
                        {
                            // Handle errors
                            foreach (var error in ps.Streams.Error)
                            {
                                Logger.LogMessage($"Error: {error}", LogTypeIntel.Error);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        Logger.LogMessage($"Exception: {ex.Message}", LogTypeIntel.Error);
                    }
                }

                // Process the system mitigations result from the XML file
                // It's necessary to make the HashSet ordinal IgnoreCase since mitigations applied from Intune vs applied locally might have different casing
                Dictionary<string, HashSet<string>> RevisedProcessMitigationsOnTheSystem =
                    MitigationPolicyProcessor.ProcessMitigationPolicies(GlobalVars.CurrentlyAppliedMitigations)
                    .ToDictionary(
                        kvp => kvp.Key,
                        kvp => new HashSet<string>(kvp.Value, StringComparer.OrdinalIgnoreCase),
                        StringComparer.OrdinalIgnoreCase
                    );

                // Import the CSV file as an object
                List<ProcessMitigationsParser.ProcessMitigationsRecords> ProcessMitigations =
                GlobalVars.ProcessMitigations
                ?? throw new ArgumentNullException(nameof(GlobalVars.ProcessMitigations), "ProcessMitigations cannot be null.");


                // Only keep the enabled mitigations in the CSV, then group the data by ProgramName
                var GroupedMitigations = ProcessMitigations
                    .Where(x => x.Action is not null && x.Action.Equals("Enable", StringComparison.OrdinalIgnoreCase))
                    // case insensitive grouping is necessary so that for e.g., lsass.exe and LSASS.exe will be out in the same group
                    .GroupBy(x => x.ProgramName, StringComparer.OrdinalIgnoreCase)
                    .Select(g => new { ProgramName = g.Key, Mitigations = g.Select(x => x.Mitigation).ToArray() })
                    .ToList();

                // A dictionary to store the output of the CSV file
                Dictionary<string, string[]> TargetMitigations = new(StringComparer.OrdinalIgnoreCase);

                // Loop through each group in the grouped mitigations array and add the ProgramName and Mitigations to the dictionary
                foreach (var item in GroupedMitigations)
                {
                    // Ensure the ProgramName is not null
                    if (item.ProgramName is not null && item.Mitigations is not null)
                    {
                        TargetMitigations[item.ProgramName] = item.Mitigations!; // Suppressing the warning
                    }
                }

                // Comparison
                // Compare the values of the two HashTables if the keys match
                foreach (var targetMitigationItem in TargetMitigations)
                {

                    // Increment the total number of the verifiable compliant values for each process that has a mitigation applied to it in the CSV file
                    GlobalVars.TotalNumberOfTrueCompliantValues++;

                    // Get the current key and value from dictionary containing the CSV data
                    string ProcessName_Target = targetMitigationItem.Key;
                    string[] ProcessMitigations_Target = targetMitigationItem.Value;

                    // Check if the dictionary containing the currently applied mitigations contains the same key
                    // Meaning the same executable is present in both dictionaries
                    // If it is, get the value from the applied mitigations dictionary
                    if (RevisedProcessMitigationsOnTheSystem.TryGetValue(ProcessName_Target, out HashSet<string>? ProcessMitigations_Applied))
                    {

                        // Convert the arrays to HashSet for order-agnostic comparison
                        HashSet<string> targetSet = new(ProcessMitigations_Target, StringComparer.OrdinalIgnoreCase);

                        // Compare the values of the two dictionaries to see if they are the same without considering the order of the elements (process mitigations)
                        if (!targetSet.SetEquals(ProcessMitigations_Applied))
                        {

                            Logger.LogMessage($"Mitigations for {ProcessName_Target} were found but they do not exactly match, performing further checks", LogTypeIntel.Information);

                            // Check if the mitigations applied to the current process at least include all of the mitigations required by the CSV file for that process
                            if (ProcessMitigations_Applied.IsSupersetOf(targetSet))
                            {

                                Logger.LogMessage($"Mitigations for {ProcessName_Target} contain all the required mitigations plus more", LogTypeIntel.Information);
                                Logger.LogMessage($"Applied Mitigations: {string.Join(",", ProcessMitigations_Applied)}", LogTypeIntel.Information);
                                Logger.LogMessage($"Target Mitigations: {string.Join(",", ProcessMitigations_Target)}", LogTypeIntel.Information);

                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                                    Compliant = true,
                                    Value = string.Join(",", ProcessMitigations_Target), // Join the array elements into a string to display them properly in the output CSV file
                                    Name = $"Process Mitigations for: {ProcessName_Target}",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });

                            }
                            else
                            {

                                Logger.LogMessage($"Mitigations for {ProcessName_Target} do not contain all of the required mitigations", LogTypeIntel.Information);
                                Logger.LogMessage($"Applied Mitigations: {string.Join(",", ProcessMitigations_Applied)}", LogTypeIntel.Information);
                                Logger.LogMessage($"Target Mitigations: {string.Join(",", ProcessMitigations_Target)}", LogTypeIntel.Information);

                                nestedObjectArray.Add(new IndividualResult
                                {
                                    FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                                    Compliant = false,
                                    Value = string.Join(",", ProcessMitigations_Applied),
                                    Name = $"Process Mitigations for: {ProcessName_Target}",
                                    Category = CatName,
                                    Method = "Cmdlet"
                                });

                            }

                        }
                        else
                        {
                            // If the values are the same, it means the process has the same mitigations applied to it as the ones in the CSV file
                            Logger.LogMessage($"Mitigations for {ProcessName_Target} are precisely compliant and match.", LogTypeIntel.Information);

                            nestedObjectArray.Add(new IndividualResult
                            {
                                FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                                Compliant = true,
                                Value = string.Join(",", ProcessMitigations_Target), // Join the array elements into a string to display them properly in the output CSV file
                                Name = $"Process Mitigations for: {ProcessName_Target}",
                                Category = CatName,
                                Method = "Cmdlet"
                            });
                        }
                    }
                    else
                    {
                        //If the process name is not found in the HashTable containing the currently applied mitigations, it means the process doesn't have any mitigations applied to it
                        Logger.LogMessage($"Mitigations for {ProcessName_Target} were not found", LogTypeIntel.Information);

                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = $"Process Mitigations for: {ProcessName_Target}",
                            Compliant = false,
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
                var DriverBlockListScheduledTaskResultObject = TaskSchedulerHelper.Get(
                    "MSFT Driver Block list update",
                    "\\MSFT Driver Block list update\\",
                    TaskSchedulerHelper.OutputType.Boolean
                );

                // Convert to boolean
                DriverBlockListScheduledTaskResult = Convert.ToBoolean(DriverBlockListScheduledTaskResultObject, CultureInfo.InvariantCulture);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Fast weekly Microsoft recommended driver block list update",
                    Compliant = DriverBlockListScheduledTaskResult,
                    Value = DriverBlockListScheduledTaskResult ? "True" : "False",
                    Name = "Fast weekly Microsoft recommended driver block list update",
                    Category = CatName,
                    Method = "CIM"
                });

                #endregion


                // Get the value and convert it to unsigned int16
                if (PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "PlatformUpdatesChannel") is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.MDAVPreferencesCurrent.PlatformUpdatesChannel), "PlatformUpdatesChannel cannot be null.");
                }

                // If the PlatformUpdatesChannel property does not exist, satisfy the conversion and prevent any error by assigning max Ushort to it
                ushort PlatformUpdatesChannel = Convert.ToUInt16(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "PlatformUpdatesChannel") ?? ushort.MaxValue);

                // resolve the number to a string using the dictionary
                _ = DefenderPlatformUpdatesChannels.Channels.TryGetValue(PlatformUpdatesChannel, out string? PlatformUpdatesChannelName);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Microsoft Defender Platform Updates Channel",
                    Compliant = string.Equals(PlatformUpdatesChannelName, "Beta", StringComparison.OrdinalIgnoreCase),
                    Value = PlatformUpdatesChannelName ?? string.Empty,
                    Name = "Microsoft Defender Platform Updates Channel",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to unsigned int16
                // If the EngineUpdatesChannel property does not exist, satisfy the conversion and prevent any error by assigning max Ushort to it
                ushort EngineUpdatesChannel = Convert.ToUInt16(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EngineUpdatesChannel") ?? ushort.MaxValue);

                // resolve the number to a string using the dictionary
                _ = DefenderPlatformUpdatesChannels.Channels.TryGetValue(EngineUpdatesChannel, out string? EngineUpdatesChannelName);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Microsoft Defender Engine Updates Channel",
                    Compliant = string.Equals(EngineUpdatesChannelName, "Beta", StringComparison.OrdinalIgnoreCase),
                    Value = EngineUpdatesChannelName ?? string.Empty,
                    Name = "Microsoft Defender Engine Updates Channel",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool AllowSwitchToAsyncInspectionResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "AllowSwitchToAsyncInspection") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Allow Switch To Async Inspection",
                    Compliant = AllowSwitchToAsyncInspectionResult,
                    Value = AllowSwitchToAsyncInspectionResult ? "True" : "False",
                    Name = "Allow Switch To Async Inspection",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool OOBEEnableRtpAndSigUpdateResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "oobeEnableRTpAndSigUpdate") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "OOBE Enable Rtp And Sig Update",
                    Compliant = OOBEEnableRtpAndSigUpdateResult,
                    Value = OOBEEnableRtpAndSigUpdateResult ? "True" : "False",
                    Name = "OOBE Enable Rtp And Sig Update",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool IntelTDTEnabledResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "IntelTDTEnabled") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Intel TDT Enabled",
                    Compliant = IntelTDTEnabledResult,
                    Value = IntelTDTEnabledResult ? "True" : "False",
                    Name = "Intel TDT Enabled",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string SmartAppControlStateResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVConfigCurrent, "SmartAppControlState") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Smart App Control State",
                    Compliant = SmartAppControlStateResult.Equals("on", StringComparison.OrdinalIgnoreCase),
                    Value = SmartAppControlStateResult,
                    Name = "Smart App Control State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string EnableControlledFolderAccessResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EnableControlledFolderAccess") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Controlled Folder Access",
                    Compliant = EnableControlledFolderAccessResult.Equals("1", StringComparison.OrdinalIgnoreCase),
                    Value = EnableControlledFolderAccessResult,
                    Name = "Controlled Folder Access",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool DisableRestorePointResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "DisableRestorePoint") ?? true);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Restore Point scanning",
                    Compliant = !DisableRestorePointResult,
                    Value = DisableRestorePointResult ? "False" : "True",
                    Name = "Enable Restore Point scanning",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // Set-MpPreference -PerformanceModeStatus Enabled => (Get-MpPreference).PerformanceModeStatus == 1 => Turns on Dev Drive Protection in Microsoft Defender GUI
                // Set-MpPreference -PerformanceModeStatus Disabled => (Get-MpPreference).PerformanceModeStatus == 0 => Turns off Dev Drive Protection in Microsoft Defender GUI
                string PerformanceModeStatusResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "PerformanceModeStatus") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Performance Mode Status",
                    Compliant = PerformanceModeStatusResult.Equals("0", StringComparison.OrdinalIgnoreCase),
                    Value = PerformanceModeStatusResult,
                    Name = "Performance Mode Status",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                bool EnableConvertWarnToBlockResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EnableConvertWarnToBlock") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Convert Warn To Block",
                    Compliant = EnableConvertWarnToBlockResult,
                    Value = EnableConvertWarnToBlockResult ? "True" : "False",
                    Name = "Enable Convert Warn To Block",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string BruteForceProtectionAggressivenessResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionAggressiveness") ?? string.Empty);

                // Check if the value is not null
                if (BruteForceProtectionAggressivenessResult is not null)
                {
                    // Check if the value is 1 or 2, both are compliant
                    if (
                BruteForceProtectionAggressivenessResult.Equals("1", StringComparison.OrdinalIgnoreCase) ||
                BruteForceProtectionAggressivenessResult.Equals("2", StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Aggressiveness",
                            Compliant = true,
                            Value = BruteForceProtectionAggressivenessResult,
                            Name = "BruteForce Protection Aggressiveness",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Aggressiveness",
                            Compliant = false,
                            Value = "N/A",
                            Name = "BruteForce Protection Aggressiveness",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "BruteForce Protection Aggressiveness",
                        Compliant = false,
                        Value = "N/A",
                        Name = "BruteForce Protection Aggressiveness",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string BruteForceProtectionMaxBlockTimeResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionMaxBlockTime") ?? string.Empty);

                // Check if the value is not null
                if (BruteForceProtectionMaxBlockTimeResult is not null)
                {
                    // Check if the value is 0 or 4294967295, both are compliant
                    if (
              BruteForceProtectionMaxBlockTimeResult.Equals("0", StringComparison.OrdinalIgnoreCase) ||
              BruteForceProtectionMaxBlockTimeResult.Equals("4294967295", StringComparison.OrdinalIgnoreCase)
                )
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Max Block Time",
                            Compliant = true,
                            Value = BruteForceProtectionMaxBlockTimeResult,
                            Name = "BruteForce Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "BruteForce Protection Max Block Time",
                            Compliant = false,
                            Value = "N/A",
                            Name = "BruteForce Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "BruteForce Protection Max Block Time",
                        Compliant = false,
                        Value = "N/A",
                        Name = "BruteForce Protection Max Block Time",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string BruteForceProtectionConfiguredStateResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionConfiguredState") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "BruteForce Protection Configured State",
                    Compliant = BruteForceProtectionConfiguredStateResult.Equals("1", StringComparison.OrdinalIgnoreCase),
                    Value = BruteForceProtectionConfiguredStateResult,
                    Name = "BruteForce Protection Configured State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string RemoteEncryptionProtectionMaxBlockTimeResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionMaxBlockTime") ?? string.Empty);

                // Check if the value is not null
                if (RemoteEncryptionProtectionMaxBlockTimeResult is not null)
                {
                    // Check if the value is 0 or 4294967295, both are compliant
                    if (
              RemoteEncryptionProtectionMaxBlockTimeResult.Equals("0", StringComparison.OrdinalIgnoreCase) ||
              RemoteEncryptionProtectionMaxBlockTimeResult.Equals("4294967295", StringComparison.OrdinalIgnoreCase)
                  )
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "Remote Encryption Protection Max Block Time",
                            Compliant = true,
                            Value = RemoteEncryptionProtectionMaxBlockTimeResult,
                            Name = "Remote Encryption Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                    else
                    {
                        nestedObjectArray.Add(new IndividualResult
                        {
                            FriendlyName = "Remote Encryption Protection Max Block Time",
                            Compliant = false,
                            Value = "N/A",
                            Name = "Remote Encryption Protection Max Block Time",
                            Category = CatName,
                            Method = "CIM"
                        });
                    }
                }
                else
                {
                    nestedObjectArray.Add(new IndividualResult
                    {
                        FriendlyName = "Remote Encryption Protection Max Block Time",
                        Compliant = false,
                        Value = "N/A",
                        Name = "Remote Encryption Protection Max Block Time",
                        Category = CatName,
                        Method = "CIM"
                    });
                }


                // Get the value and convert it to string
                string RemoteEncryptionProtectionAggressivenessResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionAggressiveness") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Remote Encryption Protection Aggressiveness",
                    // Check if the value is 1 or 2, both are compliant
                    Compliant = RemoteEncryptionProtectionAggressivenessResult.Equals("1", StringComparison.OrdinalIgnoreCase) || RemoteEncryptionProtectionAggressivenessResult.Equals("2", StringComparison.OrdinalIgnoreCase),
                    Value = RemoteEncryptionProtectionAggressivenessResult,
                    Name = "Remote Encryption Protection Aggressiveness",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                string RemoteEncryptionProtectionConfiguredStateResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "RemoteEncryptionProtectionConfiguredState") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Remote Encryption Protection Configured State",
                    Compliant = RemoteEncryptionProtectionConfiguredStateResult.Equals("1", StringComparison.OrdinalIgnoreCase),
                    Value = RemoteEncryptionProtectionConfiguredStateResult,
                    Name = "Remote Encryption Protection Configured State",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#cloudblocklevel
                string CloudBlockLevelResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "CloudBlockLevel") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Cloud Block Level",
                    Compliant = CloudBlockLevelResult.Equals("6", StringComparison.OrdinalIgnoreCase),
                    Value = CloudBlockLevelResult,
                    Name = "Cloud Block Level",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowemailscanning
                bool DisableEmailScanningResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "DisableEmailScanning") ?? true);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Email Scanning",
                    Compliant = !DisableEmailScanningResult,
                    Value = DisableEmailScanningResult ? "False" : "True",
                    Name = "Email Scanning",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#submitsamplesconsent
                string SubmitSamplesConsentResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "SubmitSamplesConsent") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Send file samples when further analysis is required",
                    Compliant = SubmitSamplesConsentResult.Equals("3", StringComparison.OrdinalIgnoreCase),
                    Value = SubmitSamplesConsentResult,
                    Name = "Send file samples when further analysis is required",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#allowcloudprotection
                string MAPSReportingResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "MAPSReporting") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Join Microsoft MAPS (aka SpyNet)",
                    Compliant = MAPSReportingResult.Equals("2", StringComparison.OrdinalIgnoreCase),
                    Value = MAPSReportingResult,
                    Name = "Join Microsoft MAPS (aka SpyNet)",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-microsoftdefenderantivirus#mpengine_enablefilehashcomputation
                bool EnableFileHashComputationResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EnableFileHashComputation") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "File Hash Computation",
                    Compliant = EnableFileHashComputationResult,
                    Value = EnableFileHashComputationResult ? "True" : "False",
                    Name = "File Hash Computation",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#cloudextendedtimeout
                string CloudExtendedTimeoutResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "CloudExtendedTimeout") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Extended cloud check (Seconds)",
                    Compliant = CloudExtendedTimeoutResult.Equals("50", StringComparison.OrdinalIgnoreCase),
                    Value = CloudExtendedTimeoutResult,
                    Name = "Extended cloud check (Seconds)",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#puaprotection
                string PUAProtectionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "PUAProtection") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Detection for potentially unwanted applications",
                    Compliant = PUAProtectionResult.Equals("1", StringComparison.OrdinalIgnoreCase),
                    Value = PUAProtectionResult,
                    Name = "Detection for potentially unwanted applications",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#disablecatchupquickscan
                bool DisableCatchupQuickScanResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "DisableCatchupQuickScan") ?? true);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Catchup Quick Scan",
                    Compliant = !DisableCatchupQuickScanResult,
                    Value = DisableCatchupQuickScanResult ? "False" : "True",
                    Name = "Catchup Quick Scan",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to bool
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#checkforsignaturesbeforerunningscan
                bool CheckForSignaturesBeforeRunningScanResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "CheckForSignaturesBeforeRunningScan") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Check For Signatures Before Running Scan",
                    Compliant = CheckForSignaturesBeforeRunningScanResult,
                    Value = CheckForSignaturesBeforeRunningScanResult ? "True" : "False",
                    Name = "Check For Signatures Before Running Scan",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#enablenetworkprotection
                string EnableNetworkProtectionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EnableNetworkProtection") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Enable Network Protection",
                    Compliant = EnableNetworkProtectionResult.Equals("1", StringComparison.OrdinalIgnoreCase),
                    Value = EnableNetworkProtectionResult,
                    Name = "Enable Network Protection",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#signatureupdateinterval
                string SignatureUpdateIntervalResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "SignatureUpdateInterval") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Interval to check for security intelligence updates",
                    Compliant = SignatureUpdateIntervalResult.Equals("3", StringComparison.OrdinalIgnoreCase),
                    Value = SignatureUpdateIntervalResult,
                    Name = "Interval to check for security intelligence updates",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/defender-csp#configurationmeteredconnectionupdates
                bool MeteredConnectionUpdatesResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "MeteredConnectionUpdates") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Allows Microsoft Defender Antivirus to update over a metered connection",
                    Compliant = MeteredConnectionUpdatesResult,
                    Value = MeteredConnectionUpdatesResult ? "True" : "False",
                    Name = "Allows Microsoft Defender Antivirus to update over a metered connection",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#threatseveritydefaultaction
                string SevereThreatDefaultActionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "SevereThreatDefaultAction") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Severe Threat level default action = Remove",
                    Compliant = SevereThreatDefaultActionResult.Equals("3", StringComparison.OrdinalIgnoreCase),
                    Value = SevereThreatDefaultActionResult,
                    Name = "Severe Threat level default action = Remove",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#threatseveritydefaultaction
                string HighThreatDefaultActionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "HighThreatDefaultAction") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "High Threat level default action = Remove",
                    Compliant = HighThreatDefaultActionResult.Equals("3", StringComparison.OrdinalIgnoreCase),
                    Value = HighThreatDefaultActionResult,
                    Name = "High Threat level default action = Remove",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#threatseveritydefaultaction
                string ModerateThreatDefaultActionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "ModerateThreatDefaultAction") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Moderate Threat level default action = Quarantine",
                    Compliant = ModerateThreatDefaultActionResult.Equals("2", StringComparison.OrdinalIgnoreCase),
                    Value = ModerateThreatDefaultActionResult,
                    Name = "Moderate Threat level default action = Quarantine",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the value and convert it to string
                // https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-defender#threatseveritydefaultaction
                string LowThreatDefaultActionResult = Convert.ToString(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "LowThreatDefaultAction") ?? string.Empty);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Low Threat level default action = Quarantine",
                    Compliant = LowThreatDefaultActionResult.Equals("2", StringComparison.OrdinalIgnoreCase),
                    Value = LowThreatDefaultActionResult,
                    Name = "Low Threat level default action = Quarantine",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                if (GlobalVars.MDM_Policy_Result01_System02 is null)
                {
                    // Handle the case where the global variable is null
                    throw new InvalidOperationException("MDM_Policy_Result01_System02 is null.");
                }
                HashtableCheckerResult MDM_Policy_Result01_System02_AllowTelemetry = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Policy_Result01_System02, "AllowTelemetry", "3");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Optional Diagnostic Data Required for Smart App Control etc.",
                    Compliant = MDM_Policy_Result01_System02_AllowTelemetry.IsMatch,
                    Value = MDM_Policy_Result01_System02_AllowTelemetry.Value,
                    Name = "Optional Diagnostic Data Required for Smart App Control etc.",
                    Category = CatName,
                    Method = "CIM"
                });


                // Get the control from MDM CIM
                HashtableCheckerResult MDM_Policy_Result01_System02_ConfigureTelemetryOptInSettingsUx = HashtableChecker.CheckValue<string>(GlobalVars.MDM_Policy_Result01_System02, "ConfigureTelemetryOptInSettingsUx", "1");

                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Configure diagnostic data opt-in settings user interface",
                    Compliant = MDM_Policy_Result01_System02_ConfigureTelemetryOptInSettingsUx.IsMatch,
                    Value = MDM_Policy_Result01_System02_ConfigureTelemetryOptInSettingsUx.Value,
                    Name = "Configure diagnostic data opt-in settings user interface",
                    Category = CatName,
                    Method = "CIM"
                });


                // Process items in Registry resources.csv file with "Group Policy" origin and add them to the $NestedObjectArray array
                foreach (var Result in (CategoryProcessing.ProcessCategory(CatName, "Group Policy")))
                {
                    ConditionalResultAdd.Add(nestedObjectArray, Result);
                }

                if (GlobalVars.FinalMegaObject is null)
                {
                    throw new ArgumentNullException(nameof(GlobalVars.FinalMegaObject), "FinalMegaObject cannot be null.");
                }
                else
                {
                    _ = GlobalVars.FinalMegaObject.TryAdd(CatName, nestedObjectArray);
                };

                // Get the value and convert it to bool
                bool BruteForceProtectionLocalNetworkBlockingResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "BruteForceProtectionLocalNetworkBlocking") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "Brute Force Protection Local Network Blocking State",
                    Compliant = BruteForceProtectionLocalNetworkBlockingResult,
                    Value = BruteForceProtectionLocalNetworkBlockingResult ? "True" : "False",
                    Name = "Brute Force Protection Local Network Blocking State",
                    Category = CatName,
                    Method = "CIM"
                });

                // Get the value and convert it to bool
                bool EnableEcsConfigurationResult = Convert.ToBoolean(PropertyHelper.GetPropertyValue(GlobalVars.MDAVPreferencesCurrent, "EnableEcsConfiguration") ?? false);
                nestedObjectArray.Add(new IndividualResult
                {
                    FriendlyName = "ECS is enabled in Microsoft Defender",
                    Compliant = EnableEcsConfigurationResult,
                    Value = EnableEcsConfigurationResult ? "True" : "False",
                    Name = "ECS is enabled in Microsoft Defender",
                    Category = CatName,
                    Method = "CIM"
                });

            });
        }
    }
}
