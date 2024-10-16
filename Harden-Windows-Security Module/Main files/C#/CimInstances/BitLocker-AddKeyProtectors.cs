using System;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Security.Principal;

#nullable enable

namespace HardenWindowsSecurity
{

    public partial class BitLocker
    {


        /// <summary>
        /// Accepts a drive letter in the following format: "C:"
        /// The returns the volume information acquired from the Win32_EncryptableVolume CIM Instance
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <returns> ManagementObject </returns>
        /// <exception cref="InvalidOperationException"></exception>
        private static ManagementObject GetVolumeFromLetter(string DriveLetter)
        {
            // Use `using` to properly dispose of the `ManagementObjectSearcher` and `ManagementObjectCollection`
            using ManagementObjectSearcher searcher = new(
                @"root\cimv2\Security\MicrosoftVolumeEncryption",
                "SELECT * FROM Win32_EncryptableVolume");

            using ManagementObjectCollection volumes = searcher.Get();

            // Filter by drive letter
            ManagementObject? driveInstance = volumes.Cast<ManagementObject>().FirstOrDefault(v => v["DriveLetter"]?.ToString() == DriveLetter);

            return driveInstance ?? throw new InvalidOperationException($"Volume for drive {DriveLetter} not found.");
        }



        /// <summary>
        /// Removes all key protectors of the specified type from the specified drive
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/getkeyprotectors-win32-encryptablevolume
        /// </summary>
        /// <param name="driveInstance"></param>
        /// <param name="keyProtectorType"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private static void RemoveTpmBasedKeyProtectors(ManagementObject driveInstance, uint keyProtectorType)
        {
            // Create a ManagementBaseObject for the arguments to GetKeyProtectors.
            ManagementBaseObject getKeyProtectorsArgs = driveInstance.GetMethodParameters("GetKeyProtectors");

            // Set the KeyProtectorType argument to the specified type.
            getKeyProtectorsArgs["KeyProtectorType"] = keyProtectorType;

            // Invoke GetKeyProtectors method to get all of the key protectors based on the selected type and store the results
            ManagementBaseObject keyProtectorResult = driveInstance.InvokeMethod("GetKeyProtectors", getKeyProtectorsArgs, null);

            // Get the array of VolumeKeyProtectorID from the result.
            string[] KeyProtectorIDs = (string[])keyProtectorResult["VolumeKeyProtectorID"];

            // Check if there is at least 1 key protector
            if (KeyProtectorIDs is not null && KeyProtectorIDs.Length >= 1)
            {
                // Loop over all of the key protectors of the specified type and remove all of them
                foreach (string KeyProtectorID in KeyProtectorIDs)
                {

                    // Prepare arguments for DeleteKeyProtector method.
                    ManagementBaseObject deleteKeyProtectorArgs = driveInstance.GetMethodParameters("DeleteKeyProtector");

                    // Set the VolumeKeyProtectorID argument to the current KeyProtectorID in the loop
                    deleteKeyProtectorArgs["VolumeKeyProtectorID"] = KeyProtectorID;

                    // Invoke DeleteKeyProtector method to remove the key protector
                    ManagementBaseObject deletionResult = driveInstance.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);

                    #region Output handling
                    uint? deletionResultCode = null;

                    if (deletionResult is not null)
                    {
                        deletionResultCode = Convert.ToUInt32(deletionResult["ReturnValue"], CultureInfo.InvariantCulture);
                    }

                    if (deletionResultCode is not null && deletionResultCode == 0)
                    {
                        Logger.LogMessage($"Successfully removed a key protector of type {keyProtectorType}", LogTypeIntel.Information);
                    }
                    else
                    {
                        HResultHelper.HandleHresultAndLog(deletionResultCode);
                        return;
                    }
                    #endregion

                }
            }
            else
            {
                Logger.LogMessage($"No key protector of type {keyProtectorType} found.", LogTypeIntel.Information);
            }
        }



        /// <summary>
        /// Adds the recovery password protector (NumericalPassword) to the specified drive
        /// This is the same RecoveryPassword that is used to unlock the drive in case of a forgotten password after using the Harden Windows Security application
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithnumericalpassword-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="Password"></param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddRecoveryPassword(string DriveLetter, string? Password)
        {
            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);


            // If we supply the password ourselves then it can be used, otherwise it should be null
            // If it's null, the CIM method will automatically assign a random password
            // If we want to supply in a password ourselves, it should be in the following format otherwise the return value will be non-zero indicating there was an error
            // "111111-111111-111111-111111-111111-111111-111111-111111"
            // Note that even the example above which only consists of 1s is acceptable since it follows the correct format.

            ManagementBaseObject protectWithPasswordArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithNumericalPassword");
            protectWithPasswordArgs["FriendlyName"] = null;
            // If the password is null, empty or whitespace then use null, otherwise use the user supplied password
            protectWithPasswordArgs["NumericalPassword"] = string.IsNullOrWhiteSpace(Password) ? null : Password;

            // Invoke the method and add the key protector
            ManagementBaseObject MethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithNumericalPassword", protectWithPasswordArgs, null);

            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (MethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(MethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("Successfully added the Recovery Password key protector.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion
        }



        /// <summary>
        /// Adds the password protector (PassPhrase) to the specified drive
        /// If the OS-drive is using TpmPin or TpmPinStartupKey then this cannot be used, so mostly suitable for non-OS drives
        /// If the drive already has this type of key protector and user tries to add it again to it, results in an error.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithpassphrase-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter">The drive letter</param>
        /// <param name="PassPhrase">The password to be used as a key protector, e.g: "1a2b3c4b" </param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddPasswordProtector(string DriveLetter, string? PassPhrase)
        {
            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (string.IsNullOrWhiteSpace(PassPhrase))
            {
                throw new InvalidOperationException("PassPhrase cannot be null or empty");
            }

            // Prepare the method with arguments
            ManagementBaseObject protectWithPassphraseArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithPassphrase");
            protectWithPassphraseArgs["FriendlyName"] = null;
            protectWithPassphraseArgs["PassPhrase"] = PassPhrase;

            // Invoke the method to add the key protector
            ManagementBaseObject MethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithPassphrase", protectWithPassphraseArgs, null);

            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (MethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(MethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("Successfully added Password key protector (aka Passphrase).", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion

        }



        /// <summary>
        /// Adds the Tpm protector to the specified drive
        /// Naturally, The group policy must allow the TPM-only protector otherwise this method results in an error
        /// If other TPM based key protectors exist, they will be removed only after this one is added.
        /// But adding this type of key protector while it is already added will result in an error.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpm-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter"></param>
        public static void AddTpmProtector(string DriveLetter)
        {
            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            // Prepare the method and supply the arguments
            ManagementBaseObject protectWithTpmArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithTPM");
            protectWithTpmArgs["FriendlyName"] = null;
            protectWithTpmArgs["PlatformValidationProfile"] = null;

            // Invoke the method to add the key protector
            ManagementBaseObject MethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithTPM", protectWithTpmArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (MethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(MethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("Successfully added the TPM key protector.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion

            // Have to remove all other TPM based key protectors
            // There can only be 1 of this type

            RemoveTpmBasedKeyProtectors(VolumeInfo, 6); // TpmPinStartupKey
            RemoveTpmBasedKeyProtectors(VolumeInfo, 5); // TpmStartupKey
            RemoveTpmBasedKeyProtectors(VolumeInfo, 4); // TpmPin

        }



        /// <summary>
        /// Adds the TpmAndPin protector to the specified drive
        /// If other TPM based key protectors exist, they will be removed only after this one is added.
        /// But adding this type of key protector while it is already added will result in an error.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandpin-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="PIN">Startup PIN to be used during system boot</param>
        public static void AddTpmAndPinProtector(string DriveLetter, string PIN)
        {

            if (string.IsNullOrWhiteSpace(PIN))
            {
                throw new InvalidOperationException("PIN cannot be null or empty");
            }

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            // Prepare the method with the arguments
            ManagementBaseObject protectWithTpmAndPinArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithTPMAndPin");
            protectWithTpmAndPinArgs["FriendlyName"] = null;
            protectWithTpmAndPinArgs["PlatformValidationProfile"] = null;
            protectWithTpmAndPinArgs["PIN"] = PIN;

            // Invoke the method to add the key protector
            ManagementBaseObject MethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithTPMAndPin", protectWithTpmAndPinArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (MethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(MethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("Successfully added the TpmAndPin key protector.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion


            // Delete all other TPM based protectors, there can only be 1 of this type
            RemoveTpmBasedKeyProtectors(VolumeInfo, 6); // TpmPinStartupKey
            RemoveTpmBasedKeyProtectors(VolumeInfo, 5); // TpmStartupKey
            RemoveTpmBasedKeyProtectors(VolumeInfo, 1);  // Tpm
        }



        /// <summary>
        /// Adds the TPM + StartupKey key protector
        /// If other TPM based key protectors exist, they will be removed only after this one is added.
        /// But adding this type of key protector while it is already added will result in an error.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithtpmandstartupkey-win32-encryptablevolume
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/saveexternalkeytofile-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter">The Drive letter in the format: "C:"</param>
        /// <param name="StartupKeyPath">Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddTpmAndStartupKeyProtector(string DriveLetter, string StartupKeyPath)
        {

            if (string.IsNullOrWhiteSpace(StartupKeyPath))
            {
                throw new InvalidOperationException("Startup Key Path cannot be null or empty");
            }

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);


            // Prepare the method with the arguments
            ManagementBaseObject protectWithTpmAndStartupKeyArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithTPMAndStartupKey");
            protectWithTpmAndStartupKeyArgs["FriendlyName"] = null;
            protectWithTpmAndStartupKeyArgs["PlatformValidationProfile"] = null;
            protectWithTpmAndStartupKeyArgs["ExternalKey"] = null;

            // Invoke the method to add the key protector
            ManagementBaseObject ProtectKeyWithTPMAndStartupKeyMethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithTPMAndStartupKey", protectWithTpmAndStartupKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (ProtectKeyWithTPMAndStartupKeyMethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(ProtectKeyWithTPMAndStartupKeyMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("The TpmAndStartupKey key protector was successfully added. Backing up the Startup key in the next step.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion


            // Save the Startup key which is a hidden file in a path
            ManagementBaseObject saveExternalKeyArgs = VolumeInfo.GetMethodParameters("SaveExternalKeyToFile");
            saveExternalKeyArgs["VolumeKeyProtectorID"] = ProtectKeyWithTPMAndStartupKeyMethodInvocationResult!["VolumeKeyProtectorId"];
            saveExternalKeyArgs["Path"] = StartupKeyPath;

            // Invoke the method to save the external key the file path
            ManagementBaseObject SaveExternalKeyToFileMethodInvocationResult = VolumeInfo.InvokeMethod("SaveExternalKeyToFile", saveExternalKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode2 = null;

            if (SaveExternalKeyToFileMethodInvocationResult is not null)
            {
                MethodInvocationResultCode2 = Convert.ToUInt32(SaveExternalKeyToFileMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode2 is not null && MethodInvocationResultCode2 == 0)
            {
                Logger.LogMessage($"Successfully backed up the Startup key to {StartupKeyPath}", LogTypeIntel.Information);

                // Delete all other TPM based protectors, there can only be 1 of this type
                RemoveTpmBasedKeyProtectors(VolumeInfo, 4); // TpmPin
                RemoveTpmBasedKeyProtectors(VolumeInfo, 1); // Tpm
                RemoveTpmBasedKeyProtectors(VolumeInfo, 6); // TpmPinStartupKey
            }
            else
            {
                // If the key wasn't saved successfully, remove the protector as a safety measure

                var deleteKeyProtectorArgs = VolumeInfo.GetMethodParameters("DeleteKeyProtector");
                deleteKeyProtectorArgs["VolumeKeyProtectorID"] = ProtectKeyWithTPMAndStartupKeyMethodInvocationResult["VolumeKeyProtectorID"];
                _ = VolumeInfo.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);

                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode2);
                return;
            }
            #endregion

        }



        /// <summary>
        /// Add the TpmAndPinAndStartupKeyProtector to the drive
        /// If other TPM based key protectors exist, they will be removed only after this one is added.
        /// But adding this type of key protector while it is already added will result in an error.
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="StartupKeyPath">Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.</param>
        /// <param name="PIN">A pin, its minimum length defined by policies</param>
        public static void AddTpmAndPinAndStartupKeyProtector(string DriveLetter, string StartupKeyPath, string PIN)
        {

            if (string.IsNullOrWhiteSpace(PIN) || string.IsNullOrWhiteSpace(StartupKeyPath))
            {
                throw new InvalidOperationException("PIN or Startup Key Path cannot be null or empty");
            }

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);


            // Prepare the method with arguments
            ManagementBaseObject protectWithTpmAndPinAndStartupKeyArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithTPMAndPinAndStartupKey");
            protectWithTpmAndPinAndStartupKeyArgs["FriendlyName"] = null;
            protectWithTpmAndPinAndStartupKeyArgs["PlatformValidationProfile"] = null;
            protectWithTpmAndPinAndStartupKeyArgs["ExternalKey"] = null;
            protectWithTpmAndPinAndStartupKeyArgs["PIN"] = PIN;

            // Invoke the method to add the key protector
            ManagementBaseObject ProtectKeyWithTPMAndPinAndStartupKeyMethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithTPMAndPinAndStartupKey", protectWithTpmAndPinAndStartupKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (ProtectKeyWithTPMAndPinAndStartupKeyMethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(ProtectKeyWithTPMAndPinAndStartupKeyMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("The TpmAndPinAndStartupKey key protector was successfully added. Will backup the startup key in the next step.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion


            ManagementBaseObject saveExternalKeyArgs = VolumeInfo.GetMethodParameters("SaveExternalKeyToFile");
            saveExternalKeyArgs["VolumeKeyProtectorID"] = ProtectKeyWithTPMAndPinAndStartupKeyMethodInvocationResult!["VolumeKeyProtectorId"];
            saveExternalKeyArgs["Path"] = StartupKeyPath;

            // Invoke the method to save the external key the file path
            ManagementBaseObject SaveExternalKeyToFileMethodInvocationResult = VolumeInfo.InvokeMethod("SaveExternalKeyToFile", saveExternalKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode2 = null;

            if (SaveExternalKeyToFileMethodInvocationResult is not null)
            {
                MethodInvocationResultCode2 = Convert.ToUInt32(SaveExternalKeyToFileMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode2 is not null && MethodInvocationResultCode2 == 0)
            {
                Logger.LogMessage($"Successfully backed up the startup key to {StartupKeyPath}", LogTypeIntel.Information);

                // Delete all other TPM based protectors, there can only be 1 of this type
                RemoveTpmBasedKeyProtectors(VolumeInfo, 4); // TpmPin
                RemoveTpmBasedKeyProtectors(VolumeInfo, 1); // Tpm
                RemoveTpmBasedKeyProtectors(VolumeInfo, 5); // TpmStartupKey
            }
            else
            {
                // If the key wasn't saved successfully, remove the protector as a safety measure

                ManagementBaseObject deleteKeyProtectorArgs = VolumeInfo.GetMethodParameters("DeleteKeyProtector");
                deleteKeyProtectorArgs["VolumeKeyProtectorID"] = ProtectKeyWithTPMAndPinAndStartupKeyMethodInvocationResult["VolumeKeyProtectorID"];
                _ = VolumeInfo.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);


                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode2);
                return;
            }
            #endregion
        }



        /// <summary>
        /// Adds the StartupKeyProtector or RecoveryKeyProtector, same thing
        /// They can be added even if the volume already has a StartupKey key protector, there can be multiple Startup Key protectors (aka ExternalKey key protectors) for 1 drive.
        /// It also works if the drive already has a TpmPinStartupKey key protector.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithexternalkey-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="StartupKeyPath">Path to a Drive or Folder, such as: @"C:\". The folder/drive path must exist otherwise error is thrown.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddStartupKeyProtector_OR_RecoveryKeyProtector(string DriveLetter, string StartupKeyPath)
        {

            if (string.IsNullOrWhiteSpace(StartupKeyPath))
            {
                throw new InvalidOperationException("Startup Key Path cannot be null or empty");
            }

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);


            // Prepare the method with arguments
            ManagementBaseObject protectWithExternalKeyArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithExternalKey");
            protectWithExternalKeyArgs["FriendlyName"] = null;
            protectWithExternalKeyArgs["ExternalKey"] = null;

            // Invoke the method to add the key protector
            ManagementBaseObject ProtectKeyWithExternalKeyMethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithExternalKey", protectWithExternalKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (ProtectKeyWithExternalKeyMethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(ProtectKeyWithExternalKeyMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("The StartupKey key protector was successfully added. Will back up it in the next step.", LogTypeIntel.Information);
                // Will move forward to the next step
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion

            // Prepare the method with arguments
            ManagementBaseObject saveExternalKeyArgs = VolumeInfo.GetMethodParameters("SaveExternalKeyToFile");
            saveExternalKeyArgs["VolumeKeyProtectorID"] = ProtectKeyWithExternalKeyMethodInvocationResult!["VolumeKeyProtectorId"];
            saveExternalKeyArgs["Path"] = StartupKeyPath;

            // Invoke the method to backup the startup key
            ManagementBaseObject SaveExternalKeyToFileMethodInvocationResult = VolumeInfo.InvokeMethod("SaveExternalKeyToFile", saveExternalKeyArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode2 = null;

            if (SaveExternalKeyToFileMethodInvocationResult is not null)
            {
                MethodInvocationResultCode2 = Convert.ToUInt32(SaveExternalKeyToFileMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode2 is not null && MethodInvocationResultCode2 == 0)
            {
                Logger.LogMessage($"Successfully backed up the Startup key to {StartupKeyPath}", LogTypeIntel.Information);
            }
            else
            {
                // If the key wasn't saved successfully, remove the protector as a safety measure

                ManagementBaseObject deleteKeyProtectorArgs = VolumeInfo.GetMethodParameters("DeleteKeyProtector");
                deleteKeyProtectorArgs["VolumeKeyProtectorID"] = ProtectKeyWithExternalKeyMethodInvocationResult["VolumeKeyProtectorID"];
                _ = VolumeInfo.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);


                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode2);

                Logger.LogMessage($"Error saving the Startup key in the defined path, removing the Startup key KeyProtector.", LogTypeIntel.Error);

                return;
            }
            #endregion

        }



        /// <summary>
        /// Adds the SidProtector to the drive
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/protectkeywithadsid-win32-encryptablevolume
        /// More info: https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/operations-guide?tabs=powershell#add-a-password-protector
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="SID"></param>
        /// <param name="ServiceAccount"></param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void AddSidProtector(string DriveLetter, string SID, bool ServiceAccount)
        {
            if (string.IsNullOrWhiteSpace(SID))
            {
                throw new InvalidOperationException("SID cannot be null or empty");
            }

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            // 1 means FVE_DPAPI_NG_FLAG_UNLOCK_AS_SERVICE_ACCOUNT
            uint flags = ServiceAccount ? 1 : (uint)0;


            // Convert the SID string to a SecurityIdentifier object
            SecurityIdentifier SIDResult = new(SID);

            // Prepare the method with arguments
            var protectWithSidArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithAdSid");
            protectWithSidArgs["FriendlyName"] = null;
            protectWithSidArgs["SidString"] = SIDResult.Value;
            protectWithSidArgs["Flags"] = flags;

            // Invoke the method to add the key protector
            ManagementBaseObject MethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithAdSid", protectWithSidArgs, null);


            #region Output handling
            uint? MethodInvocationResultCode = null;

            if (MethodInvocationResult is not null)
            {
                MethodInvocationResultCode = Convert.ToUInt32(MethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
            {
                Logger.LogMessage("Successfully added the SID key protector.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                return;
            }
            #endregion

        }

    }

}
