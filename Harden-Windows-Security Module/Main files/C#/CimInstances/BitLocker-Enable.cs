using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Management;
using System.Windows;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class BitLocker
    {

        // A variable that keeps track of errors if they occur during BitLocker workflows
        internal static bool HasErrorsOccurred;

        // A variable that keeps track of BitLocker group policies whether they are applied or not
        internal static bool PoliciesApplied;

        // Encryption types of the OS Drive supported by the Harden Windows Security App
        public enum OSEncryptionType
        {
            Normal,
            Enhanced
        }


        /// <summary>
        /// Enables BitLocker encryption for the OS Drive
        /// Note: Password Protector cannot/should not be used for OS the drive. Secure TPM-Based key protectors should be used for the OS drive.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/preparevolume-win32-encryptablevolume
        /// 1) Full Space (instead of Used-space only)
        /// 2) Skip hardware test
        /// 3) Unspecified encryption between hardware/software
        /// 4) Encryption Method = XTS-AES-256
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="OSEncryptionType"></param>
        /// <param name="PIN"></param>
        /// <param name="StartupKeyPath"></param>
        /// <param name="FreePlusUsedSpace">if true, both used and free space will be encrypted</param>
        internal static void Enable(string DriveLetter, OSEncryptionType OSEncryptionType, string? PIN, string? StartupKeyPath, bool FreePlusUsedSpace)
        {
            #region TPM Status Check
            TpmResult TPMResult = TpmStatus.GetV2();

            if (!TPMResult.IsEnabled || !TPMResult.IsActivated)
            {
                Logger.LogMessage("TPM is not enabled or activated, BitLocker cannot be enabled.", LogTypeIntel.Error);
                return;
            }
            #endregion

            // Get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Get the extended volume info based on the drive letter
            BitLockerVolume VolumeInfoExtended = GetEncryptedVolumeInfo(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // If the drive is fully encrypted, check its key protectors
            if (VolumeInfoExtended.ConversionStatus is BitLocker.ConversionStatus.FullyEncrypted)
            {
                Logger.LogMessage($"The OS drive is fully encrypted, will check if it conforms to the selected {OSEncryptionType} level.", LogTypeIntel.Information);

                if (VolumeInfoExtended.EncryptionMethod is not BitLocker.EncryptionMethod.XTS_AES_256)
                {
                    Logger.LogMessage($"The OS drive is encrypted but with {VolumeInfoExtended.EncryptionMethod} instead of the more secure {BitLocker.EncryptionMethod.XTS_AES_256}. This is an informational notice.", LogTypeIntel.WarningInteractionRequired);
                }


                // Get the key protectors of the OS Drive after making sure it is fully encrypted
                List<BitLocker.KeyProtectorType?> KeyProtectors = VolumeInfoExtended.KeyProtector!
                .Select(kp => kp.KeyProtectorType).ToList();

                if (KeyProtectors is null || KeyProtectors.Count == 0)
                {
                    Logger.LogMessage("The OS drive is encrypted but it has no key protectors", LogTypeIntel.ErrorInteractionRequired);
                    HasErrorsOccurred = true;
                    return;
                }

                // If Normal security level was selected
                if (OSEncryptionType is BitLocker.OSEncryptionType.Normal)
                {
                    // If all the required key protectors for Normal security level are present, then return from the method
                    if (KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword) && KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPin))
                    {
                        Logger.LogMessage("The OS Drive is already fully encrypted with Normal Security level.", LogTypeIntel.InformationInteractionRequired);
                        HasErrorsOccurred = true;
                        return;
                    }

                    // If Recovery password is not present, add it
                    if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword))
                    {

                        Logger.LogMessage($"OS drive is encrypted, selected encryption is {OSEncryptionType} but there is no {BitLocker.KeyProtectorType.RecoveryPassword} key protector, adding it now.", LogTypeIntel.Information);

                        AddRecoveryPassword(DriveLetter, null);
                        if (HasErrorsOccurred) { return; }
                    }

                    // At this point we are sure the drive is fully encrypted, has Recovery Password
                    // And Normal security level is being used, so check if the drive is encrypted with Enhanced security level already
                    if (KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPinStartupKey))
                    {
                        Logger.LogMessage("For OS Drive encryption, Normal level was selected by the user but Enhanced level already detected, displaying MessageBox to the user for confirmation.", LogTypeIntel.Information);

                        MessageBoxResult result = MessageBox.Show(
                            "The OS Drive is already encrypted with the Enhanced Security level. Do you want to proceed with changing it to Normal Security level?",
                            "Confirmation",                              // Title
                            MessageBoxButton.YesNoCancel,                // Buttons
                            MessageBoxImage.Question                     // Icon
                        );

                        // If user selected no, cancel or closed the dialog box, then return from the method
                        // Otherwise proceed with replacing the TpmPinStartupKey with TpmPin key protector
                        if (result is MessageBoxResult.No or MessageBoxResult.Cancel or MessageBoxResult.None)
                        {
                            Logger.LogMessage("User cancelled changing Enhanced to Normal encryption level for the OS Drive.", LogTypeIntel.Information);

                            HasErrorsOccurred = true;
                            return;
                        }
                        else
                        {
                            Logger.LogMessage("User chose to proceed with changing Enhanced to Normal encryption level for the OS Drive.", LogTypeIntel.Information);
                        }
                    }

                    // If TpmPin is not present, add it
                    if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPin))
                    {
                        Logger.LogMessage($"OS drive is encrypted, selected encryption is {OSEncryptionType} but there is no {BitLocker.KeyProtectorType.TpmPin} key protector, adding it now.", LogTypeIntel.Information);

                        if (string.IsNullOrWhiteSpace(PIN))
                        {
                            Logger.LogMessage("No PIN was specified for the NormalSecurity Level, exiting", LogTypeIntel.Error);
                            return;
                        }

                        AddTpmAndPinProtector(DriveLetter, PIN);
                        if (HasErrorsOccurred) { return; }
                    }

                }
                // If Enhanced security level was selected
                else
                {
                    // If all the key protectors required for the Enhanced security level are present then return from the method
                    if (KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword) && KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPinStartupKey))
                    {
                        Logger.LogMessage("The OS Drive is already fully encrypted with Enhanced Security level.", LogTypeIntel.InformationInteractionRequired);
                        HasErrorsOccurred = true;
                        return;
                    }

                    // If Recovery password is not present, add it
                    if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword))
                    {

                        Logger.LogMessage($"OS drive is encrypted, selected encryption is {OSEncryptionType} but there is no {BitLocker.KeyProtectorType.RecoveryPassword} key protector, adding it now.", LogTypeIntel.Information);

                        AddRecoveryPassword(DriveLetter, null);
                        if (HasErrorsOccurred) { return; }
                    }

                    // If TpmPinStartupKey is not present, add it
                    if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.TpmPinStartupKey))
                    {

                        Logger.LogMessage($"OS drive is encrypted, selected encryption is {OSEncryptionType} but there is no {BitLocker.KeyProtectorType.TpmPinStartupKey} key protector, adding it now.", LogTypeIntel.Information);

                        if (string.IsNullOrWhiteSpace(PIN) || string.IsNullOrWhiteSpace(StartupKeyPath))
                        {
                            Logger.LogMessage("No PIN or Startup Key was specified for the Enhanced Security Level, exiting", LogTypeIntel.Error);
                            return;
                        }
                        AddTpmAndPinAndStartupKeyProtector(DriveLetter, StartupKeyPath, PIN);
                        if (HasErrorsOccurred) { return; }
                    }
                }
            }

            // Continue with full encryption if the drive is fully decrypted
            else if (VolumeInfoExtended.ConversionStatus is BitLocker.ConversionStatus.FullyDecrypted)
            {

                // Prepare the method with arguments
                ManagementBaseObject PrepareVolumeArgs = VolumeInfo.GetMethodParameters("PrepareVolume");
                PrepareVolumeArgs["DiscoveryVolumeType"] = "<default>";
                PrepareVolumeArgs["ForceEncryptionType"] = (uint)0; // Unspecified Type is the right default if hardware encryption is not explicitly requested

                if (HasErrorsOccurred) { return; }

                // Invoke the method to prepare the volume
                // If the drive is fully or partially encrypted, this method would return result: FVE_E_NOT_DECRYPTED 2150694969(0x80310039), which is unhandled by the HResult method.
                // And that error won't happen since the check for drive being fully decrypted already happens earlier
                // And also if that happens, it is gracefully handled.
                // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
                // See note below for further error handling
                ManagementBaseObject PrepareVolumeMethodInvocationResult = VolumeInfo.InvokeMethod("PrepareVolume", PrepareVolumeArgs, null);

                if (HasErrorsOccurred) { return; }

                #region Output handling
                uint? PrepareVolumeResultCode = null;

                if (PrepareVolumeMethodInvocationResult is not null)
                {
                    PrepareVolumeResultCode = Convert.ToUInt32(PrepareVolumeMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (PrepareVolumeResultCode is not null && PrepareVolumeResultCode == 0)
                {
                    Logger.LogMessage($"Successfully prepared the drive {DriveLetter} for encryption.", LogTypeIntel.Information);
                }
                // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
                // If the prepare method was previously used or if Add key protector methods were used, the preparation would happen
                // and it shouldn't terminate the method if a 2nd preparation is attempted, the method should just proceed to the next step
                // FVE_E_NOT_DECRYPTED
                else if (PrepareVolumeResultCode == 2150694969)
                {
                    Logger.LogMessage($"The volume with the drive letter {DriveLetter} has already been prepared, continuing...", LogTypeIntel.Information);
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(PrepareVolumeResultCode);
                    return;
                }
                #endregion


                if (OSEncryptionType is OSEncryptionType.Normal)
                {

                    if (string.IsNullOrWhiteSpace(PIN))
                    {
                        Logger.LogMessage("No PIN was specified for the NormalSecurity Level, exiting", LogTypeIntel.Error);
                        return;
                    }

                    AddTpmAndPinProtector(DriveLetter, PIN);

                    if (HasErrorsOccurred) { return; }

                    AddRecoveryPassword(DriveLetter, null);

                    if (HasErrorsOccurred) { return; }

                }
                else
                {
                    if (string.IsNullOrWhiteSpace(PIN) || string.IsNullOrWhiteSpace(StartupKeyPath))
                    {
                        Logger.LogMessage("No PIN or Startup Key was specified for the Enhanced Security Level, exiting", LogTypeIntel.Error);
                        return;
                    }

                    if (HasErrorsOccurred) { return; }

                    AddTpmAndPinAndStartupKeyProtector(DriveLetter, StartupKeyPath, PIN);

                    if (HasErrorsOccurred) { return; }

                    AddRecoveryPassword(DriveLetter, null);

                    if (HasErrorsOccurred) { return; }
                }


                // Get these again after prep and key protector addition

                // Get the volume info based on the drive letter
                VolumeInfo = GetVolumeFromLetter(DriveLetter);

                if (HasErrorsOccurred) { return; }

                // Prepare the method with arguments
                ManagementBaseObject EncryptArgs = VolumeInfo.GetMethodParameters("Encrypt");
                EncryptArgs["EncryptionMethod"] = 7; // XTS-AEX-256
                EncryptArgs["EncryptionFlags"] = FreePlusUsedSpace ? 0 : (uint)1; // 0 = Used + Free space | 1 = Used Space only

                // Invoke the method to Encrypt the volume
                ManagementBaseObject EncryptMethodInvocationResult = VolumeInfo.InvokeMethod("Encrypt", EncryptArgs, null);

                if (HasErrorsOccurred) { return; }

                #region Output handling
                uint? EncryptResultCode = null;

                if (EncryptMethodInvocationResult is not null)
                {
                    EncryptResultCode = Convert.ToUInt32(EncryptMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (EncryptResultCode is not null && EncryptResultCode == 0)
                {
                    Logger.LogMessage($"Successfully Encrypted the drive {DriveLetter}.", LogTypeIntel.Information);
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(EncryptResultCode);
                    return;
                }
                #endregion


                // Enabling key protectors
                EnableKeyProtectors(DriveLetter);
            }

            // Do this if the disk is neither fully encrypted nor fully decrypted
            else
            {
                Logger.LogMessage($"For full disk encryption, the drive's conversion status must be {BitLocker.ConversionStatus.FullyDecrypted}, and for security level change it must be {BitLocker.ConversionStatus.FullyEncrypted}, but it is {VolumeInfoExtended.ConversionStatus} at the moment.", LogTypeIntel.ErrorInteractionRequired);
                return;
            }
        }


        /// <summary>
        /// Enables BitLocker encryption for Fixed drives (Non-OS drives)
        /// 1) Full Space (instead of Used-space only)
        /// 2) Skip hardware test
        /// 3) Unspecified encryption between hardware/software
        /// 4) Encryption Method = XTS-AES-256
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="FreePlusUsedSpace">if true, both used and free space will be encrypted</param>
        internal static void Enable(string DriveLetter, bool FreePlusUsedSpace)
        {

            // Get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Get the extended volume info based on the drive letter
            BitLockerVolume VolumeInfoExtended = GetEncryptedVolumeInfo(DriveLetter);

            if (HasErrorsOccurred) { return; }


            // Make sure the OS Drive is encrypted first, or else we would add recovery password key protector and then get error about the same problem during auto-unlock key protector enablement
            BitLockerVolume OSDriveVolumeInfo = HardenWindowsSecurity.BitLocker.GetEncryptedVolumeInfo(Environment.GetEnvironmentVariable("SystemDrive") ?? "C:\\");
            if (OSDriveVolumeInfo.ProtectionStatus is not BitLocker.ProtectionStatus.Protected)
            {
                Logger.LogMessage($"Operation System drive must be encrypted first before encrypting Non-OS drives.", LogTypeIntel.ErrorInteractionRequired);
                BitLocker.HasErrorsOccurred = true;
                return;
            }

            // If the drive is already fully encrypted, check its key protectors
            if (VolumeInfoExtended.ConversionStatus is BitLocker.ConversionStatus.FullyEncrypted)
            {

                Logger.LogMessage($"The drive {DriveLetter} is fully encrypted, will check its key protectors.", LogTypeIntel.Information);


                if (VolumeInfoExtended.EncryptionMethod is not BitLocker.EncryptionMethod.XTS_AES_256)
                {
                    Logger.LogMessage($"The drive {DriveLetter} is encrypted but with {VolumeInfoExtended.EncryptionMethod} instead of the more secure {BitLocker.EncryptionMethod.XTS_AES_256}. This is an informational notice.", LogTypeIntel.WarningInteractionRequired);
                }

                // Get the key protectors of the Drive after making sure it is fully encrypted
                List<BitLocker.KeyProtectorType?> KeyProtectors = VolumeInfoExtended.KeyProtector!
                .Select(kp => kp.KeyProtectorType).ToList();

                if (KeyProtectors is null || KeyProtectors.Count == 0)
                {
                    Logger.LogMessage($"The drive {DriveLetter} is encrypted but it has no key protectors", LogTypeIntel.ErrorInteractionRequired);
                    HasErrorsOccurred = true;
                    return;
                }

                // If the drive is already fully encrypted with the required key protectors then return from the method
                if (KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword) && KeyProtectors.Contains(BitLocker.KeyProtectorType.ExternalKey))
                {

                    #region
                    // Delete any possible old leftover ExternalKey key protectors
                    List<BitLocker.KeyProtector> ExternalKeys = VolumeInfoExtended.KeyProtector!.Where(kp => kp.KeyProtectorType is KeyProtectorType.ExternalKey).ToList();

                    // This step ensures any leftover or unbound external key key protectors will be removed and a working one will be added
                    // If the current one is working and bound, it won't be removed and will be gracefully skipped over.
                    foreach (KeyProtector ExKp in ExternalKeys)
                    {
                        if (ExKp.KeyProtectorID is not null)
                        {
                            Logger.LogMessage($"Removing ExternalKey key protector with the ID {ExKp.KeyProtectorID} for the drive {DriveLetter}. Will set a new one bound to the OS drive in the next step.", LogTypeIntel.Information);

                            RemoveKeyProtector(DriveLetter, ExKp.KeyProtectorID, true);
                        }
                    }


                    // Get the extended volume info based on the drive letter again
                    // Because if the ExternalKey key protectors were deleted in the previous steps,
                    // The extended drive info must be updated to reflect that change
                    VolumeInfoExtended = GetEncryptedVolumeInfo(DriveLetter);

                    if (HasErrorsOccurred) { return; }

                    // Get the key protectors of the Drive again for the reason mentioned above
                    KeyProtectors = VolumeInfoExtended.KeyProtector!
                    .Select(kp => kp.KeyProtectorType).ToList();


                    // If the Auto-unlock (aka ExternalKey) key protector is not present, add it
                    // This only runs if all the ExternalKey key protectors were deleted in the previous step
                    // Indicating that none of them were bound to the OS Drive and were leftovers of previous OS Installations
                    if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.ExternalKey))
                    {
                        Logger.LogMessage($"Adding a new {BitLocker.KeyProtectorType.ExternalKey} key protector for Auto-unlock to the drive {DriveLetter}.", LogTypeIntel.Information);

                        EnableBitLockerAutoUnlock(DriveLetter);

                        if (HasErrorsOccurred) { return; }
                    }

                    #endregion


                    #region
                    // Check for presence of multiple recovery password key protectors

                    List<BitLocker.KeyProtector> PasswordProtectors = VolumeInfoExtended.KeyProtector!.Where(kp => kp.KeyProtectorType is KeyProtectorType.RecoveryPassword).ToList();

                    if (PasswordProtectors.Count > 1)
                    {
                        Logger.LogMessage($"drive {DriveLetter} has {PasswordProtectors} recovery password key protectors. Usually only one is enough.", LogTypeIntel.Information);
                    }
                    #endregion

                    Logger.LogMessage($"The drive {DriveLetter} is fully encrypted with all the required key protectors.", LogTypeIntel.InformationInteractionRequired);

                    // Exit the method and do not proceed further if the drive was already encrypted
                    // And key protector checks have been performed
                    HasErrorsOccurred = true;
                    return;
                }

                // If Recovery password is not present, add it
                if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.RecoveryPassword))
                {
                    Logger.LogMessage($"Drive {DriveLetter} is encrypted, but there is no {BitLocker.KeyProtectorType.RecoveryPassword} key protector, adding it now.", LogTypeIntel.Information);

                    AddRecoveryPassword(DriveLetter, null);
                    if (HasErrorsOccurred) { return; }
                }

                // If the Auto-unlock (aka ExternalKey) key protector is not present, add it
                if (!KeyProtectors.Contains(BitLocker.KeyProtectorType.ExternalKey))
                {

                    Logger.LogMessage($"Drive {DriveLetter} is encrypted, but there is no {BitLocker.KeyProtectorType.ExternalKey} key protector for Auto-unlock, adding it now.", LogTypeIntel.Information);

                    EnableBitLockerAutoUnlock(DriveLetter);

                    if (HasErrorsOccurred) { return; }
                }
            }

            // If the drive is fully decrypted, begin full drive encryption
            else if (VolumeInfoExtended.ConversionStatus is BitLocker.ConversionStatus.FullyDecrypted)
            {

                // Prepare the method with arguments
                ManagementBaseObject PrepareVolumeArgs = VolumeInfo.GetMethodParameters("PrepareVolume");
                PrepareVolumeArgs["DiscoveryVolumeType"] = "<default>";
                PrepareVolumeArgs["ForceEncryptionType"] = (uint)0; // Unspecified Type is the right default if hardware encryption is not explicitly requested

                if (HasErrorsOccurred) { return; }

                // Invoke the method to prepare the volume
                // If the drive is fully or partially encrypted, this method would return result: FVE_E_NOT_DECRYPTED 2150694969(0x80310039), which is unhandled by the HResult method.
                // And that error won't happen since the check for drive being fully decrypted already happens earlier
                // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
                // See note below for further error handling
                ManagementBaseObject PrepareVolumeMethodInvocationResult = VolumeInfo.InvokeMethod("PrepareVolume", PrepareVolumeArgs, null);

                if (HasErrorsOccurred) { return; }

                #region Output handling
                uint? PrepareVolumeResultCode = null;

                if (PrepareVolumeMethodInvocationResult is not null)
                {
                    PrepareVolumeResultCode = Convert.ToUInt32(PrepareVolumeMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (PrepareVolumeResultCode is not null && PrepareVolumeResultCode == 0)
                {
                    Logger.LogMessage($"Successfully prepared the drive {DriveLetter} for encryption.", LogTypeIntel.Information);
                }
                // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
                // If the prepare method was previously used or if Add key protector methods were used, the preparation would happen
                // and it shouldn't terminate the method if a 2nd preparation is attempted, the method should just proceed to the next step
                // FVE_E_NOT_DECRYPTED
                else if (PrepareVolumeResultCode == 2150694969)
                {
                    Logger.LogMessage($"The volume with the drive letter {DriveLetter} has already been prepared, continuing...", LogTypeIntel.Information);
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(PrepareVolumeResultCode);
                    return;
                }
                #endregion



                if (HasErrorsOccurred) { return; }

                AddRecoveryPassword(DriveLetter, null);

                if (HasErrorsOccurred) { return; }

                EnableBitLockerAutoUnlock(DriveLetter);

                if (HasErrorsOccurred) { return; }



                // Get these again after prep and key protector addition

                // Get the volume info based on the drive letter
                VolumeInfo = GetVolumeFromLetter(DriveLetter);

                if (HasErrorsOccurred) { return; }

                // Prepare the method with arguments
                ManagementBaseObject EncryptArgs = VolumeInfo.GetMethodParameters("Encrypt");
                EncryptArgs["EncryptionMethod"] = 7; // XTS-AEX-256
                EncryptArgs["EncryptionFlags"] = FreePlusUsedSpace ? 0 : (uint)1; // 0 = Used + Free space | 1 = Used Space only

                // Invoke the method to Encrypt the volume
                ManagementBaseObject EncryptMethodInvocationResult = VolumeInfo.InvokeMethod("Encrypt", EncryptArgs, null);

                if (HasErrorsOccurred) { return; }

                #region Output handling
                uint? EncryptResultCode = null;

                if (EncryptMethodInvocationResult is not null)
                {
                    EncryptResultCode = Convert.ToUInt32(EncryptMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (EncryptResultCode is not null && EncryptResultCode == 0)
                {
                    Logger.LogMessage($"Successfully Encrypted the drive {DriveLetter}.", LogTypeIntel.Information);
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(EncryptResultCode);
                    return;
                }
                #endregion
            }

            // Do this if the disk is neither fully encrypted nor fully decrypted
            else
            {
                Logger.LogMessage($"For full disk encryption, the drive's conversion status must be {BitLocker.ConversionStatus.FullyDecrypted}, and for key protector check it must be {BitLocker.ConversionStatus.FullyEncrypted}, but it is {VolumeInfoExtended.ConversionStatus} at the moment.", LogTypeIntel.ErrorInteractionRequired);
                return;
            }
        }


        /// <summary>
        /// Enables BitLocker encryption for Removable drives
        /// 1) Full Space (instead of Used-space only)
        /// 2) Skip hardware test
        /// 3) Unspecified encryption between hardware/software
        /// 4) Encryption Method = XTS-AES-256
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="Password"></param>
        /// <param name="FreePlusUsedSpace">if true, both used and free space will be encrypted</param>
        internal static void Enable(string DriveLetter, string? Password, bool FreePlusUsedSpace)
        {

            // Get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Get the extended volume info based on the drive letter
            BitLockerVolume VolumeInfoExtended = GetEncryptedVolumeInfo(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Exit the method if the volume is not Fully Decrypted
            if (VolumeInfoExtended.ConversionStatus is not BitLocker.ConversionStatus.FullyDecrypted)
            {
                Logger.LogMessage($"In order to encrypt a volume with this method, its Conversion Status must be {BitLocker.ConversionStatus.FullyDecrypted}, but it is {VolumeInfoExtended.ConversionStatus} at the moment.", LogTypeIntel.ErrorInteractionRequired);
                return;
            }


            // Prepare the method with arguments
            ManagementBaseObject PrepareVolumeArgs = VolumeInfo.GetMethodParameters("PrepareVolume");
            PrepareVolumeArgs["DiscoveryVolumeType"] = "<default>";
            PrepareVolumeArgs["ForceEncryptionType"] = (uint)0; // Unspecified Type is the right default if hardware encryption is not explicitly requested

            if (HasErrorsOccurred) { return; }

            // Invoke the method to prepare the volume
            // If the drive is fully or partially encrypted, this method would return result: FVE_E_NOT_DECRYPTED 2150694969(0x80310039), which is unhandled by the HResult method.
            // And that error won't happen since the check for drive being fully decrypted already happens earlier
            // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
            // See note below for further error handling
            ManagementBaseObject PrepareVolumeMethodInvocationResult = VolumeInfo.InvokeMethod("PrepareVolume", PrepareVolumeArgs, null);

            if (HasErrorsOccurred) { return; }

            #region Output handling
            uint? PrepareVolumeResultCode = null;

            if (PrepareVolumeMethodInvocationResult is not null)
            {
                PrepareVolumeResultCode = Convert.ToUInt32(PrepareVolumeMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (PrepareVolumeResultCode is not null && PrepareVolumeResultCode == 0)
            {
                Logger.LogMessage($"Successfully prepared the drive {DriveLetter} for encryption.", LogTypeIntel.Information);
            }
            // https://learn.microsoft.com/en-us/windows/win32/secprov/encryptafterhardwaretest-win32-encryptablevolume
            // If the prepare method was previously used or if Add key protector methods were used, the preparation would happen
            // and it shouldn't terminate the method if a 2nd preparation is attempted, the method should just proceed to the next step
            // FVE_E_NOT_DECRYPTED
            else if (PrepareVolumeResultCode == 2150694969)
            {
                Logger.LogMessage($"The volume with the drive letter {DriveLetter} has already been prepared, continuing...", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(PrepareVolumeResultCode);
                return;
            }
            #endregion



            if (string.IsNullOrEmpty(Password))
            {
                Logger.LogMessage("No Password was specified for the Removable Drive Encryption, exiting", LogTypeIntel.Error);
                return;
            }

            if (HasErrorsOccurred) { return; }

            AddPasswordProtector(DriveLetter, Password);

            if (HasErrorsOccurred) { return; }

            AddRecoveryPassword(DriveLetter, null);

            if (HasErrorsOccurred) { return; }

            // Get these again after prep and key protector addition

            // Get the volume info based on the drive letter
            VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Prepare the method with arguments
            ManagementBaseObject EncryptArgs = VolumeInfo.GetMethodParameters("Encrypt");
            EncryptArgs["EncryptionMethod"] = 7; // XTS-AEX-256
            EncryptArgs["EncryptionFlags"] = FreePlusUsedSpace ? 0 : (uint)1; // 0 = Used + Free space | 1 = Used Space only

            // Invoke the method to Encrypt the volume
            ManagementBaseObject EncryptMethodInvocationResult = VolumeInfo.InvokeMethod("Encrypt", EncryptArgs, null);

            if (HasErrorsOccurred) { return; }

            #region Output handling
            uint? EncryptResultCode = null;

            if (EncryptMethodInvocationResult is not null)
            {
                EncryptResultCode = Convert.ToUInt32(EncryptMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (EncryptResultCode is not null && EncryptResultCode == 0)
            {
                Logger.LogMessage($"Successfully Encrypted the drive {DriveLetter}.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(EncryptResultCode);
                return;
            }
            #endregion
        }

    }

}
