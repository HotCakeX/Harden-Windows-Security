using System;
using System.Globalization;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class BitLocker
    {

        /// <summary>
        /// Decrypts a BitLocker encrypted drive
        /// If the drive is OS drive, it will check if it has auto-unlock keys that belong to other data drives.
        /// </summary>
        /// <param name="DriveLetter"></param>
        internal static void Disable(string DriveLetter)
        {

            // Get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            if (HasErrorsOccurred) { return; }

            // Get the extended volume info based on the drive letter
            BitLockerVolume VolumeInfoExtended = GetEncryptedVolumeInfo(DriveLetter);

            if (HasErrorsOccurred) { return; }


            if (VolumeInfoExtended.ConversionStatus is BitLocker.ConversionStatus.FullyDecrypted)
            {
                Logger.LogMessage($"The drive {DriveLetter} is already decrypted", LogTypeIntel.InformationInteractionRequired);
                return;
            }


            if (VolumeInfoExtended.VolumeType is VolumeType.OperationSystem)
            {

                Logger.LogMessage($"Operation system drive detected during BitLocker disablement", LogTypeIntel.Information);

                Logger.LogMessage("Checking whether The Operation System drive has auto-unlock keys that belong to other data drives.", LogTypeIntel.Information);

                // https://learn.microsoft.com/en-us/windows/win32/secprov/isautounlockkeystored-win32-encryptablevolume

                // Get the method parameters for IsAutoUnlockKeyStored (even if they are empty)
                ManagementBaseObject IsAutoUnlockKeyStoredArgs = VolumeInfo.GetMethodParameters("IsAutoUnlockKeyStored");

                // Invoke the method with an empty argument object
                ManagementBaseObject IsAutoUnlockKeyStoredMethodInvocationResult = VolumeInfo.InvokeMethod("IsAutoUnlockKeyStored", IsAutoUnlockKeyStoredArgs, null);


                #region Output handling
                uint? MethodInvocationResultCode = null;

                if (IsAutoUnlockKeyStoredMethodInvocationResult is not null)
                {
                    MethodInvocationResultCode = Convert.ToUInt32(IsAutoUnlockKeyStoredMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
                {
                    Logger.LogMessage("Successfully checked the OS Drive for any stored auto-unlock keys.", LogTypeIntel.Information);
                    // Will move forward to the next step
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                    return;
                }
                #endregion

                if (IsAutoUnlockKeyStoredMethodInvocationResult!["IsAutoUnlockKeyStored"] is true)
                {
                    // https://learn.microsoft.com/en-us/windows/win32/secprov/decrypt-win32-encryptablevolume#return-value
                    HResultHelper.HandleHresultAndLog(2150694953);
                    return;
                }



                // Get the volume info based on the drive letter again (Just in case if up to date info is required)
                VolumeInfo = GetVolumeFromLetter(DriveLetter);

                if (HasErrorsOccurred) { return; }
            }

            // The following sections happen regardless of whether the DriveLetter belongs to an OS Drive or not

            // https://learn.microsoft.com/en-us/windows/win32/secprov/decrypt-win32-encryptablevolume
            // Get the method parameters for Decrypt (even if they are empty)
            ManagementBaseObject DecryptArgs = VolumeInfo.GetMethodParameters("Decrypt");

            // Invoke the method with an empty argument object
            ManagementBaseObject DecryptMethodInvocationResult = VolumeInfo.InvokeMethod("Decrypt", DecryptArgs, null);


            #region Output handling
            uint? DecryptMethodInvocationResultCode = null;

            if (DecryptMethodInvocationResult is not null)
            {
                DecryptMethodInvocationResultCode = Convert.ToUInt32(DecryptMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (DecryptMethodInvocationResultCode is not null && DecryptMethodInvocationResultCode == 0)
            {
                Logger.LogMessage($"Successfully Decrypted the drive {DriveLetter}", LogTypeIntel.InformationInteractionRequired);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(DecryptMethodInvocationResultCode);
                return;
            }
            #endregion

        }

    }
}
