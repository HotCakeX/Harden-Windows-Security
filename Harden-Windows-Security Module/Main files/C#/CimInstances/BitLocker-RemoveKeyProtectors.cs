using System;
using System.Globalization;
using System.Linq;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class BitLocker
    {

        // https://learn.microsoft.com/en-us/windows/win32/secprov/deletekeyprotector-win32-encryptablevolume#return-value
        private const uint FVE_E_KEY_REQUIRED = 2150694941;
        private const uint FVE_E_VOLUME_BOUND_ALREADY = 2150694943;



        /// <summary>
        /// Removes a key protector of an encrypted volume based on the key protector ID
        /// </summary>
        /// <param name="DriveLetter"></param>
        /// <param name="KeyProtectorID"></param>
        /// <param name="NoErrorIfBound">
        /// If the key protector being deleted is bound to the volume and used to keep the drive unlocked then do not throw errors.
        /// This usually happens when trying to remove all ExternalKey key protectors of a Non-OS Drive when it is detected to have more than 1.
        /// </param>
        public static void RemoveKeyProtector(string DriveLetter, string KeyProtectorID, bool NoErrorIfBound)
        {

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            // Get all other info about the drive
            BitLockerVolume VolumeExtendedInfo = GetEncryptedVolumeInfo(DriveLetter);

            // Get the key protector from the drive based on the user supplied ID
            KeyProtector? DetectedKeyProtector = VolumeExtendedInfo?.KeyProtector?.Where(KeyProtector => KeyProtector.KeyProtectorID == KeyProtectorID).FirstOrDefault();


            if (DetectedKeyProtector is null)
            {
                Logger.LogMessage($"Key protector with the ID {KeyProtectorID} not found on the volume {DriveLetter}", LogTypeIntel.Warning);
                return;
            }


            if (DetectedKeyProtector.KeyProtectorType is BitLocker.KeyProtectorType.TpmNetworkKey)
            {
                Logger.LogMessage($"The detected Key Protector type is TpmNetworkKey, it must be disabled and removed using group policies.", LogTypeIntel.Warning);
                return;
            }


            if (DetectedKeyProtector.KeyProtectorType is BitLocker.KeyProtectorType.PublicKey)
            {
                Logger.LogMessage($"Removal of PublicKey type key protector not supported yet.", LogTypeIntel.Warning);
                return;
            }


            // Prepare arguments for DeleteKeyProtector method.
            ManagementBaseObject deleteKeyProtectorArgs = VolumeInfo.GetMethodParameters("DeleteKeyProtector");

            // Set the VolumeKeyProtectorID argument to the current KeyProtectorID in the loop
            deleteKeyProtectorArgs["VolumeKeyProtectorID"] = KeyProtectorID;

            // Invoke DeleteKeyProtector method to remove the key protector
            // https://learn.microsoft.com/en-us/windows/win32/secprov/deletekeyprotectors-win32-encryptablevolume
            ManagementBaseObject deletionResult = VolumeInfo.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);

            #region Output handling

            uint? deletionResultCode = null;

            deletionResultCode = Convert.ToUInt32(deletionResult["ReturnValue"], CultureInfo.InvariantCulture);

            if (deletionResultCode == FVE_E_KEY_REQUIRED)
            {

                Logger.LogMessage($"The key protectors need to be disabled first, disabling now.", LogTypeIntel.Information);

                // https://learn.microsoft.com/en-us/windows/win32/secprov/disablekeyprotectors-win32-encryptablevolume
                ManagementBaseObject disableKeyProtectorsResult = VolumeInfo.InvokeMethod("DisableKeyProtectors", null, null);

                uint? disablementResultCode = null;

                disablementResultCode = Convert.ToUInt32(disableKeyProtectorsResult["ReturnValue"], CultureInfo.InvariantCulture);


                if (disablementResultCode == 0)
                {
                    Logger.LogMessage("Successfully disabled the key protectors, attempting the deletion again.", LogTypeIntel.Information);

                    // Invoke DeleteKeyProtector method, Again, to remove the key protector
                    deletionResult = VolumeInfo.InvokeMethod("DeleteKeyProtector", deleteKeyProtectorArgs, null);

                    deletionResultCode = Convert.ToUInt32(deletionResult["ReturnValue"], CultureInfo.InvariantCulture);

                }
                else
                {
                    HResultHelper.HandleHresultAndLog(disablementResultCode);
                    return;
                }
            }

            // Check the deletion result code at the end, whether the key protector required disablement or not
            if (deletionResultCode == 0)
            {
                Logger.LogMessage("Successfully deleted the key protector.", LogTypeIntel.Information);
            }
            else if (NoErrorIfBound && deletionResultCode == FVE_E_VOLUME_BOUND_ALREADY)
            {
                Logger.LogMessage("The key protector is bound to the volume and used to keep the drive unlocked, skipping the deletion.", LogTypeIntel.Information);
                return;
            }
            else
            {
                HResultHelper.HandleHresultAndLog(deletionResultCode);
                return;
            }

            #endregion

        }
    }
}
