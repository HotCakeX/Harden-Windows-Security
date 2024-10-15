using System;
using System.Globalization;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class BitLocker
    {
        /// <summary>
        /// Enables the key protectors of an encrypted volume, doesn't decrypt or encrypt the drive.
        /// The drive can remain encrypted and you use Suspend-BitLocker cmdlet to turn the protection off.
        /// After using this method, the "Protection Status" will be on.
        /// Same as Resume-BitLocker PowerShell cmdlet.
        /// This method must run at the end of the operation when turning on (enabling) BitLocker for the OS drive when it's fully decrypted and has no key protectors.
        /// It can run on a drive where key protectors are already enabled, won't change anything.
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/enablekeyprotectors-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter"></param>
        public static void EnableKeyProtectors(string DriveLetter)
        {

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);

            // Invoke the method to enable the key protectors
            // The first null indicates that the method does not require any input parameters.
            // The second null indicates that there are no special options being passed for this WMI operation.
            ManagementBaseObject KeyProtectorEnablementResult = VolumeInfo.InvokeMethod("EnableKeyProtectors", null, null);


            #region Output handling
            uint? KeyProtectorEnablementResultCode = null;

            if (KeyProtectorEnablementResult is not null)
            {
                KeyProtectorEnablementResultCode = Convert.ToUInt32(KeyProtectorEnablementResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (KeyProtectorEnablementResultCode is not null && KeyProtectorEnablementResultCode == 0)
            {
                Logger.LogMessage($"Successfully enabled the key protectors of the drive {DriveLetter}.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(KeyProtectorEnablementResultCode);
                return;
            }
            #endregion
        }
    }
}
