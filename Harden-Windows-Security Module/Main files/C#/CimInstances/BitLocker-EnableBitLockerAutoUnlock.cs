using System;
using System.Globalization;
using System.Management;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class BitLocker
    {
        /// <summary>
        /// Enables Auto unlock | Suitable for Non-OS Drives
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/isautounlockenabled-win32-encryptablevolume
        /// https://learn.microsoft.com/en-us/windows/win32/secprov/enableautounlock-win32-encryptablevolume
        /// </summary>
        /// <param name="DriveLetter">Drive letter in the following format: "C:"</param>
        public static void EnableBitLockerAutoUnlock(string DriveLetter)
        {

            // First get the volume info based on the drive letter
            ManagementObject VolumeInfo = GetVolumeFromLetter(DriveLetter);


            // Invoke the method to enable the key protectors
            // The first null indicates that the method does not require any input parameters.
            // The second null indicates that there are no special options being passed for this WMI operation.
            ManagementBaseObject IsAutoUnlockEnabledResult = VolumeInfo.InvokeMethod("IsAutoUnlockEnabled", null, null);


            #region Output handling
            uint? IsAutoUnlockEnabledResultCode = null;

            if (IsAutoUnlockEnabledResult is not null)
            {
                IsAutoUnlockEnabledResultCode = Convert.ToUInt32(IsAutoUnlockEnabledResult["ReturnValue"], CultureInfo.InvariantCulture);
            }

            if (IsAutoUnlockEnabledResultCode is not null && IsAutoUnlockEnabledResultCode == 0)
            {
                Logger.LogMessage($"Successfully queried the Auto-unlock status of the drive {DriveLetter}.", LogTypeIntel.Information);
            }
            else
            {
                HResultHelper.HandleHresultAndLog(IsAutoUnlockEnabledResultCode);
                return;
            }
            #endregion



            if (!Convert.ToBoolean(IsAutoUnlockEnabledResult?["IsAutoUnlockEnabled"], CultureInfo.InvariantCulture))
            {
                Logger.LogMessage($"Auto-unlock is not enabled on the drive {DriveLetter}, enabling it now.", LogTypeIntel.Information);


                // Get the method parameters for ProtectKeyWithExternalKey (even if they are empty)
                ManagementBaseObject ProtectKeyArgs = VolumeInfo.GetMethodParameters("ProtectKeyWithExternalKey");

                // Invoke the method with an empty argument object
                // This is required because using ("ProtectKeyWithExternalKey", null, null) would result in a COM error unhandled by HResult method.
                ManagementBaseObject ProtectKeyWithExternalKeyMethodInvocationResult = VolumeInfo.InvokeMethod("ProtectKeyWithExternalKey", ProtectKeyArgs, null);


                #region Output handling
                uint? MethodInvocationResultCode = null;

                if (ProtectKeyWithExternalKeyMethodInvocationResult is not null)
                {
                    MethodInvocationResultCode = Convert.ToUInt32(ProtectKeyWithExternalKeyMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (MethodInvocationResultCode is not null && MethodInvocationResultCode == 0)
                {
                    Logger.LogMessage("The ExternalKey key protector was successfully added.", LogTypeIntel.Information);
                    // Will move forward to the next step
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(MethodInvocationResultCode);
                    return;
                }
                #endregion



                // Prepare the method with arguments
                ManagementBaseObject EnableAutoUnlockArgs = VolumeInfo.GetMethodParameters("EnableAutoUnlock");
                EnableAutoUnlockArgs["VolumeKeyProtectorID"] = ProtectKeyWithExternalKeyMethodInvocationResult?["VolumeKeyProtectorID"];

                // Invoke the method to enable Auto-unlock
                ManagementBaseObject EnableAutoUnlockMethodInvocationResult = VolumeInfo.InvokeMethod("EnableAutoUnlock", EnableAutoUnlockArgs, null);


                #region Output handling
                uint? EnableAutoUnlockMethodInvocationResultCode = null;

                if (EnableAutoUnlockMethodInvocationResult is not null)
                {
                    EnableAutoUnlockMethodInvocationResultCode = Convert.ToUInt32(EnableAutoUnlockMethodInvocationResult["ReturnValue"], CultureInfo.InvariantCulture);
                }

                if (EnableAutoUnlockMethodInvocationResultCode is not null && EnableAutoUnlockMethodInvocationResultCode == 0)
                {
                    Logger.LogMessage($"Auto-Unlock has been successfully enabled for the drive: {DriveLetter}", LogTypeIntel.Information);
                }
                else
                {
                    HResultHelper.HandleHresultAndLog(EnableAutoUnlockMethodInvocationResultCode);

                    Logger.LogMessage($"Error enabling Auto-Unlock for the drive {DriveLetter}: {EnableAutoUnlockMethodInvocationResultCode} . Removing the previously set ExternalKey Key Protector.", LogTypeIntel.Error);


                    RemoveKeyProtector(DriveLetter, ProtectKeyWithExternalKeyMethodInvocationResult?["VolumeKeyProtectorID"].ToString()!, false);

                    return;
                }
                #endregion

            }
            else
            {
                Logger.LogMessage($"Auto-unlock is already enabled on the drive {DriveLetter}.", LogTypeIntel.Information);
            }
        }
    }
}
