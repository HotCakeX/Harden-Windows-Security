using System;
using System.Runtime.InteropServices;

namespace HardenWindowsSecurity
{
    public class FirmwareChecker
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFirmwareType(out FirmwareType firmwareType);

        // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-firmware_type
        public enum FirmwareType
        {
            FirmwareTypeUnknown,
            FirmwareTypeBios,
            FirmwareTypeUefi,
            FirmwareTypeMax
        }

        // Check the firmware type
        public static FirmwareType CheckFirmwareType()
        {
            if (GetFirmwareType(out FirmwareType firmwareType))
            {
                return firmwareType;
            }
            // Return Unknown if unable to determine firmware type
            return FirmwareType.FirmwareTypeUnknown;
        }
    }
}
