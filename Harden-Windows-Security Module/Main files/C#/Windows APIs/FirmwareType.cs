namespace HardenWindowsSecurity;

internal static class FirmwareChecker
{

	// https://learn.microsoft.com/en-us/windows/win32/api/winnt/ne-winnt-firmware_type
	internal enum FirmwareType
	{
		FirmwareTypeUnknown,
		FirmwareTypeBios,
		FirmwareTypeUefi,
		FirmwareTypeMax
	}

	// Check the firmware type
	internal static FirmwareType CheckFirmwareType()
	{
		if (NativeMethods.GetFirmwareType(out FirmwareType firmwareType))
		{
			return firmwareType;
		}
		// Return Unknown if unable to determine firmware type
		return FirmwareType.FirmwareTypeUnknown;
	}
}
