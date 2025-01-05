using System;
using System.Runtime.InteropServices;
using static HardenWindowsSecurity.FirmwareChecker;
using static HardenWindowsSecurity.SystemInformationClass;

namespace HardenWindowsSecurity;

internal static class NativeMethods
{

	// https://learn.microsoft.com/en-us/windows/win32/api/sddl/nf-sddl-convertsidtostringsida
	[DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern bool ConvertSidToStringSid(IntPtr pSID, out IntPtr ptrSid);

	[DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern uint TpmIsEnabled(out byte pfIsEnabled);

	[DllImport("TpmCoreProvisioning", CharSet = CharSet.Unicode)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern uint TpmIsActivated(out byte pfIsActivated);

	[DllImport("ntdll.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern Int32 NtQuerySystemInformation(
		SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
		IntPtr SystemInformation,
		Int32 SystemInformationLength,
		out Int32 ReturnLength);

	// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfirmwaretype
	[DllImport(dllName: "kernel32.dll", SetLastError = true)]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern bool GetFirmwareType(out FirmwareType firmwareType);

	[DllImport("shell32.dll")]
	[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
	internal static extern int SHGetKnownFolderPath(
		ref Guid rfid, uint dwFlags, IntPtr hToken, out IntPtr ppszPath);
}
