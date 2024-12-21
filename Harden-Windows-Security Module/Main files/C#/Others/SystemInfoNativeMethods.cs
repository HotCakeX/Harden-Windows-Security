using System;
using System.Runtime.InteropServices;

namespace HardenWindowsSecurity;

    /// <summary>
    /// bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
    /// can be used to find out if the DMA Protection is ON \ OFF.
    /// will show this by emitting 1 for True (Kernel DMA Protection Available) and 0 for False (Kernel DMA Protection Not Available)
    /// </summary>
    internal static class SystemInformationClass
    {
        internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
        {
            SystemDmaGuardPolicyInformation = 202
        }

        [DllImport("ntdll.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static extern Int32 NtQuerySystemInformation(
            SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
            IntPtr SystemInformation,
            Int32 SystemInformationLength,
            out Int32 ReturnLength);

        internal static byte BootDmaCheck()
        {
            Int32 result;
            Int32 SystemInformationLength = 1;
            IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);

            // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation
            result = NtQuerySystemInformation(
                SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
                SystemInformation,
                SystemInformationLength,
                out _);

            if (result == 0)
            {
                byte info = Marshal.ReadByte(SystemInformation, 0);
                Marshal.FreeHGlobal(SystemInformation);
                return info;
            }

            Marshal.FreeHGlobal(SystemInformation);
            return 0;
        }
    }
