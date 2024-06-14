// bootDMAProtection check - checks for Kernel DMA Protection status in System information or msinfo32
using System;
using System.Runtime.InteropServices;

namespace SystemInfo
{
  public static class NativeMethods
  {
    internal enum SYSTEM_DMA_GUARD_POLICY_INFORMATION : int
    {
      SystemDmaGuardPolicyInformation = 202
    }

    [DllImport("ntdll.dll")]
    internal static extern Int32 NtQuerySystemInformation(
        SYSTEM_DMA_GUARD_POLICY_INFORMATION SystemDmaGuardPolicyInformation,
        IntPtr SystemInformation,
        Int32 SystemInformationLength,
        out Int32 ReturnLength);

    public static byte BootDmaCheck()
    {
      Int32 result;
      Int32 SystemInformationLength = 1;
      IntPtr SystemInformation = Marshal.AllocHGlobal(SystemInformationLength);
      Int32 ReturnLength;

      result = NativeMethods.NtQuerySystemInformation(
          NativeMethods.SYSTEM_DMA_GUARD_POLICY_INFORMATION.SystemDmaGuardPolicyInformation,
          SystemInformation,
          SystemInformationLength,
          out ReturnLength);

      if (result == 0)
      {
        byte info = Marshal.ReadByte(SystemInformation, 0);
        Marshal.FreeHGlobal(SystemInformation); // free the allocated memory
        return info;
      }

      Marshal.FreeHGlobal(SystemInformation); // free the allocated memory
      return 0;
    }
  }
}
