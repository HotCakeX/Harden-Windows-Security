using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

public class CodeIntegrityOption
{
    public string Name { get; set; }
    public string Description { get; set; }
}

public class SystemCodeIntegrityInfo
{
    public uint CodeIntegrityOptions { get; set; }
    public List<CodeIntegrityOption> CodeIntegrityDetails { get; set; }
}

public static class NtQuerySystemInfo
{
    private const int SystemCodeIntegrityInformation = 103;

    [StructLayout(LayoutKind.Sequential)]
    private struct SYSTEM_CODEINTEGRITY_INFORMATION
    {
        public uint Length;
        public uint CodeIntegrityOptions;
    }

    // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information
    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int SystemInformationClass, IntPtr SystemInformation, int SystemInformationLength, ref int ReturnLength);

    public static SystemCodeIntegrityInfo GetSystemCodeIntegrityInformation()
    {
        SYSTEM_CODEINTEGRITY_INFORMATION sci = new SYSTEM_CODEINTEGRITY_INFORMATION();
        sci.Length = (uint)Marshal.SizeOf(typeof(SYSTEM_CODEINTEGRITY_INFORMATION));
        IntPtr buffer = Marshal.AllocHGlobal((int)sci.Length);
        Marshal.StructureToPtr(sci, buffer, false);

        try
        {
            int length = 0;
            int result = NtQuerySystemInformation(SystemCodeIntegrityInformation, buffer, (int)sci.Length, ref length);
            if (result != 0)
                throw new Exception("NtQuerySystemInformation failed with status: " + result);

            sci = Marshal.PtrToStructure<SYSTEM_CODEINTEGRITY_INFORMATION>(buffer);
            return new SystemCodeIntegrityInfo
            {
                CodeIntegrityOptions = sci.CodeIntegrityOptions,
                CodeIntegrityDetails = GetCodeIntegrityDetails(sci.CodeIntegrityOptions)
            };
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static List<CodeIntegrityOption> GetCodeIntegrityDetails(uint options)
    {
        var details = new List<CodeIntegrityOption>();

        if ((options & 0x00000001) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_ENABLED", Description = "Enforcement of kernel mode Code Integrity is enabled." });
        if ((options & 0x00000002) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_TESTSIGN", Description = "Test signed content is allowed by Code Integrity." });
        if ((options & 0x00000004) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_UMCI_ENABLED", Description = "Enforcement of user mode Code Integrity is enabled." });
        if ((options & 0x00000008) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED", Description = "Enforcement of user mode Code Integrity is enabled in audit mode." });
        if ((options & 0x00000010) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED", Description = "User mode binaries being run from certain paths are allowed to run even if they fail code integrity checks." });
        if ((options & 0x00000020) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_TEST_BUILD", Description = "The build of Code Integrity is from a test build." });
        if ((options & 0x00000040) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD", Description = "The build of Code Integrity is from a pre-production build." });
        if ((options & 0x00000080) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED", Description = "The kernel debugger is attached and Code Integrity may allow unsigned code to load." });
        if ((options & 0x00000100) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_FLIGHT_BUILD", Description = "The build of Code Integrity is from a flight build." });
        if ((options & 0x00000200) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_FLIGHTING_ENABLED", Description = "Flight signed content is allowed by Code Integrity." });
        if ((options & 0x00000400) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED", Description = "Hypervisor enforced Code Integrity is enabled for kernel mode components." });
        if ((options & 0x00000800) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED", Description = "Hypervisor enforced Code Integrity is enabled in audit mode." });
        if ((options & 0x00001000) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED", Description = "Hypervisor enforced Code Integrity is enabled for kernel mode components, but in strict mode." });
        if ((options & 0x00002000) != 0) details.Add(new CodeIntegrityOption { Name = "CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED", Description = "Hypervisor enforced Code Integrity is enabled with enforcement of Isolated User Mode component signing." });

        return details;
    }
}
