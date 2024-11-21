using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace WDACConfig.CodeIntegrity
{

    internal sealed class CodeIntegrityOption
    {
        internal required string Name { get; set; }
        internal required string Description { get; set; }
    }

    internal sealed class SystemCodeIntegrityInfo
    {
        internal uint CodeIntegrityOptions { get; set; }
        internal required List<CodeIntegrityOption> CodeIntegrityDetails { get; set; }
    }

    internal static partial class DetailsRetrieval
    {
        private const int SystemCodeIntegrityInformation = 103;

        [StructLayout(LayoutKind.Sequential)]
        private struct SYSTEM_CODEINTEGRITY_INFORMATION
        {
            public uint Length;
            public uint CodeIntegrityOptions;
        }

        // https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_codeintegrity_information
        [LibraryImport("ntdll.dll", SetLastError = true)]
        private static partial int NtQuerySystemInformation(
        int SystemInformationClass,
        IntPtr SystemInformation,
        int SystemInformationLength,
        ref int ReturnLength
        );


        private static List<CodeIntegrityOption> GetCodeIntegrityDetails(uint options)
        {
            List<CodeIntegrityOption> details = [];

            // Define a dictionary to map option flags to their corresponding descriptions
            Dictionary<uint, (string Name, string Description)> codeIntegrityFlags = new()
            {
                { 0x00000001, ("CODEINTEGRITY_OPTION_ENABLED", "Enforcement of kernel mode Code Integrity is enabled.") },
                { 0x00000002, ("CODEINTEGRITY_OPTION_TESTSIGN", "Test signed content is allowed by Code Integrity.") },
                { 0x00000004, ("CODEINTEGRITY_OPTION_UMCI_ENABLED", "Enforcement of user mode Code Integrity is enabled.") },
                { 0x00000008, ("CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED", "Enforcement of user mode Code Integrity is enabled in audit mode.") },
                { 0x00000010, ("CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED", "User mode binaries from certain paths can run even if they fail code integrity checks.") },
                { 0x00000020, ("CODEINTEGRITY_OPTION_TEST_BUILD", "The build of Code Integrity is from a test build.") },
                { 0x00000040, ("CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD", "The build of Code Integrity is from a pre-production build.") },
                { 0x00000080, ("CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED", "The kernel debugger is attached, allowing unsigned code to load.") },
                { 0x00000100, ("CODEINTEGRITY_OPTION_FLIGHT_BUILD", "The build of Code Integrity is from a flight build.") },
                { 0x00000200, ("CODEINTEGRITY_OPTION_FLIGHTING_ENABLED", "Flight signed content is allowed by Code Integrity.") },
                { 0x00000400, ("CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED", "Hypervisor enforced Code Integrity is enabled for kernel mode components.") },
                { 0x00000800, ("CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED", "Hypervisor enforced Code Integrity is enabled in audit mode.") },
                { 0x00001000, ("CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED", "Hypervisor enforced Code Integrity is enabled for kernel mode in strict mode.") },
                { 0x00002000, ("CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED", "Hypervisor enforced Code Integrity with Isolated User Mode component signing.") }
            };

            // Loop through the dictionary and check if each flag is set in the options
            foreach (KeyValuePair<uint, (string Name, string Description)> flag in codeIntegrityFlags)
            {
                if ((options & flag.Key) != 0)
                {
                    details.Add(new CodeIntegrityOption
                    {
                        Name = flag.Value.Name,
                        Description = flag.Value.Description
                    });
                }
            }

            return details;

        }

        /// <summary>
        /// Gets the system code integrity information
        /// </summary>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        internal static SystemCodeIntegrityInfo Get()
        {

            SYSTEM_CODEINTEGRITY_INFORMATION sci = new()
            {
                Length = (uint)Marshal.SizeOf<SYSTEM_CODEINTEGRITY_INFORMATION>()
            };

            IntPtr buffer = Marshal.AllocHGlobal((int)sci.Length);
            Marshal.StructureToPtr(sci, buffer, false);

            try
            {
                int length = 0;

                int result = NtQuerySystemInformation(SystemCodeIntegrityInformation, buffer, (int)sci.Length, ref length);

                if (result != 0)
                    throw new InvalidOperationException("NtQuerySystemInformation failed with status: " + result);

                sci = Marshal.PtrToStructure<SYSTEM_CODEINTEGRITY_INFORMATION>(buffer);

                SystemCodeIntegrityInfo output = new()
                {
                    CodeIntegrityOptions = sci.CodeIntegrityOptions,
                    CodeIntegrityDetails = GetCodeIntegrityDetails(sci.CodeIntegrityOptions)
                };

                return output;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }
}
