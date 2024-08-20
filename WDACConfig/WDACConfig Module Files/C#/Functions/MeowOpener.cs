using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    // Declares a public static class that cannot be instantiated.
    public static class MeowParser
    {
        // P/Invoke declaration to import the 'CryptAcquireContext' function from 'AdvApi32.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontexta
        [DllImport("AdvApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptAcquireContext(
            out IntPtr MainCryptProviderHandle, // Output parameter to receive the handle of the cryptographic service provider.
            [MarshalAs(UnmanagedType.LPTStr)] string Container, // The name of the key container within the cryptographic service provider.
            [MarshalAs(UnmanagedType.LPTStr)] string Provider, // The name of the cryptographic service provider.
            uint ProviderType, // The type of provider to acquire.
            uint Flags); // Flags to control the function behavior.

        // P/Invoke declaration to import the 'CryptReleaseContext' function from 'AdvApi32.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptreleasecontext
        [DllImport("AdvApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern bool CryptReleaseContext(IntPtr MainCryptProviderHandle, uint Flags); // Releases the handle acquired by 'CryptAcquireContext'.

        // P/Invoke declaration to import the 'CryptCATOpen' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatopen
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATOpen(
            [MarshalAs(UnmanagedType.LPWStr)] string FileName, // The name of the catalog file.
            uint OpenFlags, // Flags to control the function behavior.
            IntPtr MainCryptProviderHandle, // Handle to the cryptographic service provider.
            uint PublicVersion, // The public version number.
            uint EncodingType); // The encoding type.

        // P/Invoke declaration to import the 'CryptCATEnumerateMember' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatenumeratemember
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATEnumerateMember(
            IntPtr MeowLogHandle, // Handle to the catalog context.
            IntPtr PrevCatalogMember); // Pointer to the previous catalog member.

        // P/Invoke declaration to import the 'CryptCATClose' function from 'WinTrust.dll'.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/nf-mscat-cryptcatclose
        [DllImport("WinTrust.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern IntPtr CryptCATClose(IntPtr MainCryptProviderHandle); // Closes the catalog context.

        // Defines a structure with sequential layout to match the native structure.
        // https://learn.microsoft.com/en-us/windows/win32/api/mscat/ns-mscat-cryptcatmember
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        internal struct MeowMemberCrypt
        {
            public uint StructureSize; // Size of the structure.
            [MarshalAs(UnmanagedType.LPWStr)]
            public string Hashes; // The hashes associated with the catalog member.
            [MarshalAs(UnmanagedType.LPWStr)]
            public string FileName; // The file name of the catalog member.
            public Guid SubjectType; // The subject type GUID.
            public uint MemberFlags; // Flags associated with the member.
            public IntPtr IndirectDataStructure; // Pointer to the indirect data structure.
            public uint CertVersion; // The certificate version.
            private uint Reserved1; // Reserved for future use.
            private IntPtr Reserved2; // Reserved for future use.
        }

        // A public static method that returns a HashSet of strings.
        public static HashSet<string> GetHashes(string SecurityCatalogFilePath)
        {
            HashSet<string> OutputHashSet = new HashSet<string>(); // Initializes a new HashSet to store the hashes.

            XmlDocument PurrfectCatalogXMLDoc = new XmlDocument(); // Creates a new XmlDocument instance.
            PurrfectCatalogXMLDoc.XmlResolver = null; // Disables the XML resolver for security reasons.
            IntPtr MainCryptProviderHandle = IntPtr.Zero; // Initializes the handle to zero.
            IntPtr MeowLogHandle = IntPtr.Zero; // Initializes the catalog context handle to zero.
            IntPtr CharmPointer = IntPtr.Zero; // Unused pointer, initialized to zero.
            IntPtr KittyPointer = IntPtr.Zero; // Pointer to iterate through catalog members, initialized to zero.

            try
            {
                // Attempts to acquire a cryptographic context.
                if (!CryptAcquireContext(out MainCryptProviderHandle, string.Empty, string.Empty, 1, 4026531840))
                {
                    // If the context is not acquired, the error can be captured (commented out).
                    // int lastWin32Error = Marshal.GetLastWin32Error();
                }

                // Opens the catalog file and gets a handle to the catalog context.
                MeowLogHandle = CryptCATOpen(SecurityCatalogFilePath, 0, MainCryptProviderHandle, 0, 0);
                if (MeowLogHandle == IntPtr.Zero)
                {
                    // If the handle is not obtained, the error can be captured (commented out).
                    // int lastWin32Error = Marshal.GetLastWin32Error();
                }

                // Creates an XML element to represent the catalog file.
                XmlElement catalogElement = PurrfectCatalogXMLDoc.CreateElement("MeowFile");
                PurrfectCatalogXMLDoc.AppendChild(catalogElement); // Appends the element to the XML document.

                // Iterates through the catalog members.
                while ((KittyPointer = CryptCATEnumerateMember(MeowLogHandle, KittyPointer)) != IntPtr.Zero)
                {
                    // Converts the pointer to a structure.
                    MeowMemberCrypt member = Marshal.PtrToStructure<MeowMemberCrypt>(KittyPointer);
                    OutputHashSet.Add(member.Hashes); // Adds the hashes to the HashSet.
                }
            }
            finally
            {
                // Releases the cryptographic context and closes the catalog context in the finally block to ensure resources are freed.
                if (MainCryptProviderHandle != IntPtr.Zero)
                    CryptReleaseContext(MainCryptProviderHandle, 0);

                if (MeowLogHandle != IntPtr.Zero)
                    CryptCATClose(MeowLogHandle);
            }
            return OutputHashSet; // Returns the HashSet containing the hashes.
        }
    }
}
