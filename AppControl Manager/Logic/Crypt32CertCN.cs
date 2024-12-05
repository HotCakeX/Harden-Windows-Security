using System;
using System.Runtime.InteropServices;

namespace AppControlManager
{
    internal static partial class CryptoAPI
    {
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringw
        [LibraryImport("crypt32.dll", EntryPoint = "CertGetNameStringW", StringMarshalling = StringMarshalling.Utf16, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        private static partial int CertGetNameString(
            IntPtr pCertContext, // The handle property of the certificate object
            int dwType,
            int dwFlags,
            IntPtr pvTypePara,
            [Out] char[] pszNameString,
            int cchNameString
        );

        // Define constants for the name types
        internal const int CERT_NAME_SIMPLE_DISPLAY_TYPE = 4; // Display type for simple names
        internal const int CERT_NAME_ATTR_TYPE = 3; // Display type for attributes
        internal const int CERT_NAME_ISSUER_FLAG = 0x1; // Flag indicating that the issuer name should be retrieved

        /// <summary>
        /// The main method of the class to get the name string
        /// </summary>
        /// <param name="pCertContext"></param>
        /// <param name="dwType"></param>
        /// <param name="pvTypePara"></param>
        /// <param name="isIssuer"></param>
        /// <returns></returns>
        internal static string GetNameString(IntPtr pCertContext, int dwType, string? pvTypePara, bool isIssuer)
        {
            // Allocate a buffer for the name string
            const int bufferSize = 1024;
            char[] nameBuffer = new char[bufferSize];

            // Convert the pvTypePara to a pointer if needed
            IntPtr pvTypeParaPtr = IntPtr.Zero;

            try
            {

                if (!string.IsNullOrEmpty(pvTypePara))
                {
                    // Using Unicode encoding for better compatibility
                    pvTypeParaPtr = Marshal.StringToHGlobalUni(pvTypePara);
                }

                // Set flags to retrieve issuer name if needed
                int flags = isIssuer ? CERT_NAME_ISSUER_FLAG : 0;

                // Call the CertGetNameString function to get the name string
                int result = CertGetNameString(
                    pCertContext,
                    dwType,
                    flags,
                    pvTypeParaPtr,
                    nameBuffer,
                    nameBuffer.Length
                );

                // Return the name string or an empty string if failed
                return result > 0 ? new string(nameBuffer, 0, result - 1) : string.Empty; // Exclude null terminator

            }
            finally
            {
                // Free the pointer if allocated
                if (pvTypeParaPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(pvTypeParaPtr);
                }

            }
        }
    }
}
