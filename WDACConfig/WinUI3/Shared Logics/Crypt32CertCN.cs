using System;
using System.Runtime.InteropServices;
using System.Text;

#nullable enable

#pragma warning disable CA1838 // Avoid 'StringBuilder' parameters for P/Invoke methods

namespace WDACConfig
{
    public class CryptoAPI
    {
        // Importing function from crypt32.dll to access certificate information
        // https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringa
        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CertGetNameString(
            IntPtr pCertContext, // the handle property of the certificate object
            int dwType,
            int dwFlags,
            IntPtr pvTypePara,
            StringBuilder pszNameString,
            int cchNameString
        );

        // Define constants for the name types
        public const int CERT_NAME_SIMPLE_DISPLAY_TYPE = 4; // Display type for simple names
        public const int CERT_NAME_ATTR_TYPE = 3; // Display type for attributes
        public const int CERT_NAME_ISSUER_FLAG = 0x1; // Flag indicating that the issuer name should be retrieved

        // Define a helper method to get the name string
        public static string GetNameString(IntPtr pCertContext, int dwType, string? pvTypePara, bool isIssuer)
        {
            // Allocate a buffer for the name string, setting it big to handle longer names if needed
            const int bufferSize = 1024;
            StringBuilder nameString = new(bufferSize);

            // Convert the pvTypePara to a pointer if needed
            IntPtr pvTypeParaPtr = IntPtr.Zero;
            if (!string.IsNullOrEmpty(pvTypePara))
            {
                // Using Unicode encoding for better compatibility
                pvTypeParaPtr = Marshal.StringToHGlobalUni(pvTypePara);
            }

            // Set flags to retrieve issuer name if needed
            int flags = isIssuer ? CERT_NAME_ISSUER_FLAG : 0;

            // Call the CertGetNameString function to get the name string
            bool result = CertGetNameString(
                pCertContext,
                dwType,
                flags,
                pvTypeParaPtr,
                nameString,
                nameString.Capacity
            );

            // Free the pointer if allocated
            if (pvTypeParaPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pvTypeParaPtr);
            }

            // Return the name string or an empty string if failed
            return result ? nameString.ToString() : string.Empty;
        }
    }
}
