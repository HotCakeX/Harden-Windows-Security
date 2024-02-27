// https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringa
using System;
using System.Runtime.InteropServices;

namespace WDACConfig
{
    public class CryptoAPI
    {
        // Importing function from crypt32.dll to access certificate information
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertGetNameString(
            IntPtr pCertContext, // the handle property of the certificate object
            int dwType,
            int dwFlags,
            IntPtr pvTypePara,
            System.Text.StringBuilder pszNameString,
            int cchNameString
        );

        // Define constants for the name types
        public const int CERT_NAME_SIMPLE_DISPLAY_TYPE = 4; // Display type for simple names
        public const int CERT_NAME_ATTR_TYPE = 3; // Display type for attributes
        public const int CERT_NAME_ISSUER_FLAG = 0x1; // Flag indicating that the issuer name should be retrieved

        // Define a helper method to get the name string
        public static string GetNameString(IntPtr pCertContext, int dwType, string pvTypePara, bool isIssuer)
        {
            // Allocate a buffer for the name string
            System.Text.StringBuilder nameString = new System.Text.StringBuilder(256);

            // Convert the pvTypePara to a pointer if needed
            IntPtr pvTypeParaPtr = IntPtr.Zero;
            if (!string.IsNullOrEmpty(pvTypePara))
            {
                pvTypeParaPtr = Marshal.StringToHGlobalAnsi(pvTypePara);
            }
            // Set flags to retrieve issuer name if needed
            int flags = 0;
            if (isIssuer)
            {
                flags |= CERT_NAME_ISSUER_FLAG;
            }
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
