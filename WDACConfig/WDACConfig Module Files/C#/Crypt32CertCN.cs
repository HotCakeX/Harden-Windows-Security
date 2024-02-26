// To get the certificate common name. For documentation on Crypt32 CertGetNameString function, see https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-certgetnamestringa
using System;
using System.Runtime.InteropServices;
namespace WDACConfig
{
    public class CryptoAPI
    {
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertGetNameString(
            IntPtr pCertContext,
            int dwType,
            int dwFlags,
            IntPtr pvTypePara,
            System.Text.StringBuilder pszNameString,
            int cchNameString
        );
    }
}
