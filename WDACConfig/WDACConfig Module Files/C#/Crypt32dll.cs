// Used by Get-NestedSignerSignature function
using System.Runtime.InteropServices;

namespace WDACConfig
{
    public class Crypt32DLL
    {
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptQueryObject(
            int dwObjectType,
            [MarshalAs(UnmanagedType.LPWStr)]
            string pvObject,
            int dwExpectedContentTypeFlags,
            int dwExpectedFormatTypeFlags,
            int dwFlags,
            ref int pdwMsgAndCertEncodingType,
            ref int pdwContentType,
            ref int pdwFormatType,
            ref System.IntPtr phCertStore,
            ref System.IntPtr phMsg,
            ref System.IntPtr ppvContext
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptMsgGetParam(
            System.IntPtr hCryptMsg,
            int dwParamType,
            int dwIndex,
            byte[] pvData,
            ref int pcbData
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CryptMsgClose(
            System.IntPtr hCryptMsg
        );
        [DllImport("crypt32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern bool CertCloseStore(
            System.IntPtr hCertStore,
            int dwFlags
        );
    }
}
