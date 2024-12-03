using System;
using System.Runtime.InteropServices;

namespace AppControlManager
{
    public enum WLDP_SECURE_SETTING_VALUE_TYPE
    {
        WldpBoolean = 0,
        WldpInteger = 1,
        WldpNone = 2,
        WldpString = 3,
        WldpFlag = 4
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    public static partial class WldpQuerySecurityPolicyWrapper
    {
        [LibraryImport("Wldp.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        internal static partial int WldpQuerySecurityPolicy(
            ref UNICODE_STRING Provider,
            ref UNICODE_STRING Key,
            ref UNICODE_STRING ValueName,
            out WLDP_SECURE_SETTING_VALUE_TYPE ValueType,
            IntPtr Value,
            ref uint ValueSize);

        public static UNICODE_STRING InitUnicodeString(string s)
        {
            UNICODE_STRING us;
            us.Length = (ushort)(s.Length * 2);
            us.MaximumLength = (ushort)((s.Length * 2) + 2);
            us.Buffer = Marshal.StringToHGlobalUni(s);
            return us;
        }
    }
}