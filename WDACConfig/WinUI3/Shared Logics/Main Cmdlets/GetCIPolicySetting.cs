using System.Runtime.InteropServices;

#nullable enable

namespace WDACConfig
{

    public class SecurePolicySetting(object? Value, WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE ValueType, uint ValueSize, bool Status, int StatusCode)
    {
        public object? Value { get; set; } = Value;
        public WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE ValueType { get; set; } = ValueType;
        public uint ValueSize { get; set; } = ValueSize;
        public bool Status { get; set; } = Status;
        public int StatusCode { get; set; } = StatusCode;
    }

    public class GetCIPolicySetting
    {

        public static SecurePolicySetting Invoke(string provider, string key, string valueName)
        {

            // Create UNICODE_STRING structures
            var ProviderUS = WDACConfig.WldpQuerySecurityPolicyWrapper.InitUnicodeString(provider);
            var KeyUS = WDACConfig.WldpQuerySecurityPolicyWrapper.InitUnicodeString(key);
            var ValueNameUS = WDACConfig.WldpQuerySecurityPolicyWrapper.InitUnicodeString(valueName);

            // Prepare output variables
            uint ValueSize = 1024;  // Changed to uint to match the P/Invoke declaration
            var Value = Marshal.AllocHGlobal((int)ValueSize);

            var result = WldpQuerySecurityPolicyWrapper.WldpQuerySecurityPolicy(
                ref ProviderUS,
                ref KeyUS,
                ref ValueNameUS,
                out WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE ValueType,
                Value,
                ref ValueSize
            );

            object? decodedValue = null;

            if (result == 0)
            {
                switch (ValueType)
                {
                    case WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE.WldpBoolean:
                        decodedValue = Marshal.ReadByte(Value) != 0;
                        break;
                    case WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE.WldpString:
                        decodedValue = Marshal.PtrToStringUni(Value);
                        break;
                    case WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE.WldpInteger:
                        decodedValue = Marshal.ReadInt32(Value);
                        break;
                    case WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE.WldpNone:
                        break;
                    case WDACConfig.WLDP_SECURE_SETTING_VALUE_TYPE.WldpFlag:
                        break;
                    default:
                        break;
                }
            }

            // Free up the resources
            Marshal.FreeHGlobal(ProviderUS.Buffer);
            Marshal.FreeHGlobal(KeyUS.Buffer);
            Marshal.FreeHGlobal(ValueNameUS.Buffer);
            Marshal.FreeHGlobal(Value);

            return new SecurePolicySetting(
                    decodedValue,
                    ValueType,
                    ValueSize,
                    result == 0,
                    result
                );
        }

    }
}
