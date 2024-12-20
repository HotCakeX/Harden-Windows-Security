using System.Runtime.InteropServices;

namespace AppControlManager;

internal sealed class SecurePolicySetting(object? Value, WLDP_SECURE_SETTING_VALUE_TYPE ValueType, uint ValueSize, bool Status, int StatusCode)
{
	internal object? Value { get; set; } = Value;
	internal WLDP_SECURE_SETTING_VALUE_TYPE ValueType { get; set; } = ValueType;
	internal uint ValueSize { get; set; } = ValueSize;
	internal bool Status { get; set; } = Status;
	internal int StatusCode { get; set; } = StatusCode;
}

internal static class GetCIPolicySetting
{

	internal static SecurePolicySetting Invoke(string provider, string key, string valueName)
	{

		// Create UNICODE_STRING structures
		UNICODE_STRING ProviderUS = WldpQuerySecurityPolicyWrapper.InitUnicodeString(provider);
		UNICODE_STRING KeyUS = WldpQuerySecurityPolicyWrapper.InitUnicodeString(key);
		UNICODE_STRING ValueNameUS = WldpQuerySecurityPolicyWrapper.InitUnicodeString(valueName);

		// Prepare output variables
		uint ValueSize = 1024;  // Changed to uint to match the P/Invoke declaration
		nint Value = Marshal.AllocHGlobal((int)ValueSize);

		int result = WldpQuerySecurityPolicyWrapper.WldpQuerySecurityPolicy(
			ref ProviderUS,
			ref KeyUS,
			ref ValueNameUS,
			out WLDP_SECURE_SETTING_VALUE_TYPE ValueType,
			Value,
			ref ValueSize
		);

		object? decodedValue = null;

		if (result == 0)
		{
			switch (ValueType)
			{
				case WLDP_SECURE_SETTING_VALUE_TYPE.WldpBoolean:
					decodedValue = Marshal.ReadByte(Value) != 0;
					break;
				case WLDP_SECURE_SETTING_VALUE_TYPE.WldpString:
					decodedValue = Marshal.PtrToStringUni(Value);
					break;
				case WLDP_SECURE_SETTING_VALUE_TYPE.WldpInteger:
					decodedValue = Marshal.ReadInt32(Value);
					break;
				case WLDP_SECURE_SETTING_VALUE_TYPE.WldpNone:
					break;
				case WLDP_SECURE_SETTING_VALUE_TYPE.WldpFlag:
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
