// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System.Runtime.InteropServices;

namespace AppControlManager.Main;

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
		UNICODE_STRING ProviderUS = NativeMethods.InitUnicodeString(provider);
		UNICODE_STRING KeyUS = NativeMethods.InitUnicodeString(key);
		UNICODE_STRING ValueNameUS = NativeMethods.InitUnicodeString(valueName);

		// Prepare output variables
		uint ValueSize = 1024;  // Changed to uint to match the P/Invoke declaration
		nint Value = Marshal.AllocHGlobal((int)ValueSize);

		int result = NativeMethods.WldpQuerySecurityPolicy(
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
