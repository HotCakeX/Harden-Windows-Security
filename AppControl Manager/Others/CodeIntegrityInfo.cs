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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace AppControlManager.Others;

internal sealed class CodeIntegrityOption(string name, string description)
{
	internal string Name => name;
	internal string Description => description;
}

internal sealed class SystemCodeIntegrityInfo(uint codeIntegrityOptions, List<CodeIntegrityOption> codeIntegrityDetails)
{
	internal uint CodeIntegrityOptions => codeIntegrityOptions;
	internal List<CodeIntegrityOption> CodeIntegrityDetails => codeIntegrityDetails;
}

internal static partial class DetailsRetrieval
{
	private const int SystemCodeIntegrityInformation = 103;

	[StructLayout(LayoutKind.Sequential)]
	private struct SYSTEM_CODEINTEGRITY_INFORMATION
	{
		internal uint Length;
		internal uint CodeIntegrityOptions;
	}


	/// <summary>
	/// Define a dictionary to map option flags to their corresponding descriptions
	/// </summary>
	private static readonly FrozenDictionary<uint, (string Name, string Description)> codeIntegrityFlags = new Dictionary<uint, (string Name, string Description)>
	{
		{ 0x00000001, ("CODEINTEGRITY_OPTION_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_ENABLED")) },

		{ 0x00000002, ("CODEINTEGRITY_OPTION_TESTSIGN",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_TESTSIGN")) },

		{ 0x00000004, ("CODEINTEGRITY_OPTION_UMCI_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_UMCI_ENABLED")) },

		{ 0x00000008, ("CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED")) },

		{ 0x00000010, ("CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED")) },

		{ 0x00000020, ("CODEINTEGRITY_OPTION_TEST_BUILD",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_TEST_BUILD")) },

		{ 0x00000040, ("CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_PREPRODUCTION_BUILD")) },

		{ 0x00000080, ("CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED")) },

		{ 0x00000100, ("CODEINTEGRITY_OPTION_FLIGHT_BUILD",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_FLIGHT_BUILD")) },

		{ 0x00000200, ("CODEINTEGRITY_OPTION_FLIGHTING_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_FLIGHTING_ENABLED")) },

		{ 0x00000400, ("CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED")) },

		{ 0x00000800, ("CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED")) },

		{ 0x00001000, ("CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED")) },

		{ 0x00002000, ("CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED",
			GlobalVars.GetStr("CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED")) }
	}.ToFrozenDictionary();


	private static List<CodeIntegrityOption> GetCodeIntegrityDetails(uint options)
	{
		List<CodeIntegrityOption> details = [];

		// Loop through the dictionary and check if each flag is set in the options
		foreach (KeyValuePair<uint, (string Name, string Description)> flag in codeIntegrityFlags)
		{
			if ((options & flag.Key) != 0)
			{
				details.Add(new CodeIntegrityOption
				(
					name: flag.Value.Name,
					description: flag.Value.Description
				));
			}
		}

		return details;

	}

	/// <summary>
	/// Gets the system code integrity information
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static unsafe SystemCodeIntegrityInfo Get()
	{
		// Creating the structure and set Length
		SYSTEM_CODEINTEGRITY_INFORMATION sci;
		sci.Length = (uint)sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
		sci.CodeIntegrityOptions = 0;

		int bufferSize = sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);

		// Allocating unmanaged memory of the exact size
		nint buffer = Marshal.AllocHGlobal(bufferSize);

		try
		{
			// Write the initialized struct directly into unmanaged memory.
			*(SYSTEM_CODEINTEGRITY_INFORMATION*)buffer = sci;

			int returnLength = 0;

			int result = NativeMethods.NtQuerySystemInformation(
				SystemCodeIntegrityInformation,
				buffer,
				bufferSize,
				ref returnLength);

			if (result != 0)
			{
				throw new InvalidOperationException("NtQuerySystemInformation failed with status: " + result);
			}

			// Read back the updated structure directly
			sci = *(SYSTEM_CODEINTEGRITY_INFORMATION*)buffer;

			SystemCodeIntegrityInfo output = new(
				codeIntegrityOptions: sci.CodeIntegrityOptions,
				codeIntegrityDetails: GetCodeIntegrityDetails(sci.CodeIntegrityOptions)
			);

			return output;
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}
}
