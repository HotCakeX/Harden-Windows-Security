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

using System;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using AppControlManager;
using AppControlManager.Others;
using HardenWindowsSecurity.GroupPolicy;

namespace HardenWindowsSecurity.Helpers;

internal static class FileTrustChecker
{
	/// <summary>
	/// The path to the MpClient.dll file
	/// </summary>
	private static readonly string DefenderPath = Path.Combine(
		Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
		"Windows Defender", "MpClient.dll");

	/// <summary>
	/// Function to check the trust of a given file path
	/// </summary>
	/// <param name="filePath"></param>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static FileTrustResult CheckFileTrust(string filePath)
	{

		IntPtr fileHandle = default;

		try
		{

			// Initializing Params structure
			Params parameters = new() { StructSize = 0x10 };

			ulong MpFileTrustExtraInfoCOUNT = 0; // Variable to store extra info count

			IntPtr extraInfoPtr = IntPtr.Zero;   // Pointer to extra info data

			// Load Windows Defender library dynamically
			IntPtr hModule = NativeMethods.LoadLibraryExW(DefenderPath, IntPtr.Zero, 0);

			if (hModule == IntPtr.Zero)
			{
				throw new FileNotFoundException(GlobalVars.GetStr("MpClientDllNotFound"));
			}

			// Get the function address of 'MpQueryFileTrustByHandle2'
			IntPtr procAddress = NativeMethods.GetProcAddress(hModule, "MpQueryFileTrustByHandle2");

			if (procAddress == IntPtr.Zero)
			{
				throw new InvalidOperationException(GlobalVars.GetStr("MpQueryFileTrustByHandle2NotFound"));
			}

			// Create a delegate for the function from the address
			NativeMethods.MpQueryFileTrustByHandle2Delegate mpQueryFileTrust = Marshal.GetDelegateForFunctionPointer<NativeMethods.MpQueryFileTrustByHandle2Delegate>(procAddress);

			// Open the file and get its handle
			fileHandle = NativeMethods.CreateFileW(filePath, 0x80000000, 0x00000001, IntPtr.Zero, 0x00000003, 0, IntPtr.Zero);

			// Check if file failed to open
			if (fileHandle == new IntPtr(-1))
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("ErrorOpeningHandleToFile"), filePath, Marshal.GetLastWin32Error()));
			}

			// Query the file's trust score using the function pointer and the file handle
			long result = mpQueryFileTrust(fileHandle, IntPtr.Zero, IntPtr.Zero, ref parameters, ref MpFileTrustExtraInfoCOUNT, ref extraInfoPtr);

			// If query is successful
			if (result is 0)
			{
				// Parse the trust score based on the enum
				TrustScore score = (TrustScore)parameters.TrustScore;

				// Output extra info if available
				if (MpFileTrustExtraInfoCOUNT > 0 && extraInfoPtr != IntPtr.Zero)
				{
					MpFileTrustExtraInfo extraInfo = Marshal.PtrToStructure<MpFileTrustExtraInfo>(extraInfoPtr);
					Logger.Write(string.Format(GlobalVars.GetStr("ExtraInfoFileReputationCheck"), extraInfo.First, extraInfo.Second, extraInfo.DataSize, extraInfo.Data), LogTypeIntel.Information);
				}
			}
			else
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("FailedToQueryReputation"), result));
			}

			return new FileTrustResult(
				reputation: GetReputation((TrustScore)parameters.TrustScore),
				source: GetTrustSource(),
				duration: $"{parameters.ValidityDurationMs} ms",
				handle: fileHandle.ToString(CultureInfo.InvariantCulture)
			);

		}

		finally
		{
			// Close the file handle after operation
			_ = NativeMethods.CloseHandle(fileHandle);
		}
	}

	// Map the trust score to a reputation string
	internal static string GetReputation(TrustScore score) => score switch
	{
		TrustScore.HighTrust => GlobalVars.GetStr("HighTrust"),
		TrustScore.Good => GlobalVars.GetStr("GoodTrust"),
		TrustScore.Unknown => GlobalVars.GetStr("UnavailableOrUnknown"),
		TrustScore.PotentiallyUnwantedApplication => GlobalVars.GetStr("PotentiallyUnwantedApplication"),
		TrustScore.Malicious => GlobalVars.GetStr("Malicious"),
		_ => string.Format(GlobalVars.GetStr("UnrecognizedScore"), (int)score)
	};

	// Smart App Control when set in Eval or On state takes control of the file reputation verification, otherwise it's up to the SmartScreen to do it
	internal enum TrustSource
	{
		SmartAppControl,
		SmartScreen
	}

	internal static TrustSource GetTrustSource()
	{
		string? result = RegistryManager.Manager.ReadRegistry(
				new(
				source: Source.Registry,
				keyName: @"SYSTEM\CurrentControlSet\Control\CI\Policy",
				valueName: "VerifiedAndReputablePolicyState",
				type: RegistryValueType.REG_DWORD,
				0,
				[])
				{
					RegValue = "1"
				});

		if (string.Equals(result, "1", StringComparison.OrdinalIgnoreCase))
		{
			return TrustSource.SmartAppControl;
		}
		else
		{
			return TrustSource.SmartScreen;
		}
	}

	internal sealed class FileTrustResult(
		string reputation,
		TrustSource source,
		string? duration,
		string handle
		)
	{
		internal string Reputation => reputation;
		internal TrustSource Source => source;
		internal string? Duration => duration;
		internal string Handle => handle;
	}

	// Enum representing different trust levels of a file
	internal enum TrustScore
	{
		PotentiallyUnwantedApplication = -3,
		Malicious = -2,
		Unknown = -1,
		Good = 0,
		HighTrust = 1
	}

	// Structure to hold extra info about the file trust
	[StructLayout(LayoutKind.Sequential)]
	internal struct MpFileTrustExtraInfo
	{
		internal uint First;             // First extra info field
		internal uint Second;            // Second extra info field
		internal uint DataSize;          // Size of the data
		internal uint AlignmentPadding;  // Padding for memory alignment
		internal IntPtr Data;            // Pointer to extra data
	}

	// Structure to hold parameters for file trust query in Microsoft Defender
	[StructLayout(LayoutKind.Sequential)]
	internal struct Params
	{
		public uint StructSize;         // Size of the structure
		public int TrustScore;          // Trust score of the file
		public ulong ValidityDurationMs; // Validity of the trust score in milliseconds
	}

}
