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

using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace CommonCore.Others;

internal static class MeowParser
{
	/// <summary>
	/// Gets the hashes of the members in a security catalog file.
	/// </summary>
	/// <param name="SecurityCatalogFilePath"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static unsafe HashSet<string> GetHashes(string SecurityCatalogFilePath)
	{
		// Initializes a new HashSet to store the hashes.
		HashSet<string> OutputHashSet = [];

		IntPtr MainCryptProviderHandle = IntPtr.Zero; // Initializes the handle to zero.
		IntPtr MeowLogHandle = IntPtr.Zero; // Initializes the catalog context handle to zero.
		IntPtr KittyPointer = IntPtr.Zero; // Pointer to iterate through catalog members, initialized to zero.

		try
		{
			// Attempt to acquire a cryptographic context using the CNG API.
			int status = NativeMethods.BCryptOpenAlgorithmProvider(out MainCryptProviderHandle, "SHA256", null, 0);

			if (status != 0)
			{
				// If the context is not acquired
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("BCryptOpenAlgorithmProviderFailedMessage"), status));
			}

			// Opens the catalog file and gets a handle to the catalog context.
			MeowLogHandle = NativeMethods.CryptCATOpen(SecurityCatalogFilePath, 0, MainCryptProviderHandle, 0, 0);

			if (MeowLogHandle == IntPtr.Zero)
			{
				// If the handle is not obtained, capture the error code.
				int error = Marshal.GetLastPInvokeError();
				Logger.Write(string.Format(GlobalVars.GetStr("CryptCATOpenFailedMessage"), error));
			}

			// Iterates through the catalog members.
			while ((KittyPointer = NativeMethods.CryptCATEnumerateMember(MeowLogHandle, KittyPointer)) != IntPtr.Zero)
			{
				// Read the unmanaged structure
				MeowMemberCrypt member = *(MeowMemberCrypt*)KittyPointer;

				// Convert unmanaged LPCWSTR pointer to managed string (hash list).
				string? hash = member.Hashes != IntPtr.Zero ? Marshal.PtrToStringUni(member.Hashes) : null;

				if (hash is not null)
				{
					_ = OutputHashSet.Add(hash);
				}
			}
		}
		finally
		{
			// Releases the cryptographic context and closes the catalog context in the finally block to ensure resources are freed.
			if (MainCryptProviderHandle != IntPtr.Zero)
			{
				// Attempt to close the algorithm provider handle.
				int closeStatus = NativeMethods.BCryptCloseAlgorithmProvider(MainCryptProviderHandle, 0);

				// Check if the function succeeded by examining the NTSTATUS code.
				if (closeStatus != 0)
				{
					// Log the error if closing the handle failed.
					Logger.Write(string.Format(GlobalVars.GetStr("BCryptCloseAlgorithmProviderFailedMessage"), closeStatus));
				}
			}

			if (MeowLogHandle != IntPtr.Zero)
				_ = NativeMethods.CryptCATClose(MeowLogHandle);
		}

		// Returns the HashSet containing the hashes.
		return OutputHashSet;
	}
}
