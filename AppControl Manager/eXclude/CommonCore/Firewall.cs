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

using System.IO;

namespace CommonCore;

internal static class Firewall
{
	//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fasp/55e50895-2e1f-4479-b130-122f9dc0265f


	/// <summary>
	/// Binary version for Windows 11 23H2 / Server 2025
	/// </summary>
	private const ushort FW_BINARY_VERSION = 0x0221;

	/// <summary>
	/// Exports the Firewall rules to a ".wfw" file.
	/// </summary>
	/// <param name="path">The location where the file will be saved to.</param>
	/// <param name="fGPO">If true, will only export the rules defined in the GPO store.
	/// If false, will only export the rules defined in the Local Windows Defender Firewall settings.</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void ExportFirewallPolicy(string path, bool fGPO)
	{
		// If we don't do this we will get the error code (0x000000B7) or 183 is for when the file already exists in the selected path.
		if (File.Exists(path))
			File.Delete(path);

		Logger.Write($"Exporting firewall policy to: {path}");

		// wszMachineOrGPO = null for local machine
		uint result = NativeMethods.FWExportPolicy(
			wszMachineOrGPO: null,
			fGPO: fGPO,
			wszFilePath: path,
			fSomeInfoLost: out bool someInfoLost);

		if (result == 0)
		{
			Logger.Write("Firewall policy exported successfully.");

			if (someInfoLost)
			{
				Logger.Write("Warning: Some information was lost during export.");
			}
		}
		else
		{
			throw new InvalidOperationException($"Failed to export firewall policy. Error code: {result} (0x{result:X8})");
		}
	}

	/// <summary>
	/// Imports the Firewall rules from a ".wfw" file.
	/// </summary>
	/// <param name="path">The location where the file will be read from.</param>
	/// <param name="fGPO">If true, will only import the rules defined for the GPO store.
	/// If false, will only import the rules defined for the Local Windows Defender Firewall settings.</param>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void ImportFirewallPolicy(string path, bool fGPO)
	{
		if (!File.Exists(path))
		{
			throw new FileNotFoundException($"Firewall policy file not found: {path}");
		}

		Logger.Write($"Importing firewall policy from: {path}");

		// wszMachineOrGPO = null for local machine
		uint result = NativeMethods.FWImportPolicy(
			wszMachineOrGPO: null,
			fGPO: fGPO,
			wszFilePath: path,
			fSomeInfoLost: out bool someInfoLost);

		if (result == 0)
		{
			Logger.Write("Firewall policy imported successfully.");

			if (someInfoLost)
			{
				Logger.Write("Warning: Some information was lost during import.");
			}
		}
		else
		{
			throw new InvalidOperationException($"Failed to import firewall policy. Error code: {result} (0x{result:X8})");
		}
	}

	/// <summary>
	/// Deletes all firewall rules from the specified store.
	/// </summary>
	/// <param name="store">The Firewall store to delete rules from.</param>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void DeleteAllFirewallRules(FW_STORE_TYPE store)
	{
		Logger.Write($"Deleting all firewall rules from {store} store...");

		// wszMachineOrGPO = null for local machine
		uint result = NativeMethods.FWOpenPolicyStore(
			wBinaryVersion: FW_BINARY_VERSION,
			wszMachineOrGPO: null,
			StoreType: store,
			AccessRight: FW_POLICY_ACCESS_RIGHT.READ_WRITE,
			dwFlags: FW_POLICY_STORE_FLAGS.NONE,
			phPolicy: out nint policyHandle);

		if (result != 0)
		{
			throw new InvalidOperationException($"Failed to open policy store. Error code: {result} (0x{result:X8})");
		}

		try
		{
			// Delete all firewall rules from the selected policy store
			result = NativeMethods.FWDeleteAllFirewallRules(policyHandle);

			if (result == 0)
			{
				Logger.Write("All firewall rules deleted successfully.");
			}
			else
			{
				throw new InvalidOperationException($"Failed to delete firewall rules. Error code: {result} (0x{result:X8})");
			}
		}
		finally
		{
			// Always close the policy store handle
			uint closeResult = NativeMethods.FWClosePolicyStore(policyHandle);
			if (closeResult != 0)
			{
				Logger.Write($"Warning: Failed to close policy store. Error code: {closeResult} (0x{closeResult:X8})");
			}
		}
	}

	internal static void RestoreDefaultFirewallPolicy()
	{
		Logger.Write("Restoring default firewall policy...");

		// Restore default firewall policy for the local machine
		// wszMachineOrGPO = null for local machine
		uint result = NativeMethods.FWRestoreDefaults(wszMachineOrGPO: null);

		if (result == 0)
		{
			Logger.Write("Firewall defaults restored successfully.");
		}
		else
		{
			throw new InvalidOperationException($"Failed to restore firewall defaults. Error code: {result} (0x{result:X8})");
		}
	}
}
