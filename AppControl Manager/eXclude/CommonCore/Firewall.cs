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
using System.IO;
using System.Runtime.InteropServices;

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

internal static class FirewallWmiHelper
{
	/// <summary>
	/// Retrieves a dictionary mapping Firewall Rule IDs (InstanceID/Name) to their Display Names.
	/// Extracts records from both the standard local store (aka Persistent Store) and the Group Policy 'localhost' store.
	/// </summary>
	/// <returns>Dictionary with Rule IDs as keys and DisplayNames as values.</returns>
	internal static Dictionary<string, string> GetFirewallRulesMapping()
	{
		Dictionary<string, string> mappings = new(StringComparer.OrdinalIgnoreCase);

		Guid CLSID_WbemLocator = new("4590F811-1D3A-11D0-891F-00AA004B2E24");
		Guid IID_IWbemLocator = new("DC12A687-737F-11CF-884D-00AA004B2E24");
		Guid CLSID_WbemContext = new("674B6698-EE92-11D0-AD71-00C04FD8FDFF");
		Guid IID_IWbemContext = new("44aca674-e8fc-11d0-a07c-00c04fb68820");

		uint CLSCTX_INPROC_SERVER = 1;
		uint RPC_C_AUTHN_WINNT = 10;
		uint RPC_C_AUTHZ_NONE = 0;
		uint RPC_C_AUTHN_LEVEL_CALL = 3;
		uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
		int WBEM_FLAG_FORWARD_ONLY = 0x20;
		int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
		int WBEM_INFINITE = -1;

		// 1. Create Locator
		int hr = NativeMethods.CoCreateInstanceWbemLocator(
			in CLSID_WbemLocator,
			IntPtr.Zero,
			CLSCTX_INPROC_SERVER,
			in IID_IWbemLocator,
			out IWbemLocator? locator);

		if (hr < 0 || locator is null)
		{
			return mappings;
		}

		// 2. Connect to the StandardCimv2 namespace
		hr = locator.ConnectServer(
			"root\\StandardCimv2",
			IntPtr.Zero,
			IntPtr.Zero,
			IntPtr.Zero,
			0,
			IntPtr.Zero,
			IntPtr.Zero,
			out IWbemServices? services);

		if (hr < 0 || services is null)
		{
			return mappings;
		}

		// 3. Set Proxy Blanket
		hr = NativeMethods.CoSetProxyBlanket(
			services,
			RPC_C_AUTHN_WINNT,
			RPC_C_AUTHZ_NONE,
			IntPtr.Zero,
			RPC_C_AUTHN_LEVEL_CALL,
			RPC_C_IMP_LEVEL_IMPERSONATE,
			IntPtr.Zero,
			0);

		if (hr < 0)
		{
			return mappings;
		}

		// Centralized fetching logic
		void FetchRules(IWbemContext? context)
		{
			int queryHr = services.ExecQuery(
				"WQL",
				"SELECT InstanceID, ElementName, DisplayName FROM MSFT_NetFirewallRule",
				WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
				context,
				out IEnumWbemClassObject? enumerator);

			if (queryHr < 0 || enumerator is null)
			{
				return;
			}

			while (true)
			{
				queryHr = enumerator.Next(WBEM_INFINITE, 1, out IWbemClassObject? obj, out uint returned);

				if (queryHr != 0 || returned == 0 || obj is null)
				{
					break;
				}

				// A. Read InstanceID (Rule Name mapped in Event Viewer Origin)
				string? name = null;
				queryHr = obj.Get("InstanceID", 0, out VARIANT valName, IntPtr.Zero, IntPtr.Zero);
				if (queryHr == 0 && valName.vt == 8 && valName.bstrVal != IntPtr.Zero) // 8 == VT_BSTR
				{
					name = Marshal.PtrToStringBSTR(valName.bstrVal);
				}
				_ = NativeMethods.VariantClear(ref valName);

				// B. Read DisplayName 
				string? displayName = null;
				queryHr = obj.Get("DisplayName", 0, out VARIANT valDisplay, IntPtr.Zero, IntPtr.Zero);
				if (queryHr == 0 && valDisplay.vt == 8 && valDisplay.bstrVal != IntPtr.Zero) // 8 == VT_BSTR
				{
					displayName = Marshal.PtrToStringBSTR(valDisplay.bstrVal);
				}
				_ = NativeMethods.VariantClear(ref valDisplay);

				// C. Safely Fallback to ElementName 
				if (string.IsNullOrWhiteSpace(displayName))
				{
					queryHr = obj.Get("ElementName", 0, out VARIANT valElement, IntPtr.Zero, IntPtr.Zero);
					if (queryHr == 0 && valElement.vt == 8 && valElement.bstrVal != IntPtr.Zero) // 8 == VT_BSTR
					{
						displayName = Marshal.PtrToStringBSTR(valElement.bstrVal);
					}
					_ = NativeMethods.VariantClear(ref valElement);
				}

				// Feed to mappings correlation dict
				if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(displayName))
				{
					mappings[name] = displayName;
				}
			}
		}

		// Loop 1 equivalent: Local Firewall rules (Default context)
		FetchRules(null);

		// Loop 2 equivalent: Local Group Policy Firewall rules
		hr = NativeMethods.CoCreateInstanceWbemContext(
			in CLSID_WbemContext,
			IntPtr.Zero,
			CLSCTX_INPROC_SERVER,
			in IID_IWbemContext,
			out IWbemContext? context);

		if (hr >= 0 && context is not null)
		{
			// Assign the WMI context to fetch only from 'localhost' Policy Store
			VARIANT storeVal = new()
			{
				vt = 8, // VT_BSTR
				bstrVal = Marshal.StringToBSTR("localhost")
			};

			_ = context.SetValue("PolicyStore", 0, in storeVal);
			_ = NativeMethods.VariantClear(ref storeVal);

			FetchRules(context);
		}

		return mappings;
	}
}
