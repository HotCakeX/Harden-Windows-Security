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

using System.Buffers.Binary;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Threading;

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

		// This Windows bug only affects GPO exports. Local firewall exports never use the workaround.
		// https://github.com/HotCakeX/Harden-Windows-Security/issues/1259
		if (fGPO && result == 5)
		{
			Logger.Write("GPO firewall export returned ERROR_ACCESS_DENIED. Retrying with the temporary in-process workaround.");
			result = FirewallExportWorkaround.Export(path, out someInfoLost);
		}

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

		const uint CLSCTX_INPROC_SERVER = 1;
		const uint RPC_C_AUTHN_WINNT = 10;
		const uint RPC_C_AUTHZ_NONE = 0;
		const uint RPC_C_AUTHN_LEVEL_CALL = 3;
		const uint RPC_C_IMP_LEVEL_IMPERSONATE = 3;
		const int WBEM_FLAG_FORWARD_ONLY = 0x20;
		const int WBEM_FLAG_RETURN_IMMEDIATELY = 0x10;
		const int WBEM_INFINITE = -1;

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

/// <summary>
/// https://github.com/HotCakeX/Harden-Windows-Security/issues/1259
/// This entire class can be removed once the bug is fixed in the Windows.
/// This workaround works for ARM64 and X64.
/// Affected builds: 25H2 and 26H2 builds (26320.9877 insider beta - 26300.9974 stable)
/// </summary>
internal static class FirewallExportWorkaround
{
	private const uint PAGE_EXECUTE_READWRITE = 0x40;
	private const uint IMAGE_SCN_MEM_EXECUTE = 0x20000000;
	private const ushort IMAGE_DOS_SIGNATURE = 0x5A4D;
	private const uint IMAGE_NT_SIGNATURE = 0x00004550;
	private static readonly Lock ExportLock = new();
	private static ReadOnlySpan<byte> X64ExpectedBytes => [0xBB, 0x05, 0x00, 0x07, 0x80];
	private static ReadOnlySpan<byte> X64PatchedBytes => [0xBB, 0x02, 0x00, 0x07, 0x80];
	private static ReadOnlySpan<byte> Arm64ExpectedBytes => [0x05, 0x00, 0x07, 0x80];
	private static ReadOnlySpan<byte> Arm64PatchedBytes => [0x02, 0x00, 0x07, 0x80];

	internal static uint Export(string path, out bool someInfoLost)
	{
		lock (ExportLock)
		{
			string modulePath = Path.Join(Environment.GetFolderPath(Environment.SpecialFolder.System), "FWPolicyIOMgr.dll");
			nint module = NativeLibrary.Load(modulePath);
			try
			{
				if (!TryLocatePatch(module, path, out PatchSite patchSite, out bool exportCompleted, out someInfoLost, out string error))
				{
					throw new InvalidOperationException($"The GPO firewall export workaround could not be safely applied. {error}");
				}

				// Behavioral validation is the requested export on both supported architectures. Calling
				// FWExportPolicy again would return ERROR_ALREADY_EXISTS because the destination now exists.
				if (exportCompleted)
				{
					Logger.Write($"The GPO firewall export succeeded with the temporary workaround at FWPolicyIOMgr.dll+0x{patchSite.Rva:X}.");
					return 0;
				}

				Logger.Write($"Temporarily applying the GPO firewall export workaround at FWPolicyIOMgr.dll+0x{patchSite.Rva:X}.");
				ApplyPatch(patchSite.Address, patchSite.PatchedBytes.Span);
				try
				{
					return NativeMethods.FWExportPolicy(null, true, path, out someInfoLost);
				}
				finally
				{
					ApplyPatch(patchSite.Address, patchSite.ExpectedBytes.Span);
					Logger.Write("Restored the original FWPolicyIOMgr.dll bytes after the GPO firewall export attempt.");
				}
			}
			finally
			{
				NativeLibrary.Free(module);
			}
		}
	}

	private static bool TryLocatePatch(
		nint module,
		string exportPath,
		out PatchSite patchSite,
		out bool exportCompleted,
		out bool someInfoLost,
		out string error)
	{
		Architecture architecture = RuntimeInformation.ProcessArchitecture;
		if (architecture == Architecture.X64)
		{
			return TryLocatePatchByBehavior(
				module,
				exportPath,
				X64ExpectedBytes,
				X64PatchedBytes,
				requireFourByteAlignment: false,
				architectureName: "X64",
				out patchSite,
				out exportCompleted,
				out someInfoLost,
				out error);
		}

		return TryLocatePatchByBehavior(
			module,
			exportPath,
			Arm64ExpectedBytes,
			Arm64PatchedBytes,
			requireFourByteAlignment: true,
			architectureName: "ARM64",
			out patchSite,
			out exportCompleted,
			out someInfoLost,
			out error);
	}

	private static bool TryLocatePatchByBehavior(
		nint module,
		string exportPath,
		ReadOnlySpan<byte> expectedBytes,
		ReadOnlySpan<byte> patchedBytes,
		bool requireFourByteAlignment,
		string architectureName,
		out PatchSite patchSite,
		out bool exportCompleted,
		out bool someInfoLost,
		out string error)
	{
		exportCompleted = false;
		someInfoLost = false;

		List<nint> candidates = FindExecutableMatches(module, expectedBytes, requireFourByteAlignment);
		if (candidates.Count == 0)
		{
			patchSite = default;
			error = $"No {architectureName} ERROR_ACCESS_DENIED instruction signature was found in an executable section.";
			return false;
		}

		foreach (nint candidate in candidates)
		{
			// Behavioral validation is also the actual export. Stop at the first successful candidate.
			ApplyPatch(candidate, patchedBytes);
			uint result;
			bool candidateInfoLost;
			try
			{
				result = NativeMethods.FWExportPolicy(null, true, exportPath, out candidateInfoLost);
			}
			finally
			{
				ApplyPatch(candidate, expectedBytes);
			}

			if (result == 0)
			{
				patchSite = new(candidate, unchecked((nuint)(candidate - module)), expectedBytes.ToArray(), patchedBytes.ToArray());
				exportCompleted = true;
				someInfoLost = candidateInfoLost;
				error = string.Empty;
				return true;
			}
		}

		patchSite = default;
		error = $"None of the {candidates.Count} {architectureName} candidates corrected the GPO export failure.";
		return false;
	}

	private static List<nint> FindExecutableMatches(nint module, ReadOnlySpan<byte> pattern, bool requireFourByteAlignment)
	{
		ReadOnlySpan<byte> dosHeader = new((void*)module, 0x40);
		if (BinaryPrimitives.ReadUInt16LittleEndian(dosHeader) != IMAGE_DOS_SIGNATURE)
		{
			return [];
		}

		int peOffset = BinaryPrimitives.ReadInt32LittleEndian(dosHeader[0x3C..]);
		if (peOffset < 0)
		{
			return [];
		}

		nint ntHeaders = module + peOffset;
		ReadOnlySpan<byte> ntPrefix = new((void*)ntHeaders, 24);
		if (BinaryPrimitives.ReadUInt32LittleEndian(ntPrefix) != IMAGE_NT_SIGNATURE)
		{
			return [];
		}

		ushort sectionCount = BinaryPrimitives.ReadUInt16LittleEndian(ntPrefix[6..]);
		ushort optionalHeaderSize = BinaryPrimitives.ReadUInt16LittleEndian(ntPrefix[20..]);
		nint sectionTable = ntHeaders + 24 + optionalHeaderSize;
		List<nint> matches = new(8);
		for (int sectionIndex = 0; sectionIndex < sectionCount; sectionIndex++)
		{
			ReadOnlySpan<byte> sectionHeader = new((void*)(sectionTable + (sectionIndex * 40)), 40);
			uint virtualSize = BinaryPrimitives.ReadUInt32LittleEndian(sectionHeader[8..]);
			uint virtualAddress = BinaryPrimitives.ReadUInt32LittleEndian(sectionHeader[12..]);
			uint characteristics = BinaryPrimitives.ReadUInt32LittleEndian(sectionHeader[36..]);
			if ((characteristics & IMAGE_SCN_MEM_EXECUTE) == 0 || virtualSize < pattern.Length || virtualSize > int.MaxValue)
			{
				continue;
			}

			nint sectionAddress = module + unchecked((int)virtualAddress);
			ReadOnlySpan<byte> section = new((void*)sectionAddress, (int)virtualSize);
			int offset = 0;
			while (offset <= section.Length - pattern.Length)
			{
				int relativeIndex = section[offset..].IndexOf(pattern);
				if (relativeIndex < 0)
				{
					break;
				}

				int matchOffset = offset + relativeIndex;
				if (!requireFourByteAlignment || (matchOffset & 3) == 0)
				{
					matches.Add(sectionAddress + matchOffset);
				}
				offset = matchOffset + 1;
			}
		}

		return matches;
	}

	private static void ApplyPatch(nint address, ReadOnlySpan<byte> bytes)
	{
		if (!NativeMethods.VirtualProtect(address, (nuint)bytes.Length, PAGE_EXECUTE_READWRITE, out uint oldProtection))
		{
			throw new Win32Exception(Marshal.GetLastPInvokeError(), "VirtualProtect failed.");
		}

		try
		{
			unsafe
			{
				bytes.CopyTo(new Span<byte>((void*)address, bytes.Length));
			}

			if (!NativeMethods.FlushInstructionCache(NativeMethods.GetCurrentProcess(), address, (nuint)bytes.Length))
			{
				throw new Win32Exception(Marshal.GetLastPInvokeError(), "FlushInstructionCache failed.");
			}
		}
		finally
		{
			if (!NativeMethods.VirtualProtect(address, (nuint)bytes.Length, oldProtection, out uint _))
			{
				Logger.Write($"{Marshal.GetLastPInvokeError()} - Failed to restore page protection.");
			}
		}
	}

	private readonly record struct PatchSite(nint Address, nuint Rva, ReadOnlyMemory<byte> ExpectedBytes, ReadOnlyMemory<byte> PatchedBytes);
}
