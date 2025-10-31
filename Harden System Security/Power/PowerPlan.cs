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

namespace HardenSystemSecurity.Power;

internal static class PowerPlan
{

	/// <summary>
	/// Built-in "Ultimate Performance" scheme GUID.
	/// </summary>
	private static readonly Guid UltimateBaseSchemeGuid = new("E9A42B02-D5DF-448D-AA00-03F14749EB61");

	/// <summary>
	/// Built-in "Balanced" scheme GUID.
	/// Used as a safe fallback when switching away from an active Ultimate plan.
	/// </summary>
	private static readonly Guid BalancedSchemeGuid = new("381B4222-F694-41F0-9685-FF5BB260DF2E");

	// Constants from WinError.h
	// https://learn.microsoft.com/windows/win32/debug/system-error-codes--0-499-
	private const uint ERROR_SUCCESS = 0;
	private const uint ERROR_MORE_DATA = 234;
	private const uint ERROR_NO_MORE_ITEMS = 259;

	/// <summary>
	/// POWER_DATA_ACCESSOR for PowerEnumerate.
	/// Enumerate top-level schemes.
	/// https://learn.microsoft.com/windows/win32/api/powrprof/nf-powrprof-powerenumerate
	/// </summary>
	private const uint ACCESS_SCHEME = 16;

	private static bool TryFindExistingUltimate(out Guid schemeGuid)
	{
		schemeGuid = Guid.Empty;

		// First, check if a scheme with the exact built-in Ultimate GUID is present
		List<Guid> schemes = EnumerateAllSchemes();
		for (int i = 0; i < schemes.Count; i++)
		{
			if (schemes[i] == UltimateBaseSchemeGuid)
			{
				schemeGuid = schemes[i];
				return true;
			}
		}

		// Otherwise, try to find a scheme whose friendly name is "Ultimate Performance"
		for (int i = 0; i < schemes.Count; i++)
		{
			string name = ReadSchemeFriendlyName(schemes[i], out uint rcName);
			if (rcName != ERROR_SUCCESS)
			{
				continue;
			}

			if (string.Equals(name, "Ultimate Performance", StringComparison.OrdinalIgnoreCase))
			{
				schemeGuid = schemes[i];
				return true;
			}
		}

		return false;
	}

	private static unsafe void TryDuplicateUltimate(out Guid newSchemeGuid)
	{
		newSchemeGuid = Guid.Empty;

		IntPtr destGuidPtr = IntPtr.Zero;

		// Copying the static readonly Guid into a local before passing by ref.
		Guid sourceSchemeGuid = UltimateBaseSchemeGuid;
		uint rc = NativeMethods.PowerDuplicateScheme(IntPtr.Zero, ref sourceSchemeGuid, out destGuidPtr);
		if (rc != ERROR_SUCCESS)
		{
			throw new InvalidOperationException($"PowerDuplicateScheme failed: {rc}");
		}

		try
		{
			if (destGuidPtr == IntPtr.Zero)
			{
				throw new InvalidOperationException("PowerDuplicateScheme returned a null GUID pointer.");
			}

			Guid duplicated = *(Guid*)destGuidPtr;
			newSchemeGuid = duplicated;
		}
		finally
		{
			if (destGuidPtr != IntPtr.Zero)
			{
				_ = NativeMethods.LocalFree(destGuidPtr);
			}
		}
	}

	private static bool TrySetActiveScheme(Guid schemeGuid)
	{
		uint rc = NativeMethods.PowerSetActiveScheme(IntPtr.Zero, ref schemeGuid);
		if (rc == ERROR_SUCCESS)
		{
			return true;
		}

		Logger.Write($"PowerSetActiveScheme failed: {rc}");
		return false;
	}

	private static unsafe bool TryGetActiveScheme(out Guid activeScheme)
	{
		activeScheme = Guid.Empty;

		IntPtr guidPtr = IntPtr.Zero;
		uint rc = NativeMethods.PowerGetActiveScheme(IntPtr.Zero, out guidPtr);
		if (rc != ERROR_SUCCESS)
		{
			Logger.Write($"PowerGetActiveScheme failed: {rc}");
			return false;
		}

		try
		{
			if (guidPtr == IntPtr.Zero)
			{
				Logger.Write("PowerGetActiveScheme returned a null GUID pointer.");
				return false;
			}

			Guid guid = *(Guid*)guidPtr;
			activeScheme = guid;
			return true;
		}
		finally
		{
			if (guidPtr != IntPtr.Zero)
			{
				_ = NativeMethods.LocalFree(guidPtr);
			}
		}
	}

	private static unsafe List<Guid> EnumerateAllSchemes()
	{
		List<Guid> result = new(8);
		uint index = 0;

		uint guidSize = (uint)sizeof(Guid);
		IntPtr buffer = Marshal.AllocHGlobal((int)guidSize);

		try
		{
			while (true)
			{
				uint currentSize = guidSize;
				uint rc = NativeMethods.PowerEnumerate(
					IntPtr.Zero,
					IntPtr.Zero,
					IntPtr.Zero,
					ACCESS_SCHEME,
					index,
					buffer,
					ref currentSize);

				if (rc == ERROR_NO_MORE_ITEMS)
				{
					break;
				}

				if (rc != ERROR_SUCCESS)
				{
					throw new InvalidOperationException("PowerEnumerate failed with Win32 error " + rc + " at index " + index);
				}

				Guid guid = *(Guid*)buffer;
				result.Add(guid);
				index++;
			}
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}

		return result;
	}

	private static string ReadSchemeFriendlyName(Guid schemeGuid, out uint win32Error)
	{
		win32Error = 0;

		// First call to get required size (in bytes)
		uint sizeBytes = 0;
		uint rc = NativeMethods.PowerReadFriendlyName(
			IntPtr.Zero,
			ref schemeGuid,
			IntPtr.Zero,
			IntPtr.Zero,
			IntPtr.Zero,
			ref sizeBytes);

		if (rc != ERROR_MORE_DATA && rc != ERROR_SUCCESS)
		{
			win32Error = rc;
			return string.Empty;
		}

		if (sizeBytes == 0)
		{
			return string.Empty;
		}

		IntPtr buffer = Marshal.AllocHGlobal((int)sizeBytes);
		try
		{
			rc = NativeMethods.PowerReadFriendlyName(
				IntPtr.Zero,
				ref schemeGuid,
				IntPtr.Zero,
				IntPtr.Zero,
				buffer,
				ref sizeBytes);

			if (rc != ERROR_SUCCESS)
			{
				win32Error = rc;
				return string.Empty;
			}

			return Marshal.PtrToStringUni(buffer) ?? string.Empty;
		}
		finally
		{
			Marshal.FreeHGlobal(buffer);
		}
	}

	/// <summary>
	/// Deletes the specified power plan (scheme) by GUID.
	/// </summary>
	private static void TryDeleteScheme(Guid schemeGuid)
	{
		uint rc = NativeMethods.PowerDeleteScheme(IntPtr.Zero, ref schemeGuid);
		if (rc == ERROR_SUCCESS)
		{
			Logger.Write("Deleted scheme: " + schemeGuid);
			return;
		}

		throw new InvalidOperationException($"PowerDeleteScheme failed to delete scheme: {schemeGuid} - Error: {rc}");
	}

	/// <summary>
	/// Enable or create-and-enable the Ultimate Performance plan.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void EnableUltimateScheme()
	{
		Logger.Write("Enabling Ultimate Performance power plan");

		bool foundExisting = TryFindExistingUltimate(out Guid targetSchemeGuid);
		if (!foundExisting)
		{
			Logger.Write("Existing 'Ultimate Performance' plan not found. Attempting to duplicate the built-in Ultimate scheme...");

			TryDuplicateUltimate(out targetSchemeGuid);

			Logger.Write("Successfully created a new Ultimate Performance plan with GUID: " + targetSchemeGuid);
		}
		else
		{
			Logger.Write("Found an existing Ultimate Performance plan with GUID: " + targetSchemeGuid);
		}

		bool setOk = TrySetActiveScheme(targetSchemeGuid);
		if (!setOk)
		{
			throw new InvalidOperationException("Failed to set the plan active");
		}

		bool gotActive = TryGetActiveScheme(out Guid activeGuid);
		if (!gotActive)
		{
			throw new InvalidOperationException("Failed to verify active plan");
		}

		if (activeGuid == targetSchemeGuid)
		{
			Logger.Write("Success. Ultimate Performance plan is now active.");
			return;
		}

		throw new InvalidOperationException("Unexpected: Active plan GUID does not match target. Active: " + activeGuid + " Target: " + targetSchemeGuid);
	}

	/// <summary>
	/// Enumerate and print all schemes, with names and GUIDs.
	/// </summary>
	internal static void ListAllSchemes()
	{
		Logger.Write("Enumerating all power plans...");

		bool gotActive = TryGetActiveScheme(out _);
		if (!gotActive)
		{
			Logger.Write("Could not get active scheme", LogTypeIntel.Warning);
		}

		List<Guid> schemes = EnumerateAllSchemes();

		int printed = 0;
		for (int i = 0; i < schemes.Count; i++)
		{
			Guid guid = schemes[i];

			string name = ReadSchemeFriendlyName(guid, out uint rcName);
			if (rcName != 0)
			{
				name = string.Empty;
			}
			if (string.IsNullOrEmpty(name))
			{
				name = "(no friendly name)";
			}

			// Minimal "details": tag known built-in templates when recognizable.
			string tag = string.Empty;
			if (guid == UltimateBaseSchemeGuid)
			{
				tag = "Ultimate (base template)";
			}
			else if (guid == BalancedSchemeGuid)
			{
				tag = "Balanced (built-in)";
			}

			if (tag.Length > 0)
			{
				Logger.Write("- " + name + "  [" + guid + "]  {" + tag + "}");
			}
			else
			{
				Logger.Write("- " + name + "  [" + guid + "]");
			}

			printed++;
		}

		Logger.Write("Listed " + printed + " scheme(s).");
		Logger.Write("Note: Any GUID shown above can be used as the source for duplication with PowerDuplicateScheme.");
	}

	/// <summary>
	/// Delete all Ultimate Performance schemes. If any target is active, switch to a safe plan first.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	internal static void DeleteUltimateSchemes()
	{
		Logger.Write("Deleting all 'Ultimate Performance' power plans...");

		// Gather all schemes that match Ultimate by name or by base GUID.
		List<Guid> allSchemes = EnumerateAllSchemes();
		List<Guid> targets = new(4);

		for (int i = 0; i < allSchemes.Count; i++)
		{
			Guid guid = allSchemes[i];
			if (guid == UltimateBaseSchemeGuid)
			{
				targets.Add(guid);
				continue;
			}

			string name = ReadSchemeFriendlyName(guid, out uint rcName);
			if (rcName == 0 && string.Equals(name, "Ultimate Performance", StringComparison.OrdinalIgnoreCase))
			{
				targets.Add(guid);
			}
		}

		if (targets.Count == 0)
		{
			Logger.Write("No 'Ultimate Performance' schemes found to delete.");
			return;
		}

		// If the active scheme is among targets, switch to a safe alternative first.
		bool gotActive = TryGetActiveScheme(out Guid activeGuid);
		if (!gotActive)
		{
			Logger.Write("Could not determine active scheme before deletion", LogTypeIntel.Warning);
			activeGuid = Guid.Empty;
		}

		bool activeIsTarget = false;
		if (gotActive)
		{
			for (int i = 0; i < targets.Count; i++)
			{
				if (targets[i] == activeGuid)
				{
					activeIsTarget = true;
					break;
				}
			}
		}

		if (activeIsTarget)
		{
			Logger.Write("Active scheme is an Ultimate plan. Switching to a safe scheme before deletion...");

			// Prefer Balanced. If setting Balanced fails, fall back to the first non-target scheme.
			bool switched = false;

			// Try Balanced first.
			bool setOk = TrySetActiveScheme(BalancedSchemeGuid);
			if (setOk)
			{
				switched = true;
			}
			else
			{
				// Fall back to the first non-target scheme we can find.
				for (int i = 0; i < allSchemes.Count; i++)
				{
					Guid candidate = allSchemes[i];

					bool candidateIsTarget = false;
					for (int j = 0; j < targets.Count; j++)
					{
						if (candidate == targets[j])
						{
							candidateIsTarget = true;
							break;
						}
					}
					if (candidateIsTarget)
					{
						continue;
					}

					bool setOk2 = TrySetActiveScheme(candidate);
					if (setOk2)
					{
						switched = true;
						break;
					}
				}
			}

			if (!switched)
			{
				throw new InvalidOperationException("Failed to switch away from the active Ultimate scheme. Aborting deletion.");
			}
		}

		// Proceed to delete targets.
		for (int i = 0; i < targets.Count; i++)
		{
			Guid toDelete = targets[i];
			TryDeleteScheme(toDelete);
		}
	}
}
