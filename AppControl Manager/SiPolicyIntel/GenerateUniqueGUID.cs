using System;
using System.Collections.Generic;

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// This classes generates latest version of GUIDs
/// </summary>
internal static class GUIDGenerator
{
	internal static string GenerateUniqueGUID()
	{
		return Guid.CreateVersion7().ToString("N") + Guid.CreateVersion7().ToString("N");
	}

	internal static string GenerateUniqueGUIDToUpper()
	{
		return Guid.CreateVersion7().ToString("N").ToUpperInvariant() + Guid.CreateVersion7().ToString("N").ToUpperInvariant();
	}

	internal static List<string> GenerateUniqueGUID(int genCount)
	{

		List<string> result = [];

		for (int i = 0; i < genCount; i++)
		{
			// Generate two version 7 GUIDs, concatenate them, and add to the result list
			result.Add(Guid.CreateVersion7().ToString("N") + Guid.CreateVersion7().ToString("N"));
		}

		return result;
	}

	internal static List<string> GenerateUniqueGUIDToUpper(int genCount)
	{

		List<string> result = [];

		for (int i = 0; i < genCount; i++)
		{
			// Generate two version 7 GUIDs, concatenate them, and add to the result list
			result.Add(Guid.CreateVersion7().ToString("N").ToUpperInvariant() + Guid.CreateVersion7().ToString("N").ToUpperInvariant());
		}

		return result;
	}
}
