using System;
using System.Collections.Generic;
using System.Linq;
using AppControlManager.SiPolicy;

namespace AppControlManager.Others;

internal static class XmlFilePathExtractor
{
	internal static HashSet<string> GetFilePaths(string xmlFilePath)
	{
		// Initialize HashSet with StringComparer.OrdinalIgnoreCase to ensure case-insensitive, ordinal comparison
		HashSet<string> filePaths = new(StringComparer.OrdinalIgnoreCase);

		// Instantiate the policy
		SiPolicy.SiPolicy policyObj = Management.Initialize(xmlFilePath, null);

		// Select all Allow FileRules
		IEnumerable<Allow>? allowRules = policyObj.FileRules?.OfType<Allow>();

		if (allowRules is not null)
		{
			foreach (Allow item in allowRules)
			{
				if (!string.IsNullOrEmpty(item.FilePath))
				{
					// Add the file path to the HashSet
					_ = filePaths.Add(item.FilePath);
				}
			}
		}
		return filePaths;
	}
}
