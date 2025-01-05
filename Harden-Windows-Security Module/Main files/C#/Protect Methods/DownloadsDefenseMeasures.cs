using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Xml;

namespace HardenWindowsSecurity;

public static partial class DownloadsDefenseMeasures
{

	// GUID for the Downloads folder
	private static Guid FolderDownloads = new("374DE290-123F-4565-9164-39C4925E467B");


	/// <summary>
	/// Prevents executables originating from the Downloads folder from running, using AppControl policy
	/// </summary>
	public static void Invoke()
	{
		ChangePSConsoleTitle.Set("🎇 Downloads Defense Measures");

		Logger.LogMessage("Running the Downloads Defense Measures category", LogTypeIntel.Information);

		string CIPPath = Path.Combine(GlobalVars.WorkingDir, "Downloads-Defense-Measures.cip");
		string XMLPath = Path.Combine(GlobalVars.path, "Resources", "Downloads-Defense-Measures.xml");

		// The path to use to save the modified XML policy file and deploy it
		string XMLPathToDeploy = Path.Combine(GlobalVars.WorkingDir, "Downloads-Defense-Measures.xml");

		// Run the CiTool and retrieve a list of base policies
		List<CiPolicyInfo> policies = CiToolHelper.GetPolicies(SystemPolicies: false, BasePolicies: true, SupplementalPolicies: false);

		bool isFound = false;

		// loop over all policies
		foreach (CiPolicyInfo item in policies)
		{
			// find the policy with the right name
			if (string.Equals(item.FriendlyName, "Downloads-Defense-Measures", StringComparison.OrdinalIgnoreCase))
			{
				isFound = true;
				break;
			}
		}

		// If the Downloads-Defense-Measures is not deployed
		if (!isFound)
		{

			IntPtr pathPtr = IntPtr.Zero;

			string? downloadsPath = null;

			try
			{
				// Get the System Downloads folder path
				int result = NativeMethods.SHGetKnownFolderPath(ref FolderDownloads, 0, IntPtr.Zero, out pathPtr);

				if (result is 0) // S_OK
				{
					downloadsPath = Marshal.PtrToStringUni(pathPtr);

					if (string.IsNullOrWhiteSpace(downloadsPath))
					{
						Logger.LogMessage("The downloads folder path was empty, exiting.", LogTypeIntel.Error);
						return;
					}

					Logger.LogMessage($"Downloads folder path: {downloadsPath}", LogTypeIntel.Information);
				}
				else
				{
					Logger.LogMessage("Failed to retrieve Downloads folder path.", LogTypeIntel.Error);
					return;
				}
			}
			finally
			{
				if (pathPtr != IntPtr.Zero)
				{
					Marshal.FreeCoTaskMem(pathPtr); // Free memory allocated by SHGetKnownFolderPath
				}
			}

			string pathToUse = downloadsPath + @"\" + '*';

			XmlDocument doc = new();
			doc.Load(XMLPath);

			XmlNamespaceManager nsmgr = new(doc.NameTable);
			nsmgr.AddNamespace("sip", "urn:schemas-microsoft-com:sipolicy");

			// Find all 'FileRules/Allow' or 'FileRules/Deny' elements
			XmlNodeList fileRules = doc.SelectNodes("//sip:FileRules/*[@FilePath]", nsmgr)!;

			foreach (XmlNode node in fileRules)
			{
				XmlAttribute filePathAttr = node.Attributes!["FilePath"]!;
				if (string.Equals(filePathAttr.Value, "To-Be-Detected", StringComparison.OrdinalIgnoreCase))
				{
					filePathAttr.Value = pathToUse;
				}
			}

			// Save the modified XML to the working directory so we don't modify the module's files
			doc.Save(XMLPathToDeploy);

			PolicyToCIPConverter.Convert(XMLPathToDeploy, CIPPath);
			CiToolHelper.UpdatePolicy(CIPPath);
		}
		else
		{
			Logger.LogMessage("The Downloads-Defense-Measures policy is already deployed", LogTypeIntel.Information);
		}

	}
}
