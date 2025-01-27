using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Management;

namespace HardenWindowsSecurity;

/// <summary>
/// Class to handle Controlled Folder Access allowed applications
/// Mostly for adding some system executables or Pwh.exe to the list during the module's operation
/// </summary>
public static class ControlledFolderAccessHandler
{
	// To track if the Reset() method has been run
	private static bool HasResetHappenedBefore;

	// To track if the Start() method has been run
	private static bool HasBackupHappenedBefore;

	// To track each component so we don't try to add it again in the same session
	private static bool PowerCfgAdded;
	private static bool PowerShellAdded;

	/// <summary>
	/// Set the Controlled Folder Access allowed applications
	/// needs arrays
	/// </summary>
	/// <param name="applications"></param>
	private static void Set(string[] applications)
	{
		using ManagementClass managementClass = new(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

		ManagementBaseObject inParams = managementClass.GetMethodParameters("Set");
		inParams["ControlledFolderAccessAllowedApplications"] = applications;

		_ = managementClass.InvokeMethod("Set", inParams, null);
	}

	/// <summary>
	/// Add applications to the Controlled Folder Access allowed applications list
	/// needs arrays
	/// Unlike Set method, it doesn't remove the existing applications
	/// </summary>
	/// <param name="applications"></param>
	private static void Add(string[] applications)
	{
		using ManagementClass managementClass = new(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

		ManagementBaseObject inParams = managementClass.GetMethodParameters("Add");
		inParams["ControlledFolderAccessAllowedApplications"] = applications;

		_ = managementClass.InvokeMethod("Add", inParams, null);
	}

	/// <summary>
	/// Remove applications from the Controlled Folder Access allowed applications list
	/// needs arrays
	/// </summary>
	/// <param name="applications"></param>
	private static void Remove(string[] applications)
	{
		using ManagementClass managementClass = new(@"root\Microsoft\Windows\Defender", "MSFT_MpPreference", null);

		ManagementBaseObject inParams = managementClass.GetMethodParameters("Remove");
		inParams["ControlledFolderAccessAllowedApplications"] = applications;

		_ = managementClass.InvokeMethod("Remove", inParams, null);
	}

	/// <summary>
	/// Backup the current Controlled Folder Access allowed applications list and add PowerShell executables to it
	/// plus powercfg.exe
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	public static void Start(bool PowerShell, bool PowerCFG)
	{
		// Make sure the user has Admin privileges
		if (!Environment.IsPrivilegedProcess)
		{
			return;
		}

		// If the backup hasn't already happened then perform it
		if (!HasBackupHappenedBefore)
		{
			Logger.LogMessage("Backing up the current Controlled Folder Access allowed apps list in order to restore them at the end", LogTypeIntel.Information);

			// Doing this so that when we Add and then Remove PowerShell executables in Controlled folder access exclusions
			// no user customization will be affected
			GlobalVars.CFABackup = MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications;

			// Set this to true indicating CFA exclusions backup has already happened
			HasBackupHappenedBefore = true;
		}


		// A HashSet of strings to store the paths of the files that will be added to the CFA exclusions
		HashSet<string> CFAExclusionsToBeAdded = [];

		if (PowerCFG && !PowerCfgAdded)
		{
			Logger.LogMessage("Temporarily adding the PowerCfg.exe executable to the Controlled Folder Access allowed apps list to set Hibernate type to full in BitLocker category.", LogTypeIntel.Information);

			// Add the powercfg.exe path to the CFA Exclusion list
			_ = CFAExclusionsToBeAdded.Add(Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "powercfg.exe"));

			PowerCfgAdded = true;
		}

		if (PowerShell && !PowerShellAdded)
		{
			// Get the path of the current process executable (.exe)
			string? executablePathExe = Process.GetCurrentProcess()?.MainModule?.FileName;

			// Ensure the file has a .exe extension because it could be the dll
			if (!string.IsNullOrWhiteSpace(executablePathExe) && Path.GetExtension(executablePathExe).Equals(".exe", StringComparison.OrdinalIgnoreCase))
			{
				Logger.LogMessage("Temporarily adding the currently running PowerShell executable to the Controlled Folder Access allowed apps list so the module can run without interruptions.", LogTypeIntel.Information);

				_ = CFAExclusionsToBeAdded.Add(executablePathExe);
			}

			PowerShellAdded = true;
		}

		if (CFAExclusionsToBeAdded.Count > 0)
		{
			// Convert the HashSet to a string array
			string[] CFAExclusionsToBeAddedArray = [.. CFAExclusionsToBeAdded];

			Add(CFAExclusionsToBeAddedArray);
		}
	}

	/// <summary>
	/// Restore the original Controlled Folder Access allowed applications list
	/// </summary>
	public static void Reset()
	{
		// Make sure the user as Admin privileges
		if (Environment.IsPrivilegedProcess)
		{
			// Since this method is called in multiple places, make sure it only runs once during app exit
			if (HasResetHappenedBefore)
			{
				return;
			}

			// restoring the original Controlled folder access allow list - if user already had added PowerShell executables to the list
			// they will be restored as well, so user customization will remain intact
			if (GlobalVars.CFABackup is not null && GlobalVars.CFABackup.Length > 0)
			{
				Logger.LogMessage("Restoring the original Controlled Folder Access allowed apps list", LogTypeIntel.Information);
				Set(applications: GlobalVars.CFABackup);
			}
			else
			{
				// If there was nothing to backup prior to adding the executables then clear the current list that contains the executables by removing everything it contains
				ControlledFolderAccessHandler.Remove(MpPreferenceHelper.GetMpPreference().ControlledFolderAccessAllowedApplications);
			}

			// Set this to true indicating CFA exclusion reset has already happened
			HasResetHappenedBefore = true;
		}

		// Set the variable to null after being done with it so subsequent attempts of this method won't run in the same session
		GlobalVars.CFABackup = null;
	}
}
