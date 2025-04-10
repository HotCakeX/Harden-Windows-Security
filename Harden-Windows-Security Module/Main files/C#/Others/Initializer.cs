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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace HardenWindowsSecurity;

// prepares the environment. It also runs commands that would otherwise run in the default constructors of each method
public static class Initializer
{

	private static bool BitLockerInfrastructureAvailabilityCheckOccurred;
	internal static bool BitLockerInfrastructureAvailable;

	/// <summary>
	/// This method runs at the beginning of each cmdlet
	/// </summary>
	/// <param name="VerbosePreference"></param>
	/// <param name="IsConfirmationDuringRunTime"></param>
	/// <exception cref="InvalidOperationException"></exception>
	/// <exception cref="PlatformNotSupportedException"></exception>
	public static void Initialize(string? VerbosePreference = "SilentlyContinue", bool IsConfirmationDuringRunTime = false)
	{

		GlobalVars.LogHeaderHasBeenWritten = false;

		// Clear the log path in the Logger class, it should be set by each cmdlet that uses the -Log parameter every time
		Logger.LogFilePathCLI = null;

		// This check is only necessary to be performed once.
		// GlobalVars.path is set to non-nullable intentionally with pragma disable
		if (string.IsNullOrWhiteSpace(GlobalVars.path))
		{
			throw new InvalidOperationException("The PSScriptRoot variable hasn't been set!");
		}

		// Set the default culture to InvariantCulture globally
		CultureInfo.DefaultThreadCurrentCulture = CultureInfo.InvariantCulture;
		CultureInfo.DefaultThreadCurrentUICulture = CultureInfo.InvariantCulture;

		// Only perform these actions if the Compliance checking is not happening through the GUI in the middle of the operations
		if (!IsConfirmationDuringRunTime)
		{

			using (RegistryKey? key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion"))
			{
				if (key is not null)
				{
					object? ubrValue = key.GetValue("UBR");
					if (ubrValue is not null && int.TryParse(ubrValue.ToString(), out int ubr))
					{
						GlobalVars.UBR = ubr;
					}
					else
					{
						throw new InvalidOperationException("The UBR value could not be retrieved from the registry: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
					}
				}
				else
				{
					throw new InvalidOperationException("The UBR key does not exist in the registry path: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion");
				}
			}

			// Concatenate OSBuildNumber and UBR to form the final string
			GlobalVars.FullOSBuild = $"{GlobalVars.OSBuildNumber}.{GlobalVars.UBR}";

			// If the working directory exists, delete it
			if (Directory.Exists(GlobalVars.WorkingDir))
			{
				Directory.Delete(GlobalVars.WorkingDir, true);
			}

			// Create the working directory
			_ = Directory.CreateDirectory(GlobalVars.WorkingDir);

			// Clear the collection
			GlobalVars.RegistryCSVItems.Clear();

			// Parse the Registry.csv and save it to the global GlobalVars.RegistryCSVItems list
			HardeningRegistryKeys.ReadCsv();

			// Clear the collection
			GlobalVars.ProcessMitigations.Clear();

			// Parse the ProcessMitigations.csv and save it to the global GlobalVars.ProcessMitigations list
			ProcessMitigationsParser.ReadCsv();

			// Convert the FullOSBuild and RequiredBuild strings to decimals so that we can compare them
			if (!TryParseBuildVersion(GlobalVars.FullOSBuild, out decimal fullOSBuild))
			{
				throw new FormatException("The OS build version strings are not in a correct format.");
			}

			// Make sure the current OS build is equal or greater than the required build number
			if (!(fullOSBuild >= GlobalVars.requiredBuild))
			{
				throw new PlatformNotSupportedException($"You are not using the latest build of the Windows OS. A minimum build of {GlobalVars.requiredBuild} is required but your OS build is {fullOSBuild}\nPlease go to Windows Update to install the updates and then try again.");
			}

		}

		// Get the MSFT_MpPreference WMI results and save them to the global variable GlobalVars.MDAVPreferencesCurrent
		GlobalVars.MDAVPreferencesCurrent = MpPreferenceHelper.GetMpPreference();

		// Get the MSFT_MpComputerStatus and save them to the global variable GlobalVars.MDAVConfigCurrent
		GlobalVars.MDAVConfigCurrent = ConfigDefenderHelper.GetMpComputerStatus();

		// Total number of Compliant values
		GlobalVars.TotalNumberOfTrueCompliantValues = 263;

		// Getting the $VerbosePreference from the calling cmdlet and saving it in the global variable
		GlobalVars.VerbosePreference = VerbosePreference;

		// Clear the collection
		GlobalVars.FinalMegaObject.Clear();

		// Clear the collection
		GlobalVars.SystemSecurityPoliciesIniObject.Clear();

		if (Environment.IsPrivilegedProcess)
		{
			// Process the MDM related CimInstances and store them in a global variable
			GlobalVars.MDMResults = MDMClassProcessor.Process();

			if (!BitLockerInfrastructureAvailabilityCheckOccurred)
			{
				BitLockerInfrastructureAvailabilityCheckOccurred = true;

				_ = Task.Run(() =>
				{
					Logger.LogMessage("Checking for BitLocker infrastructure availability", LogTypeIntel.Information);

					Dictionary<string, string> features = WindowsFeatureChecker.GetOptionalFeatureStates();

					if (features.TryGetValue("BitLocker", out string? BitLockerStatus))
					{
						// On Server OS, BitLocker infra, including its CIM namespaces, are not available but they are available as optional features
						// On Client OS, BitLocker infra is available by default and not available as an optional feature
						if (string.Equals(BitLockerStatus, "Enabled", StringComparison.OrdinalIgnoreCase))
						{
							BitLockerInfrastructureAvailable = true;
							Logger.LogMessage("BitLocker infrastructure is available.", LogTypeIntel.Information);
						}
						else
						{
							Logger.LogMessage("BitLocker infrastructure is not available or enabled on this system", LogTypeIntel.Information);
						}
					}
					else
					{
						BitLockerInfrastructureAvailable = true;
						Logger.LogMessage("BitLocker infrastructure is available.", LogTypeIntel.Information);
					}
				});
			}
		}
	}

	// This method gracefully parses the OS build version strings to decimals
	// and performs this in a culture-independent way
	// in languages such as Swedish where the decimal separator is , instead of .
	// this will work properly
	// in PowerShell we can see the separator by running: (Get-Culture).NumberFormat.NumberDecimalSeparator
	private static bool TryParseBuildVersion(string buildVersion, out decimal result)
	{
		// Use CultureInfo.InvariantCulture for parsing
		return Decimal.TryParse(buildVersion, NumberStyles.Number, CultureInfo.InvariantCulture, out result);
	}

}
