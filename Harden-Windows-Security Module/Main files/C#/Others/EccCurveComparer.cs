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
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;

namespace HardenWindowsSecurity;

internal static class EccCurveComparer
{
	/// <summary>
	/// This method gets the currently applied ECC Curves from the system using PowerShell and evaluates them against the hardcoded list
	/// The comparison takes into account the exact position of the curves as well.
	/// </summary>
	/// <returns></returns>
	internal static EccCurveComparisonResult GetEccCurveComparison()
	{
		// Get current ECC curves from PowerShell and store them in a list
		List<string> currentEccCurves = GetCurrentEccCurves();

		// List of compliant ECC curves to compare against
		List<string> compliantEccCurves = ["nistP521", "curve25519", "NistP384", "NistP256"];

		// Compare both arrays for equality in terms of members and their exact position
		bool areCurvesCompliant = currentEccCurves.SequenceEqual(compliantEccCurves, StringComparer.OrdinalIgnoreCase);

		// Create and return the result object
		return new EccCurveComparisonResult(areCurvesCompliant: areCurvesCompliant, currentEccCurves: currentEccCurves);
	}

	private static readonly char[] separator = [' ', '\r', '\n'];

	// Get the current ECC curves from the system
	private static List<string> GetCurrentEccCurves()
	{
		// List to store the current ECC curves
		List<string> currentEccCurvesToOutput = [];

		// Initialize PowerShell instance
		using (PowerShell powerShell = PowerShell.Create())
		{
			// Add the PowerShell command to get ECC curves
			_ = powerShell.AddCommand("Get-TlsEccCurve");

			// Execute the command and get the result
			Collection<PSObject?> results = powerShell.Invoke();

			// Extract the ECC curves from the results
			foreach (PSObject? result in results)
			{
				// Make sure the result is not null
				if (result is not null)
				{
					// Split the result string into an array of substrings based on specified delimiters
					// new[] { ' ', '\r', '\n' } - An array of characters to use as delimiters: space, carriage return, and newline
					// StringSplitOptions.RemoveEmptyEntries - An option to remove empty entries from the result array
					string[] curves = result.ToString().Split(separator, StringSplitOptions.RemoveEmptyEntries);
					currentEccCurvesToOutput.AddRange(curves);
				}
			}
		}

		return currentEccCurvesToOutput;
	}
}
