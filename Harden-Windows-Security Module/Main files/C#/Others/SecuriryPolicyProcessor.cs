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
using System.Linq;

namespace HardenWindowsSecurity;

internal static class SecurityPolicyChecker
{
	/// <summary>
	/// The method is used to verify the compliance of security group policies on the system against the predefined values in the SecurityPoliciesVerification.csv
	/// </summary>
	/// <param name="category">The category to filter the CSV file content by</param>
	/// <returns></returns>
	internal static List<IndividualResult> CheckPolicyCompliance(ComplianceCategories category)
	{
		// Create a list of IndividualResult objects
		List<IndividualResult> nestedObjectArray = [];

		// Filter the CSV data to only get the records that match the input category
		List<SecurityPolicyRecord>? csvRecords = GlobalVars.SecurityPolicyRecords?
			.Where(record => record.Category == category)
			.ToList();

		// Ensure csvRecords is not null before iterating
		if (csvRecords is not null)
		{
			// Loop over each filtered CSV data
			foreach (SecurityPolicyRecord record in csvRecords)
			{
				string? section = record.Section;
				string? path = record.Path;
				string? expectedValue = record.Value;
				string? name = record.Name;

				bool complianceResult = false;

				string? actualValue = null;

				// Ensure SystemSecurityPoliciesIniObject is not null and check for section
				if (section is not null && // Check if section is not null
					GlobalVars.SystemSecurityPoliciesIniObject.TryGetValue(section, out Dictionary<string, string>? sectionDict) &&
					sectionDict is not null &&
					path is not null && // Check if path is not null
					sectionDict.TryGetValue(path, out string? value))
				{
					actualValue = value;
					complianceResult = actualValue == expectedValue;
				}

				nestedObjectArray.Add(new IndividualResult
				{
					FriendlyName = name ?? string.Empty,
					Compliant = complianceResult,
					Value = actualValue,
					Name = name ?? string.Empty,
					Category = category,
					Method = ConfirmSystemComplianceMethods.Method.SecurityGroupPolicy
				});
			}
		}
		else
		{
			throw new InvalidOperationException("CSV Records cannot be null.");
		}

		return nestedObjectArray;
	}
}
