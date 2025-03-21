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
using AppControlManager.ViewModels;

namespace AppControlManager.Others;

/// <summary>
/// Represents a policy with various attributes
/// </summary>
internal sealed class CiPolicyInfo
{
	internal string? PolicyID { get; set; }           // Unique identifier for the policy
	internal string? BasePolicyID { get; set; }       // Identifier for the base policy
	internal string? FriendlyName { get; set; }       // Human-readable name of the policy
	internal Version? Version { get; set; }            // Version object representing the policy version
	internal string? VersionString { get; set; }       // Original version string from the policy data
	internal bool IsSystemPolicy { get; set; }         // Indicates if it's a system policy
	internal bool IsSignedPolicy { get; set; }         // Indicates if the policy is signed
	internal bool IsOnDisk { get; set; }               // Indicates if the policy is present on disk
	internal bool IsEnforced { get; set; }             // Indicates if the policy is enforced
	internal bool IsAuthorized { get; set; }           // Indicates if the policy is authorized
	internal List<string>? PolicyOptions { get; set; } // List of options or settings related to the policy


	// A property to format PolicyOptions as a comma-separated string
	internal string PolicyOptionsDisplay => PolicyOptions is not null ? string.Join(", ", PolicyOptions) : string.Empty;


	// A property for the parent view model of the ViewCurrentPolicies page to store a reference to it
	// so we can access the variables in the View Model class via compiled binding in XAML.
	internal ViewCurrentPoliciesVM? ParentViewModel { get; set; }
}
