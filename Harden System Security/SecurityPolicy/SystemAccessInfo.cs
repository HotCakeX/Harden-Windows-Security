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

namespace HardenSystemSecurity.SecurityPolicy;

/// <summary>
/// Represents the policies defined in the [System Access]
/// </summary>
internal sealed class SystemAccessInfo
{
	internal int MinimumPasswordAge { get; set; }
	internal int MaximumPasswordAge { get; set; }
	internal int MinimumPasswordLength { get; set; }
	internal int PasswordComplexity { get; set; }
	internal int PasswordHistorySize { get; set; }
	internal int LockoutBadCount { get; set; }
	internal int ResetLockoutCount { get; set; }
	internal int LockoutDuration { get; set; }
	internal int AllowAdministratorLockout { get; set; }
	internal int RequireLogonToChangePassword { get; set; }
	internal int ForceLogoffWhenHourExpire { get; set; }
	internal string NewAdministratorName { get; set; } = string.Empty;
	internal string NewGuestName { get; set; } = string.Empty;
	internal int ClearTextPassword { get; set; }
	// internal int LSAAnonymousNameLookup { get; set; }  - Not sure how to retrieve this via API yet - reading the value from registry key is not accurate.
	internal int EnableAdminAccount { get; set; }
	internal int EnableGuestAccount { get; set; }
}
