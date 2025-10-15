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

namespace HardenSystemSecurity.Protect;

/// <summary>
/// The main categories for protection. The JSON files for each category must match this enum member names.
/// </summary>
internal enum Categories : uint
{
	MicrosoftSecurityBaseline = 0,
	Microsoft365AppsSecurityBaseline = 1,
	MicrosoftDefender = 2,
	AttackSurfaceReductionRules = 3,
	BitLockerSettings = 4,
	TLSSecurity = 5,
	LockScreen = 6,
	UserAccountControl = 7,
	DeviceGuard = 8,
	WindowsFirewall = 9,
	OptionalWindowsFeatures = 10,
	WindowsNetworking = 11,
	MiscellaneousConfigurations = 12,
	WindowsUpdateConfigurations = 13,
	EdgeBrowserConfigurations = 14,
	CertificateChecking = 15,
	CountryIPBlocking = 16,
	NonAdminCommands = 17,
	MSFTSecBaselines_OptionalOverrides = 18
}
