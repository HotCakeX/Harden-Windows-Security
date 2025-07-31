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

internal enum SubCategories : uint
{
	MSDefender_SmartAppControl = 0,
	MSDefender_BetaUpdateChannelsForDefender = 1,
	MSDefender_OptionalDiagnosticData = 2,
	DeviceGuard_MandatoryModeForVBS = 3,
	TLS_ForBattleNet = 4,
	LockScreen_RequireCTRLAltDel = 5,
	LockScreen_NoLastSignedIn = 6,
	UAC_NoFastUserSwitching = 7,
	UAC_OnlyElevateSigned = 8,
	WindowsNetworking_BlockNTLM = 9,
	MiscellaneousConfigurations_EnableWindowsProtectedPrint = 10,
	MiscellaneousConfigurations_EnableLongPathSupport = 11,
	MiscellaneousConfigurations_ForceStrongKeyProtection = 12,
	MiscellaneousConfigurations_ReducedTelemetry = 13,
	CountryIPBlocking_BlockOFACSanctionedCountries = 14
}
