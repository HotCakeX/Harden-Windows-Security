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

namespace AppControlManager.SiPolicy;

internal static class CustomPolicyCreator
{
	/// <summary>
	/// Creates an empty <see cref="SiPolicy"/> with minimal settings, serving as a vessel for new rules.
	/// </summary>
	/// <returns></returns>
	internal static SiPolicy CreateEmpty() => new(
			versionEx: "1.0.0.0",
			platformID: "{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}",
			policyID: "{7AE40A06-9CFC-47E7-A74C-0B6BC71E3B93}",
			basePolicyID: "{7AE40A06-9CFC-47E7-A74C-0B6BC71E3B93}",
			rules: [new(OptionType.EnabledUnsignedSystemIntegrityPolicy)],
			policyType: PolicyType.BasePolicy
		)
	{
		HvciOptions = 2,
		Settings = [
				new(provider: "AllHostIds", key: "AllKeys", valueName: "EnterpriseDefinedClsId", value: new(true)),
				new(provider: "PolicyInfo", key: "Information", valueName: "Id", value: new("129661"))
				]
	};

}
